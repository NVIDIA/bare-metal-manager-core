/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Managed-switch decommissioning.

use carbide_redfish::libredfish::RedfishAuth;
use carbide_uuid::switch::SwitchId;
use component_manager::nv_switch_manager::SwitchFactoryResetState;
use libredfish::model::service_root::RedfishVendor;
use mac_address::MacAddress;
use model::bmc_suppression::{BmcSuppressionSubsystem, NewBmcSuppression};
use model::component_manager::PowerAction;
use model::switch::{
    Switch, SwitchControllerState, SwitchDecommissioningState, VerifyNvosDhcpReleaseState,
};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::SwitchStateHandlerContextObjects;
use crate::endpoint::resolve_switch_endpoint;

fn decommissioning(state: SwitchDecommissioningState) -> SwitchControllerState {
    SwitchControllerState::Decommissioning {
        decommissioning_state: state,
    }
}

fn missing_data(switch_id: &SwitchId, missing: &'static str) -> StateHandlerError {
    StateHandlerError::MissingData {
        object_id: switch_id.to_string(),
        missing,
    }
}

fn external_error(operation: &str, error: impl std::fmt::Display) -> StateHandlerError {
    StateHandlerError::GenericError(eyre::eyre!("{operation}: {error}"))
}

async fn suppress_dhcp(
    switch_id: &SwitchId,
    mac_address: MacAddress,
    interface: &str,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<sqlx::PgTransaction<'static>, StateHandlerError> {
    let mut txn = ctx.services.db_pool.begin().await?;
    db::bmc_suppression::upsert(
        &mut txn,
        &NewBmcSuppression {
            bmc_mac_address: mac_address,
            subsystem: BmcSuppressionSubsystem::Dhcp,
            reason: format!(
                "managed switch {switch_id} is being decommissioned; suppressing {interface} DHCP"
            ),
        },
    )
    .await?;
    Ok(txn)
}

async fn dhcp_suppression_acknowledged(
    mac_address: MacAddress,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<bool, StateHandlerError> {
    Ok(db::bmc_suppression::find(
        &ctx.services.db_pool,
        mac_address,
        BmcSuppressionSubsystem::Dhcp,
    )
    .await?
    .is_some_and(|suppression| suppression.acknowledged_at.is_some()))
}

pub(super) async fn handle_decommissioning(
    switch_id: &SwitchId,
    switch: &Switch,
    decommissioning_state: &SwitchDecommissioningState,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    match decommissioning_state {
        SwitchDecommissioningState::Preparing => handle_preparing(switch_id, ctx),
        SwitchDecommissioningState::FactoryResetNvos { job_id } => {
            handle_factory_reset_nvos(switch_id, job_id.as_deref(), ctx).await
        }
        SwitchDecommissioningState::VerifyNvosDhcpRelease { verifying_state } => {
            handle_verify_nvos_dhcp_release(switch_id, verifying_state, ctx).await
        }
        SwitchDecommissioningState::FactoryResetBmc => {
            handle_factory_reset_bmc(switch_id, switch, ctx).await
        }
        SwitchDecommissioningState::VerifyDhcpRelease => {
            handle_verify_dhcp_release(switch_id, switch, ctx).await
        }
        SwitchDecommissioningState::Decommissioned => Ok(StateHandlerOutcome::do_nothing()),
    }
}

fn handle_preparing(
    switch_id: &SwitchId,
    ctx: &StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let component_manager = ctx.services.component_manager.as_ref().ok_or_else(|| {
        StateHandlerError::InvalidState(format!(
            "switch {switch_id} requires the RMS component-manager backend for decommissioning"
        ))
    })?;
    if component_manager.nv_switch.name() != "rms" {
        return Err(StateHandlerError::InvalidState(format!(
            "switch {switch_id} requires the RMS component-manager backend for decommissioning; configured backend is {}",
            component_manager.nv_switch.name()
        )));
    }

    Ok(StateHandlerOutcome::transition(decommissioning(
        SwitchDecommissioningState::FactoryResetNvos { job_id: None },
    )))
}

async fn handle_factory_reset_nvos(
    switch_id: &SwitchId,
    job_id: Option<&str>,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let component_manager = ctx.services.component_manager.clone().ok_or_else(|| {
        StateHandlerError::InvalidState(format!(
            "switch {switch_id} requires the RMS component-manager backend for decommissioning"
        ))
    })?;

    if let Some(job_id) = job_id {
        let status = component_manager
            .nv_switch
            .get_switch_factory_reset_job_status(job_id)
            .await
            .map_err(|error| external_error("failed to read NVOS factory-reset job", error))?;
        return match status.state {
            SwitchFactoryResetState::Pending => Ok(StateHandlerOutcome::wait(format!(
                "waiting for NVOS factory-reset job {job_id}"
            ))),
            SwitchFactoryResetState::Completed => Ok(StateHandlerOutcome::transition(
                decommissioning(SwitchDecommissioningState::VerifyNvosDhcpRelease {
                    verifying_state: VerifyNvosDhcpReleaseState::ForceRestarting,
                }),
            )),
            SwitchFactoryResetState::Failed => {
                Err(StateHandlerError::ManualInterventionRequired(format!(
                    "NVOS factory-reset job {job_id} failed{}",
                    status
                        .error
                        .as_deref()
                        .map(|error| format!(": {error}"))
                        .unwrap_or_default()
                )))
            }
        };
    }

    let endpoint = resolve_switch_endpoint(
        switch_id,
        &ctx.services.db_pool,
        &ctx.services.credential_manager,
    )
    .await?;
    let tls_server_domain = endpoint.nvos_host_name.clone();
    let job_id = component_manager
        .nv_switch
        .batch_reset_switch_factory_default(&[endpoint], tls_server_domain.as_deref())
        .await
        .map_err(|error| external_error("failed to submit NVOS factory reset", error))?;
    Ok(StateHandlerOutcome::transition(decommissioning(
        SwitchDecommissioningState::FactoryResetNvos {
            job_id: Some(job_id),
        },
    )))
}

async fn handle_verify_nvos_dhcp_release(
    switch_id: &SwitchId,
    verifying_state: &VerifyNvosDhcpReleaseState,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let endpoint = resolve_switch_endpoint(
        switch_id,
        &ctx.services.db_pool,
        &ctx.services.credential_manager,
    )
    .await?;
    match verifying_state {
        VerifyNvosDhcpReleaseState::ForceRestarting => {
            let component_manager = ctx.services.component_manager.as_ref().ok_or_else(|| {
                StateHandlerError::InvalidState(format!(
                    "switch {switch_id} requires the RMS component-manager backend for decommissioning"
                ))
            })?;
            let result = component_manager
                .nv_switch
                .power_control(std::slice::from_ref(&endpoint), PowerAction::ForceRestart)
                .await
                .map_err(|error| external_error("failed to force restart NVOS", error))?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "component manager returned no force-restart result for switch {switch_id}"
                    ))
                })?;
            if !result.success {
                return Err(StateHandlerError::GenericError(eyre::eyre!(
                    "failed to force restart NVOS for switch {switch_id}: {}",
                    result.error.as_deref().unwrap_or("unknown error")
                )));
            }

            let txn = suppress_dhcp(switch_id, endpoint.nvos_mac, "NVOS", ctx).await?;
            Ok(StateHandlerOutcome::transition(decommissioning(
                SwitchDecommissioningState::VerifyNvosDhcpRelease {
                    verifying_state: VerifyNvosDhcpReleaseState::WaitingForDhcpAcknowledgement,
                },
            ))
            .with_txn(txn))
        }
        VerifyNvosDhcpReleaseState::WaitingForDhcpAcknowledgement => {
            if !dhcp_suppression_acknowledged(endpoint.nvos_mac, ctx).await? {
                return Ok(StateHandlerOutcome::wait(
                    "waiting for NVOS DHCP suppression acknowledgement".to_string(),
                ));
            }

            Ok(StateHandlerOutcome::transition(decommissioning(
                SwitchDecommissioningState::FactoryResetBmc,
            )))
        }
    }
}

async fn handle_factory_reset_bmc(
    switch_id: &SwitchId,
    switch: &Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let bmc_info = switch
        .bmc_info
        .as_ref()
        .ok_or_else(|| missing_data(switch_id, "bmc_info"))?;
    let bmc_ip_address = bmc_info
        .ip
        .ok_or_else(|| missing_data(switch_id, "bmc_ip"))?;
    let bmc_mac_address = bmc_info
        .mac
        .ok_or_else(|| missing_data(switch_id, "bmc_mac"))?;

    let redfish_client = ctx
        .services
        .redfish_client_pool
        .create_client(
            &bmc_ip_address.to_string(),
            bmc_info.port,
            RedfishAuth::for_bmc_mac(bmc_mac_address),
            Some(RedfishVendor::NvidiaGBSwitch),
        )
        .await
        .map_err(|error| external_error("failed to create switch BMC Redfish client", error))?;
    redfish_client
        .bmc_reset_to_defaults()
        .await
        .map_err(|error| external_error("failed to factory reset switch BMC", error))?;
    let txn = suppress_dhcp(switch_id, bmc_mac_address, "BMC", ctx).await?;

    Ok(StateHandlerOutcome::transition(decommissioning(
        SwitchDecommissioningState::VerifyDhcpRelease,
    ))
    .with_txn(txn))
}

async fn handle_verify_dhcp_release(
    switch_id: &SwitchId,
    switch: &Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let bmc_mac_address = switch
        .bmc_info
        .as_ref()
        .and_then(|bmc_info| bmc_info.mac)
        .ok_or_else(|| missing_data(switch_id, "bmc_mac"))?;
    if !dhcp_suppression_acknowledged(bmc_mac_address, ctx).await? {
        return Ok(StateHandlerOutcome::wait(
            "waiting for BMC DHCP suppression acknowledgement".to_string(),
        ));
    }

    Ok(StateHandlerOutcome::transition(decommissioning(
        SwitchDecommissioningState::Decommissioned,
    )))
}
