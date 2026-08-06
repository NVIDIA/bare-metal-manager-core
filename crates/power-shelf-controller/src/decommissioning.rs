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

//! Managed power-shelf decommissioning handlers.

use carbide_credential_rotation::BmcEndpoint;
use carbide_utils::redfish::BmcAccessInfo;
use carbide_uuid::power_shelf::PowerShelfId;
use model::bmc_suppression::{BmcSuppressionSubsystem, NewBmcSuppression};
use model::power_shelf::{
    PowerShelf, PowerShelfControllerState, PowerShelfVerifyingDhcpReleaseState,
};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::PowerShelfStateHandlerContextObjects;

fn bmc_mac(power_shelf: &PowerShelf) -> Result<mac_address::MacAddress, StateHandlerError> {
    power_shelf
        .bmc_info
        .as_ref()
        .and_then(|info| info.mac)
        .or(power_shelf.bmc_mac_address)
        .ok_or_else(|| StateHandlerError::MissingData {
            object_id: power_shelf.id.to_string(),
            missing: "bmc_mac",
        })
}

pub(super) async fn handle_preparing(
    power_shelf_id: &PowerShelfId,
    power_shelf: &PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    let mut txn = ctx.services.db_pool.begin().await?;
    let suppression = db::bmc_suppression::upsert(
        &mut txn,
        &NewBmcSuppression {
            bmc_mac_address: bmc_mac(power_shelf)?,
            subsystem: BmcSuppressionSubsystem::SiteExplorer,
            reason: format!("power shelf {power_shelf_id} is being decommissioned"),
        },
    )
    .await?;

    let outcome = if suppression.acknowledged_at.is_some() {
        StateHandlerOutcome::transition(PowerShelfControllerState::VerifyingDhcpRelease {
            verifying_state: PowerShelfVerifyingDhcpReleaseState::FactoryResetBmc,
        })
    } else {
        StateHandlerOutcome::wait(
            "waiting for Site Explorer suppression acknowledgement".to_string(),
        )
    };
    Ok(outcome.with_txn(txn))
}

async fn handle_factory_reset_bmc(
    power_shelf_id: &PowerShelfId,
    power_shelf: &PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    let endpoint = BmcEndpoint::from_power_shelf(power_shelf).ok_or_else(|| {
        StateHandlerError::MissingData {
            object_id: power_shelf_id.to_string(),
            missing: "addressable_bmc",
        }
    })?;
    let access = BmcAccessInfo {
        host: endpoint.host,
        port: endpoint.port,
        mac_address: endpoint.device_mac,
    };
    ctx.services
        .redfish_client_pool
        .client_by_info(&access)
        .await
        .map_err(|error| {
            StateHandlerError::GenericError(eyre::eyre!(
                "failed to create Redfish client for power shelf {power_shelf_id}: {error}"
            ))
        })?
        .bmc_reset_to_defaults()
        .await
        .map_err(|error| {
            StateHandlerError::GenericError(eyre::eyre!(
                "failed to factory reset BMC for power shelf {power_shelf_id}: {error}"
            ))
        })?;

    let mut txn = ctx.services.db_pool.begin().await?;
    db::bmc_suppression::upsert(
        &mut txn,
        &NewBmcSuppression {
            bmc_mac_address: access.mac_address,
            subsystem: BmcSuppressionSubsystem::Dhcp,
            reason: format!(
                "power shelf {power_shelf_id} is being decommissioned; suppressing BMC DHCP"
            ),
        },
    )
    .await?;
    db::machine_interface::record_deletion(&mut txn).await?;

    Ok(
        StateHandlerOutcome::transition(PowerShelfControllerState::VerifyingDhcpRelease {
            verifying_state: PowerShelfVerifyingDhcpReleaseState::WaitingForBmcDhcpAcknowledgement,
        })
        .with_txn(txn),
    )
}

pub(super) async fn handle_verifying_dhcp_release(
    verifying_state: &PowerShelfVerifyingDhcpReleaseState,
    power_shelf: &PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    if matches!(
        verifying_state,
        PowerShelfVerifyingDhcpReleaseState::FactoryResetBmc
    ) {
        return handle_factory_reset_bmc(&power_shelf.id, power_shelf, ctx).await;
    }

    let suppression = db::bmc_suppression::find(
        &ctx.services.db_pool,
        bmc_mac(power_shelf)?,
        BmcSuppressionSubsystem::Dhcp,
    )
    .await?;

    if suppression.is_some_and(|suppression| suppression.acknowledged_at.is_some()) {
        Ok(StateHandlerOutcome::transition(
            PowerShelfControllerState::Decommissioned,
        ))
    } else {
        Ok(StateHandlerOutcome::wait(
            "waiting for BMC DHCP suppression acknowledgement after factory reset".to_string(),
        ))
    }
}
