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

//! Handler for SwitchControllerState::Configuring.

use carbide_secrets::credentials::{CredentialKey, Credentials};
use carbide_uuid::switch::SwitchId;
use model::switch::{ConfigureCertificateState, ConfiguringState, Switch, SwitchControllerState};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::certificate::{
    ConfigureSwitchCertificateMode, StartConfigureSwitchCertificateResult,
    poll_configure_switch_certificate_job, start_configure_switch_certificate,
};
use crate::context::SwitchStateHandlerContextObjects;

/// Handles the Configuring state for a switch.
pub async fn handle_configuring(
    switch_id: &SwitchId,
    state: &mut Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let config_state = match &state.controller_state.value {
        SwitchControllerState::Configuring { config_state } => config_state.clone(),
        _ => unreachable!("handle_configuring called with non-Configuring state"),
    };

    match config_state {
        ConfiguringState::ConfigureCertificate {
            configure_certificate,
        } => handle_configure_certificate(switch_id, state, ctx, configure_certificate).await,
        ConfiguringState::RotateOsPassword => {
            handle_rotate_os_password(switch_id, state, ctx).await
        }
    }
}

async fn handle_rotate_os_password(
    switch_id: &SwitchId,
    state: &mut Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let Some(bmc_mac_address) = state.bmc_mac_address else {
        return Ok(StateHandlerOutcome::transition(
            SwitchControllerState::Error {
                cause: "No BMC MAC address on switch".to_string(),
            },
        ));
    };

    let key = CredentialKey::SwitchNvosAdmin { bmc_mac_address };

    if let Ok(Some(Credentials::UsernamePassword { .. })) =
        ctx.services.credential_manager.get_credentials(&key).await
    {
        tracing::info!(
            switch_id = ?switch_id,
            bmc_mac_address = %bmc_mac_address,
            "Switch: NVOS admin credentials already exist in vault",
        );
        return Ok(StateHandlerOutcome::transition(
            SwitchControllerState::FetchInfo,
        ));
    }

    let outcome = StateHandlerOutcome::transition(SwitchControllerState::FetchInfo);

    // REQ-6 (set NVOS from factory) is not implemented yet, so this is gated off.
    // Today NICo does not change the NVOS password from the factory default: it
    // only copies the operator-provided credential into Vault (the `else` branch)
    // so the rest of NICo can authenticate, and records no rotation convergence
    // (the backfill skips `nvos` for the same reason). When REQ-6 lands, flip
    // `update_device_password` to `true`: that branch rotates the password on the
    // switch, stores the resulting NICo-owned credential, and records `nvos`
    // convergence (keyed by BMC MAC) committed atomically with the transition.
    //
    // IMPORTANT: before flipping this on, REQ-6 must also seed a
    // `sitewide_credential_rotation` row for `nvos` (via the backfill migration
    // or at runtime). `record_device_converged` now requires the site-wide
    // target to exist and returns `MissingSitewideRotationTarget` otherwise --
    // unlike the other credential types, nvos has no backfilled row today, so
    // ungating without seeding it would make every switch fail here.
    let update_device_password = false;
    if update_device_password {
        let mut txn = ctx.services.db_pool.begin().await?;

        // TODO(REQ-6): rotate the NVOS password on the switch here (factory ->
        // NICo-owned) and store the resulting credential in Vault before recording
        // convergence below. Only once the password is actually changed on the
        // device has the switch converged to the current nvos target.
        db::credential_rotation::record_device_converged(
            &mut txn,
            bmc_mac_address,
            db::credential_rotation::CredentialRotationType::Nvos,
        )
        .await
        .map_err(|e| {
            StateHandlerError::GenericError(eyre::eyre!(
                "switch {:?}: failed to record nvos rotation convergence: {}",
                switch_id,
                e
            ))
        })?;

        Ok(outcome.with_txn(txn))
    } else {
        // Copy the operator-provided NVOS admin credential from the expected
        // switch into Vault. This does not touch the switch, so no convergence is
        // recorded.
        let mut txn = ctx.services.db_pool.begin().await?;
        let expected_switch =
            db::expected_switch::find_by_bmc_mac_address(&mut txn, bmc_mac_address).await?;
        txn.commit().await?;

        let expected_switch = match expected_switch {
            Some(es) => es,
            None => {
                return Ok(StateHandlerOutcome::transition(
                    SwitchControllerState::Error {
                        cause: format!("No expected switch found for BMC MAC {}", bmc_mac_address),
                    },
                ));
            }
        };

        let (username, password) =
            match (expected_switch.nvos_username, expected_switch.nvos_password) {
                (Some(username), Some(password)) => (username, password),
                _ => {
                    tracing::info!(
                        switch_id = ?switch_id,
                        bmc_mac_address = %bmc_mac_address,
                        "Switch: no NVOS credentials in vault or expected switch; skipping",
                    );
                    return Ok(outcome);
                }
            };

        let credentials = Credentials::UsernamePassword { username, password };

        ctx.services
            .credential_manager
            .set_credentials(&key, &credentials)
            .await
            .map_err(|e| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "switch {:?}: failed to store NVOS credentials in vault: {}",
                    switch_id,
                    e
                ))
            })?;

        tracing::info!(
            switch_id = ?switch_id,
            bmc_mac_address = %bmc_mac_address,
            "Switch: stored NVOS admin credentials from expected switch into vault",
        );

        Ok(outcome)
    }
}

async fn handle_configure_certificate(
    switch_id: &SwitchId,
    state: &mut Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
    configure_certificate: ConfigureCertificateState,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    match configure_certificate {
        ConfigureCertificateState::Start => {
            handle_configure_certificate_start(switch_id, state, ctx).await
        }
        ConfigureCertificateState::WaitForComplete { job_id } => {
            handle_configure_certificate_wait_for_complete(switch_id, ctx, &job_id).await
        }
    }
}

async fn handle_configure_certificate_start(
    switch_id: &SwitchId,
    state: &Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    match start_configure_switch_certificate(
        switch_id,
        state,
        ctx,
        None,
        ConfigureSwitchCertificateMode::BringUp,
    )
    .await?
    {
        StartConfigureSwitchCertificateResult::EarlyTransition(outcome) => Ok(outcome),
        StartConfigureSwitchCertificateResult::JobStarted(job_id) => Ok(
            StateHandlerOutcome::transition(SwitchControllerState::Configuring {
                config_state: ConfiguringState::ConfigureCertificate {
                    configure_certificate: ConfigureCertificateState::WaitForComplete { job_id },
                },
            }),
        ),
    }
}

async fn handle_configure_certificate_wait_for_complete(
    switch_id: &SwitchId,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
    job_id: &str,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    match poll_configure_switch_certificate_job(switch_id, ctx, job_id).await? {
        crate::certificate::ConfigureSwitchCertificatePollOutcome::Completed => {
            tracing::info!(
                %job_id,
                switch_id = ?switch_id,
                "Switch: switch certificate configuration completed",
            );
            Ok(StateHandlerOutcome::transition(
                SwitchControllerState::Configuring {
                    config_state: ConfiguringState::RotateOsPassword,
                },
            ))
        }
        crate::certificate::ConfigureSwitchCertificatePollOutcome::Failed(cause) => Ok(
            StateHandlerOutcome::transition(SwitchControllerState::Error { cause }),
        ),
        crate::certificate::ConfigureSwitchCertificatePollOutcome::InProgress => Ok(
            StateHandlerOutcome::wait(format!("switch certificate job {job_id} in progress")),
        ),
    }
}
