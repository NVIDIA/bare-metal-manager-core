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

//! Power-shelf-controller BMC (PMC) credential rotation (REQ-2).
//!
//! The shared [`carbide_credential_rotation`] engine owns the password dance,
//! backoff, and crash-safety; this module is the thin power-shelf-controller
//! adapter, mirroring the switch-controller's `rotating_bmc.rs`. A power shelf
//! has exactly one BMC (its PMC), so there is no per-device fan-out: one
//! endpoint, one [`rotate_bmc`] call per tick.
//!
//! - *Should we enter rotation?* [`should_enter_bmc_rotation`] honors an operator
//!   force-converge request first (even when the site-wide flag is off), then the
//!   passive gate (`bmc_rotation_enabled` && the cached [`BmcRotationGate`] says
//!   the PMC lags the staged target).
//! - *Do one rotation tick.* [`handle_rotating_bmc`] converges the PMC via
//!   [`rotate_bmc`], folds the outcome through the shared state-neutral
//!   [`advance`] retry seam, and returns to `Ready` (clearing a satisfied force
//!   request) or re-enters `RotatingBmc` with an incremented retry budget.
//!
//! Unlike the switch path (all NVIDIA MGX, so a fixed dispatch vendor), a power
//! shelf's Lite-On/Delta PMC vendor is not persisted and is not exposed in the
//! Redfish service root, so the engine probes it at rotation time
//! ([`BmcEndpoint::into_target_probing_vendor`]) -- the repo's standard
//! power-shelf vendor determination.
//!
//! A BMC password change never touches the power shelf's power delivery, so this
//! is safe in `Ready`.

use carbide_credential_rotation::{
    BmcEndpoint, BmcRotationTick, RotateOutcome, RotationStep, advance, rotate_bmc,
};
use carbide_uuid::power_shelf::PowerShelfId;
use model::power_shelf::{PowerShelf, PowerShelfControllerState};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::{PowerShelfStateHandlerContextObjects, PowerShelfStateHandlerServices};

/// Whether a Ready power shelf should enter `PowerShelfControllerState::RotatingBmc`
/// now.
///
/// An operator force-converge request always wins -- the ops escape hatch is
/// honored even when the site-wide flag is off. Otherwise the passive gate fires
/// only when BMC rotation is enabled site-wide *and* the PMC lags the staged
/// target; the flag is checked first so a disabled site never runs the per-device
/// gate query.
pub async fn should_enter_bmc_rotation(
    services: &PowerShelfStateHandlerServices,
    power_shelf: &PowerShelf,
) -> Result<bool, StateHandlerError> {
    if power_shelf.bmc_credential_rotation_requested {
        return Ok(true);
    }
    if !services.bmc_rotation_enabled {
        return Ok(false);
    }
    let Some(endpoint) = BmcEndpoint::from_power_shelf(power_shelf) else {
        return Ok(false);
    };
    services
        .bmc_rotation_gate
        .bmc_rotation_needed(&services.db_pool, endpoint.device_mac)
        .await
        .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("bmc rotation gate query: {e}")))
}

/// Run one rotation tick over the power shelf's PMC and decide the next state.
///
/// `force` (an operator escape-hatch request on this power shelf row) bypasses
/// the device's backoff quarantine inside [`rotate_bmc`]. A settled tick returns
/// to `Ready` and clears a satisfied force request; a transient bookkeeping
/// failure re-enters `RotatingBmc` bounded by the shared retry budget; an
/// exhausted budget (`GaveUp`) returns to `Ready` but leaves a pending force
/// request set so the entry guard re-attempts on a later sweep.
pub async fn handle_rotating_bmc(
    power_shelf_id: &PowerShelfId,
    power_shelf: &PowerShelf,
    retry_count: u32,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    let force = power_shelf.bmc_credential_rotation_requested;

    let tick = match BmcEndpoint::from_power_shelf(power_shelf) {
        Some(endpoint) => rotate_power_shelf_bmc(ctx.services, endpoint, force).await,
        // A forced request announces a missing PMC so its one-shot flag still
        // clears; a passive sweep silently settles an unaddressable power shelf
        // (the entry guard never selects it).
        None => {
            if force {
                tracing::warn!(
                    %power_shelf_id,
                    "force-converge request on a power shelf with no addressable BMC; clearing the request without action"
                );
            }
            BmcRotationTick::Settled
        }
    };

    match advance(tick, retry_count, power_shelf_id) {
        step @ (RotationStep::Settled | RotationStep::GaveUp) => {
            // Only a settled tick clears a one-shot force request: the forced
            // attempt genuinely fired. GaveUp exhausted the transient-retry
            // budget without the forced attempt cleanly running, so leave the
            // flag set and let the entry guard re-attempt on a later sweep rather
            // than silently drop the operator's request.
            let txn = if force && matches!(step, RotationStep::Settled) {
                let mut t = ctx.services.db_pool.begin().await?;
                db::power_shelf::clear_bmc_credential_rotation_requested(&mut t, *power_shelf_id)
                    .await?;
                Some(t)
            } else {
                None
            };
            Ok(StateHandlerOutcome::transition(PowerShelfControllerState::Ready).with_txn_opt(txn))
        }
        RotationStep::Retry { retry_count } => Ok(StateHandlerOutcome::transition(
            PowerShelfControllerState::RotatingBmc { retry_count },
        )),
    }
}

/// Rotate the power shelf's PMC toward the staged target. `force` bypasses the
/// device's backoff quarantine (operator escape hatch). Returns
/// [`BmcRotationTick::Retry`] only on a transient bookkeeping error; device
/// faults are quarantined inside [`rotate_bmc`] and reported as `Settled`.
async fn rotate_power_shelf_bmc(
    services: &PowerShelfStateHandlerServices,
    endpoint: BmcEndpoint,
    force: bool,
) -> BmcRotationTick {
    // A power shelf's Lite-On/Delta PMC vendor is neither persisted nor exposed
    // in the Redfish service root, so the engine resolves it at rotation time by
    // probing the Chassis manufacturer (the repo's standard power-shelf vendor
    // determination). The probe runs inside the engine's quarantine-on-failure
    // envelope, so a failed probe records backoff rather than looping the guard.
    let target = endpoint.into_target_probing_vendor();
    match rotate_bmc(
        &services.db_pool,
        services.credential_manager.as_ref(),
        services.redfish_client_pool.as_ref(),
        &target,
        force,
    )
    .await
    {
        Ok(RotateOutcome::Converged) => {
            tracing::info!(mac = %target.device_mac, force, "power shelf BMC (PMC) converged to site-wide rotation target");
            BmcRotationTick::Settled
        }
        Ok(RotateOutcome::Quarantined { until }) => {
            tracing::warn!(
                mac = %target.device_mac,
                %until,
                "power shelf BMC (PMC) rotation attempt failed; quarantined until backoff elapses"
            );
            BmcRotationTick::Settled
        }
        Ok(RotateOutcome::NoWork) => BmcRotationTick::Settled,
        Err(e) => {
            tracing::warn!(
                mac = %target.device_mac,
                error = %e,
                "transient power shelf BMC (PMC) rotation bookkeeping failure; will retry the tick"
            );
            BmcRotationTick::Retry
        }
    }
}
