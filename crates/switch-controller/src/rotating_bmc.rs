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

//! Switch-controller BMC credential rotation (REQ-2).
//!
//! The shared [`carbide_credential_rotation`] engine owns the password dance,
//! backoff, and crash-safety; this module is the thin switch-controller adapter,
//! mirroring the machine-controller's `rotation.rs`. A switch has exactly one
//! BMC, so there is no per-device fan-out: one endpoint, one [`rotate_bmc`] call
//! per tick.
//!
//! - *Should we enter rotation?* [`should_enter_bmc_rotation`] honors an operator
//!   force-converge request first (even when the site-wide flag is off), then the
//!   passive gate (`bmc_rotation_enabled` && the cached [`BmcRotationGate`] says
//!   the BMC lags the staged target).
//! - *Do one rotation tick.* [`handle_rotating_bmc`] converges the switch BMC via
//!   [`rotate_bmc`], folds the outcome through the shared state-neutral
//!   [`advance`] retry seam, and returns to `Ready` (clearing a satisfied force
//!   request) or re-enters `RotatingBmc` with an incremented retry budget.
//!
//! A BMC password change never touches the switch data plane, so this is safe in
//! `Ready`.

use carbide_credential_rotation::{
    BmcEndpoint, BmcRotationTick, RotateOutcome, RotationStep, advance, rotate_bmc,
};
use carbide_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
use carbide_uuid::switch::SwitchId;
use libredfish::model::service_root::RedfishVendor;
use mac_address::MacAddress;
use model::switch::{Switch, SwitchControllerState};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::{SwitchStateHandlerContextObjects, SwitchStateHandlerServices};

/// Whether a Ready switch should enter `SwitchControllerState::RotatingBmc` now.
///
/// An operator force-converge request always wins -- the ops escape hatch is
/// honored even when the site-wide flag is off. Otherwise the passive gate fires
/// only when BMC rotation is enabled site-wide *and* the BMC lags the staged
/// target; the flag is checked first so a disabled site never runs the per-device
/// gate query.
pub async fn should_enter_bmc_rotation(
    services: &SwitchStateHandlerServices,
    switch: &Switch,
) -> Result<bool, StateHandlerError> {
    if switch.bmc_credential_rotation_requested {
        return Ok(true);
    }
    if !services.bmc_rotation_enabled {
        return Ok(false);
    }
    let Some(endpoint) = BmcEndpoint::from_switch(switch.bmc_info.as_ref()) else {
        return Ok(false);
    };
    services
        .bmc_rotation_gate
        .bmc_rotation_needed(&services.db_pool, endpoint.device_mac)
        .await
        .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("bmc rotation gate query: {e}")))
}

/// Run one rotation tick over the switch BMC and decide the next state.
///
/// `force` (an operator escape-hatch request on this switch row) bypasses the
/// device's backoff quarantine inside [`rotate_bmc`]. A settled tick returns to
/// `Ready` and clears a satisfied force request; a transient bookkeeping failure
/// re-enters `RotatingBmc` bounded by the shared retry budget; an exhausted
/// budget (`GaveUp`) returns to `Ready` but leaves a pending force request set so
/// the entry guard re-attempts on a later sweep.
pub async fn handle_rotating_bmc(
    switch_id: &SwitchId,
    switch: &Switch,
    retry_count: u32,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let force = switch.bmc_credential_rotation_requested;

    let tick = match BmcEndpoint::from_switch(switch.bmc_info.as_ref()) {
        Some(endpoint) => rotate_switch_bmc(ctx.services, endpoint, force).await,
        // A forced request announces a missing BMC so its one-shot flag still
        // clears; a passive sweep silently settles an unaddressable switch (the
        // entry guard never selects it).
        None if force => {
            tracing::warn!(
                %switch_id,
                "force-converge request on a switch with no addressable BMC; clearing the request without action"
            );
            BmcRotationTick::Settled
        }
        None => BmcRotationTick::Settled,
    };

    match advance(tick, retry_count, switch_id) {
        step @ (RotationStep::Settled | RotationStep::GaveUp) => {
            // Only a settled tick clears a one-shot force request: the forced
            // attempt genuinely fired. GaveUp exhausted the transient-retry
            // budget without the forced attempt cleanly running, so leave the
            // flag set and let the entry guard re-attempt on a later sweep rather
            // than silently drop the operator's request.
            let mut txn = None;
            if force && matches!(step, RotationStep::Settled) {
                let mut t = ctx.services.db_pool.begin().await?;
                db::switch::clear_bmc_credential_rotation_requested(&mut t, *switch_id).await?;
                txn = Some(t);
            }
            Ok(StateHandlerOutcome::transition(SwitchControllerState::Ready).with_txn_opt(txn))
        }
        RotationStep::Retry { retry_count } => Ok(StateHandlerOutcome::transition(
            SwitchControllerState::RotatingBmc { retry_count },
        )),
    }
}

/// Rotate the switch BMC toward the staged target. `force` bypasses the device's
/// backoff quarantine (operator escape hatch). Returns [`BmcRotationTick::Retry`]
/// only on a transient bookkeeping error; device faults are quarantined inside
/// [`rotate_bmc`] and reported as `Settled`.
async fn rotate_switch_bmc(
    services: &SwitchStateHandlerServices,
    endpoint: BmcEndpoint,
    force: bool,
) -> BmcRotationTick {
    let vendor = resolve_dispatch_vendor(services, &endpoint).await;
    let target = endpoint.into_target(vendor);
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
            tracing::info!(mac = %target.device_mac, force, "switch BMC converged to site-wide rotation target");
            BmcRotationTick::Settled
        }
        Ok(RotateOutcome::Quarantined { until }) => {
            tracing::warn!(
                mac = %target.device_mac,
                %until,
                "switch BMC rotation attempt failed; quarantined until backoff elapses"
            );
            BmcRotationTick::Settled
        }
        Ok(RotateOutcome::NoWork) => BmcRotationTick::Settled,
        Err(e) => {
            tracing::warn!(
                mac = %target.device_mac,
                error = %e,
                "transient switch BMC rotation bookkeeping failure; will retry the tick"
            );
            BmcRotationTick::Retry
        }
    }
}

/// Resolve the precise dispatch vendor `set_bmc_root_password` branches on by
/// probing at rotation time (switch BMC vendors are not persisted). A probe
/// failure falls back to `RedfishVendor::Unknown`, which the engine surfaces as a
/// device-level error and quarantines with backoff -- so an unreachable BMC backs
/// off rather than hot-looping the controller through Ready -> RotatingBmc ->
/// Ready every sweep.
async fn resolve_dispatch_vendor(
    services: &SwitchStateHandlerServices,
    endpoint: &BmcEndpoint,
) -> RedfishVendor {
    let Some(credentials) = per_device_bmc_credentials(services, endpoint.device_mac).await else {
        return RedfishVendor::Unknown;
    };
    match services
        .redfish_client_pool
        .probe_bmc_vendor(&endpoint.host, endpoint.port, credentials)
        .await
    {
        Ok(vendor) => vendor,
        Err(e) => {
            tracing::warn!(
                mac = %endpoint.device_mac,
                error = %e,
                "switch BMC vendor probe failed; rotation engine will quarantine the device"
            );
            RedfishVendor::Unknown
        }
    }
}

/// Read the current per-device BMC root secret, used only to satisfy the vendor
/// probe's Chassis-fallback authentication. The engine re-reads it under its own
/// crash-safe path; a missing secret here just yields an `Unknown` vendor.
async fn per_device_bmc_credentials(
    services: &SwitchStateHandlerServices,
    mac: MacAddress,
) -> Option<Credentials> {
    let key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: mac,
        },
    };
    match services.credential_manager.get_credentials(&key).await {
        Ok(credentials) => credentials,
        Err(e) => {
            tracing::warn!(%mac, error = %e, "failed reading per-device switch BMC secret for vendor probe");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use model::bmc_info::BmcInfo;

    use super::*;

    fn mac(last: u8) -> MacAddress {
        MacAddress::new([0x02, 0, 0, 0, 0, last])
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn bmc_info(mac: Option<MacAddress>, ip: Option<IpAddr>, port: Option<u16>) -> BmcInfo {
        BmcInfo {
            machine_interface_id: None,
            ip,
            port,
            mac,
            version: None,
            firmware_version: None,
        }
    }

    #[test]
    fn endpoint_resolves_from_bmc_info() {
        let info = bmc_info(Some(mac(1)), Some(ip(1)), Some(8443));
        let endpoint = BmcEndpoint::from_switch(Some(&info))
            .expect("a fully addressable BMC yields an endpoint");
        assert_eq!(endpoint.device_mac, mac(1));
        assert_eq!(endpoint.host, ip(1).to_string());
        assert_eq!(endpoint.port, Some(8443));
    }

    #[test]
    fn endpoint_is_none_without_bmc_info() {
        assert!(BmcEndpoint::from_switch(None).is_none());
    }

    #[test]
    fn endpoint_is_none_when_mac_missing() {
        // No MAC means the rotation row / per-device secret cannot be keyed.
        let info = bmc_info(None, Some(ip(1)), None);
        assert!(BmcEndpoint::from_switch(Some(&info)).is_none());
    }

    #[test]
    fn endpoint_is_none_when_ip_missing() {
        // No IP means the BMC cannot be reached.
        let info = bmc_info(Some(mac(1)), None, None);
        assert!(BmcEndpoint::from_switch(Some(&info)).is_none());
    }
}
