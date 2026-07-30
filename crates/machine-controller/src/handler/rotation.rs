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

//! Machine-controller BMC credential rotation (REQ-2).
//!
//! The shared [`carbide_credential_rotation`] engine owns the actual password
//! dance, backoff, and crash-safety; this module is the thin machine-controller
//! adapter. It answers two questions for the state machine:
//!
//! - *Should we enter rotation?* [`bmc_rotation_needed`] asks the cached
//!   [`BmcRotationGate`] whether the host BMC or any of its DPU BMCs lags the
//!   staged site-wide target. The gate keeps the steady state at one cheap
//!   aggregate query per TTL window (see the engine crate docs).
//! - *Do one rotation tick.* [`rotate_managed_host_bmcs`] converges the host BMC
//!   and each DPU BMC toward the target via [`rotate_bmc`], then reports whether
//!   the tick settled (every device reached a terminal outcome) or hit a
//!   transient bookkeeping failure worth retrying.
//!
//! A BMC password change never touches host power or the running OS, so this is
//! safe both for pool hosts (top-level [`ManagedHostState::RotatingBmc`]) and
//! under live tenancy (`Assigned/RotatingBmc`).

use carbide_credential_rotation::{BmcRotationTarget, RotateOutcome, rotate_bmc};
use carbide_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
use carbide_uuid::machine::MachineId;
use libredfish::model::service_root::RedfishVendor;
use mac_address::MacAddress;
use model::machine::{Machine, ManagedHostStateSnapshot};
use sqlx::PgTransaction;
use state_controller::state_handler::StateHandlerError;

use crate::context::MachineStateHandlerServices;

/// Transient-failure retry budget for a single BMC-rotation entry. Device-level
/// failures are handled by the engine (quarantine + backoff), so this only
/// bounds re-entries caused by transient bookkeeping errors before the state
/// machine gives up and returns to its steady state; the entry guard re-enters
/// on the next sweep if a device still lags.
pub(crate) const MAX_BMC_ROTATION_RETRIES: u32 = 3;

/// One BMC endpoint under a managed host: the host BMC or a DPU BMC. `device_mac`
/// keys both the `device_credential_rotation` row and the per-device Vault
/// secret; the dispatch vendor is resolved by probing at rotation time.
struct BmcEndpoint {
    device_mac: MacAddress,
    host: String,
    port: Option<u16>,
}

impl BmcEndpoint {
    /// Build an endpoint from a machine's BMC info, or `None` when the BMC lacks
    /// a MAC or IP (unkeyable / unreachable, so it is skipped).
    fn from_machine(machine: &Machine) -> Option<Self> {
        let info = &machine.status.bmc_info;
        Some(Self {
            device_mac: info.mac?,
            host: info.ip?.to_string(),
            port: info.port,
        })
    }
}

/// The host BMC followed by each DPU BMC that exposes both a MAC and an IP. A
/// device missing either cannot be keyed or reached, so it is skipped (the
/// entry guard likewise never selects it).
fn managed_host_bmc_endpoints(
    mh: &ManagedHostStateSnapshot,
) -> impl Iterator<Item = BmcEndpoint> + '_ {
    std::iter::once(&mh.host_snapshot)
        .chain(mh.dpu_snapshots.iter())
        .filter_map(BmcEndpoint::from_machine)
}

/// `true` when the host BMC or any DPU BMC is behind the staged site-wide target
/// and not currently quarantined -- i.e. the machine should enter its
/// BMC-rotation state.
pub(crate) async fn bmc_rotation_needed(
    services: &MachineStateHandlerServices,
    mh: &ManagedHostStateSnapshot,
) -> Result<bool, StateHandlerError> {
    for endpoint in managed_host_bmc_endpoints(mh) {
        let needed = services
            .bmc_rotation_gate
            .bmc_rotation_needed(&services.db_pool, endpoint.device_mac)
            .await
            .map_err(|e| {
                StateHandlerError::GenericError(eyre::eyre!("bmc rotation gate query: {e}"))
            })?;
        if needed {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a Ready host should enter `ManagedHostState::RotatingBmc` now.
///
/// An operator force-converge request always wins -- the ops escape hatch is
/// honored even when the site-wide flag is off. Otherwise the passive gate
/// fires only when BMC rotation is enabled site-wide *and* a device lags the
/// staged target; the flag is checked first so a disabled site never runs the
/// per-device gate query.
pub(crate) async fn should_enter_bmc_rotation(
    services: &MachineStateHandlerServices,
    mh: &ManagedHostStateSnapshot,
) -> Result<bool, StateHandlerError> {
    if bmc_rotation_force_requested(mh) {
        return Ok(true);
    }
    Ok(services.site_config.bmc_rotation_enabled && bmc_rotation_needed(services, mh).await?)
}

/// Outcome of one BMC-rotation tick across all of a managed host's BMCs.
pub(crate) enum BmcRotationTick {
    /// Every device reached a terminal outcome (converged, quarantined, or no
    /// work). The controller should leave the rotation state; the entry guard
    /// re-enters later if a quarantined device becomes eligible again.
    Settled,
    /// At least one device hit a transient bookkeeping failure. The controller
    /// should retry the tick, bounded by the state's retry budget.
    Retry,
}

/// Run one rotation tick over the host BMC and each DPU BMC. A device is rotated
/// when it is force-requested (operator escape hatch, which also bypasses that
/// device's backoff quarantine) or when passive site-wide rotation is enabled;
/// a device that is neither is left alone this tick. Because `force` is decided
/// per device, a forced DPU and a passively-lagging host converge together in
/// the same tick. Each device is independent (its own rotation row, secret, and
/// backoff), so one lagging or quarantined device never blocks the others.
/// Device-level failures are recorded and quarantined inside [`rotate_bmc`];
/// only transient bookkeeping errors surface here as [`BmcRotationTick::Retry`].
pub(crate) async fn rotate_managed_host_bmcs(
    services: &MachineStateHandlerServices,
    mh: &ManagedHostStateSnapshot,
) -> BmcRotationTick {
    let is_sitewide_bmc_rotation_enabled = services.site_config.bmc_rotation_enabled;
    let mut tick = BmcRotationTick::Settled;
    for machine in std::iter::once(&mh.host_snapshot).chain(mh.dpu_snapshots.iter()) {
        let force = machine.bmc_credential_rotation_requested;
        if !force && !is_sitewide_bmc_rotation_enabled {
            continue;
        }
        match BmcEndpoint::from_machine(machine) {
            Some(endpoint) => {
                if matches!(
                    rotate_endpoint(services, endpoint, force).await,
                    BmcRotationTick::Retry
                ) {
                    // One transient bookkeeping failure asks the whole tick to
                    // retry; the other endpoints still ran, and their per-device
                    // rows persist.
                    tick = BmcRotationTick::Retry;
                }
            }
            // A forced request announces a missing BMC so its one-shot flag
            // still clears; a passive sweep silently skips an unaddressable
            // device, exactly as `managed_host_bmc_endpoints` does.
            None if force => tracing::warn!(
                machine_id = %machine.id,
                "force-converge request on a machine with no addressable BMC; clearing the request without action"
            ),
            None => {}
        }
    }
    tick
}

/// The machines under this managed host (the host machine and each DPU machine)
/// that carry a pending operator force-converge request. Each such machine owns
/// exactly one BMC, so the flag's location names the target device -- no MAC is
/// needed in the request payload.
fn forced_bmc_machines(mh: &ManagedHostStateSnapshot) -> impl Iterator<Item = &Machine> {
    std::iter::once(&mh.host_snapshot)
        .chain(mh.dpu_snapshots.iter())
        .filter(|m| m.bmc_credential_rotation_requested)
}

/// `true` when an operator has recorded a force-converge request against the host
/// machine or any of its DPU machines. Presence alone drives entry into
/// `RotatingBmc`.
pub(crate) fn bmc_rotation_force_requested(mh: &ManagedHostStateSnapshot) -> bool {
    forced_bmc_machines(mh).next().is_some()
}

/// The machine ids carrying a pending force-converge request, so the controller
/// can clear exactly those rows once the forced tick settles.
fn forced_bmc_machine_ids(mh: &ManagedHostStateSnapshot) -> impl Iterator<Item = MachineId> + '_ {
    forced_bmc_machines(mh).map(|m| m.id)
}

/// Clear the one-shot force-converge flag on exactly the machines that carried a
/// pending request *in this snapshot*, returning the transaction to commit with
/// the state transition. Returns `None` when nothing was forced, so the common
/// passive path performs no write.
///
/// Only the observed-forced machines are cleared -- never the whole managed host
/// -- so a request that lands mid-tick (after this snapshot was read, hence not
/// acted on this tick) survives for the next sweep instead of being silently
/// dropped. Call this only on a settled tick, where the forced attempt genuinely
/// fired.
pub(crate) async fn clear_forced_bmc_requests(
    services: &MachineStateHandlerServices,
    mh: &ManagedHostStateSnapshot,
) -> Result<Option<PgTransaction<'static>>, StateHandlerError> {
    let mut forced_machine_ids = forced_bmc_machine_ids(mh).peekable();
    if forced_machine_ids.peek().is_none() {
        return Ok(None);
    }
    let mut txn = services.db_pool.begin().await?;
    for machine_id in forced_machine_ids {
        db::machine::clear_bmc_credential_rotation_requested(&mut txn, machine_id).await?;
    }
    Ok(Some(txn))
}

/// Rotate a single BMC endpoint toward the staged target. `force` bypasses the
/// device's backoff quarantine (operator escape hatch). Returns
/// [`BmcRotationTick::Retry`] only on a transient bookkeeping error; device
/// faults are quarantined inside [`rotate_bmc`] and reported as `Settled`.
async fn rotate_endpoint(
    services: &MachineStateHandlerServices,
    endpoint: BmcEndpoint,
    force: bool,
) -> BmcRotationTick {
    let vendor = resolve_dispatch_vendor(services, &endpoint).await;
    let target = BmcRotationTarget {
        device_mac: endpoint.device_mac,
        host: endpoint.host,
        port: endpoint.port,
        vendor,
    };
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
            tracing::info!(mac = %target.device_mac, force, "BMC converged to site-wide rotation target");
            BmcRotationTick::Settled
        }
        Ok(RotateOutcome::Quarantined { until }) => {
            tracing::warn!(
                mac = %target.device_mac,
                %until,
                "BMC rotation attempt failed; quarantined until backoff elapses"
            );
            BmcRotationTick::Settled
        }
        Ok(RotateOutcome::NoWork) => BmcRotationTick::Settled,
        Err(e) => {
            tracing::warn!(
                mac = %target.device_mac,
                error = %e,
                "transient BMC rotation bookkeeping failure; will retry the tick"
            );
            BmcRotationTick::Retry
        }
    }
}

/// What the state machine should do after one BMC-rotation tick, independent of
/// which state drives it. Keeping this state-neutral lets the pool
/// (`ManagedHostState::RotatingBmc`) and, later, the tenant
/// (`Assigned/RotatingBmc`) dispatch arms share one retry/budget policy and
/// remain thin maps onto their own state constructors.
pub(crate) enum RotationStep {
    /// The tick reached a terminal outcome for every device (converged,
    /// quarantined, or no work): leave the rotation state, and it is safe to
    /// clear any one-shot force request because the forced attempt genuinely
    /// fired. The entry guard re-enters on a later sweep if a device lags again.
    Settled,
    /// The transient-retry budget was exhausted without settling. Leave the
    /// rotation state, but do *not* treat a force request as satisfied: the
    /// forced attempt never cleanly ran (the failures were pre-hardware
    /// bookkeeping errors that record no quarantine), so leaving the flag set
    /// lets the entry guard re-attempt on a later sweep instead of silently
    /// dropping the operator's request.
    GaveUp,
    /// Re-enter the rotation state carrying this incremented retry count.
    Retry { retry_count: u32 },
}

/// Fold one tick outcome and the current retry count into the next
/// [`RotationStep`]. Device-level failures are already handled by the engine
/// (quarantine + backoff); this only bounds re-entries caused by *transient
/// bookkeeping* failures before the state machine falls back to its steady
/// state.
pub(crate) fn advance(
    tick: BmcRotationTick,
    retry_count: u32,
    host_machine_id: &MachineId,
) -> RotationStep {
    match tick {
        BmcRotationTick::Settled => RotationStep::Settled,
        BmcRotationTick::Retry => {
            let next = retry_count + 1;
            if next >= MAX_BMC_ROTATION_RETRIES {
                tracing::warn!(
                    %host_machine_id,
                    "BMC rotation exhausted its transient-retry budget; returning to steady state (a pending force request stays set so the entry guard re-attempts on a later sweep; a passively-lagging device is re-selected by the gate)"
                );
                RotationStep::GaveUp
            } else {
                RotationStep::Retry { retry_count: next }
            }
        }
    }
}

/// Resolve the precise dispatch vendor `set_bmc_root_password` branches on by
/// probing at rotation time.
///
/// The stored hardware `BMCVendor` is deliberately not used: it is derived from
/// DMI `sys_vendor` and is too coarse (every NVIDIA `RedfishVendor` -- DPU,
/// GBx00, GH200, ... -- collapses to `BMCVendor::Nvidia`), and the precise
/// `RedfishVendor` is not persisted anywhere. Probing is exactly what the switch
/// and power-shelf controllers do and what the engine's `BmcRotationTarget`
/// contract expects. A probe failure falls back to `RedfishVendor::Unknown`,
/// which the engine surfaces as a device-level error and quarantines with
/// backoff -- so an unreachable BMC backs off rather than hot-looping the
/// controller through Ready -> RotatingBmc -> Ready every sweep.
async fn resolve_dispatch_vendor(
    services: &MachineStateHandlerServices,
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
                "BMC vendor probe failed; rotation engine will quarantine the device"
            );
            RedfishVendor::Unknown
        }
    }
}

/// Read the current per-device BMC root secret, used only to satisfy the vendor
/// probe's Chassis-fallback authentication. The engine re-reads it under its own
/// crash-safe path; a missing secret here just yields an `Unknown` vendor.
async fn per_device_bmc_credentials(
    services: &MachineStateHandlerServices,
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
            tracing::warn!(%mac, error = %e, "failed reading per-device BMC secret for vendor probe");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use model::test_support::machine_snapshot::managed_host_state_snapshot;

    use super::*;

    fn mac(last: u8) -> MacAddress {
        MacAddress::new([0x02, 0, 0, 0, 0, last])
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    /// The fixture bundles a host with two DPUs sharing one BMC address; give
    /// each a distinct `(mac, ip)` so endpoint ordering and per-device selection
    /// are observable.
    fn snapshot_with_distinct_bmcs() -> ManagedHostStateSnapshot {
        let mut mh = managed_host_state_snapshot();
        mh.host_snapshot.status.bmc_info.mac = Some(mac(1));
        mh.host_snapshot.status.bmc_info.ip = Some(ip(1));
        mh.dpu_snapshots[0].status.bmc_info.mac = Some(mac(2));
        mh.dpu_snapshots[0].status.bmc_info.ip = Some(ip(2));
        mh.dpu_snapshots[1].status.bmc_info.mac = Some(mac(3));
        mh.dpu_snapshots[1].status.bmc_info.ip = Some(ip(3));
        mh
    }

    fn selected_macs(mh: &ManagedHostStateSnapshot) -> Vec<MacAddress> {
        managed_host_bmc_endpoints(mh)
            .map(|e| e.device_mac)
            .collect()
    }

    #[test]
    fn endpoints_are_host_then_dpus_in_order() {
        assert_eq!(
            selected_macs(&snapshot_with_distinct_bmcs()),
            vec![mac(1), mac(2), mac(3)],
            "the host BMC leads, followed by each DPU BMC in order"
        );
    }

    #[test]
    fn a_device_missing_its_mac_or_ip_is_skipped() {
        // A BMC with no MAC cannot key its rotation row/secret; one with no IP
        // cannot be reached. Either omission drops just that device, never the
        // rest.
        let mut mh = snapshot_with_distinct_bmcs();
        mh.dpu_snapshots[0].status.bmc_info.mac = None;
        mh.dpu_snapshots[1].status.bmc_info.ip = None;

        assert_eq!(
            selected_macs(&mh),
            vec![mac(1)],
            "only the fully-addressable host BMC remains"
        );
    }

    #[test]
    fn a_host_missing_its_bmc_mac_yields_only_dpus() {
        let mut mh = snapshot_with_distinct_bmcs();
        mh.host_snapshot.status.bmc_info.mac = None;

        assert_eq!(selected_macs(&mh), vec![mac(2), mac(3)]);
    }

    #[test]
    fn bmc_endpoint_carries_resolved_host_and_port() {
        let mh = snapshot_with_distinct_bmcs();
        let endpoint =
            BmcEndpoint::from_machine(&mh.host_snapshot).expect("host BMC is fully addressable");
        assert_eq!(endpoint.device_mac, mac(1));
        assert_eq!(endpoint.host, ip(1).to_string());
        // The fixture seeds the standard Redfish port.
        assert_eq!(endpoint.port, Some(443));
    }

    fn machine_id() -> MachineId {
        MachineId::from_str("fm100ds7blqjsadm2uuh3qqbf1h7k8pmf47um6v9uckrg7l03po8mhqgvng").unwrap()
    }

    #[test]
    fn advance_settles_regardless_of_retry_count() {
        // A settled tick always leaves the rotation state, even mid-budget: every
        // device reached a terminal outcome, so there is nothing left to retry.
        // `Settled` (not `GaveUp`) is what authorizes the caller to clear a
        // satisfied force request.
        assert!(matches!(
            advance(BmcRotationTick::Settled, 0, &machine_id()),
            RotationStep::Settled
        ));
        assert!(matches!(
            advance(
                BmcRotationTick::Settled,
                MAX_BMC_ROTATION_RETRIES - 1,
                &machine_id()
            ),
            RotationStep::Settled
        ));
    }

    #[test]
    fn advance_retries_with_incremented_count_within_budget() {
        // A transient failure below budget re-enters carrying count+1, so the
        // budget actually advances toward its bound rather than looping forever.
        let RotationStep::Retry { retry_count } = advance(BmcRotationTick::Retry, 0, &machine_id())
        else {
            panic!("a transient failure below budget must retry");
        };
        assert_eq!(retry_count, 1);
    }

    #[test]
    fn advance_gives_up_at_budget() {
        // The last attempt before the bound (count+1 == MAX) stops retrying and
        // falls back to the steady state instead of exceeding the budget. It
        // reports `GaveUp` rather than `Settled` so the caller leaves a pending
        // force request in place (the forced attempt never cleanly ran) instead
        // of silently clearing it.
        assert!(matches!(
            advance(
                BmcRotationTick::Retry,
                MAX_BMC_ROTATION_RETRIES - 1,
                &machine_id()
            ),
            RotationStep::GaveUp
        ));
    }
}
