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

use std::collections::BTreeSet;
use std::net::IpAddr;

use ::rpc::forge as rpc;
use carbide_secrets::credentials::{BmcCredentialType, CredentialKey};
use mac_address::MacAddress;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

/// Erase all NICo-owned site records for a server BMC MAC address, giving an
/// operator a clean slate to re-ingest a replacement host.
///
/// The MAC is the *input* to this operation: deletion is MAC-driven. Records are
/// resolved from cached state -- machine interfaces (MAC-exact), the site-explorer
/// exploration reports whose stored data references the MAC, and the explored
/// managed-host rows at those BMC IPs -- plus the BMC credentials in vault and the
/// convergence markers keyed by the MAC. No live BMC/Redfish call is made, so a
/// machine that is powered off, gone, or relocated is still cleaned. It deliberately
/// does not touch expected machines -- NICo does not own that data.
///
/// It refuses to run when any interface for the MAC is still owned by a live device
/// (machine, DPU, switch or power shelf), or when a BMC IP for the MAC still belongs
/// to an ingested machine; those go through the appropriate force-delete path.
/// Safety for the destructive path comes from `dry_run` (which reports what would be
/// erased, including whether BMC credentials exist) plus the CLI's `--confirm`.
pub(crate) async fn erase_host_metadata_by_bmc_mac(
    api: &Api,
    request: Request<rpc::EraseHostMetadataByBmcMacRequest>,
) -> Result<Response<rpc::EraseHostMetadataByBmcMacResponse>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    // A malformed MAC is a client error, not an internal one.
    let bmc_mac: MacAddress = request.bmc_mac.parse().map_err(|e| {
        CarbideError::InvalidArgument(format!("invalid BMC MAC {:?}: {e}", request.bmc_mac))
    })?;
    let dry_run = request.dry_run;

    // Read the vault BMC credential *before* acquiring the admin-segment lock, so the
    // locked section below performs no network I/O and cannot stall other operations
    // waiting on vault. This only reports/decides credential clearing; it never gates
    // the DB deletion, which is MAC-driven.
    let bmc_credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: bmc_mac,
        },
    };
    let has_bmc_credentials = api
        .credential_manager
        .get_credentials(&bmc_credential_key)
        .await
        .map_err(|e| CarbideError::internal(format!("error reading BMC credential: {e:?}")))?
        .is_some();

    let mut txn = api.txn_begin().await?;

    // Serialize with force-delete and the allocator by taking the admin-segment lock
    // first, matching `admin_force_delete_machine`'s lock ordering. Everything below
    // the lock is DB-only (no remote calls), so the lock is held only briefly.
    db::machine_interface::lock_all_admin_segments(txn.as_pgconn()).await?;

    let interfaces = db::machine_interface::find_by_mac_address(txn.as_pgconn(), bmc_mac).await?;

    // Refuse when the MAC still belongs to a live device -- a machine, DPU, switch or
    // power shelf. Those have their own lifecycle/force-delete paths; this cleanup
    // tool must never delete a device that is still in service.
    //
    // Known limitation: the switch/power-shelf association paths do not take
    // `lock_all_admin_segments`, so an association committed between this check and the
    // deletes below could race. This matches `admin_force_delete_machine`, which relies
    // on the same lock; hardening both is a separate, codebase-wide change.
    if let Some(owner) = interfaces.iter().find_map(owning_device) {
        return Err(CarbideError::InvalidArgument(format!(
            "cannot erase metadata for {bmc_mac}: an interface is still owned by {owner}. \
             use the appropriate force-delete instead"
        ))
        .into());
    }

    // Exploration reports whose cached data references this MAC (JSONB search over
    // stored data, not a live BMC call). The search matches the MAC under Systems[]
    // or Managers[]; only delete an endpoint that is actually this BMC -- protect any
    // whose Manager advertises a *different* MAC (it belongs to another host that
    // merely lists this MAC on a system NIC). Mirrors the managed-host protection.
    let matched_endpoints =
        db::explored_endpoints::find_by_mac_address(txn.as_pgconn(), bmc_mac).await?;
    let (endpoints, protected_endpoints): (Vec<_>, Vec<_>) = matched_endpoints
        .into_iter()
        .partition(|e| !endpoint_claimed_by_other_bmc(e, bmc_mac));
    for endpoint in &protected_endpoints {
        tracing::warn!(
            bmc_mac = %bmc_mac,
            endpoint_ip = %endpoint.address,
            "erase-metadata: protecting explored endpoint; its BMC advertises a different MAC",
        );
    }

    // MAC-driven BMC IP set: interface addresses plus the IPs of the endpoints we
    // will delete.
    let mut bmc_ips: BTreeSet<IpAddr> = interfaces
        .iter()
        .flat_map(|i| i.addresses.iter().copied())
        .collect();
    bmc_ips.extend(endpoints.iter().map(|e| e.address));

    // Classify the candidate IPs first: an IP where an exploration report currently
    // advertises a *different* BMC MAC has been reassigned away from this MAC. Such an
    // IP is no longer ours -- it is neither ours to clean nor ours to refuse over.
    // This classification must run *before* the live-machine guard below: a stale
    // interface for this MAC can still carry an old IP that now belongs to a different,
    // ingested host, and refusing on that would abort a legitimate orphan cleanup while
    // pointing the operator at force-delete for someone else's machine.
    let mut ips_owned_by_other_bmc: BTreeSet<IpAddr> = BTreeSet::new();
    for &bmc_ip in &bmc_ips {
        let endpoints_at_ip =
            db::explored_endpoints::find_all_by_ip(bmc_ip, txn.as_pgconn()).await?;
        if endpoints_at_ip
            .iter()
            .any(|e| endpoint_claimed_by_other_bmc(e, bmc_mac))
        {
            tracing::warn!(
                bmc_mac = %bmc_mac,
                endpoint_ip = %bmc_ip,
                "erase-metadata: BMC IP now belongs to a different BMC; leaving its records alone",
            );
            ips_owned_by_other_bmc.insert(bmc_ip);
        }
    }

    // Refuse if a BMC IP that is still *ours* belongs to a live (ingested) machine --
    // that is the force-delete path, not a leftover cleanup.
    for bmc_ip in bmc_ips
        .iter()
        .filter(|ip| !ips_owned_by_other_bmc.contains(ip))
    {
        if carbide_site_explorer::is_endpoint_in_managed_host(*bmc_ip, txn.as_pgconn())
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?
        {
            return Err(CarbideError::InvalidArgument(format!(
                "cannot erase metadata for {bmc_mac}: a machine exists for BMC endpoint \
                 {bmc_ip}. use `nico-admin-cli machine force-delete` instead"
            ))
            .into());
        }
    }

    // Only clean managed-host rows at IPs that are still ours.
    let managed_host_ips: Vec<IpAddr> = bmc_ips
        .iter()
        .copied()
        .filter(|ip| !ips_owned_by_other_bmc.contains(ip))
        .collect();
    let managed_hosts =
        db::explored_managed_host::find_by_ips(txn.as_pgconn(), managed_host_ips).await?;

    // Sorted for deterministic delete/lock ordering.
    let mut endpoint_ips: Vec<IpAddr> = endpoints.iter().map(|e| e.address).collect();
    endpoint_ips.sort();

    let response = rpc::EraseHostMetadataByBmcMacResponse {
        dry_run,
        machine_interface_ids: interfaces.iter().map(|i| i.id.to_string()).collect(),
        explored_endpoint_ips: endpoint_ips.iter().map(|ip| ip.to_string()).collect(),
        explored_managed_host_ips: managed_hosts
            .iter()
            .map(|h| h.host_bmc_ip.to_string())
            .collect(),
        // In dry-run this reports whether credentials exist (and so would be
        // cleared); in a real run it reports that they were cleared.
        bmc_credentials_cleared: has_bmc_credentials,
    };

    if dry_run {
        return Ok(Response::new(response));
    }

    // Erase the DB-backed records in one transaction, in the same deadlock-safe order
    // `admin_force_delete_machine` uses: managed hosts, then endpoints, then
    // interfaces.
    for host in &managed_hosts {
        db::explored_managed_host::delete_by_host_bmc_addr(txn.as_pgconn(), host.host_bmc_ip)
            .await?;
    }
    db::explored_endpoints::delete_many(txn.as_pgconn(), &endpoint_ips).await?;
    for iface in &interfaces {
        // `machine_boot_override` has an FK to `machine_interfaces` with no
        // ON DELETE CASCADE, so clear any override first or the interface delete
        // fails with a foreign-key violation.
        db::machine_boot_override::clear(txn.as_pgconn(), iface.id).await?;
        db::machine_interface::delete(&iface.id, txn.as_pgconn()).await?;
    }
    // Interface deletion preserves a `retained_boot_interfaces` row for the MAC, so no
    // stale boot metadata survives to affect re-ingestion of the replacement host.
    //
    // ORDER IS LOAD-BEARING: `machine_interface::delete` *upserts* the retained row on
    // its way out, so this must run after the loop above. Hoisting it earlier would
    // leave a freshly-created row behind and silently defeat the clean slate.
    let _ = db::retained_boot_interface::take_by_mac(txn.as_pgconn(), bmc_mac, None).await?;
    // Drop the host-UEFI convergence marker keyed by this MAC; the BMC marker is
    // dropped alongside the vault secret below.
    db::credential_rotation::delete_device_converged(
        txn.as_pgconn(),
        bmc_mac,
        db::credential_rotation::CredentialRotationType::HostUefi,
    )
    .await?;

    txn.commit().await?;

    // Clear the BMC credentials in vault, the BMC convergence marker, and this MAC's
    // Redfish sessions/lockout cache (the helper also calls `bmc_session_manager
    // ::flush_mac`, so a stale session or lockout entry cannot block the returning
    // spare). Runs after the DB commit -- outside the lock -- mirroring `machine
    // force-delete --delete-bmc-credentials`. Called unconditionally: the underlying
    // deletes are idempotent, so a marker left behind without a credential is still
    // removed, and a run that failed after the vault delete can be safely re-run.
    crate::handlers::credential::delete_bmc_root_credentials_by_mac(api, bmc_mac).await?;

    Ok(Response::new(response))
}

/// Names the live device that owns this interface, if any. Machines, DPUs,
/// switches and power shelves each have their own lifecycle and must never be
/// cleaned up through erase-metadata.
fn owning_device(iface: &model::machine::MachineInterfaceSnapshot) -> Option<String> {
    iface
        .machine_id
        .map(|id| format!("machine {id}"))
        .or_else(|| {
            iface
                .attached_dpu_machine_id
                .map(|id| format!("DPU machine {id}"))
        })
        .or_else(|| iface.switch_id.map(|id| format!("switch {id}")))
        .or_else(|| iface.power_shelf_id.map(|id| format!("power shelf {id}")))
}

/// True when the endpoint's own BMC (Redfish Manager) advertises at least one MAC and
/// none of them is `mac` -- i.e. the exploration report at that IP belongs to a
/// *different* BMC, and must be protected even if `mac` appears on one of its host
/// system NICs. Endpoints with no Manager MAC recorded are not treated as owned by
/// another BMC, so deletion stays MAC-driven for them.
fn endpoint_claimed_by_other_bmc(
    endpoint: &model::site_explorer::ExploredEndpoint,
    mac: MacAddress,
) -> bool {
    let mut has_manager_mac = false;
    for manager_mac in endpoint
        .report
        .managers
        .iter()
        .flat_map(|manager| &manager.ethernet_interfaces)
        .filter_map(|iface| iface.mac_address)
    {
        if manager_mac == mac {
            return false;
        }
        has_manager_mac = true;
    }
    has_manager_mac
}
