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

use std::net::SocketAddr;

use ::rpc::forge as rpc;
use carbide_redfish::boot_interface::BootInterfaceTarget;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use model::machine::LoadSnapshotOptions;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine_boot_interface::MachineBootInterface;
use model::network_segment::NetworkSegmentType;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::auth::AuthContext;
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn set_primary_dpu(
    api: &Api,
    request: Request<rpc::SetPrimaryDpuRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let host_machine_id = request
        .host_machine_id
        .ok_or_else(|| CarbideError::InvalidArgument("host machine ID is required".to_string()))?;
    let dpu_machine_id = request
        .dpu_machine_id
        .ok_or_else(|| CarbideError::InvalidArgument("DPU machine ID is required".to_string()))?;

    log_machine_id(&host_machine_id);

    // `set-primary-dpu` is the DPU-only alias for `set-primary-interface`: it
    // keeps the zero-DPU guard and resolves the DPU to its host interface, then
    // defers to the generic core that does the actual work.
    let mut txn = api.txn_begin().await?;

    // Reject early on a zero-DPU host to provide a better error, otherwise we'd
    // fail later looking for the DPU's interface, which is more confusing.
    let snapshot =
        db::managed_host::load_snapshot(&mut txn, &host_machine_id, LoadSnapshotOptions::default())
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "Machine",
                id: host_machine_id.to_string(),
            })?;
    if !snapshot.has_managed_dpus() {
        return Err(CarbideError::FailedPrecondition(format!(
            "host {host_machine_id} has no DPUs; set-primary-dpu does not apply to zero-DPU hosts"
        ))
        .into());
    }

    let interface_map =
        db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id]).await?;
    let new_primary_interface_id = interface_map
        .get(&host_machine_id)
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "Machine",
            id: host_machine_id.to_string(),
        })?
        .iter()
        .find(|interface| interface.attached_dpu_machine_id == Some(dpu_machine_id))
        .map(|interface| interface.id)
        .ok_or_else(|| {
            CarbideError::InvalidArgument(format!(
                "DPU {dpu_machine_id} has no interface on host {host_machine_id}"
            ))
        })?;
    txn.rollback().await?;

    set_primary_interface_core(
        api,
        host_machine_id,
        new_primary_interface_id,
        request.reboot,
    )
    .await
}

/// Make any host interface -- DPU or not -- the primary (boot) interface,
/// identified directly by its machine-interface id. This is the generic form of
/// [`set_primary_dpu`]; unlike that alias it also works on zero-DPU hosts.
pub(crate) async fn set_primary_interface(
    api: &Api,
    request: Request<rpc::SetPrimaryInterfaceRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let host_machine_id = request
        .host_machine_id
        .ok_or_else(|| CarbideError::InvalidArgument("host machine ID is required".to_string()))?;
    let interface_id = request
        .interface_id
        .ok_or_else(|| CarbideError::InvalidArgument("interface ID is required".to_string()))?;

    log_machine_id(&host_machine_id);

    set_primary_interface_core(api, host_machine_id, interface_id, request.reboot).await
}

// Move the primary (boot) interface flag to `new_primary_interface_id` and point
// the host's boot device at it. Shared by `set_primary_dpu` and
// `set_primary_interface`.
//
// Originally a work-around for FORGE-7085: a host BMC can report the primary DPU
// as something other than the lowest-slot DPU, and because the host names
// interfaces by PCI address the behavior differs between identical machines.
//
// Broken into the following parts:
// 1. collect interface and bmc information
// 2. set the boot device
// 3. update the primary interface and network config versions.
// 4. reboot the host if requested.
//
// No transaction should be held during 2 or 4 since they are requests to the host bmc.
async fn set_primary_interface_core(
    api: &Api,
    host_machine_id: MachineId,
    new_primary_interface_id: MachineInterfaceId,
    reboot: bool,
) -> Result<Response<()>, Status> {
    // `host_machine_id` must be a host machine. Reject DPU (or other non-host) ids
    // up front -- before any DB load or BMC side effect -- so callers get a clear
    // InvalidArgument instead of a confusing failure deeper in interface/BMC lookup.
    // `set_primary_dpu` resolves its DPU to the host's interface and also passes a
    // host id here, so this guards both entry points.
    if !host_machine_id.machine_type().is_host() {
        return Err(CarbideError::InvalidArgument(format!(
            "machine {host_machine_id} is not a host machine; set-primary-interface can \
             only promote an interface on a host"
        ))
        .into());
    }

    let mut txn = api.txn_begin().await?;

    let interface_map =
        db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id]).await?;
    let interface_snapshots =
        interface_map
            .get(&host_machine_id)
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "Machine",
                id: host_machine_id.to_string(),
            })?;

    // Find the current primary and the requested new primary before the db
    // update, since the "only one primary" constraint will fail if the new
    // interface is set before the old one is cleared.
    let mut current_primary_interface = None;
    let mut new_primary_interface = None;
    for interface_snapshot in interface_snapshots {
        if interface_snapshot.id == new_primary_interface_id {
            new_primary_interface = Some(interface_snapshot);
        } else if interface_snapshot.primary_interface {
            current_primary_interface = Some(interface_snapshot);
        }
    }
    let current_primary_interface_id = current_primary_interface.map(|interface| interface.id);
    // Whether the host currently has an Admin-segment primary. Drives whether the
    // pre-move admin reconciliation below is needed (see its comment).
    let current_primary_is_admin = current_primary_interface
        .is_some_and(|interface| interface.network_segment_type == Some(NetworkSegmentType::Admin));

    let new_primary_interface = new_primary_interface.ok_or_else(|| {
        CarbideError::InvalidArgument(format!(
            "interface {new_primary_interface_id} not found on host {host_machine_id}"
        ))
    })?;
    if new_primary_interface.primary_interface {
        return Err(CarbideError::InvalidArgument(
            "requested interface is already primary".to_string(),
        )
        .into());
    }

    // On a DPU-managed host the primary interface must stay on the Admin segment:
    // the host's admin DHCP address and DNS identity follow the primary, and
    // `reconcile_admin_addresses_for_host` (below) errors if a host with
    // DPU-backed admin interfaces is left with no primary admin interface.
    // Promoting a non-admin interface would trip that *after* the BMC boot order
    // was already changed, leaving the BMC and the database disagreeing. Zero-DPU
    // hosts have no DPU-backed admin interface, so this never constrains them.
    let host_has_dpu_backed_admin_interface = interface_snapshots.iter().any(|interface| {
        interface
            .attached_dpu_machine_id
            .is_some_and(|dpu| dpu != host_machine_id)
            && interface.network_segment_type == Some(NetworkSegmentType::Admin)
    });
    if host_has_dpu_backed_admin_interface
        && new_primary_interface.network_segment_type != Some(NetworkSegmentType::Admin)
    {
        return Err(CarbideError::InvalidArgument(format!(
            "interface {new_primary_interface_id} is not on the admin segment; a \
             DPU-managed host's primary interface must be an admin interface"
        ))
        .into());
    }

    let primary_interface_mac_address = new_primary_interface.mac_address;
    let boot_interface_id = new_primary_interface.boot_interface_id.clone();

    tracing::info!(
        machine_id = %host_machine_id,
        new_primary = %new_primary_interface_id,
        previous_primary = ?current_primary_interface_id,
        "moving the host's primary (boot) interface",
    );

    // we need to set the boot device or the host will no longer be able to boot.  we need BMC info.
    // the same BMC info is used if a reboot was requested.
    let machine = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "Machine",
            id: host_machine_id.to_string(),
        })?;

    let bmc_addr = machine
        .bmc_info
        .ip
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "BMC IP",
            id: host_machine_id.to_string(),
        })?;

    let bmc_socket_addr = SocketAddr::new(bmc_addr, 443);

    let bmc_interface = db::machine_interface::find_by_ip(&mut txn, bmc_addr)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "BMC Interface",
            id: bmc_addr.to_string(),
        })?;

    txn.rollback().await?;

    // Set the boot device. The new primary interface row already stores its
    // Redfish interface id, so send the complete (MAC + id) pair when present,
    // allowing for interface ID fallback (and target the MAC alone otherwise).
    let boot_target = match boot_interface_id {
        Some(interface_id) => BootInterfaceTarget::Pair(MachineBootInterface {
            mac_address: primary_interface_mac_address,
            interface_id,
        }),
        None => BootInterfaceTarget::MacOnly(primary_interface_mac_address),
    };
    api.endpoint_explorer
        .set_boot_order_dpu_first(bmc_socket_addr, &bmc_interface, &boot_target)
        .await
        .map_err(|e| CarbideError::internal(e.to_string()))?;

    let mut txn = api.txn_begin().await?;

    // Advisory-lock the admin segments before the `set_primary_interface`
    // row writes below, so this transaction holds locks in the allocator
    // order (segment advisory lock first, then interface rows) on both
    // branches -- the reconcile passes re-acquire the same locks as no-ops.
    db::machine_interface::lock_all_admin_segments(&mut txn).await?;

    // Normalize the current admin primary's address before moving the flag, so the
    // active DHCP address is one reconciliation can move onto the new primary --
    // but only when there IS a current admin primary to preserve. If the host has
    // no admin primary (e.g. a DPU-backed host whose primary was cleared or sits
    // off the Admin segment -- an off-happy-path state), this pre-move pass would
    // error on that broken state *after* the BMC boot order was already changed,
    // leaving the BMC and database disagreeing. Skipping it lets set_primary_interface
    // repair such a host; the post-move pass below sets the new primary's admin
    // ownership from scratch.
    if current_primary_is_admin {
        db::machine_interface::reconcile_admin_addresses_for_host(&mut txn, &host_machine_id)
            .await?;
    }

    // update the primary interface: clear the old primary (if any), then set the new.
    if let Some(current_primary_interface_id) = current_primary_interface_id {
        db::machine_interface::set_primary_interface(
            &current_primary_interface_id,
            false,
            &mut txn,
        )
        .await?;
    }
    db::machine_interface::set_primary_interface(&new_primary_interface_id, true, &mut txn).await?;

    // Reconcile admin address ownership after the primary flag moves.
    db::machine_interface::reconcile_admin_addresses_for_host(&mut txn, &host_machine_id).await?;

    let (network_config, network_config_version) =
        db::machine::get_network_config(txn.as_pgconn(), &host_machine_id)
            .await?
            .take();
    db::machine::try_update_network_config(
        &mut txn,
        &host_machine_id,
        network_config_version,
        &network_config,
    )
    .await?;

    // if there is an instance, update the instances network config version so the DPUs pick up the new config
    if let Some(instance) = db::instance::find_by_machine_id(&mut txn, &host_machine_id).await? {
        db::instance::update_network_config(
            &mut txn,
            instance.id,
            instance.network_config_version,
            &instance.config.network,
            true,
        )
        .await?;
    }

    txn.commit().await?;

    // optionally reboot the host.  if there is an instance, this is probably a required step,
    // but an operator will need to make that call.  The scout image handles this pretty well,
    // albeit with a leftover IP on the unused interface
    if reboot {
        api.endpoint_explorer
            .redfish_power_control(
                bmc_socket_addr,
                &bmc_interface,
                libredfish::SystemPowerControl::ForceRestart,
            )
            .await
            .map_err(|e| CarbideError::internal(e.to_string()))?;
    }
    Ok(Response::new(()))
}

/// Maintenance mode: Put a machine into maintenance mode or take it out.
///
/// Switching a host into maintenance mode prevents an instance being assigned
/// to it and suppresses external alerting on the host. It also excludes the
/// host from state-machine SLA tracking so that machines being worked on by an
/// operator do not page on-call for time-in-state breaches (e.g. stuck-instance
/// alerts) regardless of which state or substate they happen to be in.
pub(crate) async fn set_maintenance(
    api: &Api,
    request: Request<rpc::MaintenanceRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let triggered_by = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|ctx| ctx.get_external_user_name())
        .map(String::from);
    let req = request.into_inner();
    let machine_id = convert_and_log_machine_id(req.host_id.as_ref())?;

    let (host_machine, mut txn) = api
        .load_machine(&machine_id, MachineSearchConfig::default())
        .await?;
    if host_machine.is_dpu() {
        return Err(CarbideError::InvalidArgument(
            "DPU ID provided. need managed host".to_string(),
        )
        .into());
    }
    let dpu_machines = db::machine::find_dpus_by_host_machine_id(&mut txn, &machine_id).await?;
    txn.commit().await?;

    // We set status on both host and dpu machine to make them easier to query from DB
    match req.operation() {
        rpc::MaintenanceOperation::Enable => {
            let Some(reference) = req.reference else {
                return Err(
                    CarbideError::InvalidArgument("missing reference url".to_string()).into(),
                );
            };

            let reference = reference.trim().to_string();
            if reference.len() < 5 {
                return Err(CarbideError::InvalidArgument(
                    "provide some valid reference. minimum expected length is 5".into(),
                )
                .into());
            }

            // Maintenance mode is implemented as a host health override
            crate::handlers::health::insert_machine_health_report(
                api,
                Request::new(rpc::InsertMachineHealthReportRequest {
                    machine_id: req.host_id,
                    health_report_entry: Some(::rpc::forge::HealthReportEntry {
                        report: Some(health_report::HealthReport {
                            source: "maintenance".to_string(),
                            triggered_by,
                            observed_at: Some(chrono::Utc::now()),
                            successes: Vec::new(),
                            alerts: vec![health_report::HealthProbeAlert {
                                id: "Maintenance".parse().unwrap(),
                                target: None,
                                in_alert_since: Some(chrono::Utc::now()),
                                message: reference.clone(),
                                tenant_message: None,
                                classifications: vec![
                                    health_report::HealthAlertClassification::prevent_allocations(),
                                    health_report::HealthAlertClassification::suppress_external_alerting(),
                                    health_report::HealthAlertClassification::exclude_from_state_machine_sla(),
                                ],
                            }],
                        }
                                     .into()),
                        mode: ::rpc::forge::HealthReportApplyMode::Merge.into(),
                    }),
                }),
            )
                .await?;
        }
        rpc::MaintenanceOperation::Disable => {
            for dpu_machine in dpu_machines.iter() {
                if dpu_machine.reprovision_requested.is_some() {
                    return Err(CarbideError::InvalidArgument(format!(
                        "reprovisioning request is set on DPU: {}. clear it first",
                        &dpu_machine.id
                    ))
                    .into());
                }
            }

            match crate::handlers::health::remove_machine_health_report(
                api,
                Request::new(rpc::RemoveMachineHealthReportRequest {
                    machine_id: req.host_id,
                    source: "maintenance".to_string(),
                }),
            )
            .await
            {
                Ok(_) => (),
                Err(status) if status.code() == tonic::Code::NotFound => (),
                Err(status) => return Err(status),
            };
        }
    };

    Ok(Response::new(()))
}
