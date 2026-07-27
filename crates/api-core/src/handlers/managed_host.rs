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

use ::rpc::forge as rpc;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    BootConfigSynchronizationState, BootConfigSynchronizationTarget, InstanceState,
    LoadSnapshotOptions, ManagedHostState, pick_boot_interface_candidate,
};
use model::machine_boot_interface::MachineBootInterfaceTarget;
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

    let initiator = request
        .extensions()
        .get::<AuthContext>()
        .and_then(AuthContext::get_external_user_name)
        .map(String::from);
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
        Some(dpu_machine_id),
        request.reboot,
        initiator,
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

    let initiator = request
        .extensions()
        .get::<AuthContext>()
        .and_then(AuthContext::get_external_user_name)
        .map(String::from);
    let request = request.into_inner();
    let host_machine_id = request
        .host_machine_id
        .ok_or_else(|| CarbideError::InvalidArgument("host machine ID is required".to_string()))?;
    let interface_id = request
        .interface_id
        .ok_or_else(|| CarbideError::InvalidArgument("interface ID is required".to_string()))?;

    log_machine_id(&host_machine_id);

    set_primary_interface_core(
        api,
        host_machine_id,
        interface_id,
        None,
        request.reboot,
        initiator,
    )
    .await
}

/// Selects a host boot interface and hands Redfish synchronization to
/// machine-controller.
///
/// Called by both the DPU-specific alias and the generic interface API. The
/// selected row, endpoint target, selection generation, assigned-host
/// authorization, and affected network versions commit together. No Redfish
/// operation is performed on the API request path.
pub(crate) async fn set_primary_interface_core(
    api: &Api,
    host_machine_id: MachineId,
    new_primary_interface_id: MachineInterfaceId,
    expected_attached_dpu_machine_id: Option<MachineId>,
    reboot: bool,
    initiator: Option<String>,
) -> Result<Response<()>, Status> {
    // Site Explorer owns a host under a PredictedHost id until Scout replaces
    // it with the stable Host id. Both are valid boot-selection targets; a DPU
    // id is not.
    let machine_type = host_machine_id.machine_type();
    if !(machine_type.is_host() || machine_type.is_predicted_host()) {
        return Err(CarbideError::InvalidArgument(format!(
            "machine {host_machine_id} has type {machine_type}; set-primary-interface can \
             only promote an interface on a host or predicted host"
        ))
        .into());
    }

    let mut txn = api.txn_begin().await?;

    // Match discovery's interface-before-machine order while putting the
    // endpoint first for Site Explorer: admin-segment advisory locks, explored
    // endpoint, machine-interface rows, then the machine row.
    db::machine_interface::lock_all_admin_segments(&mut txn).await?;
    let initial_machine =
        db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "Machine",
                id: host_machine_id.to_string(),
            })?;
    let bmc_addr =
        initial_machine
            .status
            .bmc_info
            .ip
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "BMC IP",
                id: host_machine_id.to_string(),
            })?;
    db::explored_endpoints::find_by_ip_for_update(bmc_addr, &mut txn).await?;
    db::machine_interface::lock_for_machine(&mut txn, host_machine_id).await?;
    let current_selection_version =
        db::machine::lock_boot_interface_selection_version(&mut txn, host_machine_id).await?;
    db::predicted_machine_interface::lock_for_machine(&mut txn, host_machine_id).await?;
    let machine = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "Machine",
            id: host_machine_id.to_string(),
        })?;
    // The initial machine read only locates the endpoint without reversing the
    // endpoint-before-machine lock order. State transitions while those locks
    // are acquired are expected and the locked read above is authoritative;
    // only a BMC-address change invalidates the endpoint row we locked.
    if machine.status.bmc_info.ip != Some(bmc_addr) {
        return Err(CarbideError::ConcurrentModificationError(
            "machine",
            initial_machine.state.version.to_string(),
        )
        .into());
    }
    let assigned = matches!(&machine.state.value, ManagedHostState::Assigned { .. });
    let unassigned_ready = matches!(&machine.state.value, ManagedHostState::Ready);
    if assigned
        && !reboot
        && matches!(
            &machine.state.value,
            ManagedHostState::Assigned {
                instance_state:
                    InstanceState::BootConfigSynchronization {
                        synchronization_state,
                        ..
                    },
            } if synchronization_state.host_changes_started()
        )
    {
        return Err(CarbideError::FailedPrecondition(format!(
            "boot-interface synchronization has already started for host {host_machine_id}; \
             wait for it to finish before changing the selection without reboot authorization"
        ))
        .into());
    }

    let interface_map =
        db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id]).await?;
    let interface_snapshots =
        interface_map
            .get(&host_machine_id)
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "Machine",
                id: host_machine_id.to_string(),
            })?;
    let predicted_interfaces =
        db::predicted_machine_interface::find_by_machine_id(&mut txn, &host_machine_id).await?;
    let current_primary_interface = interface_snapshots
        .iter()
        .find(|interface| interface.primary_interface);
    let new_primary_interface = interface_snapshots
        .iter()
        .find(|interface| interface.id == new_primary_interface_id)
        .ok_or_else(|| {
            CarbideError::InvalidArgument(format!(
                "interface {new_primary_interface_id} not found on host {host_machine_id}"
            ))
        })?;
    if let Some(expected_dpu_machine_id) = expected_attached_dpu_machine_id
        && new_primary_interface.attached_dpu_machine_id != Some(expected_dpu_machine_id)
    {
        return Err(CarbideError::InvalidArgument(format!(
            "DPU {expected_dpu_machine_id} has no interface on host {host_machine_id}"
        ))
        .into());
    }
    if !new_primary_interface
        .network_segment_type
        .as_ref()
        .is_some_and(NetworkSegmentType::supports_host_boot)
    {
        let segment = new_primary_interface
            .network_segment_type
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "none".to_string());
        return Err(CarbideError::InvalidArgument(format!(
            "interface {new_primary_interface_id} uses segment type {segment}; a host boot \
             interface must use the admin or host_inband segment"
        ))
        .into());
    }
    let current_effective_interface_id =
        pick_boot_interface_candidate(interface_snapshots, &predicted_interfaces)
            .and_then(|candidate| candidate.machine_interface_id());
    let selection_changed = !new_primary_interface.primary_interface
        || current_effective_interface_id != Some(new_primary_interface_id);
    let current_primary_interface_id = current_primary_interface.map(|interface| interface.id);
    let current_primary_is_admin = current_primary_interface
        .is_some_and(|interface| interface.network_segment_type == Some(NetworkSegmentType::Admin));
    let boot_target = MachineBootInterfaceTarget::from_parts(
        Some(new_primary_interface.mac_address),
        new_primary_interface.boot_interface_id.clone(),
    )
    .expect("a machine interface always has a MAC address");
    db::predicted_machine_interface::clear_primary_for_machine(&mut txn, host_machine_id).await?;

    let synchronization_requested = selection_changed || reboot;
    let minimum_report_version = if selection_changed || (unassigned_ready && reboot) {
        db::explored_endpoints::request_boot_interface_observation(bmc_addr, &boot_target, &mut txn)
            .await?
    } else {
        db::explored_endpoints::set_boot_interface_target(bmc_addr, &boot_target, &mut txn).await?
    };

    tracing::info!(
        machine_id = %host_machine_id,
        machine_interface_id = %new_primary_interface_id,
        previous_machine_interface_id = ?current_primary_interface_id,
        selection_changed,
        synchronization_requested,
        assigned_synchronization_authorized = reboot && assigned,
        synchronization_deferred =
            synchronization_requested
                && ((assigned && !reboot) || (!assigned && !unassigned_ready)),
        controller_state = ?machine.state.value,
        "Selected the host boot interface",
    );

    // Normalize the current admin primary before moving the flag so its active
    // DHCP address can move to the selected interface. When there is no current
    // admin primary, the post-move pass below establishes address ownership
    // directly from the new selection.
    if selection_changed && current_primary_is_admin {
        db::machine_interface::reconcile_admin_addresses_for_host(&mut txn, &host_machine_id)
            .await?;
    }

    if selection_changed {
        db::machine_interface::demote_primary_interfaces_for_machine(&host_machine_id, &mut txn)
            .await?;
        db::machine_interface::set_primary_interface(&new_primary_interface_id, true, &mut txn)
            .await?;
    }

    // Reconcile admin address ownership after the primary flag moves and
    // publish the resulting host-group and instance network configuration.
    db::machine_interface::reconcile_admin_addresses_after_boot_interface_selection(
        &mut txn,
        &host_machine_id,
        selection_changed,
    )
    .await?;

    let selection_version = db::machine::set_boot_config_synchronization_request(
        &mut txn,
        host_machine_id,
        current_selection_version,
        new_primary_interface_id,
        selection_changed,
        // Assigned selection is intentionally non-disruptive until the caller
        // authorizes controller-owned Redfish work with `reboot=true`.
        reboot && assigned,
        initiator,
    )
    .await?;

    if unassigned_ready && synchronization_requested {
        let old_state_version = machine.state.version;
        let updated = db::machine::update_state_if_version_matches(
            &mut txn,
            &host_machine_id,
            old_state_version,
            old_state_version.increment(),
            &ManagedHostState::BootConfigSynchronization {
                synchronization_state:
                    BootConfigSynchronizationState::WaitingForInitialObservation {
                        target: BootConfigSynchronizationTarget {
                            machine_interface_id: Some(new_primary_interface_id),
                            boot_interface: boot_target,
                            selection_version,
                        },
                        minimum_report_version,
                    },
                synchronization_retry_count: 0,
            },
        )
        .await?;
        if !updated {
            return Err(CarbideError::internal(format!(
                "host {host_machine_id} changed state while selecting its boot interface"
            ))
            .into());
        }
    }

    txn.commit().await?;
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
