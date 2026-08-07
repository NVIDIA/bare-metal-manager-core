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
use model::machine::ManagedHostState;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine_boot_interface::{
    MachineBootInterface, MachineBootInterfaceTarget, canonical_redfish_boot_interface_id,
};
use model::network_segment::NetworkSegmentType;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::auth::AuthContext;
use crate::handlers::utils::{convert_and_log_machine_id, enqueue_boot_interface_reconciliation};

fn boot_target_for_interface(
    mac_address: mac_address::MacAddress,
    interface_id: Option<String>,
) -> MachineBootInterfaceTarget {
    match interface_id
        .as_deref()
        .and_then(canonical_redfish_boot_interface_id)
    {
        Some(interface_id) => MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address,
            interface_id: interface_id.to_string(),
        }),
        None => MachineBootInterfaceTarget::MacOnly(mac_address),
    }
}

/// Identifies the row directly or through the DPU attached to it.
#[derive(Clone, Copy)]
enum PrimaryInterfaceSelector {
    Interface(MachineInterfaceId),
    Dpu(MachineId),
}

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
    // `reboot` is only a compatibility alias for `force_reconcile`.
    #[allow(deprecated)]
    let force_reconcile = request.force_reconcile || request.reboot;

    log_machine_id(&host_machine_id);

    set_primary_interface_core(
        api,
        host_machine_id,
        PrimaryInterfaceSelector::Dpu(dpu_machine_id),
        force_reconcile,
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
    // `reboot` is only a compatibility alias for `force_reconcile`.
    #[allow(deprecated)]
    let force_reconcile = request.force_reconcile || request.reboot;

    log_machine_id(&host_machine_id);

    set_primary_interface_core(
        api,
        host_machine_id,
        PrimaryInterfaceSelector::Interface(interface_id),
        force_reconcile,
    )
    .await
}

/// Moves the database primary to the selected interface and records that exact
/// row as the host's desired boot target.
///
/// The transaction locks admin segments, host interfaces, and then the host
/// machine in the same order as Site Explorer. Once it commits, the machine
/// controller owns the Redfish write and any reboot needed to converge it.
async fn set_primary_interface_core(
    api: &Api,
    host_machine_id: MachineId,
    selector: PrimaryInterfaceSelector,
    force_reconcile: bool,
) -> Result<Response<()>, Status> {
    if !host_machine_id.machine_type().is_host() {
        return Err(CarbideError::InvalidArgument(format!(
            "machine {host_machine_id} is not a host machine; set-primary-interface can \
             only promote an interface on a host"
        ))
        .into());
    }

    // Admission permit BEFORE the transaction: waiters on the admin-segment
    // advisory lock must queue in memory, not on open pool connections.
    let _admin_admission = db::machine_interface::admin_lock_admission().await;
    let mut txn = api.txn_begin().await?;

    // Site Explorer takes these locks before it changes interface ownership.
    // Matching that order keeps an operator write from deadlocking discovery.
    db::machine_interface::lock_all_admin_segments(&mut txn).await?;
    let interface_snapshots =
        db::machine_interface::find_by_machine_id_for_update(&mut txn, &host_machine_id).await?;
    let machine = db::machine::find_one(
        &mut txn,
        &host_machine_id,
        MachineSearchConfig {
            for_update: true,
            ..Default::default()
        },
    )
    .await?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "Machine",
        id: host_machine_id.to_string(),
    })?;

    let new_primary_interface_id = match selector {
        PrimaryInterfaceSelector::Interface(interface_id) => interface_id,
        PrimaryInterfaceSelector::Dpu(dpu_machine_id) => {
            if !interface_snapshots.iter().any(|interface| {
                interface
                    .attached_dpu_machine_id
                    .is_some_and(|machine_id| machine_id.machine_type().is_dpu())
            }) {
                return Err(CarbideError::FailedPrecondition(format!(
                    "host {host_machine_id} has no DPUs; set-primary-dpu does not apply to zero-DPU hosts"
                ))
                .into());
            }

            interface_snapshots
                .iter()
                .find(|interface| interface.attached_dpu_machine_id == Some(dpu_machine_id))
                .map(|interface| interface.id)
                .ok_or_else(|| {
                    CarbideError::InvalidArgument(format!(
                        "DPU {dpu_machine_id} has no interface on host {host_machine_id}"
                    ))
                })?
        }
    };

    let current_primary_interface = interface_snapshots
        .iter()
        .find(|interface| interface.primary_interface);
    let current_primary_interface_id = current_primary_interface.map(|interface| interface.id);
    let current_primary_is_admin = current_primary_interface
        .is_some_and(|interface| interface.network_segment_type == Some(NetworkSegmentType::Admin));

    let new_primary_interface = interface_snapshots
        .iter()
        .find(|interface| interface.id == new_primary_interface_id)
        .ok_or_else(|| {
            CarbideError::InvalidArgument(format!(
                "interface {new_primary_interface_id} not found on host {host_machine_id}"
            ))
        })?;
    let primary_is_unchanged = new_primary_interface.primary_interface;
    if primary_is_unchanged && !force_reconcile {
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
            .is_some_and(|machine_id| machine_id.machine_type().is_dpu())
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
    let boot_target = boot_target_for_interface(primary_interface_mac_address, boot_interface_id);
    let instance = db::instance::find_by_machine_id(&mut txn, &host_machine_id).await?;
    let should_enqueue =
        matches!(machine.current_state(), ManagedHostState::Ready) && instance.is_none();

    if !primary_is_unchanged {
        tracing::info!(
            machine_id = %host_machine_id,
            new_primary_interface_id = %new_primary_interface_id,
            previous_primary_interface_id = ?current_primary_interface_id,
            "Moving host primary interface",
        );

        // Preserve the active admin address before moving the primary flag. A
        // host with no current admin primary skips this pass so the write can
        // repair that broken state in the post-move reconciliation below.
        if current_primary_is_admin {
            db::machine_interface::reconcile_admin_addresses_for_host(&mut txn, &host_machine_id)
                .await?;
        }

        if let Some(current_primary_interface_id) = current_primary_interface_id {
            db::machine_interface::set_primary_interface(
                &current_primary_interface_id,
                false,
                &mut txn,
            )
            .await?;
        }
        db::machine_interface::set_primary_interface(&new_primary_interface_id, true, &mut txn)
            .await?;
        db::machine_interface::reconcile_admin_addresses_for_host(&mut txn, &host_machine_id)
            .await?;

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

        if let Some(instance) = &instance {
            db::instance::update_network_config(
                &mut txn,
                instance.id,
                instance.network_config_version,
                &instance.config.network,
                true,
            )
            .await?;
        }
    }

    if force_reconcile {
        db::machine_desired_boot_interface::force_set(&mut txn, &host_machine_id, &boot_target)
            .await?;
    } else {
        db::machine_desired_boot_interface::set(&mut txn, &host_machine_id, &boot_target).await?;
    }

    txn.commit().await?;

    enqueue_boot_interface_reconciliation(api, host_machine_id, should_enqueue).await;

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
                        dpu_machine.id
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

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::*;

    #[test]
    fn boot_target_normalizes_interface_ids() {
        let mac_address = "00:00:5e:00:53:02".parse().unwrap();

        value_scenarios!(run = |interface_id| {
            boot_target_for_interface(mac_address, interface_id)
        };
            "complete id" {
                Some("NIC.Slot.7-1-1".to_string()) =>
                    MachineBootInterfaceTarget::Pair(MachineBootInterface {
                        mac_address,
                        interface_id: "NIC.Slot.7-1-1".to_string(),
                    }),
            }

            "padded id" {
                Some(" \tNIC.Slot.7-1-1\n ".to_string()) =>
                    MachineBootInterfaceTarget::Pair(MachineBootInterface {
                        mac_address,
                        interface_id: "NIC.Slot.7-1-1".to_string(),
                    }),
            }

            "blank id" {
                Some("\t\n".to_string()) => MachineBootInterfaceTarget::MacOnly(mac_address),
            }

            "missing id" {
                None => MachineBootInterfaceTarget::MacOnly(mac_address),
            }
        );
    }
}
