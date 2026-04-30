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

//! Handler for RackState::Maintenance.

use carbide_uuid::rack::{RackId, RackProfileId};
use db::{
    host_machine_update as db_host_machine_update, machine as db_machine,
    machine_topology as db_machine_topology, rack as db_rack, rack_firmware as db_rack_firmware,
    switch as db_switch,
};
use librms::protos::rack_manager as rms;
use model::rack::{
    ConfigureNmxClusterState, FirmwareUpgradeDeviceInfo, FirmwareUpgradeDeviceStatus,
    FirmwareUpgradeState, MaintenanceActivity, MaintenanceScope, NvosUpdateJob, NvosUpdateState,
    NvosUpdateSwitchStatus, Rack, RackFirmwareUpgradeState, RackFirmwareUpgradeStatus,
    RackMaintenanceState, RackPowerState, RackState, RackValidationState, ResolvedNvosArtifact,
    SwitchNvosUpdateState, SwitchNvosUpdateStatus,
};
use model::rack_firmware::{RackFirmware, RackFirmwareSearchFilter};
use model::rack_type::RackHardwareType;

use crate::rack::firmware_update::{
    RackFirmwareInventory, RackSwitchFirmwareInventory, build_firmware_update_batches,
    build_new_node_info, firmware_type_for_profile, load_rack_firmware_inventory,
    load_rack_switch_firmware_inventory, submit_firmware_update_batches,
};
use crate::rack::rms_client::SwitchSystemImageRmsClient;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::fabric_manager::{
    get_scale_up_fabric_services_status, persist_fabric_manager_statuses, persist_primary_switch,
    select_primary_switch, validate_switch_inventory_for_nmx_cluster,
};
use crate::state_controller::rack::validating::strip_rv_labels;
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

/// Strips all `rv.*` metadata labels from every machine in the rack.
///
/// Called on `Maintenance(Completed)` to ensure machines enter the next
/// validation cycle with a clean slate. RVS is expected to re-populate these
/// labels when it starts a new run.
async fn clear_rv_labels(
    rack: &Rack,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<(), StateHandlerError> {
    let mut txn = ctx.services.db_pool.begin().await?;

    let machines = super::get_machines_from_rack(rack, &mut txn).await?;

    for machine in machines.into_iter() {
        let mut metadata = machine.metadata;
        let id = machine.id;
        let ver = machine.version;

        if strip_rv_labels(&mut metadata) {
            db_machine::update_metadata(&mut txn, &id, ver, metadata).await?;
        }
    }

    txn.commit().await?;
    Ok(())
}

async fn trigger_rack_firmware_reprovisioning_requests(
    txn: &mut sqlx::PgConnection,
    rack_id: &RackId,
    machine_ids: &[carbide_uuid::machine::MachineId],
    switch_ids: &[carbide_uuid::switch::SwitchId],
) -> Result<(), StateHandlerError> {
    for machine_id in machine_ids {
        db_host_machine_update::trigger_host_reprovisioning_request(
            txn,
            &format!("rack-{}", rack_id),
            machine_id,
        )
        .await?;
    }
    for switch_id in switch_ids {
        db_switch::set_switch_reprovisioning_requested(
            txn,
            *switch_id,
            &format!("rack-{}", rack_id),
        )
        .await?;
    }
    Ok(())
}

fn desired_rack_hardware_type(
    id: &RackId,
    rack_profile_id: Option<&RackProfileId>,
    ctx: &StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> RackHardwareType {
    super::resolve_profile(id, rack_profile_id, ctx)
        .and_then(|profile| profile.rack_hardware_type.clone())
        .unwrap_or_else(RackHardwareType::any)
}

fn preferred_nvos_lookup_keys(
    id: &RackId,
    rack_profile_id: Option<&RackProfileId>,
    ctx: &StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(class) = super::resolve_profile(id, rack_profile_id, ctx)
        .and_then(|profile| profile.rack_hardware_class)
    {
        keys.push(format!("NVOS_{}", class));
    }
    if !keys.iter().any(|key| key == "NVOS_prod") {
        keys.push("NVOS_prod".to_string());
    }
    keys
}

fn resolve_nvos_artifact_from_firmware(
    firmware: &RackFirmware,
    lookup_keys: &[String],
) -> Result<Option<ResolvedNvosArtifact>, StateHandlerError> {
    let Some(parsed_components) = firmware.parsed_components.as_ref().map(|json| &json.0) else {
        return Ok(None);
    };

    let images = parsed_components
        .get("switch_system_images")
        .and_then(|value| value.get("Switch Tray"));

    let Some(images) = images else {
        return Ok(None);
    };

    for lookup_key in lookup_keys {
        let Some(entry) = images.get(lookup_key) else {
            continue;
        };

        let image_filename = entry
            .get("image_filename")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "rack firmware {} has malformed {} lookup entry: missing image_filename",
                    firmware.id,
                    lookup_key
                ))
            })?;

        let version = entry
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);

        return Ok(Some(ResolvedNvosArtifact {
            firmware_id: firmware.id.clone(),
            image_filename: image_filename.to_string(),
            local_file_path: format!(
                "/forge-boot-artifacts/blobs/internal/fw/rack_firmware/{}/{}",
                firmware.id, image_filename
            ),
            version,
        }));
    }

    Ok(None)
}

async fn resolve_default_nvos_artifact(
    id: &RackId,
    rack_profile_id: Option<&RackProfileId>,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<Option<ResolvedNvosArtifact>, StateHandlerError> {
    let desired_hw_type = desired_rack_hardware_type(id, rack_profile_id, ctx);
    let lookup_keys = preferred_nvos_lookup_keys(id, rack_profile_id, ctx);
    let mut hardware_types = vec![desired_hw_type.clone()];
    if !desired_hw_type.is_any() {
        hardware_types.push(RackHardwareType::any());
    }

    let mut conn = ctx.services.db_pool.acquire().await.map_err(|e| {
        StateHandlerError::GenericError(eyre::eyre!(
            "failed to acquire db connection for NVOS lookup: {}",
            e
        ))
    })?;

    for rack_hardware_type in hardware_types {
        let firmware_rows = db_rack_firmware::list_all(
            &mut conn,
            RackFirmwareSearchFilter {
                only_available: true,
                rack_hardware_type: Some(rack_hardware_type),
            },
        )
        .await
        .map_err(|e| StateHandlerError::GenericError(eyre::eyre!(e.to_string())))?;

        for firmware in firmware_rows.into_iter().filter(|fw| fw.is_default) {
            if let Some(artifact) = resolve_nvos_artifact_from_firmware(&firmware, &lookup_keys)? {
                return Ok(Some(artifact));
            }
        }
    }

    Ok(None)
}

async fn resolve_requested_or_default_nvos_artifact(
    id: &RackId,
    rack_profile_id: Option<&RackProfileId>,
    rack_firmware_id: Option<&str>,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<Option<ResolvedNvosArtifact>, StateHandlerError> {
    let Some(rack_firmware_id) = rack_firmware_id else {
        return resolve_default_nvos_artifact(id, rack_profile_id, ctx).await;
    };

    let firmware = match db_rack_firmware::find_by_id(&ctx.services.db_pool, rack_firmware_id).await
    {
        Ok(firmware) => firmware,
        Err(db::DatabaseError::NotFoundError { .. }) => {
            return Err(StateHandlerError::GenericError(eyre::eyre!(
                "requested NVOS rack firmware '{}' not found",
                rack_firmware_id
            )));
        }
        Err(error) => return Err(error.into()),
    };

    if !firmware.available {
        return Err(StateHandlerError::GenericError(eyre::eyre!(
            "requested NVOS rack firmware '{}' exists but is not available",
            rack_firmware_id
        )));
    }

    let lookup_keys = preferred_nvos_lookup_keys(id, rack_profile_id, ctx);
    resolve_nvos_artifact_from_firmware(&firmware, &lookup_keys)?.map_or_else(
        || {
            Err(StateHandlerError::GenericError(eyre::eyre!(
                "requested NVOS rack firmware '{}' has no switch system image for lookup keys [{}]",
                rack_firmware_id,
                lookup_keys.join(", ")
            )))
        },
        |artifact| Ok(Some(artifact)),
    )
}

async fn clear_rack_firmware_device_statuses(
    txn: &mut sqlx::PgConnection,
    machine_ids: &[carbide_uuid::machine::MachineId],
    switch_ids: &[carbide_uuid::switch::SwitchId],
) -> Result<(), StateHandlerError> {
    for machine_id in machine_ids {
        db_machine::update_rack_fw_details(txn, machine_id, None).await?;
    }
    for switch_id in switch_ids {
        db_switch::update_firmware_upgrade_status(txn, *switch_id, None).await?;
    }
    Ok(())
}

async fn clear_nvos_update_statuses(
    txn: &mut sqlx::PgConnection,
    switch_ids: &[carbide_uuid::switch::SwitchId],
) -> Result<(), StateHandlerError> {
    for switch_id in switch_ids {
        db_switch::update_nvos_update_status(txn, *switch_id, None).await?;
    }
    Ok(())
}

fn skip_firmware_upgrade_outcome(
    rack_id: &RackId,
    reason: impl AsRef<str>,
    scope: &MaintenanceScope,
) -> StateHandlerOutcome<RackState> {
    let next = next_state_after_firmware(scope);
    tracing::info!(
        rack_id = %rack_id,
        reason = %reason.as_ref(),
        next_state = %next,
        "Skipping rack firmware upgrade"
    );
    StateHandlerOutcome::transition(RackState::Maintenance {
        maintenance_state: next,
    })
}

/// Transition the rack to `Error` from a maintenance handler failure.
///
/// Clears `maintenance_requested` (and persists it) so the `Error` handler
/// does not immediately re-enter `Maintenance` and loop on the same failure.
/// The user must explicitly request maintenance again to retry.
async fn transition_to_rack_error(
    rack_id: &RackId,
    state: &mut Rack,
    cause: impl Into<String>,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    let cause = cause.into();
    tracing::warn!(rack_id = %rack_id, %cause, "Rack firmware upgrade failed before polling started");
    let outcome = StateHandlerOutcome::transition(RackState::Error { cause });
    clear_maintenance_requested_on_error(rack_id, state, outcome, ctx).await
}

async fn transition_to_rack_error_with_firmware_job(
    rack_id: &RackId,
    state: &mut Rack,
    firmware_id: impl Into<String>,
    cause: impl Into<String>,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    let cause = cause.into();
    tracing::warn!(rack_id = %rack_id, %cause, "Rack firmware upgrade failed before polling started");

    let now = chrono::Utc::now();
    let job = model::rack::FirmwareUpgradeJob {
        firmware_id: Some(firmware_id.into()),
        status: Some("failed".into()),
        started_at: Some(now),
        completed_at: Some(now),
        ..Default::default()
    };
    state.firmware_upgrade_job = Some(job.clone());
    state.config.maintenance_requested = None;

    let mut txn = ctx.services.db_pool.begin().await?;
    db_rack::update_firmware_upgrade_job(txn.as_mut(), rack_id, Some(&job)).await?;
    db_rack::update(txn.as_mut(), rack_id, &state.config).await?;

    Ok(StateHandlerOutcome::transition(RackState::Error { cause }).with_txn(txn))
}

/// If `maintenance_requested` is set, clear it and persist the updated config
/// using a fresh transaction attached to the outcome. Used when transitioning
/// from `Maintenance` to `Error` to break the Error → Maintenance loop.
async fn clear_maintenance_requested_on_error(
    rack_id: &RackId,
    state: &mut Rack,
    outcome: StateHandlerOutcome<RackState>,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    if state.config.maintenance_requested.is_none() {
        return Ok(outcome);
    }
    state.config.maintenance_requested = None;
    let mut txn = ctx.services.db_pool.begin().await?;
    db_rack::update(txn.as_mut(), rack_id, &state.config).await?;
    Ok(outcome.with_txn(txn))
}

fn nvos_update_requested(scope: &MaintenanceScope) -> bool {
    scope
        .activities
        .iter()
        .any(|activity| matches!(activity, MaintenanceActivity::NvosUpdate { .. }))
}

fn implicit_nvos_update_requested(scope: &MaintenanceScope) -> bool {
    scope.should_run(&MaintenanceActivity::NvosUpdate {
        rack_firmware_id: None,
    }) && !nvos_update_requested(scope)
}

fn requested_rack_firmware_id(scope: &MaintenanceScope) -> Option<String> {
    scope.activities.iter().find_map(|activity| match activity {
        MaintenanceActivity::NvosUpdate { rack_firmware_id } => rack_firmware_id.clone(),
        _ => None,
    })
}

fn nvos_update_start_state(scope: &MaintenanceScope) -> RackMaintenanceState {
    RackMaintenanceState::NVOSUpdate {
        nvos_update: NvosUpdateState::Start {
            rack_firmware_id: requested_rack_firmware_id(scope),
        },
    }
}

/// Returns the next maintenance sub-state after firmware upgrade, skipping
/// activities not requested in the scope.
fn next_state_after_firmware(scope: &MaintenanceScope) -> RackMaintenanceState {
    if scope.should_run(&MaintenanceActivity::NvosUpdate {
        rack_firmware_id: None,
    }) {
        nvos_update_start_state(scope)
    } else {
        next_state_after_nvos(scope)
    }
}

/// Returns the next maintenance sub-state after NVOS update, skipping
/// activities not requested in the scope.
fn next_state_after_nvos(scope: &MaintenanceScope) -> RackMaintenanceState {
    if scope.should_run(&MaintenanceActivity::ConfigureNmxCluster) {
        RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster: ConfigureNmxClusterState::Start,
        }
    } else {
        next_state_after_configure(scope)
    }
}

/// Returns the next maintenance sub-state after ConfigureNmxCluster, skipping
/// activities not requested in the scope.
fn next_state_after_configure(scope: &MaintenanceScope) -> RackMaintenanceState {
    if scope.should_run(&MaintenanceActivity::PowerSequence) {
        RackMaintenanceState::PowerSequence {
            rack_power: RackPowerState::PoweringOn,
        }
    } else {
        RackMaintenanceState::Completed
    }
}

/// Returns the first maintenance sub-state to enter based on the requested
/// activities in the scope. Called from Ready/Error when entering Maintenance.
pub(crate) fn first_maintenance_state(scope: &MaintenanceScope) -> RackMaintenanceState {
    if scope.should_run(&MaintenanceActivity::FirmwareUpgrade {
        firmware_version: None,
        components: vec![],
    }) {
        RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::Start,
        }
    } else {
        next_state_after_firmware(scope)
    }
}

/// Filters a full-rack firmware inventory down to only the devices listed in
/// the maintenance scope. When `scope.is_full_rack()` the inventory is
/// returned unchanged.
fn filter_inventory_by_scope(
    mut inventory: RackFirmwareInventory,
    scope: &MaintenanceScope,
) -> RackFirmwareInventory {
    if scope.is_full_rack() {
        return inventory;
    }

    if scope.machine_ids.is_empty() {
        inventory.machine_ids.clear();
        inventory.machines.clear();
    } else {
        let allowed: std::collections::HashSet<_> = scope.machine_ids.iter().collect();
        inventory.machine_ids.retain(|id| allowed.contains(id));
        inventory.machines.retain(|d| {
            match d.node_id.parse::<carbide_uuid::machine::MachineId>() {
                Ok(ref id) => allowed.contains(id),
                Err(_) => false,
            }
        });
    }

    if scope.switch_ids.is_empty() {
        inventory.switch_ids.clear();
        inventory.switches.clear();
    } else {
        let allowed: std::collections::HashSet<_> = scope.switch_ids.iter().collect();
        inventory.switch_ids.retain(|id| allowed.contains(id));
        inventory.switches.retain(
            |d| match d.node_id.parse::<carbide_uuid::switch::SwitchId>() {
                Ok(ref id) => allowed.contains(id),
                Err(_) => false,
            },
        );
    }

    inventory
}

fn filter_switch_inventory_by_scope(
    mut inventory: RackSwitchFirmwareInventory,
    scope: &MaintenanceScope,
) -> RackSwitchFirmwareInventory {
    if scope.is_full_rack() {
        return inventory;
    }

    if scope.switch_ids.is_empty() {
        inventory.switch_ids.clear();
        inventory.switches.clear();
    } else {
        let allowed: std::collections::HashSet<_> = scope.switch_ids.iter().collect();
        inventory.switch_ids.retain(|id| allowed.contains(id));
        inventory.switches.retain(
            |d| match d.node_id.parse::<carbide_uuid::switch::SwitchId>() {
                Ok(ref id) => allowed.contains(id),
                Err(_) => false,
            },
        );
    }

    inventory
}

fn skip_configure_nmx_cluster_outcome(
    rack_id: &RackId,
    reason: impl AsRef<str>,
    scope: &MaintenanceScope,
) -> StateHandlerOutcome<RackState> {
    let next = next_state_after_configure(scope);
    tracing::info!(
        rack_id = %rack_id,
        reason = %reason.as_ref(),
        next_state = %next,
        "Skipping ConfigureNmxCluster"
    );
    StateHandlerOutcome::transition(RackState::Maintenance {
        maintenance_state: next,
    })
}

fn build_switch_device_info_request(
    rack_id: &RackId,
    switches: &[FirmwareUpgradeDeviceInfo],
) -> rms::GetDeviceInfoByDeviceListRequest {
    rms::GetDeviceInfoByDeviceListRequest {
        nodes: Some(rms::NodeSet {
            devices: switches
                .iter()
                .map(|switch| build_new_node_info(rack_id, switch, rms::NodeType::Switch))
                .collect(),
        }),
        ..Default::default()
    }
}

/// Submit compute and switch firmware-update batches to RMS and persist the
/// per-device child job IDs returned by UpdateFirmwareByDeviceList.
async fn rms_start_firmware_upgrade(
    rms_client: &dyn librms::RmsApi,
    firmware_id: &str,
    batches: Vec<crate::rack::firmware_update::FirmwareUpdateBatchRequest>,
) -> model::rack::FirmwareUpgradeJob {
    let started_at = chrono::Utc::now();
    let submissions = submit_firmware_update_batches(rms_client, batches).await;
    let mut job = model::rack::FirmwareUpgradeJob {
        firmware_id: Some(firmware_id.to_string()),
        started_at: Some(started_at),
        ..Default::default()
    };

    for submission in submissions {
        match submission.response {
            Ok(response) => {
                if !response.job_id.is_empty() {
                    job.batch_job_ids.push(response.job_id.clone());
                }

                let child_jobs = response
                    .node_jobs
                    .iter()
                    .map(|child| (child.node_id.as_str(), child.job_id.clone()))
                    .collect::<std::collections::HashMap<_, _>>();
                let node_errors = response
                    .node_results
                    .iter()
                    .map(|result| (result.node_id.as_str(), result.error_message.clone()))
                    .collect::<std::collections::HashMap<_, _>>();
                let parent_job_id =
                    (!response.job_id.is_empty()).then_some(response.job_id.clone());

                let target_devices = match submission.display_name {
                    "Compute Node" => &mut job.machines,
                    "Switch" => &mut job.switches,
                    _ => continue,
                };

                for device in submission.devices {
                    let mut status = FirmwareUpgradeDeviceStatus {
                        node_id: device.node_id.clone(),
                        mac: device.mac.clone(),
                        bmc_ip: device.bmc_ip.clone(),
                        status: "in_progress".into(),
                        job_id: None,
                        parent_job_id: parent_job_id.clone(),
                        error_message: None,
                    };

                    if let Some(error_message) = node_errors.get(device.node_id.as_str()) {
                        status.status = "failed".into();
                        status.error_message = Some(error_message.clone());
                    } else if let Some(job_id) = child_jobs.get(device.node_id.as_str()) {
                        status.job_id = Some(job_id.clone());
                    } else {
                        status.status = "failed".into();
                        status.error_message =
                            Some("RMS did not return a child firmware job for this device".into());
                    }

                    target_devices.push(status);
                }
            }
            Err(error) => {
                let target_devices = match submission.display_name {
                    "Compute Node" => &mut job.machines,
                    "Switch" => &mut job.switches,
                    _ => continue,
                };

                for device in submission.devices {
                    target_devices.push(FirmwareUpgradeDeviceStatus {
                        node_id: device.node_id.clone(),
                        mac: device.mac.clone(),
                        bmc_ip: device.bmc_ip.clone(),
                        status: "failed".into(),
                        job_id: None,
                        parent_job_id: None,
                        error_message: Some(error.clone()),
                    });
                }
            }
        }
    }

    job.job_id = job.batch_job_ids.first().cloned();
    let all_devices: Vec<_> = job.all_devices().collect();
    let failed = all_devices
        .iter()
        .filter(|device| device.status == "failed")
        .count();
    let completed = all_devices
        .iter()
        .filter(|device| device.status == "completed")
        .count();
    let total = all_devices.len();
    let terminal = completed + failed;

    job.status = Some(
        if total > 0 && terminal < total {
            "in_progress"
        } else if failed > 0 {
            "failed"
        } else {
            "completed"
        }
        .into(),
    );
    if total > 0 && terminal == total {
        job.completed_at = Some(chrono::Utc::now());
    }

    job
}

/// Poll RMS GetFirmwareJobStatus for each tracked child job and update the
/// in-memory rack firmware job with the latest per-device result.
async fn rms_get_firmware_upgrade_status(
    rms_client: &dyn librms::RmsApi,
    job: &model::rack::FirmwareUpgradeJob,
) -> Result<model::rack::FirmwareUpgradeJob, StateHandlerError> {
    let mut updated = job.clone();
    for device in updated.all_devices_mut() {
        if matches!(device.status.as_str(), "completed" | "failed") {
            continue;
        }

        let Some(job_id) = device.job_id.clone() else {
            device.status = "failed".into();
            if device.error_message.is_none() {
                device.error_message = Some("Device has no firmware job ID to poll".into());
            }
            continue;
        };

        let response = rms_client
            .get_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusRequest {
                job_id: job_id.clone(),
                ..Default::default()
            })
            .await;

        match response {
            Ok(response)
                if response.status == librms::protos::rack_manager::ReturnCode::Success as i32 =>
            {
                if !response.node_id.is_empty() {
                    device.node_id = response.node_id.clone();
                }
                match response.job_state {
                    0 => {
                        device.status = "pending".into();
                        device.error_message = None;
                    }
                    1 => {
                        device.status = "in_progress".into();
                        device.error_message = None;
                    }
                    2 => {
                        device.status = "completed".into();
                        device.error_message = None;
                    }
                    3 => {
                        device.status = "failed".into();
                        device.error_message = Some(if response.error_message.is_empty() {
                            response.state_description
                        } else {
                            response.error_message
                        });
                    }
                    _ => {
                        tracing::warn!(
                            job_id = %job_id,
                            job_state = response.job_state,
                            "RMS returned unknown firmware job state; keeping previous device status"
                        );
                        device.error_message = Some(format!(
                            "Unknown RMS firmware job state {}",
                            response.job_state
                        ));
                    }
                }
            }
            Ok(response) => {
                let message = if response.error_message.is_empty() {
                    if response.state_description.is_empty() {
                        format!("RMS could not report status for firmware job {}", job_id)
                    } else {
                        response.state_description
                    }
                } else {
                    response.error_message
                };
                tracing::warn!(
                    job_id = %job_id,
                    status = response.status,
                    error = %message,
                    "RMS returned a non-success firmware job status lookup; retrying later"
                );
                device.error_message = Some(message);
            }
            Err(error) => {
                tracing::warn!(
                    job_id = %job_id,
                    error = %error,
                    "Transient RMS firmware job polling error; retrying later"
                );
                device.error_message = Some(error.to_string());
            }
        }
    }

    let all_devices: Vec<_> = updated.all_devices().collect();
    let failed = all_devices
        .iter()
        .filter(|device| device.status == "failed")
        .count();
    let completed = all_devices
        .iter()
        .filter(|device| device.status == "completed")
        .count();
    let total = all_devices.len();
    let terminal = completed + failed;

    updated.status = Some(
        if total > 0 && terminal < total {
            "in_progress"
        } else if failed > 0 {
            "failed"
        } else {
            "completed"
        }
        .into(),
    );
    updated.completed_at = if total > 0 && terminal == total {
        Some(chrono::Utc::now())
    } else {
        None
    };

    Ok(updated)
}

async fn rms_start_nvos_update(
    rms_client: &dyn SwitchSystemImageRmsClient,
    rack_id: &RackId,
    artifact: &ResolvedNvosArtifact,
    switches: Vec<FirmwareUpgradeDeviceInfo>,
) -> Result<NvosUpdateJob, StateHandlerError> {
    let started_at = chrono::Utc::now();
    let response = rms_client
        .update_switch_system_image(rms::UpdateSwitchSystemImageRequest {
            nodes: Some(rms::NodeSet {
                devices: switches
                    .iter()
                    .map(|switch| build_new_node_info(rack_id, switch, rms::NodeType::Switch))
                    .collect(),
            }),
            image_filename: artifact.image_filename.clone(),
            local_file_path: artifact.local_file_path.clone(),
            ..Default::default()
        })
        .await
        .map_err(|error| {
            StateHandlerError::GenericError(eyre::eyre!(
                "failed to submit NVOS update to RMS: {}",
                error
            ))
        })?;

    if response.status != rms::ReturnCode::Success as i32
        && response.job_id.is_empty()
        && response.node_jobs.is_empty()
    {
        let message = if response.message.is_empty() {
            "RMS returned failure for UpdateSwitchSystemImage".to_string()
        } else {
            response.message
        };
        return Err(StateHandlerError::GenericError(eyre::eyre!(message)));
    }

    let parent_job_id = (!response.job_id.is_empty()).then_some(response.job_id.clone());
    let child_jobs = response
        .node_jobs
        .iter()
        .map(|child| (child.node_id.as_str(), child.job_id.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let node_errors = response
        .node_results
        .iter()
        .map(|result| (result.node_id.as_str(), result.error_message.clone()))
        .collect::<std::collections::HashMap<_, _>>();

    let switches: Vec<_> = switches
        .into_iter()
        .map(|switch| {
            let mut status = NvosUpdateSwitchStatus {
                node_id: switch.node_id.clone(),
                mac: switch.mac,
                bmc_ip: switch.bmc_ip,
                nvos_ip: switch.os_ip.unwrap_or_default(),
                status: "pending".into(),
                job_id: child_jobs
                    .get(switch.node_id.as_str())
                    .cloned()
                    .or_else(|| parent_job_id.clone()),
                error_message: None,
            };

            if let Some(error_message) = node_errors.get(switch.node_id.as_str()) {
                status.status = "failed".into();
                status.error_message = Some(error_message.clone());
            } else if status.job_id.is_none() {
                status.status = "failed".into();
                status.error_message =
                    Some("RMS did not return a switch system image job for this switch".into());
            }

            status
        })
        .collect();

    let failed = switches
        .iter()
        .filter(|switch| switch.status == "failed")
        .count();
    let completed = switches
        .iter()
        .filter(|switch| switch.status == "completed")
        .count();
    let total = switches.len();
    let terminal = completed + failed;

    Ok(NvosUpdateJob {
        job_id: parent_job_id,
        firmware_id: artifact.firmware_id.clone(),
        image_filename: artifact.image_filename.clone(),
        local_file_path: artifact.local_file_path.clone(),
        version: artifact.version.clone(),
        status: Some(
            if total > 0 && terminal < total {
                "in_progress"
            } else if failed > 0 {
                "failed"
            } else {
                "completed"
            }
            .into(),
        ),
        started_at: Some(started_at),
        completed_at: if total > 0 && terminal == total {
            Some(chrono::Utc::now())
        } else {
            None
        },
        switches,
    })
}

async fn rms_get_nvos_update_status(
    rms_client: &dyn SwitchSystemImageRmsClient,
    job: &NvosUpdateJob,
) -> Result<NvosUpdateJob, StateHandlerError> {
    let mut updated = job.clone();
    let parent_job_id = updated.job_id.clone();

    for switch in updated.all_switches_mut() {
        if matches!(switch.status.as_str(), "completed" | "failed") {
            continue;
        }

        let Some(job_id) = switch.job_id.clone().or_else(|| parent_job_id.clone()) else {
            switch.status = "failed".into();
            if switch.error_message.is_none() {
                switch.error_message = Some("Switch has no NVOS job ID to poll".into());
            }
            continue;
        };

        let response = rms_client
            .get_switch_system_image_job_status(rms::GetSwitchSystemImageJobStatusRequest {
                job_id: job_id.clone(),
                ..Default::default()
            })
            .await;

        apply_nvos_job_status_response(switch, &job_id, response);
    }

    let total = updated.all_switches().count();
    let completed = updated
        .all_switches()
        .filter(|switch| switch.status == "completed")
        .count();
    let failed = updated
        .all_switches()
        .filter(|switch| switch.status == "failed")
        .count();
    let terminal = completed + failed;

    updated.status = Some(
        if total > 0 && terminal < total {
            "in_progress"
        } else if failed > 0 {
            "failed"
        } else {
            "completed"
        }
        .into(),
    );
    updated.completed_at = if total > 0 && terminal == total {
        Some(chrono::Utc::now())
    } else {
        None
    };

    Ok(updated)
}

pub(crate) fn apply_nvos_job_status_response(
    switch: &mut NvosUpdateSwitchStatus,
    job_id: &str,
    response: Result<rms::GetSwitchSystemImageJobStatusResponse, tonic::Status>,
) {
    match response {
        Ok(response) if response.status == rms::ReturnCode::Success as i32 => {
            if !response.node_id.is_empty() {
                switch.node_id = response.node_id.clone();
            }

            match response.state.to_ascii_lowercase().as_str() {
                "queued" | "pending" => {
                    switch.status = "pending".into();
                    switch.error_message = None;
                }
                "running" | "in_progress" | "active" => {
                    switch.status = "in_progress".into();
                    switch.error_message = None;
                }
                "completed" | "success" | "done" => {
                    switch.status = "completed".into();
                    switch.error_message = None;
                }
                "failed" | "error" => {
                    switch.status = "failed".into();
                    switch.error_message = Some(if response.error_message.is_empty() {
                        response.message
                    } else {
                        response.error_message
                    });
                }
                other => {
                    tracing::warn!(
                        job_id = %job_id,
                        state = %other,
                        "RMS returned unknown switch system image job state; keeping previous status",
                    );
                    switch.error_message =
                        Some(format!("Unknown RMS switch image job state {}", other));
                }
            }
        }
        Ok(response) => {
            let message = if response.error_message.is_empty() {
                if response.message.is_empty() {
                    format!("RMS could not report status for NVOS job {}", job_id)
                } else {
                    response.message
                }
            } else {
                response.error_message
            };
            tracing::warn!(
                job_id = %job_id,
                status = response.status,
                error = %message,
                "RMS returned a non-success switch image job status lookup; retrying later",
            );
            switch.error_message = Some(message);
        }
        Err(error) => {
            tracing::warn!(
                job_id = %job_id,
                error = %error,
                "Transient RMS switch image job polling error; retrying later",
            );
            switch.error_message = Some(error.to_string());
        }
    }
}

pub async fn handle_maintenance(
    id: &RackId,
    state: &mut Rack,
    rack_profile_id: Option<&RackProfileId>,
    maintenance_state: &RackMaintenanceState,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    let scope = state
        .config
        .maintenance_requested
        .clone()
        .unwrap_or_default();
    let scope = &scope;

    match maintenance_state {
        RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade,
        } => match rack_firmware_upgrade {
            FirmwareUpgradeState::Start => {
                let Some(profile) = super::resolve_profile(id, rack_profile_id, ctx) else {
                    return Ok(skip_firmware_upgrade_outcome(
                        id,
                        "rack profile is missing or unknown",
                        scope,
                    ));
                };
                let Some(rack_hardware_type) = profile.rack_hardware_type.as_ref() else {
                    return Ok(skip_firmware_upgrade_outcome(
                        id,
                        "rack capabilities do not define rack_hardware_type",
                        scope,
                    ));
                };
                let (requested_fw_version, requested_components) = scope
                    .activities
                    .iter()
                    .find_map(|a| match a {
                        MaintenanceActivity::FirmwareUpgrade {
                            firmware_version,
                            components,
                        } => Some((firmware_version.as_deref(), components.as_slice())),
                        _ => None,
                    })
                    .unwrap_or((None, &[]));

                let firmware = if let Some(fw_version) = requested_fw_version {
                    match db_rack_firmware::find_by_id(&ctx.services.db_pool, fw_version).await {
                        Ok(fw) => fw,
                        Err(db::DatabaseError::NotFoundError { .. }) => {
                            return transition_to_rack_error_with_firmware_job(
                                id,
                                state,
                                fw_version,
                                format!("requested rack firmware '{}' not found", fw_version),
                                ctx,
                            )
                            .await;
                        }
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    match db_rack_firmware::find_default_by_rack_hardware_type(
                        &ctx.services.db_pool,
                        rack_hardware_type,
                    )
                    .await
                    {
                        Ok(fw) => fw,
                        Err(db::DatabaseError::NotFoundError { .. }) => {
                            return Ok(skip_firmware_upgrade_outcome(
                                id,
                                format!(
                                    "no default rack firmware configured for hardware type '{}'",
                                    rack_hardware_type
                                ),
                                scope,
                            ));
                        }
                        Err(error) => return Err(error.into()),
                    }
                };

                if !firmware.available {
                    if let Some(fw_version) = requested_fw_version {
                        return transition_to_rack_error_with_firmware_job(
                            id,
                            state,
                            fw_version,
                            format!(
                                "requested rack firmware '{}' exists but is not available",
                                firmware.id
                            ),
                            ctx,
                        )
                        .await;
                    }
                    return Ok(skip_firmware_upgrade_outcome(
                        id,
                        format!(
                            "rack firmware '{}' exists but is not available",
                            firmware.id
                        ),
                        scope,
                    ));
                }

                let inventory = load_rack_firmware_inventory(
                    &ctx.services.db_pool,
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to load rack firmware inventory: {}",
                        error
                    ))
                })?;
                let inventory = filter_inventory_by_scope(inventory, scope);
                let firmware_type = firmware_type_for_profile(profile);
                let batches = match build_firmware_update_batches(
                    id,
                    &firmware,
                    firmware_type,
                    &inventory,
                    requested_components,
                ) {
                    Ok(batches) if batches.is_empty() => {
                        return Ok(skip_firmware_upgrade_outcome(
                            id,
                            "no compute or switch devices require rack firmware updates",
                            scope,
                        ));
                    }
                    Ok(batches) => batches,
                    Err(error) => {
                        return transition_to_rack_error_with_firmware_job(
                            id,
                            state,
                            firmware.id.clone(),
                            format!(
                                "failed to build firmware update requests for firmware '{}': {}",
                                firmware.id, error
                            ),
                            ctx,
                        )
                        .await;
                    }
                };
                let Some(rms_client) = ctx.services.rms_client.as_ref() else {
                    return transition_to_rack_error_with_firmware_job(
                        id,
                        state,
                        firmware.id.clone(),
                        "RMS client not configured",
                        ctx,
                    )
                    .await;
                };

                tracing::info!(
                    rack_id = %id,
                    rack_hardware_type = %rack_hardware_type,
                    firmware_id = %firmware.id,
                    firmware_type,
                    machine_count = inventory.machines.len(),
                    switch_count = inventory.switches.len(),
                    "Rack firmware upgrade starting"
                );
                let mut job =
                    rms_start_firmware_upgrade(rms_client.as_ref(), &firmware.id, batches).await;

                let mut txn = ctx.services.db_pool.begin().await?;
                trigger_rack_firmware_reprovisioning_requests(
                    txn.as_mut(),
                    id,
                    &inventory.machine_ids,
                    &inventory.switch_ids,
                )
                .await?;
                clear_rack_firmware_device_statuses(
                    txn.as_mut(),
                    &inventory.machine_ids,
                    &inventory.switch_ids,
                )
                .await?;
                job.started_at = Some(chrono::Utc::now());
                db_rack::update_firmware_upgrade_job(txn.as_mut(), id, Some(&job)).await?;
                state.firmware_upgrade_job = Some(job);

                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: RackMaintenanceState::FirmwareUpgrade {
                        rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
                    },
                })
                .with_txn(txn))
            }
            FirmwareUpgradeState::WaitForComplete => {
                if state.firmware_upgrade_job.is_none() {
                    return Ok(StateHandlerOutcome::wait(
                        "firmware upgrade: no job recorded yet".into(),
                    ));
                }
                let Some(rms_client) = ctx.services.rms_client.as_ref() else {
                    return transition_to_rack_error(id, state, "RMS client not configured", ctx)
                        .await;
                };
                let current_job = state.firmware_upgrade_job.as_ref().unwrap();
                let mut job =
                    rms_get_firmware_upgrade_status(rms_client.as_ref(), current_job).await?;

                let all: Vec<_> = job.all_devices().collect();
                let total = all.len();
                let completed = all.iter().filter(|d| d.status == "completed").count();
                let failed = all.iter().filter(|d| d.status == "failed").count();
                let terminal = completed + failed;
                let default_nvos_artifact =
                    if terminal == total && failed == 0 && implicit_nvos_update_requested(scope) {
                        resolve_default_nvos_artifact(id, rack_profile_id, ctx).await?
                    } else {
                        None
                    };

                let mut txn = ctx.services.db_pool.begin().await?;

                let build_status =
                    |device: &FirmwareUpgradeDeviceStatus| -> RackFirmwareUpgradeStatus {
                        let state = match device.status.as_str() {
                            "completed" => RackFirmwareUpgradeState::Completed,
                            "failed" => RackFirmwareUpgradeState::Failed {
                                cause: format!("RMS reported failure for {}", device.mac),
                            },
                            "in_progress" => RackFirmwareUpgradeState::InProgress,
                            _ => RackFirmwareUpgradeState::Started,
                        };
                        RackFirmwareUpgradeStatus {
                            task_id: device
                                .job_id
                                .clone()
                                .or_else(|| device.parent_job_id.clone())
                                .or_else(|| job.job_id.clone())
                                .unwrap_or_else(|| "unknown".to_string()),
                            status: state,
                            started_at: job.started_at,
                            ended_at: if device.status == "completed" || device.status == "failed" {
                                job.completed_at.or(Some(chrono::Utc::now()))
                            } else {
                                None
                            },
                        }
                    };

                for device in job.machines.iter() {
                    let machine_id = if !device.node_id.is_empty() {
                        device
                            .node_id
                            .parse::<carbide_uuid::machine::MachineId>()
                            .ok()
                    } else {
                        let mac: mac_address::MacAddress = match device.mac.parse() {
                            Ok(mac) => mac,
                            Err(_) => continue,
                        };
                        db_machine_topology::find_machine_id_by_bmc_mac(txn.as_mut(), mac).await?
                    };
                    if let Some(machine_id) = machine_id {
                        let fw_status = build_status(device);
                        db_machine::update_rack_fw_details(
                            txn.as_mut(),
                            &machine_id,
                            Some(&fw_status),
                        )
                        .await?;
                    }
                }

                for device in job.switches.iter() {
                    let switch_id = if !device.node_id.is_empty() {
                        device
                            .node_id
                            .parse::<carbide_uuid::switch::SwitchId>()
                            .ok()
                    } else {
                        let mac: mac_address::MacAddress = match device.mac.parse() {
                            Ok(mac) => mac,
                            Err(_) => continue,
                        };
                        db_switch::find_ids(
                            txn.as_mut(),
                            model::switch::SwitchSearchFilter {
                                bmc_mac: Some(mac),
                                rack_id: Some(id.clone()),
                                ..Default::default()
                            },
                        )
                        .await?
                        .first()
                        .copied()
                    };
                    if let Some(switch_id) = switch_id {
                        let fw_status = build_status(device);
                        db_switch::update_firmware_upgrade_status(
                            txn.as_mut(),
                            switch_id,
                            Some(&fw_status),
                        )
                        .await?;
                    }
                }

                if terminal < total {
                    db_rack::update_firmware_upgrade_job(txn.as_mut(), id, Some(&job)).await?;
                    state.firmware_upgrade_job = Some(job);
                    return Ok(StateHandlerOutcome::wait(format!(
                        "firmware upgrade: {}/{} devices terminal (completed={}, failed={})",
                        terminal, total, completed, failed
                    ))
                    .with_txn(txn));
                }

                if failed > 0 {
                    let now = chrono::Utc::now();
                    job.status = Some("failed".into());
                    if job.completed_at.is_none() {
                        job.completed_at = Some(now);
                    }
                    db_rack::update_firmware_upgrade_job(txn.as_mut(), id, Some(&job)).await?;
                    state.firmware_upgrade_job = Some(job);
                    if state.config.maintenance_requested.is_some() {
                        state.config.maintenance_requested = None;
                        db_rack::update(txn.as_mut(), id, &state.config).await?;
                    }
                    return Ok(StateHandlerOutcome::transition(RackState::Error {
                        cause: format!(
                            "firmware upgrade failed: {}/{} devices failed",
                            failed, total
                        ),
                    })
                    .with_txn(txn));
                }

                let now = chrono::Utc::now();
                job.status = Some("completed".into());
                if job.completed_at.is_none() {
                    job.completed_at = Some(now);
                }
                db_rack::update_firmware_upgrade_job(txn.as_mut(), id, Some(&job)).await?;
                state.firmware_upgrade_job = Some(job);

                let next_maintenance_state = if nvos_update_requested(scope) {
                    let next = next_state_after_firmware(scope);
                    tracing::info!(
                        rack_id = %id,
                        completed,
                        total,
                        next_state = %next,
                        "Rack firmware upgrade complete; advancing to explicitly requested next activity"
                    );
                    next
                } else if let Some(artifact) = default_nvos_artifact {
                    tracing::info!(
                        "Rack {} has a default NVOS artifact available; advancing to NVOSUpdate(Start) with firmware {} ({})",
                        id,
                        artifact.firmware_id,
                        artifact.image_filename,
                    );
                    RackMaintenanceState::NVOSUpdate {
                        nvos_update: NvosUpdateState::Start {
                            rack_firmware_id: Some(artifact.firmware_id),
                        },
                    }
                } else {
                    let next = next_state_after_nvos(scope);
                    tracing::info!(
                        rack_id = %id,
                        completed,
                        total,
                        next_state = %next,
                        "Rack firmware upgrade complete; no default NVOS artifact available, advancing"
                    );
                    next
                };

                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: next_maintenance_state,
                })
                .with_txn(txn))
            }
        },
        RackMaintenanceState::NVOSUpdate { nvos_update } => match nvos_update {
            NvosUpdateState::Start { rack_firmware_id } => {
                let artifact = match resolve_requested_or_default_nvos_artifact(
                    id,
                    rack_profile_id,
                    rack_firmware_id.as_deref(),
                    ctx,
                )
                .await?
                {
                    Some(artifact) => artifact,
                    None if nvos_update_requested(scope) => {
                        return transition_to_rack_error(
                            id,
                            state,
                            "requested NVOS update could not find a default switch system image",
                            ctx,
                        )
                        .await;
                    }
                    None => {
                        // A missing rack_firmware_id already falls back to the default rack
                        // firmware. None here means no default switch system image was found.
                        let next = next_state_after_nvos(scope);
                        tracing::info!(
                            rack_id = %id,
                            next_state = %next,
                            "No default NVOS artifact available, advancing"
                        );
                        return Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                            maintenance_state: next,
                        }));
                    }
                };

                let Some(rms_client) = ctx.services.switch_system_image_rms_client.as_deref()
                else {
                    return transition_to_rack_error(id, state, "RMS client not configured", ctx)
                        .await;
                };

                let inventory = load_rack_firmware_inventory(
                    &ctx.services.db_pool,
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to load rack inventory for NVOS update: {}",
                        error
                    ))
                })?;
                let inventory = filter_inventory_by_scope(inventory, scope);

                if inventory.switches.is_empty() {
                    let next = next_state_after_nvos(scope);
                    tracing::info!(
                        rack_id = %id,
                        next_state = %next,
                        "No switches selected for NVOS update, advancing"
                    );
                    return Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                        maintenance_state: next,
                    }));
                }

                tracing::info!(
                    "Rack {} NVOS update starting with firmware {} ({})",
                    id,
                    artifact.firmware_id,
                    artifact.image_filename,
                );

                for switch in &inventory.switches {
                    switch.os_ip.as_ref().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre::eyre!(
                            "switch {} has no NVOS IP for rack NVOS update",
                            switch.mac
                        ))
                    })?;
                    switch.os_username.as_ref().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre::eyre!(
                            "switch {} has no NVOS username for rack NVOS update",
                            switch.mac
                        ))
                    })?;
                    switch.os_password.as_ref().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre::eyre!(
                            "switch {} has no NVOS password for rack NVOS update",
                            switch.mac
                        ))
                    })?;
                }

                let job =
                    rms_start_nvos_update(rms_client, id, &artifact, inventory.switches).await?;

                let mut txn = ctx.services.db_pool.begin().await?;
                clear_nvos_update_statuses(txn.as_mut(), &inventory.switch_ids).await?;
                db_rack::update_nvos_update_job(txn.as_mut(), id, Some(&job)).await?;
                state.nvos_update_job = Some(job);

                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: RackMaintenanceState::NVOSUpdate {
                        nvos_update: NvosUpdateState::WaitForComplete,
                    },
                })
                .with_txn(txn))
            }
            NvosUpdateState::WaitForComplete => {
                let current_job = match &state.nvos_update_job {
                    Some(job) => job,
                    None => {
                        return Ok(StateHandlerOutcome::wait(
                            "nvos update: no job recorded yet".into(),
                        ));
                    }
                };
                let Some(rms_client) = ctx.services.switch_system_image_rms_client.as_deref()
                else {
                    return transition_to_rack_error(id, state, "RMS client not configured", ctx)
                        .await;
                };

                let job = rms_get_nvos_update_status(rms_client, current_job).await?;
                let mut txn = ctx.services.db_pool.begin().await?;

                let build_status = |switch: &NvosUpdateSwitchStatus| -> SwitchNvosUpdateStatus {
                    let status = match switch.status.as_str() {
                        "completed" => SwitchNvosUpdateState::Completed,
                        "failed" => SwitchNvosUpdateState::Failed {
                            cause: switch.error_message.clone().unwrap_or_else(|| {
                                format!("RMS reported NVOS failure for {}", switch.mac)
                            }),
                        },
                        "in_progress" => SwitchNvosUpdateState::InProgress,
                        _ => SwitchNvosUpdateState::Started,
                    };

                    SwitchNvosUpdateStatus {
                        task_id: switch
                            .job_id
                            .clone()
                            .or_else(|| job.job_id.clone())
                            .unwrap_or_else(|| "unknown".to_string()),
                        firmware_id: job.firmware_id.clone(),
                        image_filename: job.image_filename.clone(),
                        status,
                        started_at: job.started_at,
                        ended_at: if switch.status == "completed" || switch.status == "failed" {
                            Some(chrono::Utc::now())
                        } else {
                            None
                        },
                    }
                };

                for switch in job.switches.iter() {
                    let switch_id = if !switch.node_id.is_empty() {
                        switch
                            .node_id
                            .parse::<carbide_uuid::switch::SwitchId>()
                            .ok()
                    } else {
                        let mac: mac_address::MacAddress = match switch.mac.parse() {
                            Ok(mac) => mac,
                            Err(_) => continue,
                        };
                        db_switch::find_ids(
                            txn.as_mut(),
                            model::switch::SwitchSearchFilter {
                                bmc_mac: Some(mac),
                                rack_id: Some(id.clone()),
                                ..Default::default()
                            },
                        )
                        .await?
                        .first()
                        .copied()
                    };
                    if let Some(switch_id) = switch_id {
                        let nvos_status = build_status(switch);
                        db_switch::update_nvos_update_status(
                            txn.as_mut(),
                            switch_id,
                            Some(&nvos_status),
                        )
                        .await?;
                    } else {
                        tracing::error!(
                            "switch {} not found in database for NVOS update",
                            switch.mac
                        );
                    }
                }

                let total = job.all_switches().count();
                let completed = job
                    .all_switches()
                    .filter(|switch| switch.status == "completed")
                    .count();
                let failed = job
                    .all_switches()
                    .filter(|switch| switch.status == "failed")
                    .count();

                if failed > 0 {
                    db_rack::update_nvos_update_job(txn.as_mut(), id, Some(&job)).await?;
                    state.nvos_update_job = Some(job);
                    if state.config.maintenance_requested.is_some() {
                        state.config.maintenance_requested = None;
                        db_rack::update(txn.as_mut(), id, &state.config).await?;
                    }
                    return Ok(StateHandlerOutcome::transition(RackState::Error {
                        cause: format!("NVOS update failed: {}/{} switches failed", failed, total),
                    })
                    .with_txn(txn));
                }

                if completed < total {
                    db_rack::update_nvos_update_job(txn.as_mut(), id, Some(&job)).await?;
                    state.nvos_update_job = Some(job);
                    return Ok(StateHandlerOutcome::wait(format!(
                        "nvos update: {}/{} switches completed",
                        completed, total
                    ))
                    .with_txn(txn));
                }

                let next = next_state_after_nvos(scope);
                tracing::info!(
                    rack_id = %id,
                    completed,
                    total,
                    next_state = %next,
                    "Rack NVOS update complete, advancing"
                );
                db_rack::update_nvos_update_job(txn.as_mut(), id, Some(&job)).await?;
                state.nvos_update_job = Some(job);
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: next,
                })
                .with_txn(txn))
            }
        },
        RackMaintenanceState::ConfigureNmxCluster {
            configure_nmx_cluster,
        } => match configure_nmx_cluster {
            ConfigureNmxClusterState::Start => {
                let Some(rms_client) = ctx.services.rms_client.as_ref() else {
                    return transition_to_rack_error(id, state, "RMS client not configured", ctx)
                        .await;
                };
                let switch_inventory = load_rack_switch_firmware_inventory(
                    &ctx.services.db_pool,
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to load rack switch firmware inventory for ConfigureNmxCluster: {}",
                        error
                    ))
                })?;
                let switch_inventory = filter_switch_inventory_by_scope(switch_inventory, scope);

                if switch_inventory.switches.is_empty() {
                    return Ok(skip_configure_nmx_cluster_outcome(
                        id,
                        "rack has no switches in inventory",
                        scope,
                    ));
                }

                if let Err(cause) =
                    validate_switch_inventory_for_nmx_cluster(&switch_inventory.switches)
                {
                    return transition_to_rack_error(id, state, cause, ctx).await;
                }

                let rack_profile_label = rack_profile_id
                    .map(|profile_id| profile_id.to_string())
                    .unwrap_or_else(|| "<none>".to_string());
                let Some(profile) = super::resolve_profile(id, rack_profile_id, ctx) else {
                    return transition_to_rack_error(
                        id,
                        state,
                        format!(
                            "rack profile '{}' is missing or unknown; cannot resolve rack_hardware_topology",
                            rack_profile_label
                        ),
                        ctx,
                    )
                    .await;
                };
                let Some(rack_hardware_topology) = profile.rack_hardware_topology else {
                    return transition_to_rack_error(
                        id,
                        state,
                        format!(
                            "rack profile '{}' does not define rack_hardware_topology",
                            rack_profile_label
                        ),
                        ctx,
                    )
                    .await;
                };

                let response = match rms_client
                    .get_device_info_by_device_list(build_switch_device_info_request(
                        id,
                        &switch_inventory.switches,
                    ))
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        return transition_to_rack_error(
                            id,
                            state,
                            format!("RMS GetDeviceInfoByDeviceList failed: {}", error),
                            ctx,
                        )
                        .await;
                    }
                };
                let primary_switch =
                    match select_primary_switch(&switch_inventory.switches, &response) {
                        Ok(primary_switch) => primary_switch,
                        Err(cause) => return transition_to_rack_error(id, state, cause, ctx).await,
                    };
                {
                    let mut txn = ctx.services.db_pool.begin().await?;
                    if let Err(cause) =
                        persist_primary_switch(txn.as_mut(), id, &primary_switch.device.node_id)
                            .await
                    {
                        drop(txn);
                        return transition_to_rack_error(id, state, cause, ctx).await;
                    }
                    txn.commit().await?;
                }

                let topology_type = rack_hardware_topology.to_string();
                tracing::info!(
                    rack_id = %id,
                    primary_switch = %primary_switch.device.node_id,
                    tray_index = primary_switch.tray_index,
                    slot_number = primary_switch.slot_number,
                    topology_type = %topology_type,
                    switch_count = switch_inventory.switches.len(),
                    "Configuring NMX cluster on primary switch"
                );
                let response = match rms_client
                    .configure_scale_up_fabric_manager(rms::ConfigureScaleUpFabricManagerRequest {
                        device: Some(build_new_node_info(
                            id,
                            &primary_switch.device,
                            rms::NodeType::Switch,
                        )),
                        topology_type: topology_type.clone(),
                        verify_ssl: false,
                        ..Default::default()
                    })
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        tracing::error!(
                            rack_id = %id,
                            primary_switch = %primary_switch.device.node_id,
                            error = %error,
                            "RMS ConfigureScaleUpFabricManager failed for switch, continuing",
                        );
                        return Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                            maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                                configure_nmx_cluster:
                                    ConfigureNmxClusterState::WaitForFabricStatus,
                            },
                        }));
                    }
                };

                if response.status != rms::ReturnCode::Success as i32 {
                    let message = if response.message.trim().is_empty() {
                        "no error details provided".to_string()
                    } else {
                        response.message
                    };
                    tracing::error!(
                        rack_id = %id,
                        primary_switch = %primary_switch.device.node_id,
                        message = %message,
                        "RMS ConfigureScaleUpFabricManager failed for switch, advancing to WaitForFabricStatus",
                    );
                    return Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                            configure_nmx_cluster: ConfigureNmxClusterState::WaitForFabricStatus,
                        },
                    }));
                }

                tracing::info!(
                    rack_id = %id,
                    primary_switch = %primary_switch.device.node_id,
                    tray_index = primary_switch.tray_index,
                    slot_number = primary_switch.slot_number,
                    topology_type = %topology_type,
                    topology_used = %if response.topology_used.is_empty() {
                        topology_type.clone()
                    } else {
                        response.topology_used.clone()
                    },
                    scale_up_fabric_state_enabled = response.scale_up_fabric_state_enabled,
                    grpc_enabled = response.grpc_enabled,
                    "ConfigureScaleUpFabricManager succeeded; advancing to WaitForFabricStatus"
                );
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                        configure_nmx_cluster: ConfigureNmxClusterState::WaitForFabricStatus,
                    },
                }))
            }
            ConfigureNmxClusterState::WaitForFabricStatus => {
                let switch_inventory = load_rack_switch_firmware_inventory(
                    &ctx.services.db_pool,
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to load rack switch firmware inventory for WaitForFabricStatus: {}",
                        error
                    ))
                })?;
                let switch_inventory = filter_switch_inventory_by_scope(switch_inventory, scope);

                if switch_inventory.switches.is_empty() {
                    return Ok(skip_configure_nmx_cluster_outcome(
                        id,
                        "rack has no switches in inventory",
                        scope,
                    ));
                }

                let fabric_status_response = match get_scale_up_fabric_services_status(
                    &ctx.services.site_config.rms,
                    id,
                    &switch_inventory.switches,
                )
                .await
                {
                    Ok(response) => response,
                    Err(cause) => return transition_to_rack_error(id, state, cause, ctx).await,
                };
                let mut txn = ctx.services.db_pool.begin().await?;
                if let Err(cause) = persist_fabric_manager_statuses(
                    txn.as_mut(),
                    id,
                    &switch_inventory.switches,
                    &fabric_status_response,
                )
                .await
                {
                    drop(txn);
                    return transition_to_rack_error(id, state, cause, ctx).await;
                }
                let next = next_state_after_configure(scope);
                tracing::info!(
                    rack_id = %id,
                    switch_count = switch_inventory.switches.len(),
                    next_state = %next,
                    "WaitForFabricStatus complete, FabricManager status persisted, advancing"
                );
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: next,
                })
                .with_txn(txn))
            }
        },
        RackMaintenanceState::PowerSequence { rack_power } => match rack_power {
            RackPowerState::PoweringOn => {
                tracing::info!("Rack {} power sequence (on) - stubbed", id);

                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: RackMaintenanceState::Completed,
                }))
            }
            RackPowerState::PoweringOff => {
                tracing::info!("Rack {} power sequence (off) - stubbed", id);
                Ok(StateHandlerOutcome::wait(
                    "power sequence (off) in progress".into(),
                ))
            }
            RackPowerState::PowerReset => {
                tracing::info!("Rack {} power sequence (reset) - stubbed", id);
                Ok(StateHandlerOutcome::wait(
                    "power sequence (reset) in progress".into(),
                ))
            }
        },
        RackMaintenanceState::Completed => {
            tracing::info!(
                rack_id = %id,
                "Maintenance completed, clearing rv.* labels and entering Validating(Pending)"
            );
            clear_rv_labels(state, ctx).await?;

            let mut outcome = StateHandlerOutcome::transition(RackState::Validating {
                validating_state: RackValidationState::Pending,
            });

            if state.config.maintenance_requested.is_some() {
                state.config.maintenance_requested = None;
                let mut txn = ctx.services.db_pool.begin().await?;
                db_rack::update(txn.as_mut(), id, &state.config).await?;
                outcome = outcome.with_txn(txn);
            }

            Ok(outcome)
        }
    }
}

#[cfg(test)]
mod tests {
    use model::rack::{
        ConfigureNmxClusterState, FirmwareUpgradeDeviceInfo, FirmwareUpgradeState,
        MaintenanceActivity, MaintenanceScope, NvosUpdateState, RackMaintenanceState,
        RackPowerState,
    };

    use super::{
        filter_inventory_by_scope, first_maintenance_state, implicit_nvos_update_requested,
        next_state_after_configure, next_state_after_firmware, next_state_after_nvos,
    };
    use crate::rack::firmware_update::RackFirmwareInventory;

    fn test_machine_id(byte: u8) -> carbide_uuid::machine::MachineId {
        use carbide_uuid::machine::{MachineIdSource, MachineType};
        carbide_uuid::machine::MachineId::new(MachineIdSource::Tpm, [byte; 32], MachineType::Host)
    }

    fn test_switch_id(byte: u8) -> carbide_uuid::switch::SwitchId {
        use carbide_uuid::switch::{SwitchIdSource, SwitchType};
        carbide_uuid::switch::SwitchId::new(SwitchIdSource::Tpm, [byte; 32], SwitchType::NvLink)
    }

    fn test_device_info(node_id: &str) -> FirmwareUpgradeDeviceInfo {
        FirmwareUpgradeDeviceInfo {
            node_id: node_id.to_string(),
            mac: "AA:BB:CC:DD:EE:FF".to_string(),
            bmc_ip: "10.0.0.1".to_string(),
            bmc_username: "admin".to_string(),
            bmc_password: "pass".to_string(),
            os_mac: None,
            os_ip: None,
            os_username: None,
            os_password: None,
        }
    }

    // ── first_maintenance_state ─────────────────────────────────────────

    #[test]
    fn first_maintenance_state_all_activities() {
        let scope = MaintenanceScope::default();
        assert!(matches!(
            first_maintenance_state(&scope),
            RackMaintenanceState::FirmwareUpgrade {
                rack_firmware_upgrade: FirmwareUpgradeState::Start,
            }
        ));
    }

    #[test]
    fn first_maintenance_state_only_firmware() {
        let scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: None,
                components: vec![],
            }],
            ..Default::default()
        };
        assert!(matches!(
            first_maintenance_state(&scope),
            RackMaintenanceState::FirmwareUpgrade { .. }
        ));
    }

    #[test]
    fn first_maintenance_state_only_configure() {
        let scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::ConfigureNmxCluster],
            ..Default::default()
        };
        assert_eq!(
            first_maintenance_state(&scope),
            RackMaintenanceState::ConfigureNmxCluster {
                configure_nmx_cluster: ConfigureNmxClusterState::Start,
            },
        );
    }

    #[test]
    fn first_maintenance_state_only_nvos() {
        let scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::NvosUpdate {
                rack_firmware_id: Some("fw-nvos".into()),
            }],
            ..Default::default()
        };
        assert_eq!(
            first_maintenance_state(&scope),
            RackMaintenanceState::NVOSUpdate {
                nvos_update: NvosUpdateState::Start {
                    rack_firmware_id: Some("fw-nvos".into()),
                },
            },
        );
    }

    #[test]
    fn first_maintenance_state_only_power_sequence() {
        let scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::PowerSequence],
            ..Default::default()
        };
        assert!(matches!(
            first_maintenance_state(&scope),
            RackMaintenanceState::PowerSequence {
                rack_power: RackPowerState::PoweringOn,
            }
        ));
    }

    #[test]
    fn first_maintenance_state_configure_and_power() {
        let scope = MaintenanceScope {
            activities: vec![
                MaintenanceActivity::ConfigureNmxCluster,
                MaintenanceActivity::PowerSequence,
            ],
            ..Default::default()
        };
        assert_eq!(
            first_maintenance_state(&scope),
            RackMaintenanceState::ConfigureNmxCluster {
                configure_nmx_cluster: ConfigureNmxClusterState::Start,
            },
        );
    }

    #[test]
    fn implicit_nvos_update_requested_for_all_activities() {
        let scope = MaintenanceScope::default();

        assert!(implicit_nvos_update_requested(&scope));
    }

    #[test]
    fn implicit_nvos_update_not_requested_for_firmware_only() {
        let scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: None,
                components: vec![],
            }],
            ..Default::default()
        };

        assert!(!implicit_nvos_update_requested(&scope));
    }

    #[test]
    fn implicit_nvos_update_not_requested_for_explicit_nvos() {
        let scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::NvosUpdate {
                rack_firmware_id: None,
            }],
            ..Default::default()
        };

        assert!(!implicit_nvos_update_requested(&scope));
    }

    // ── next_state_after_firmware ───────────────────────────────────────

    #[test]
    fn after_firmware_all_activities_goes_to_nvos() {
        let scope = MaintenanceScope::default();
        assert!(matches!(
            next_state_after_firmware(&scope),
            RackMaintenanceState::NVOSUpdate { .. },
        ));
    }

    #[test]
    fn after_firmware_without_configure_goes_to_power() {
        let scope = MaintenanceScope {
            activities: vec![
                MaintenanceActivity::FirmwareUpgrade {
                    firmware_version: None,
                    components: vec![],
                },
                MaintenanceActivity::PowerSequence,
            ],
            ..Default::default()
        };
        assert!(matches!(
            next_state_after_firmware(&scope),
            RackMaintenanceState::PowerSequence { .. }
        ));
    }

    #[test]
    fn after_firmware_only_firmware_goes_to_completed() {
        let scope = MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: None,
                components: vec![],
            }],
            ..Default::default()
        };
        assert_eq!(
            next_state_after_firmware(&scope),
            RackMaintenanceState::Completed,
        );
    }

    #[test]
    fn after_firmware_explicit_nvos_preserves_requested_firmware() {
        let scope = MaintenanceScope {
            activities: vec![
                MaintenanceActivity::FirmwareUpgrade {
                    firmware_version: None,
                    components: vec![],
                },
                MaintenanceActivity::NvosUpdate {
                    rack_firmware_id: Some("fw-nvos".into()),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            next_state_after_firmware(&scope),
            RackMaintenanceState::NVOSUpdate {
                nvos_update: NvosUpdateState::Start {
                    rack_firmware_id: Some("fw-nvos".into()),
                },
            },
        );
    }

    // ── next_state_after_nvos ──────────────────────────────────────────

    #[test]
    fn after_nvos_all_activities_goes_to_configure() {
        let scope = MaintenanceScope::default();
        assert_eq!(
            next_state_after_nvos(&scope),
            RackMaintenanceState::ConfigureNmxCluster {
                configure_nmx_cluster: ConfigureNmxClusterState::Start,
            },
        );
    }

    #[test]
    fn after_nvos_without_configure_goes_to_power() {
        let scope = MaintenanceScope {
            activities: vec![
                MaintenanceActivity::NvosUpdate {
                    rack_firmware_id: None,
                },
                MaintenanceActivity::PowerSequence,
            ],
            ..Default::default()
        };
        assert!(matches!(
            next_state_after_nvos(&scope),
            RackMaintenanceState::PowerSequence { .. }
        ));
    }

    // ── next_state_after_configure ──────────────────────────────────────

    #[test]
    fn after_configure_all_activities_goes_to_power() {
        let scope = MaintenanceScope::default();
        assert!(matches!(
            next_state_after_configure(&scope),
            RackMaintenanceState::PowerSequence {
                rack_power: RackPowerState::PoweringOn,
            }
        ));
    }

    #[test]
    fn after_configure_without_power_goes_to_completed() {
        let scope = MaintenanceScope {
            activities: vec![
                MaintenanceActivity::FirmwareUpgrade {
                    firmware_version: None,
                    components: vec![],
                },
                MaintenanceActivity::ConfigureNmxCluster,
            ],
            ..Default::default()
        };
        assert_eq!(
            next_state_after_configure(&scope),
            RackMaintenanceState::Completed,
        );
    }

    // ── filter_inventory_by_scope ───────────────────────────────────────

    fn sample_inventory() -> RackFirmwareInventory {
        let m1 = test_machine_id(1);
        let m2 = test_machine_id(2);
        let s1 = test_switch_id(1);
        let s2 = test_switch_id(2);
        RackFirmwareInventory {
            machine_ids: vec![m1, m2],
            switch_ids: vec![s1, s2],
            machines: vec![
                test_device_info(&m1.to_string()),
                test_device_info(&m2.to_string()),
            ],
            switches: vec![
                test_device_info(&s1.to_string()),
                test_device_info(&s2.to_string()),
            ],
        }
    }

    #[test]
    fn filter_inventory_full_rack_is_noop() {
        let inventory = sample_inventory();
        let scope = MaintenanceScope::default();
        let filtered = filter_inventory_by_scope(inventory, &scope);
        assert_eq!(filtered.machine_ids.len(), 2);
        assert_eq!(filtered.switch_ids.len(), 2);
        assert_eq!(filtered.machines.len(), 2);
        assert_eq!(filtered.switches.len(), 2);
    }

    #[test]
    fn filter_inventory_partial_machines_only() {
        let inventory = sample_inventory();
        let m1 = test_machine_id(1);
        let scope = MaintenanceScope {
            machine_ids: vec![m1],
            ..Default::default()
        };
        let filtered = filter_inventory_by_scope(inventory, &scope);
        assert_eq!(filtered.machine_ids, vec![m1]);
        assert_eq!(filtered.machines.len(), 1);
        assert_eq!(filtered.machines[0].node_id, m1.to_string());
        assert!(filtered.switch_ids.is_empty());
        assert!(filtered.switches.is_empty());
    }

    #[test]
    fn filter_inventory_partial_switches_only() {
        let inventory = sample_inventory();
        let s2 = test_switch_id(2);
        let scope = MaintenanceScope {
            switch_ids: vec![s2],
            ..Default::default()
        };
        let filtered = filter_inventory_by_scope(inventory, &scope);
        assert!(filtered.machine_ids.is_empty());
        assert!(filtered.machines.is_empty());
        assert_eq!(filtered.switch_ids, vec![s2]);
        assert_eq!(filtered.switches.len(), 1);
        assert_eq!(filtered.switches[0].node_id, s2.to_string());
    }

    #[test]
    fn filter_inventory_partial_both() {
        let inventory = sample_inventory();
        let m2 = test_machine_id(2);
        let s1 = test_switch_id(1);
        let scope = MaintenanceScope {
            machine_ids: vec![m2],
            switch_ids: vec![s1],
            ..Default::default()
        };
        let filtered = filter_inventory_by_scope(inventory, &scope);
        assert_eq!(filtered.machine_ids, vec![m2]);
        assert_eq!(filtered.machines.len(), 1);
        assert_eq!(filtered.switch_ids, vec![s1]);
        assert_eq!(filtered.switches.len(), 1);
    }

    #[test]
    fn filter_inventory_unknown_id_excluded() {
        let inventory = sample_inventory();
        let unknown = test_machine_id(99);
        let scope = MaintenanceScope {
            machine_ids: vec![unknown],
            ..Default::default()
        };
        let filtered = filter_inventory_by_scope(inventory, &scope);
        assert!(filtered.machine_ids.is_empty());
        assert!(filtered.machines.is_empty());
    }
}
