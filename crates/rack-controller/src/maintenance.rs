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

use carbide_rack::firmware_object::{
    ANY_RACK_HARDWARE_TYPE, profile_hardware_type_wire_value, rack_maintenance_access_token_key,
};
use carbide_rack::firmware_update::{
    RackFirmwareInventory, RackSwitchFirmwareInventory, build_new_node_info,
    firmware_type_for_profile, load_rack_firmware_inventory, load_rack_switch_firmware_inventory,
};
use carbide_rack::rack_manager_error;
use carbide_rack::rms_client::SwitchSystemImageRmsClient;
use carbide_rack_controller::config::RmsConfig;
use carbide_rack_controller::context::RackStateHandlerContextObjects;
use carbide_rack_controller::fabric_manager::{
    batch_get_scale_up_fabric_service_status, persist_fabric_manager_statuses,
    persist_primary_switch, select_primary_switch, validate_switch_inventory_for_nmx_cluster,
};
use carbide_rack_controller::validating::strip_rv_labels;
use carbide_secrets::credentials::{CredentialManager, Credentials};
use carbide_uuid::rack::{RackId, RackProfileId};
use db::{
    host_machine_update as db_host_machine_update, machine as db_machine,
    machine_topology as db_machine_topology, rack as db_rack, switch as db_switch,
};
use librms::protos::rack_manager as rms;
use model::rack::{
    ConfigureNmxClusterState, FirmwareUpgradeDeviceInfo, FirmwareUpgradeDeviceStatus,
    FirmwareUpgradeState, MaintenanceActivity, MaintenanceScope, NvosUpdateJob, NvosUpdateState,
    NvosUpdateSwitchStatus, Rack, RackFirmwareUpgradeState, RackFirmwareUpgradeStatus,
    RackMaintenanceState, RackPowerState, RackState, RackValidationState, SwitchNvosUpdateState,
    SwitchNvosUpdateStatus,
};
use model::rack_type::RackProfile;
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate as carbide_rack_controller;

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
    continue_after_firmware_upgrade: bool,
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
        db_switch::set_switch_reprovisioning_requested_with_firmware_continuation(
            txn,
            *switch_id,
            &format!("rack-{}", rack_id),
            continue_after_firmware_upgrade,
        )
        .await?;
    }
    Ok(())
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

fn requested_nvos_config_json(scope: &MaintenanceScope) -> Option<String> {
    scope.activities.iter().find_map(|activity| match activity {
        MaintenanceActivity::NvosUpdate { config_json } => {
            (!config_json.trim().is_empty()).then(|| config_json.clone())
        }
        _ => None,
    })
}

fn explicit_firmware_upgrade_requested(scope: &MaintenanceScope) -> bool {
    scope
        .activities
        .iter()
        .any(|activity| matches!(activity, MaintenanceActivity::FirmwareUpgrade { .. }))
}

fn profile_hardware_type_or_any(profile: Option<&RackProfile>) -> String {
    profile
        .map(profile_hardware_type_wire_value)
        .filter(|hardware_type| !hardware_type.trim().is_empty())
        .unwrap_or_else(|| ANY_RACK_HARDWARE_TYPE.to_string())
}

fn requested_firmware_object_json_upgrade(
    scope: &MaintenanceScope,
) -> Option<(Option<String>, Vec<String>, bool)> {
    scope.activities.iter().find_map(|activity| match activity {
        MaintenanceActivity::FirmwareUpgrade {
            firmware_version,
            components,
            force_update,
        } => Some((firmware_version.clone(), components.clone(), *force_update)),
        _ => None,
    })
}

async fn load_rack_maintenance_access_token(
    credential_manager: &dyn CredentialManager,
    rack_id: &RackId,
) -> Result<String, StateHandlerError> {
    let key = rack_maintenance_access_token_key(rack_id);
    let credentials = credential_manager
        .get_credentials(&key)
        .await
        .map_err(|error| {
            StateHandlerError::GenericError(eyre::eyre!(
                "failed to load rack maintenance access token: {}",
                error
            ))
        })?
        .ok_or_else(|| {
            StateHandlerError::GenericError(eyre::eyre!(
                "rack maintenance access token is not available"
            ))
        })?;

    let Credentials::UsernamePassword { password, .. } = credentials;
    Ok(password)
}

async fn delete_rack_maintenance_access_token(
    credential_manager: &dyn CredentialManager,
    rack_id: &RackId,
) {
    if let Err(error) = credential_manager
        .delete_credentials(&rack_maintenance_access_token_key(rack_id))
        .await
    {
        tracing::warn!(
            rack_id = %rack_id,
            error = %error,
            "failed to delete rack maintenance access token",
        );
    }
}

fn nvos_update_start_state(_scope: &MaintenanceScope) -> RackMaintenanceState {
    RackMaintenanceState::NVOSUpdate {
        nvos_update: NvosUpdateState::Start,
    }
}

/// Returns the next maintenance sub-state after firmware upgrade, skipping
/// activities not requested in the scope.
fn next_state_after_firmware(scope: &MaintenanceScope) -> RackMaintenanceState {
    if nvos_update_requested(scope) {
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
        force_update: false,
    }) {
        RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::Start,
        }
    } else {
        next_state_after_firmware(scope)
    }
}

/// Filters a full-rack firmware inventory down to compute/switch devices listed
/// in the maintenance scope. Power-shelf firmware-object JSON apply is not
/// implemented yet.
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
) -> rms::BatchGetNodeDeviceInfoRequest {
    rms::BatchGetNodeDeviceInfoRequest {
        nodes: Some(rms::NodeSet {
            nodes: switches
                .iter()
                .map(|switch| build_new_node_info(rack_id, switch, rms::NodeType::Switch))
                .collect(),
        }),
    }
}

const NMX_CONFIGURE_RMS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn build_nmx_configure_rms_client(rms_config: &RmsConfig) -> Option<librms::RackManagerApi> {
    let url = rms_config
        .api_url
        .as_deref()
        .filter(|url| !url.is_empty())?;
    let mut rms_client_config = librms::client_config::RmsClientConfig::new(
        rms_config.root_ca_path.clone(),
        rms_config.client_cert.clone(),
        rms_config.client_key.clone(),
        rms_config.enforce_tls,
    );
    rms_client_config.connect_timeout = Some(NMX_CONFIGURE_RMS_CONNECT_TIMEOUT);
    let rms_api_config = librms::client::RmsApiConfig::new(url, &rms_client_config);
    Some(librms::RackManagerApi::new(&rms_api_config))
}

fn rms_component_filters_from_components(
    components: &[String],
    include_machines: bool,
    include_switches: bool,
) -> std::collections::HashMap<i32, rms::FirmwareObjectComponentFilter> {
    if components.is_empty() {
        return std::collections::HashMap::new();
    }

    let mut filters = std::collections::HashMap::new();
    if include_machines {
        filters.insert(
            rms::NodeType::Compute as i32,
            rms::FirmwareObjectComponentFilter {
                components: components.to_vec(),
            },
        );
    }
    if include_switches {
        filters.insert(
            rms::NodeType::Switch as i32,
            rms::FirmwareObjectComponentFilter {
                components: components.to_vec(),
            },
        );
    }
    filters
}

fn firmware_device_status(
    device: FirmwareUpgradeDeviceInfo,
    parent_job_id: Option<String>,
    child_jobs: &std::collections::HashMap<String, String>,
    node_errors: &std::collections::HashMap<String, String>,
    batch_error: Option<&str>,
) -> FirmwareUpgradeDeviceStatus {
    let mut status = FirmwareUpgradeDeviceStatus {
        node_id: device.node_id.clone(),
        mac: device.mac,
        bmc_ip: device.bmc_ip,
        status: "in_progress".into(),
        job_id: None,
        parent_job_id,
        error_message: None,
    };

    if let Some(error_message) = node_errors.get(&device.node_id) {
        status.status = "failed".into();
        status.error_message = Some(error_message.clone());
    } else if let Some(job_id) = child_jobs.get(&device.node_id) {
        status.job_id = Some(job_id.clone());
    } else {
        status.status = "failed".into();
        status.error_message = Some(
            batch_error
                .unwrap_or("RMS did not return a child firmware job for this device")
                .to_string(),
        );
    }

    status
}

struct RmsFirmwareObjectJsonApply<'a> {
    rack_id: &'a RackId,
    config_json: &'a str,
    access_token: &'a str,
    firmware_type: &'a str,
    hardware_type: &'a str,
    force_update: bool,
    components: &'a [String],
    machines: Vec<FirmwareUpgradeDeviceInfo>,
    switches: Vec<FirmwareUpgradeDeviceInfo>,
}

async fn rms_start_firmware_upgrade_from_json(
    rms_client: &dyn librms::RmsApi,
    request: RmsFirmwareObjectJsonApply<'_>,
) -> Result<model::rack::FirmwareUpgradeJob, StateHandlerError> {
    let started_at = chrono::Utc::now();
    let machine_count = request.machines.len();
    let switch_count = request.switches.len();
    let mut nodes = Vec::with_capacity(machine_count + switch_count);
    nodes.extend(
        request
            .machines
            .iter()
            .map(|device| build_new_node_info(request.rack_id, device, rms::NodeType::Compute)),
    );
    nodes.extend(
        request
            .switches
            .iter()
            .map(|device| build_new_node_info(request.rack_id, device, rms::NodeType::Switch)),
    );

    let response = rms_client
        .apply_firmware_object(rms::ApplyFirmwareObjectRequest {
            rack_id: request.rack_id.to_string(),
            config_json: request.config_json.to_string(),
            access_token: request.access_token.to_string(),
            firmware_type: request.firmware_type.to_string(),
            hardware_type: request.hardware_type.to_string(),
            nodes: Some(rms::NodeSet { nodes }),
            force_update: request.force_update,
            component_filters: rms_component_filters_from_components(
                request.components,
                machine_count > 0,
                switch_count > 0,
            ),
        })
        .await
        .map_err(|error| {
            StateHandlerError::GenericError(eyre::eyre!(
                "failed to submit firmware object JSON apply to RMS: {}",
                error
            ))
        })?;

    let batch_response = response.response.as_ref();
    let batch_status = batch_response
        .map(|batch_response| batch_response.status)
        .unwrap_or(rms::ReturnCode::Failure as i32);
    let batch_job_id = batch_response
        .map(|batch_response| batch_response.job_id.as_str())
        .unwrap_or_default();
    if batch_status != rms::ReturnCode::Success as i32
        && batch_job_id.is_empty()
        && response.jobs.is_empty()
    {
        let message = batch_response
            .map(|batch_response| batch_response.message.as_str())
            .unwrap_or_default();
        let message = if message.is_empty() {
            "RMS returned failure for ApplyFirmwareObject".to_string()
        } else {
            message.to_string()
        };
        return Err(StateHandlerError::GenericError(eyre::eyre!(message)));
    }

    let parent_job_id = (!batch_job_id.is_empty()).then(|| batch_job_id.to_string());
    let child_jobs = response
        .jobs
        .iter()
        .map(|child| (child.node_id.clone(), child.job_id.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let node_errors = batch_response
        .map(|batch_response| {
            batch_response
                .node_results
                .iter()
                .filter(|result| {
                    result.status != rms::ReturnCode::Success as i32
                        || !result.error_message.is_empty()
                })
                .map(|result| (result.node_id.clone(), result.error_message.clone()))
                .collect::<std::collections::HashMap<_, _>>()
        })
        .unwrap_or_default();
    let batch_error = batch_response.and_then(|batch_response| {
        if batch_response.status == rms::ReturnCode::Success as i32
            || batch_response.message.is_empty()
        {
            None
        } else {
            Some(batch_response.message.clone())
        }
    });

    let mut job = model::rack::FirmwareUpgradeJob {
        job_id: parent_job_id.clone(),
        firmware_id: Some(response.object_id),
        started_at: Some(started_at),
        batch_job_ids: parent_job_id.iter().cloned().collect(),
        machines: request
            .machines
            .into_iter()
            .map(|device| {
                firmware_device_status(
                    device,
                    parent_job_id.clone(),
                    &child_jobs,
                    &node_errors,
                    batch_error.as_deref(),
                )
            })
            .collect(),
        switches: request
            .switches
            .into_iter()
            .map(|device| {
                firmware_device_status(
                    device,
                    parent_job_id.clone(),
                    &child_jobs,
                    &node_errors,
                    batch_error.as_deref(),
                )
            })
            .collect(),
        ..Default::default()
    };

    tracing::info!(
        rack_id = %request.rack_id,
        parent_job_id = ?job.job_id,
        object_id = ?job.firmware_id,
        machine_count,
        switch_count,
        "RMS firmware object JSON apply submitted",
    );

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

    Ok(job)
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
            })
            .await;

        match response {
            Ok(response)
                if response.status == librms::protos::rack_manager::ReturnCode::Success as i32 =>
            {
                if !response.node_id.is_empty() {
                    device.node_id = response.node_id.clone();
                }
                match rms::FirmwareJobState::try_from(response.job_state) {
                    Ok(rms::FirmwareJobState::Queued) => {
                        device.status = "pending".into();
                        device.error_message = None;
                    }
                    Ok(rms::FirmwareJobState::Running) => {
                        device.status = "in_progress".into();
                        device.error_message = None;
                    }
                    Ok(rms::FirmwareJobState::Completed) => {
                        device.status = "completed".into();
                        device.error_message = None;
                    }
                    Ok(rms::FirmwareJobState::Failed) => {
                        device.status = "failed".into();
                        device.error_message = Some(if response.error_message.is_empty() {
                            response.state_description
                        } else {
                            response.error_message
                        });
                    }
                    Ok(rms::FirmwareJobState::Unspecified) | Err(_) => {
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
                let error = rack_manager_error("get_firmware_job_status", error);
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

struct NvosUpdateSource<'a> {
    config_json: &'a str,
    access_token: &'a str,
}

async fn rms_start_nvos_update(
    rms_client: &dyn SwitchSystemImageRmsClient,
    rack_id: &RackId,
    source: NvosUpdateSource<'_>,
    software_type: &str,
    hardware_type: &str,
    switches: Vec<FirmwareUpgradeDeviceInfo>,
) -> Result<NvosUpdateJob, StateHandlerError> {
    let started_at = chrono::Utc::now();
    let nodes: Vec<_> = switches
        .iter()
        .map(|switch| build_new_node_info(rack_id, switch, rms::NodeType::Switch))
        .collect();
    let nodes = Some(rms::NodeSet { nodes });
    let NvosUpdateSource {
        config_json,
        access_token,
    } = source;
    let response = rms_client
        .apply_switch_system_image(rms::ApplySwitchSystemImageRequest {
            rack_id: rack_id.to_string(),
            config_json: config_json.to_string(),
            access_token: access_token.to_string(),
            software_type: software_type.to_string(),
            hardware_type: hardware_type.to_string(),
            nodes,
        })
        .await
        .map_err(|error| {
            StateHandlerError::GenericError(eyre::eyre!(
                "failed to submit NVOS update to RMS: {}",
                error
            ))
        })?;

    let batch_response = response.response.as_ref();
    let batch_status = batch_response
        .map(|batch_response| batch_response.status)
        .unwrap_or(rms::ReturnCode::Failure as i32);
    let batch_job_id = batch_response
        .map(|batch_response| batch_response.job_id.as_str())
        .unwrap_or_default();
    if batch_status != rms::ReturnCode::Success as i32
        && batch_job_id.is_empty()
        && response.jobs.is_empty()
    {
        let message = batch_response
            .map(|batch_response| batch_response.message.as_str())
            .unwrap_or_default();
        let message = if message.is_empty() {
            "RMS returned failure for ApplySwitchSystemImage".to_string()
        } else {
            message.to_string()
        };
        return Err(StateHandlerError::GenericError(eyre::eyre!(message)));
    }

    let parent_job_id = (!batch_job_id.is_empty()).then(|| batch_job_id.to_string());
    let child_jobs = response
        .jobs
        .iter()
        .map(|child| (child.node_id.clone(), child.job_id.clone()))
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
                    .get(&switch.node_id)
                    .cloned()
                    .or_else(|| parent_job_id.clone()),
                error_message: None,
            };

            if status.job_id.is_none() {
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
        firmware_id: response.object_id,
        image_filename: response.image_filename,
        local_file_path: String::new(),
        version: None,
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

pub fn apply_nvos_job_status_response(
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
                let Some((config_json, components, force_update)) =
                    requested_firmware_object_json_upgrade(scope)
                else {
                    if explicit_firmware_upgrade_requested(scope) {
                        return transition_to_rack_error(
                            id,
                            state,
                            "firmware-upgrade rack maintenance requires SOT JSON and access token",
                            ctx,
                        )
                        .await;
                    }
                    return Ok(skip_firmware_upgrade_outcome(
                        id,
                        "firmware object JSON source is not configured for rack maintenance; skipping firmware update",
                        scope,
                    ));
                };
                // Defensive: older persisted maintenance state may predate API-side JSON validation.
                let Some(config_json) = config_json.filter(|json| !json.trim().is_empty()) else {
                    return transition_to_rack_error(
                        id,
                        state,
                        "firmware object JSON source is configured but target firmware version does not contain SOT JSON",
                        ctx,
                    )
                    .await;
                };
                let nvos_json_pending = requested_nvos_config_json(scope).is_some();
                let Some(rms_client) = ctx.services.rms_client.as_ref() else {
                    delete_rack_maintenance_access_token(
                        ctx.services.credential_manager.as_ref(),
                        id,
                    )
                    .await;
                    return transition_to_rack_error(id, state, "RMS client not configured", ctx)
                        .await;
                };
                let access_token = match load_rack_maintenance_access_token(
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                {
                    Ok(access_token) => access_token,
                    Err(error) => {
                        let message = error.to_string();
                        return transition_to_rack_error(id, state, &message, ctx).await;
                    }
                };
                let profile = super::resolve_profile(id, rack_profile_id, ctx);
                let rack_hardware_type = profile_hardware_type_or_any(profile);
                let firmware_type = profile
                    .map(firmware_type_for_profile)
                    .unwrap_or("prod")
                    .to_string();
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

                if inventory.machines.is_empty() && inventory.switches.is_empty() {
                    if !nvos_json_pending {
                        delete_rack_maintenance_access_token(
                            ctx.services.credential_manager.as_ref(),
                            id,
                        )
                        .await;
                    }
                    return Ok(skip_firmware_upgrade_outcome(
                        id,
                        "no compute or switch devices require rack firmware updates",
                        scope,
                    ));
                }

                tracing::info!(
                    rack_id = %id,
                    firmware_type = %firmware_type,
                    hardware_type = %rack_hardware_type,
                    force_update,
                    machine_count = inventory.machines.len(),
                    switch_count = inventory.switches.len(),
                    "Rack firmware object JSON apply starting",
                );

                let submit_result = rms_start_firmware_upgrade_from_json(
                    rms_client.as_ref(),
                    RmsFirmwareObjectJsonApply {
                        rack_id: id,
                        config_json: &config_json,
                        access_token: &access_token,
                        firmware_type: &firmware_type,
                        hardware_type: &rack_hardware_type,
                        force_update,
                        components: &components,
                        machines: inventory.machines.clone(),
                        switches: inventory.switches.clone(),
                    },
                )
                .await;
                if submit_result.is_err() || !nvos_json_pending {
                    delete_rack_maintenance_access_token(
                        ctx.services.credential_manager.as_ref(),
                        id,
                    )
                    .await;
                }

                let mut job = match submit_result {
                    Ok(job) => job,
                    Err(error) => {
                        return transition_to_rack_error_with_firmware_job(
                            id,
                            state,
                            "firmware-object-json",
                            error.to_string(),
                            ctx,
                        )
                        .await;
                    }
                };

                let mut txn = ctx.services.db_pool.begin().await?;
                let continue_after_firmware_upgrade = nvos_update_requested(scope);
                trigger_rack_firmware_reprovisioning_requests(
                    txn.as_mut(),
                    id,
                    &inventory.machine_ids,
                    &inventory.switch_ids,
                    continue_after_firmware_upgrade,
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
                    if requested_nvos_config_json(scope).is_some() {
                        delete_rack_maintenance_access_token(
                            ctx.services.credential_manager.as_ref(),
                            id,
                        )
                        .await;
                    }
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
                if failed > 0 && requested_nvos_config_json(scope).is_some() {
                    delete_rack_maintenance_access_token(
                        ctx.services.credential_manager.as_ref(),
                        id,
                    )
                    .await;
                }
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
                } else {
                    let next = next_state_after_nvos(scope);
                    tracing::info!(
                        rack_id = %id,
                        completed,
                        total,
                        next_state = %next,
                        "Rack firmware upgrade complete; no explicit NVOS update requested, advancing"
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
            NvosUpdateState::Start => {
                let Some(config_json) = requested_nvos_config_json(scope) else {
                    return transition_to_rack_error(
                        id,
                        state,
                        "nvos-update rack maintenance requires SOT JSON and access token",
                        ctx,
                    )
                    .await;
                };
                let Some(rms_client) = ctx.services.switch_system_image_rms_client.as_deref()
                else {
                    delete_rack_maintenance_access_token(
                        ctx.services.credential_manager.as_ref(),
                        id,
                    )
                    .await;
                    return transition_to_rack_error(id, state, "RMS client not configured", ctx)
                        .await;
                };
                let access_token = match load_rack_maintenance_access_token(
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                {
                    Ok(access_token) => access_token,
                    Err(error) => {
                        let message = error.to_string();
                        return transition_to_rack_error(id, state, &message, ctx).await;
                    }
                };
                let profile = super::resolve_profile(id, rack_profile_id, ctx);
                let rack_hardware_type = profile_hardware_type_or_any(profile);
                let software_type = profile.map(firmware_type_for_profile).unwrap_or("prod");

                let switch_inventory = load_rack_switch_firmware_inventory(
                    &ctx.services.db_pool,
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to load rack switch firmware inventory for NVOS update: {}",
                        error
                    ))
                })?;
                let switch_inventory = filter_switch_inventory_by_scope(switch_inventory, scope);

                if switch_inventory.switches.is_empty() {
                    delete_rack_maintenance_access_token(
                        ctx.services.credential_manager.as_ref(),
                        id,
                    )
                    .await;
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
                    rack_id = %id,
                    software_type,
                    hardware_type = %rack_hardware_type,
                    switch_count = switch_inventory.switches.len(),
                    "Rack switch system image FromJSON update starting",
                );

                for switch in &switch_inventory.switches {
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

                let source = NvosUpdateSource {
                    config_json: &config_json,
                    access_token: &access_token,
                };
                let submit_result = rms_start_nvos_update(
                    rms_client,
                    id,
                    source,
                    software_type,
                    &rack_hardware_type,
                    switch_inventory.switches,
                )
                .await;
                delete_rack_maintenance_access_token(ctx.services.credential_manager.as_ref(), id)
                    .await;

                let job = match submit_result {
                    Ok(job) => job,
                    Err(error) => return Err(error),
                };

                let mut txn = ctx.services.db_pool.begin().await?;
                clear_nvos_update_statuses(txn.as_mut(), &switch_inventory.switch_ids).await?;
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
                tracing::info!(
                    rack_id = %id,
                    "Starting ConfigureNmxCluster; advancing to DisableScaleUpFabricState"
                );
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                        configure_nmx_cluster: ConfigureNmxClusterState::DisableScaleUpFabricState,
                    },
                }))
            }
            ConfigureNmxClusterState::DisableScaleUpFabricState => {
                let nmx_configure_rms_client =
                    build_nmx_configure_rms_client(&ctx.services.site_config.rms);
                let rms_client: &dyn librms::RmsApi =
                    if let Some(rms_client) = nmx_configure_rms_client.as_ref() {
                        rms_client
                    } else {
                        let Some(rms_client) = ctx.services.rms_client.as_ref() else {
                            return transition_to_rack_error(
                                id,
                                state,
                                "RMS client not configured",
                                ctx,
                            )
                            .await;
                        };
                        rms_client.as_ref()
                    };
                let switch_inventory = load_rack_switch_firmware_inventory(
                    &ctx.services.db_pool,
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to load rack switch firmware inventory for DisableScaleUpFabricState: {}",
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

                tracing::info!(
                    rack_id = %id,
                    switch_count = switch_inventory.switches.len(),
                    "Disabling ScaleUpFabric state before selecting ConfigureNmxCluster primary switch"
                );
                let response = match rms_client
                    .batch_set_scale_up_fabric_state(rms::BatchSetScaleUpFabricStateRequest {
                        nodes: Some(rms::NodeSet {
                            nodes: switch_inventory
                                .switches
                                .iter()
                                .map(|switch| {
                                    build_new_node_info(id, switch, rms::NodeType::Switch)
                                })
                                .collect(),
                        }),
                        enabled: false,
                    })
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        let error = rack_manager_error("batch_set_scale_up_fabric_state", error);
                        return transition_to_rack_error(id, state, error.to_string(), ctx).await;
                    }
                };

                let batch = response.response.unwrap_or_default();
                let stats = batch.stats.unwrap_or_default();

                if batch.status != rms::ReturnCode::Success as i32 || stats.failed_nodes > 0 {
                    let node_error = batch
                        .node_results
                        .iter()
                        .find(|result| {
                            result.status != rms::ReturnCode::Success as i32
                                || !result.error_message.is_empty()
                        })
                        .map(|result| {
                            if result.error_message.is_empty() {
                                format!("status={}", result.status)
                            } else {
                                result.error_message.clone()
                            }
                        });
                    let summary = if !batch.message.trim().is_empty() {
                        batch.message
                    } else if let Some(error) = node_error {
                        error
                    } else {
                        format!(
                            "batch status {}, failed_nodes {}",
                            batch.status, stats.failed_nodes,
                        )
                    };
                    tracing::error!(
                        rack_id = %id,
                        batch_status = batch.status,
                        successful_nodes = stats.successful_nodes,
                        failed_nodes = stats.failed_nodes,
                        summary = %summary,
                        "RMS BatchSetScaleUpFabricState failed",
                    );
                    return transition_to_rack_error(
                        id,
                        state,
                        format!("RMS BatchSetScaleUpFabricState failed: {}", summary),
                        ctx,
                    )
                    .await;
                }

                tracing::info!(
                    rack_id = %id,
                    successful_nodes = stats.successful_nodes,
                    switch_count = switch_inventory.switches.len(),
                    "ScaleUpFabric state disabled; advancing to ConfigureScaleUpFabricManager"
                );
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: RackMaintenanceState::ConfigureNmxCluster {
                        configure_nmx_cluster:
                            ConfigureNmxClusterState::ConfigureScaleUpFabricManager,
                    },
                }))
            }
            ConfigureNmxClusterState::ConfigureScaleUpFabricManager => {
                let nmx_configure_rms_client =
                    build_nmx_configure_rms_client(&ctx.services.site_config.rms);
                let rms_client: &dyn librms::RmsApi =
                    if let Some(rms_client) = nmx_configure_rms_client.as_ref() {
                        rms_client
                    } else {
                        let Some(rms_client) = ctx.services.rms_client.as_ref() else {
                            return transition_to_rack_error(
                                id,
                                state,
                                "RMS client not configured",
                                ctx,
                            )
                            .await;
                        };
                        rms_client.as_ref()
                    };
                let switch_inventory = load_rack_switch_firmware_inventory(
                    &ctx.services.db_pool,
                    ctx.services.credential_manager.as_ref(),
                    id,
                )
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to load rack switch firmware inventory for ConfigureScaleUpFabricManager: {}",
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
                    .batch_get_node_device_info(build_switch_device_info_request(
                        id,
                        &switch_inventory.switches,
                    ))
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        let error = rack_manager_error("batch_get_node_device_info", error);
                        return transition_to_rack_error(id, state, error.to_string(), ctx).await;
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
                        node: Some(build_new_node_info(
                            id,
                            &primary_switch.device,
                            rms::NodeType::Switch,
                        )),
                        topology_type: topology_type.clone(),
                    })
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        let error = rack_manager_error("configure_scale_up_fabric_manager", error);
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

                let fabric_status_response = match batch_get_scale_up_fabric_service_status(
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
    use carbide_rack::firmware_update::RackFirmwareInventory;
    use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
    use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
    use model::rack::{
        ConfigureNmxClusterState, FirmwareUpgradeDeviceInfo, FirmwareUpgradeState,
        MaintenanceActivity, MaintenanceScope, NvosUpdateState, RackMaintenanceState,
        RackPowerState,
    };
    use model::rack_type::{RackHardwareType, RackProfile};

    use super::{
        filter_inventory_by_scope, firmware_device_status, first_maintenance_state,
        next_state_after_configure, next_state_after_firmware, next_state_after_nvos,
        profile_hardware_type_or_any,
    };

    fn test_machine_id(seed: u8) -> MachineId {
        let mut hash = [0u8; 32];
        hash[0] = seed;
        MachineId::new(MachineIdSource::Tpm, hash, MachineType::Host)
    }

    fn test_switch_id(seed: u8) -> SwitchId {
        let mut hash = [0u8; 32];
        hash[0] = seed;
        SwitchId::new(SwitchIdSource::Tpm, hash, SwitchType::NvLink)
    }

    fn test_device_info(node_id: impl ToString) -> FirmwareUpgradeDeviceInfo {
        FirmwareUpgradeDeviceInfo {
            node_id: node_id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            bmc_username: "admin".to_string(),
            bmc_password: "password".to_string(),
            os_mac: None,
            os_ip: None,
            os_username: None,
            os_password: None,
        }
    }

    fn sample_inventory() -> RackFirmwareInventory {
        let machine_a = test_machine_id(1);
        let machine_b = test_machine_id(2);
        let switch_a = test_switch_id(3);
        let switch_b = test_switch_id(4);

        RackFirmwareInventory {
            machine_ids: vec![machine_a, machine_b],
            machines: vec![test_device_info(machine_a), test_device_info(machine_b)],
            switch_ids: vec![switch_a, switch_b],
            switches: vec![test_device_info(switch_a), test_device_info(switch_b)],
        }
    }

    #[test]
    fn profile_hardware_type_or_any_defaults_missing_values_to_any() {
        assert_eq!(profile_hardware_type_or_any(None), "any");
        assert_eq!(
            profile_hardware_type_or_any(Some(&RackProfile::default())),
            "any"
        );

        let profile = RackProfile {
            rack_hardware_type: Some(RackHardwareType::from("gb200")),
            ..Default::default()
        };

        assert_eq!(profile_hardware_type_or_any(Some(&profile)), "gb200");
    }

    #[test]
    fn filter_inventory_by_scope_full_rack_keeps_all_devices() {
        let inventory = sample_inventory();
        let filtered = filter_inventory_by_scope(inventory, &MaintenanceScope::default());

        assert_eq!(filtered.machine_ids.len(), 2);
        assert_eq!(filtered.machines.len(), 2);
        assert_eq!(filtered.switch_ids.len(), 2);
        assert_eq!(filtered.switches.len(), 2);
    }

    #[test]
    fn filter_inventory_by_scope_machines_only() {
        let machine_id = test_machine_id(1);
        let scope = MaintenanceScope {
            machine_ids: vec![machine_id],
            ..Default::default()
        };
        let filtered = filter_inventory_by_scope(sample_inventory(), &scope);

        assert_eq!(filtered.machine_ids, vec![machine_id]);
        assert_eq!(filtered.machines.len(), 1);
        assert_eq!(filtered.machines[0].node_id, machine_id.to_string());
        assert!(filtered.switch_ids.is_empty());
        assert!(filtered.switches.is_empty());
    }

    #[test]
    fn filter_inventory_by_scope_switches_only() {
        let switch_id = test_switch_id(3);
        let scope = MaintenanceScope {
            switch_ids: vec![switch_id],
            ..Default::default()
        };
        let filtered = filter_inventory_by_scope(sample_inventory(), &scope);

        assert!(filtered.machine_ids.is_empty());
        assert!(filtered.machines.is_empty());
        assert_eq!(filtered.switch_ids, vec![switch_id]);
        assert_eq!(filtered.switches.len(), 1);
        assert_eq!(filtered.switches[0].node_id, switch_id.to_string());
    }

    #[test]
    fn filter_inventory_by_scope_machines_and_switches() {
        let machine_id = test_machine_id(2);
        let switch_id = test_switch_id(4);
        let scope = MaintenanceScope {
            machine_ids: vec![machine_id],
            switch_ids: vec![switch_id],
            ..Default::default()
        };
        let filtered = filter_inventory_by_scope(sample_inventory(), &scope);

        assert_eq!(filtered.machine_ids, vec![machine_id]);
        assert_eq!(filtered.machines.len(), 1);
        assert_eq!(filtered.machines[0].node_id, machine_id.to_string());
        assert_eq!(filtered.switch_ids, vec![switch_id]);
        assert_eq!(filtered.switches.len(), 1);
        assert_eq!(filtered.switches[0].node_id, switch_id.to_string());
    }

    #[test]
    fn filter_inventory_by_scope_excludes_unknown_device_ids() {
        let machine_id = test_machine_id(1);
        let switch_id = test_switch_id(3);
        let scope = MaintenanceScope {
            machine_ids: vec![machine_id],
            switch_ids: vec![switch_id],
            ..Default::default()
        };
        let mut inventory = sample_inventory();
        inventory
            .machines
            .push(test_device_info("not-a-machine-id"));
        inventory.switches.push(test_device_info("not-a-switch-id"));

        let filtered = filter_inventory_by_scope(inventory, &scope);

        assert_eq!(filtered.machine_ids, vec![machine_id]);
        assert_eq!(filtered.machines.len(), 1);
        assert_eq!(filtered.machines[0].node_id, machine_id.to_string());
        assert_eq!(filtered.switch_ids, vec![switch_id]);
        assert_eq!(filtered.switches.len(), 1);
        assert_eq!(filtered.switches[0].node_id, switch_id.to_string());
    }

    #[test]
    fn firmware_device_status_uses_batch_error_when_child_job_missing() {
        let status = firmware_device_status(
            test_device_info("node-1"),
            Some("parent-job".to_string()),
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
            Some("invalid SOT JSON"),
        );

        assert_eq!(status.status, "failed");
        assert_eq!(status.error_message.as_deref(), Some("invalid SOT JSON"));
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
                force_update: false,
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
                config_json: r#"{"Id":"fw-nvos"}"#.into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            first_maintenance_state(&scope),
            RackMaintenanceState::NVOSUpdate {
                nvos_update: NvosUpdateState::Start,
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

    // ── next_state_after_firmware ───────────────────────────────────────

    #[test]
    fn after_firmware_all_activities_skips_nvos_without_explicit_json() {
        let scope = MaintenanceScope::default();
        assert_eq!(
            next_state_after_firmware(&scope),
            next_state_after_nvos(&scope)
        );
    }

    #[test]
    fn after_firmware_without_configure_goes_to_power() {
        let scope = MaintenanceScope {
            activities: vec![
                MaintenanceActivity::FirmwareUpgrade {
                    firmware_version: None,
                    components: vec![],
                    force_update: false,
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
                force_update: false,
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
                    force_update: false,
                },
                MaintenanceActivity::NvosUpdate {
                    config_json: r#"{"Id":"fw-nvos"}"#.into(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            next_state_after_firmware(&scope),
            RackMaintenanceState::NVOSUpdate {
                nvos_update: NvosUpdateState::Start,
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
                    config_json: r#"{"Id":"fw-nvos"}"#.into(),
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
                    force_update: false,
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
}
