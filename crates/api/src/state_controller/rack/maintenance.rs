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
use model::rack::{
    FirmwareUpgradeDeviceStatus, FirmwareUpgradeState, Rack, RackFirmwareUpgradeState,
    RackFirmwareUpgradeStatus, RackMaintenanceState, RackPowerState, RackState,
    RackValidationState,
};

use crate::rack::firmware_update::{
    build_firmware_update_batches, firmware_type_for_profile, load_rack_firmware_inventory,
    submit_firmware_update_batches,
};
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
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

fn skip_firmware_upgrade_outcome(
    rack_id: &RackId,
    reason: impl AsRef<str>,
) -> StateHandlerOutcome<RackState> {
    tracing::info!(
        rack_id = %rack_id,
        reason = %reason.as_ref(),
        "Skipping rack firmware upgrade and advancing to ConfigureNmxCluster"
    );
    StateHandlerOutcome::transition(RackState::Maintenance {
        maintenance_state: RackMaintenanceState::ConfigureNmxCluster,
    })
}

fn transition_to_rack_error(
    rack_id: &RackId,
    cause: impl Into<String>,
) -> StateHandlerOutcome<RackState> {
    let cause = cause.into();
    tracing::warn!(rack_id = %rack_id, %cause, "Rack firmware upgrade failed before polling started");
    StateHandlerOutcome::transition(RackState::Error { cause })
}

/// Submit compute and switch firmware-update batches to RMS and persist the
/// per-device child job IDs returned by UpdateFirmwareByDeviceList.
async fn rms_start_firmware_upgrade(
    rms_client: &dyn librms::RmsApi,
    batches: Vec<crate::rack::firmware_update::FirmwareUpdateBatchRequest>,
) -> model::rack::FirmwareUpgradeJob {
    let started_at = chrono::Utc::now();
    let submissions = submit_firmware_update_batches(rms_client, batches).await;
    let mut job = model::rack::FirmwareUpgradeJob {
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

pub async fn handle_maintenance(
    id: &RackId,
    state: &mut Rack,
    rack_profile_id: Option<&RackProfileId>,
    maintenance_state: &RackMaintenanceState,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    match maintenance_state {
        RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade,
        } => match rack_firmware_upgrade {
            FirmwareUpgradeState::Start => {
                let Some(profile) = super::resolve_profile(id, rack_profile_id, ctx) else {
                    return Ok(skip_firmware_upgrade_outcome(
                        id,
                        "rack profile is missing or unknown",
                    ));
                };
                let Some(rack_hardware_type) = profile.rack_hardware_type.as_ref() else {
                    return Ok(skip_firmware_upgrade_outcome(
                        id,
                        "rack capabilities do not define rack_hardware_type",
                    ));
                };
                let default_firmware = match db_rack_firmware::find_default_by_rack_hardware_type(
                    &ctx.services.db_pool,
                    rack_hardware_type,
                )
                .await
                {
                    Ok(firmware) => firmware,
                    Err(db::DatabaseError::NotFoundError { .. }) => {
                        return Ok(skip_firmware_upgrade_outcome(
                            id,
                            format!(
                                "no default rack firmware configured for hardware type '{}'",
                                rack_hardware_type
                            ),
                        ));
                    }
                    Err(error) => return Err(error.into()),
                };

                if !default_firmware.available {
                    return Ok(skip_firmware_upgrade_outcome(
                        id,
                        format!(
                            "default rack firmware '{}' exists but is not available",
                            default_firmware.id
                        ),
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
                let firmware_type = firmware_type_for_profile(profile);
                let batches = match build_firmware_update_batches(
                    id,
                    &default_firmware,
                    firmware_type,
                    &inventory,
                ) {
                    Ok(batches) if batches.is_empty() => {
                        return Ok(skip_firmware_upgrade_outcome(
                            id,
                            "no compute or switch devices require rack firmware updates",
                        ));
                    }
                    Ok(batches) => batches,
                    Err(error) => {
                        return Ok(transition_to_rack_error(
                            id,
                            format!(
                                "failed to build firmware update requests for default firmware '{}': {}",
                                default_firmware.id, error
                            ),
                        ));
                    }
                };
                let Some(rms_client) = ctx.services.rms_client.as_ref() else {
                    return Ok(transition_to_rack_error(id, "RMS client not configured"));
                };

                tracing::info!(
                    rack_id = %id,
                    rack_hardware_type = %rack_hardware_type,
                    default_firmware_id = %default_firmware.id,
                    firmware_type,
                    machine_count = inventory.machines.len(),
                    switch_count = inventory.switches.len(),
                    "Rack firmware upgrade starting"
                );
                let mut job = rms_start_firmware_upgrade(rms_client.as_ref(), batches).await;

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
                let current_job = match &state.firmware_upgrade_job {
                    Some(j) => j,
                    None => {
                        return Ok(StateHandlerOutcome::wait(
                            "firmware upgrade: no job recorded yet".into(),
                        ));
                    }
                };
                let Some(rms_client) = ctx.services.rms_client.as_ref() else {
                    return Ok(transition_to_rack_error(id, "RMS client not configured"));
                };
                let job = rms_get_firmware_upgrade_status(rms_client.as_ref(), current_job).await?;

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

                let all: Vec<_> = job.all_devices().collect();
                let total = all.len();
                let completed = all.iter().filter(|d| d.status == "completed").count();
                let failed = all.iter().filter(|d| d.status == "failed").count();
                let terminal = completed + failed;

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
                    db_rack::update_firmware_upgrade_job(txn.as_mut(), id, Some(&job)).await?;
                    state.firmware_upgrade_job = Some(job);
                    return Ok(StateHandlerOutcome::transition(RackState::Error {
                        cause: format!(
                            "firmware upgrade failed: {}/{} devices failed",
                            failed, total
                        ),
                    })
                    .with_txn(txn));
                }

                tracing::info!(
                    "Rack {} firmware upgrade complete ({}/{} devices), advancing to ConfigureNmxCluster",
                    id,
                    completed,
                    total
                );
                db_rack::update_firmware_upgrade_job(txn.as_mut(), id, None).await?;
                state.firmware_upgrade_job = None;
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    maintenance_state: RackMaintenanceState::ConfigureNmxCluster,
                })
                .with_txn(txn))
            }
        },
        RackMaintenanceState::ConfigureNmxCluster => {
            tracing::info!(
                "Rack {} ConfigureNmxCluster - stubbed, advancing to Completed",
                id
            );
            Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                maintenance_state: RackMaintenanceState::PowerSequence {
                    rack_power: RackPowerState::PoweringOn,
                },
            }))
        }
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
                "Rack {} maintenance completed, clearing rv.* labels and entering Validating(Pending)",
                id
            );
            clear_rv_labels(state, ctx).await?;
            Ok(StateHandlerOutcome::transition(RackState::Validating {
                validating_state: RackValidationState::Pending,
            }))
        }
    }
}
