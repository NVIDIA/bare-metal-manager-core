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

use carbide_uuid::rack::RackId;
use db::{
    host_machine_update as db_host_machine_update, machine as db_machine,
    machine_interface as db_machine_interface, machine_topology as db_machine_topology,
    power_shelf as db_power_shelf, rack as db_rack, switch as db_switch,
};
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, Credentials,
};
use model::machine::machine_search_config::MachineSearchConfig;
use model::rack::{
    FirmwareUpgradeDeviceInfo, FirmwareUpgradeDeviceStatus, FirmwareUpgradeState, Rack, RackConfig,
    RackFirmwareUpgradeState, RackFirmwareUpgradeStatus, RackMaintenanceState, RackPowerState,
    RackState, RackValidationState,
};

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

/// Fetches BMC root credentials from Vault for the given MAC address,
/// falling back to sitewide BMC root credentials if per-device creds are not found.
async fn fetch_bmc_credentials(
    credential_manager: &dyn CredentialManager,
    bmc_mac: mac_address::MacAddress,
) -> Result<(String, String), StateHandlerError> {
    let key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: bmc_mac,
        },
    };

    let creds = match credential_manager.get_credentials(&key).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            let sitewide_key = CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::SiteWideRoot,
            };
            credential_manager
                .get_credentials(&sitewide_key)
                .await
                .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("vault error: {}", e)))?
                .ok_or_else(|| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "no BMC credentials in vault for {} or sitewide",
                        bmc_mac
                    ))
                })?
        }
        Err(e) => {
            return Err(StateHandlerError::GenericError(eyre::eyre!(
                "vault error: {}",
                e
            )));
        }
    };

    match creds {
        Credentials::UsernamePassword { username, password } => Ok((username, password)),
    }
}

/// Fetches switch NVOS admin credentials from Vault for the given BMC MAC.
/// Returns `None` if not found (NVOS creds are optional).
async fn fetch_nvos_credentials(
    credential_manager: &dyn CredentialManager,
    bmc_mac: mac_address::MacAddress,
) -> Option<(String, String)> {
    let key = CredentialKey::SwitchNvosAdmin {
        bmc_mac_address: bmc_mac,
    };
    match credential_manager.get_credentials(&key).await {
        Ok(Some(Credentials::UsernamePassword { username, password })) => {
            Some((username, password))
        }
        _ => None,
    }
}

/// Stub: call RMS to start a firmware upgrade for the given devices.
/// TODO: Replace with a real RMS client call that submits the firmware
/// upgrade request and returns the RMS-assigned job identifier.
fn rms_start_firmware_upgrade(
    rack_id: &RackId,
    machines: Vec<FirmwareUpgradeDeviceInfo>,
    switches: Vec<FirmwareUpgradeDeviceInfo>,
    power_shelves: Vec<FirmwareUpgradeDeviceInfo>,
) -> Result<model::rack::FirmwareUpgradeJob, StateHandlerError> {
    let total = machines.len() + switches.len() + power_shelves.len();

    tracing::info!(
        "RMS stub: starting firmware upgrade for rack {} — {} devices (machines={}, switches={}, power_shelves={})",
        rack_id,
        total,
        machines.len(),
        switches.len(),
        power_shelves.len(),
    );

    for device in machines
        .iter()
        .chain(switches.iter())
        .chain(power_shelves.iter())
    {
        tracing::debug!(
            "RMS stub: device mac={} bmc_ip={} bmc_user={} os_ip={:?}",
            device.mac,
            device.bmc_ip,
            device.bmc_username,
            device.os_ip,
        );
    }

    let to_status = |d: &FirmwareUpgradeDeviceInfo| FirmwareUpgradeDeviceStatus {
        mac: d.mac.clone(),
        bmc_ip: d.bmc_ip.clone(),
        status: "pending".into(),
    };

    Ok(model::rack::FirmwareUpgradeJob {
        job_id: Some(format!(
            "fw-{}-{}",
            rack_id,
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        )),
        status: Some("in_progress".into()),
        started_at: Some(chrono::Utc::now()),
        completed_at: None,
        machines: machines.iter().map(to_status).collect(),
        switches: switches.iter().map(to_status).collect(),
        power_shelves: power_shelves.iter().map(to_status).collect(),
    })
}

/// Stub: poll RMS for the current status of a firmware upgrade job.
/// Returns an updated `FirmwareUpgradeJob` with per-device statuses.
///
/// TODO: Replace with a real RMS client call that queries the job status
/// and returns the actual per-device firmware upgrade progress.
fn rms_get_firmware_upgrade_status(
    job: &model::rack::FirmwareUpgradeJob,
) -> Result<model::rack::FirmwareUpgradeJob, StateHandlerError> {
    let mut updated = job.clone();
    for device in updated.all_devices_mut() {
        device.status = "completed".into();
    }
    updated.status = Some("completed".into());
    updated.completed_at = Some(chrono::Utc::now());
    tracing::info!(
        "RMS stub: job {} polled — all devices completed",
        job.job_id.as_deref().unwrap_or("?")
    );
    Ok(updated)
}

pub async fn handle_maintenance(
    id: &RackId,
    state: &mut Rack,
    _config: &RackConfig,
    maintenance_state: &RackMaintenanceState,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    match maintenance_state {
        RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade,
        } => match rack_firmware_upgrade {
            FirmwareUpgradeState::Start => {
                tracing::info!(
                    "Rack {} firmware upgrade starting — issuing reprovisioning requests",
                    id
                );
                let (m_bmc_pairs, m_intfs, switch_endpoints, power_shelf_endpoints) = {
                    let mut txn = ctx.services.db_pool.begin().await?;

                    let machine_ids = db_machine::find_machine_ids(
                        txn.as_mut(),
                        MachineSearchConfig {
                            rack_id: Some(id.clone()),
                            ..Default::default()
                        },
                    )
                    .await?;
                    for machine_id in machine_ids.iter() {
                        db_host_machine_update::trigger_host_reprovisioning_request(
                            txn.as_mut(),
                            &format!("rack-{}", id),
                            machine_id,
                        )
                        .await?;
                    }

                    let switch_ids = db_switch::find_ids(
                        txn.as_mut(),
                        model::switch::SwitchSearchFilter {
                            rack_id: Some(id.clone()),
                            ..Default::default()
                        },
                    )
                    .await?;
                    for switch_id in switch_ids.iter() {
                        db_switch::set_switch_reprovisioning_requested(
                            txn.as_mut(),
                            *switch_id,
                            &format!("rack-{}", id),
                        )
                        .await?;
                    }

                    let power_shelf_ids = db_power_shelf::find_ids(
                        txn.as_mut(),
                        model::power_shelf::PowerShelfSearchFilter {
                            rack_id: Some(id.clone()),
                            ..Default::default()
                        },
                    )
                    .await?;

                    let bmc_pairs = db_machine_topology::find_machine_bmc_pairs_by_machine_id(
                        txn.as_mut(),
                        machine_ids.clone(),
                    )
                    .await?;
                    let intfs =
                        db_machine_interface::find_by_machine_ids(txn.as_mut(), &machine_ids)
                            .await?;
                    let s_ep =
                        db_switch::find_switch_endpoints_by_ids(txn.as_mut(), &switch_ids).await?;
                    let p_ep = db_power_shelf::find_power_shelf_endpoints_by_ids(
                        txn.as_mut(),
                        &power_shelf_ids,
                    )
                    .await?;

                    txn.commit().await?;
                    (bmc_pairs, intfs, s_ep, p_ep)
                };

                let cred_mgr = ctx.services.credential_manager.as_ref();

                let mut machines = Vec::with_capacity(m_bmc_pairs.len());
                for (machine_id, bmc_ip) in &m_bmc_pairs {
                    let bmc_mac = m_intfs
                        .get(machine_id)
                        .and_then(|intfs| intfs.iter().find(|i| i.primary_interface))
                        .map(|i| i.mac_address);
                    let (bmc_username, bmc_password) = if let Some(mac) = bmc_mac {
                        fetch_bmc_credentials(cred_mgr, mac).await?
                    } else {
                        (String::new(), String::new())
                    };
                    machines.push(FirmwareUpgradeDeviceInfo {
                        mac: bmc_mac.map(|m| m.to_string()).unwrap_or_default(),
                        bmc_ip: bmc_ip.as_deref().unwrap_or_default().to_string(),
                        bmc_username,
                        bmc_password,
                        os_ip: None,
                        os_username: None,
                        os_password: None,
                    });
                }

                let mut switches = Vec::with_capacity(switch_endpoints.len());
                for s in &switch_endpoints {
                    let (bmc_username, bmc_password) =
                        fetch_bmc_credentials(cred_mgr, s.bmc_mac).await?;
                    let nvos_creds = fetch_nvos_credentials(cred_mgr, s.bmc_mac).await;
                    switches.push(FirmwareUpgradeDeviceInfo {
                        mac: s.bmc_mac.to_string(),
                        bmc_ip: s.bmc_ip.to_string(),
                        bmc_username,
                        bmc_password,
                        os_ip: s.nvos_ip.map(|ip| ip.to_string()),
                        os_username: nvos_creds.as_ref().map(|(u, _)| u.clone()),
                        os_password: nvos_creds.map(|(_, p)| p),
                    });
                }

                let mut power_shelves = Vec::with_capacity(power_shelf_endpoints.len());
                for p in &power_shelf_endpoints {
                    let (bmc_username, bmc_password) =
                        fetch_bmc_credentials(cred_mgr, p.pmc_mac).await?;
                    power_shelves.push(FirmwareUpgradeDeviceInfo {
                        mac: p.pmc_mac.to_string(),
                        bmc_ip: p.pmc_ip.to_string(),
                        bmc_username,
                        bmc_password,
                        os_ip: None,
                        os_username: None,
                        os_password: None,
                    });
                }

                let job = rms_start_firmware_upgrade(id, machines, switches, power_shelves)?;

                let mut txn = ctx.services.db_pool.begin().await?;
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

                let job = rms_get_firmware_upgrade_status(current_job)?;

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
                            task_id: job.job_id.clone().unwrap_or_else(|| "unknown".to_string()),
                            status: state,
                            started_at: job.started_at,
                            ended_at: if device.status == "completed" || device.status == "failed" {
                                Some(chrono::Utc::now())
                            } else {
                                None
                            },
                        }
                    };

                for device in job.machines.iter() {
                    let mac: mac_address::MacAddress = match device.mac.parse() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if let Some(machine_id) =
                        db_machine_topology::find_machine_id_by_bmc_mac(txn.as_mut(), mac).await?
                    {
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
                    let mac: mac_address::MacAddress = match device.mac.parse() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if let Some(switch_id) = db_switch::find_ids(
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
                    {
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

                if failed > 0 {
                    return Ok(StateHandlerOutcome::transition(RackState::Error {
                        cause: format!(
                            "firmware upgrade failed: {}/{} devices failed",
                            failed, total
                        ),
                    })
                    .with_txn(txn));
                }

                if completed < total {
                    db_rack::update_firmware_upgrade_job(txn.as_mut(), id, Some(&job)).await?;
                    state.firmware_upgrade_job = Some(job);
                    return Ok(StateHandlerOutcome::wait(format!(
                        "firmware upgrade: {}/{} devices completed",
                        completed, total
                    ))
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
            let run_id = format!("run-{}-{}", id, chrono::Utc::now().format("%Y%m%d-%H%M%S"));
            tracing::info!(
                "Rack {} maintenance completed, entering validation (run_id={})",
                id,
                run_id
            );
            state.config.validation_run_id = Some(run_id);
            let mut txn = ctx.services.db_pool.begin().await?;
            db_rack::update(txn.as_mut(), id, &state.config).await?;
            Ok(StateHandlerOutcome::transition(RackState::Validating {
                validating_state: RackValidationState::Pending,
            })
            .with_txn(txn))
        }
    }
}
