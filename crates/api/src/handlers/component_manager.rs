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

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ::rpc::common::SystemPowerControl;
use ::rpc::forge::{self as rpc, BmcEndpointRequest};
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::switch::SwitchId;
use component_manager::component_manager::ComponentManager;
use component_manager::error::ComponentManagerError;
use component_manager::nv_switch_manager::SwitchEndpoint;
use component_manager::power_shelf_manager::{PowerShelfEndpoint, PowerShelfVendor};
use db::{self, WithTransaction};
use futures_util::FutureExt;
use mac_address::MacAddress;
use model::component_manager::{PowerAction, PowerShelfComponent};
use model::rack::{FirmwareUpgradeJob, MaintenanceActivity};
use tonic::{Code, Request, Response, Status};

use crate::api::{Api, log_request_data};

const MACHINE_POWER_OVERRIDE_SOURCE: &str = "component_power_control";
const MACHINE_POWER_OVERRIDE_MESSAGE: &str = "Compute-Tray component power control in progress";

fn require_component_manager(api: &Api) -> Result<&ComponentManager, Status> {
    api.component_manager
        .as_ref()
        .ok_or_else(|| Status::unimplemented("component manager is not configured"))
}

fn component_manager_error_to_status(err: ComponentManagerError) -> Status {
    match err {
        ComponentManagerError::Unavailable(msg) => Status::unavailable(msg),
        ComponentManagerError::NotFound(msg) => Status::not_found(msg),
        ComponentManagerError::InvalidArgument(msg) => Status::invalid_argument(msg),
        ComponentManagerError::Internal(msg) => Status::internal(msg),
        ComponentManagerError::Transport(e) => Status::unavailable(format!("transport error: {e}")),
        ComponentManagerError::Status(s) => s,
        ComponentManagerError::Rms(msg) => Status::internal(format!("RMS error: {msg}")),
    }
}

fn make_result(
    id: &str,
    status: rpc::ComponentManagerStatusCode,
    error: Option<String>,
) -> rpc::ComponentResult {
    rpc::ComponentResult {
        component_id: id.to_owned(),
        status: status as i32,
        error: error.unwrap_or_default(),
    }
}

fn success_result(id: &str) -> rpc::ComponentResult {
    make_result(id, rpc::ComponentManagerStatusCode::Success, None)
}

fn not_found_result(id: &str) -> rpc::ComponentResult {
    make_result(
        id,
        rpc::ComponentManagerStatusCode::NotFound,
        Some(format!("no explored endpoint found for {id}")),
    )
}

fn error_result(id: &str, error: String) -> rpc::ComponentResult {
    make_result(
        id,
        rpc::ComponentManagerStatusCode::InternalError,
        Some(error),
    )
}

fn status_result(id: &str, status: Status) -> rpc::ComponentResult {
    let component_status = match status.code() {
        Code::InvalidArgument | Code::FailedPrecondition | Code::OutOfRange => {
            rpc::ComponentManagerStatusCode::InvalidArgument
        }
        Code::NotFound => rpc::ComponentManagerStatusCode::NotFound,
        Code::AlreadyExists => rpc::ComponentManagerStatusCode::AlreadyExists,
        Code::Unavailable | Code::DeadlineExceeded | Code::ResourceExhausted => {
            rpc::ComponentManagerStatusCode::Unavailable
        }
        _ => rpc::ComponentManagerStatusCode::InternalError,
    };
    make_result(id, component_status, Some(status.message().to_string()))
}

fn not_found_component_result(id: &str, message: impl Into<String>) -> rpc::ComponentResult {
    make_result(
        id,
        rpc::ComponentManagerStatusCode::NotFound,
        Some(message.into()),
    )
}

fn invalid_argument_component_result(id: &str, message: impl Into<String>) -> rpc::ComponentResult {
    make_result(
        id,
        rpc::ComponentManagerStatusCode::InvalidArgument,
        Some(message.into()),
    )
}

fn rack_requested_firmware_version(rack: &model::rack::Rack) -> Option<String> {
    rack.config
        .maintenance_requested
        .as_ref()?
        .activities
        .iter()
        .find_map(|activity| match activity {
            MaintenanceActivity::FirmwareUpgrade {
                firmware_version: Some(firmware_version),
                ..
            } if !firmware_version.is_empty() => Some(firmware_version.clone()),
            _ => None,
        })
}

fn rack_firmware_upgrade_requested(rack: &model::rack::Rack) -> bool {
    rack.config
        .maintenance_requested
        .as_ref()
        .is_some_and(|scope| {
            scope.activities.is_empty()
                || scope
                    .activities
                    .iter()
                    .any(|activity| matches!(activity, MaintenanceActivity::FirmwareUpgrade { .. }))
        })
}

fn firmware_job_state(job: &FirmwareUpgradeJob) -> i32 {
    if let Some(status) = job.status.as_deref() {
        match status.to_ascii_lowercase().as_str() {
            "queued" | "pending" => return rpc::FirmwareUpdateState::FwStateQueued as i32,
            "running" | "in_progress" | "active" => {
                return rpc::FirmwareUpdateState::FwStateInProgress as i32;
            }
            "verifying" => return rpc::FirmwareUpdateState::FwStateVerifying as i32,
            "completed" | "success" | "done" => {
                return rpc::FirmwareUpdateState::FwStateCompleted as i32;
            }
            "failed" | "error" => return rpc::FirmwareUpdateState::FwStateFailed as i32,
            "cancelled" | "canceled" => return rpc::FirmwareUpdateState::FwStateCancelled as i32,
            _ => {}
        }
    }

    let devices: Vec<_> = job.all_devices().collect();
    let total = devices.len();

    if total == 0 {
        return rpc::FirmwareUpdateState::FwStateUnknown as i32;
    }

    let completed = devices
        .iter()
        .filter(|device| device.status == "completed")
        .count();
    let failed = devices
        .iter()
        .filter(|device| device.status == "failed")
        .count();
    let terminal = completed + failed;
    let has_in_progress = devices
        .iter()
        .any(|device| matches!(device.status.as_str(), "in_progress" | "running" | "active"));
    let all_queued = devices
        .iter()
        .all(|device| matches!(device.status.as_str(), "pending" | "queued" | "started"));

    if failed > 0 && terminal == total {
        rpc::FirmwareUpdateState::FwStateFailed as i32
    } else if completed == total {
        rpc::FirmwareUpdateState::FwStateCompleted as i32
    } else if terminal > 0 || has_in_progress || job.started_at.is_some() {
        rpc::FirmwareUpdateState::FwStateInProgress as i32
    } else if all_queued {
        rpc::FirmwareUpdateState::FwStateQueued as i32
    } else {
        rpc::FirmwareUpdateState::FwStateUnknown as i32
    }
}

fn rack_firmware_status(rack: &model::rack::Rack) -> rpc::FirmwareUpdateStatus {
    let requested_version = rack_requested_firmware_version(rack);
    let firmware_upgrade_requested = rack_firmware_upgrade_requested(rack);
    let job = rack.firmware_upgrade_job.as_ref();
    let state = if let Some(job) = job {
        firmware_job_state(job)
    } else if firmware_upgrade_requested {
        rpc::FirmwareUpdateState::FwStateQueued as i32
    } else {
        rpc::FirmwareUpdateState::FwStateUnknown as i32
    };
    let target_version = requested_version
        .or_else(|| job.and_then(|job| job.firmware_id.clone()))
        .unwrap_or_default();
    let updated_at = job
        .and_then(|job| job.completed_at.or(job.started_at))
        .or_else(|| firmware_upgrade_requested.then_some(rack.updated))
        .map(Into::into);

    rpc::FirmwareUpdateStatus {
        result: Some(success_result(rack.id.as_ref())),
        state,
        target_version,
        updated_at,
    }
}

fn build_inventory_entries(
    id_strings: &[String],
    report_by_id: &HashMap<String, model::site_explorer::EndpointExplorationReport>,
) -> Vec<rpc::ComponentInventoryEntry> {
    id_strings
        .iter()
        .map(|id| match report_by_id.get(id) {
            Some(report) => rpc::ComponentInventoryEntry {
                result: Some(success_result(id)),
                report: Some(report.clone().into()),
            },
            None => rpc::ComponentInventoryEntry {
                result: Some(not_found_result(id)),
                report: None,
            },
        })
        .collect()
}

fn map_power_action(raw: i32) -> Result<PowerAction, Status> {
    match SystemPowerControl::try_from(raw) {
        Ok(SystemPowerControl::On) => Ok(PowerAction::On),
        Ok(SystemPowerControl::GracefulShutdown) => Ok(PowerAction::GracefulShutdown),
        Ok(SystemPowerControl::ForceOff) => Ok(PowerAction::ForceOff),
        Ok(SystemPowerControl::GracefulRestart) => Ok(PowerAction::GracefulRestart),
        Ok(SystemPowerControl::ForceRestart) => Ok(PowerAction::ForceRestart),
        Ok(SystemPowerControl::AcPowercycle) => Ok(PowerAction::AcPowercycle),
        Ok(SystemPowerControl::Unknown) | Err(_) => Err(Status::invalid_argument(format!(
            "unknown power action: {raw}"
        ))),
    }
}

fn map_compute_tray_component_names(raw: &[i32]) -> Result<Vec<String>, Status> {
    raw.iter()
        .filter(|&&v| v != rpc::ComputeTrayComponent::Unknown as i32)
        .map(|&v| match rpc::ComputeTrayComponent::try_from(v) {
            Ok(rpc::ComputeTrayComponent::Bmc) => Ok("BMC".to_string()),
            Ok(rpc::ComputeTrayComponent::Bios) => Ok("BIOS".to_string()),
            _ => Err(Status::invalid_argument(format!(
                "unknown compute tray component: {v}"
            ))),
        })
        .collect()
}

fn map_nv_switch_component_names(raw: &[i32]) -> Result<Vec<String>, Status> {
    raw.iter()
        .filter(|&&v| v != rpc::NvSwitchComponent::Unknown as i32)
        .map(|&v| match rpc::NvSwitchComponent::try_from(v) {
            Ok(rpc::NvSwitchComponent::Bmc) => Ok("BMC".to_string()),
            Ok(rpc::NvSwitchComponent::Cpld) => Ok("CPLD".to_string()),
            Ok(rpc::NvSwitchComponent::Bios) => Ok("BIOS".to_string()),
            Ok(rpc::NvSwitchComponent::Nvos) => Ok("NVOS".to_string()),
            _ => Err(Status::invalid_argument(format!(
                "unknown NV-Switch component: {v}"
            ))),
        })
        .collect()
}

fn map_power_shelf_components(raw: &[i32]) -> Result<Vec<PowerShelfComponent>, Status> {
    raw.iter()
        .filter(|&&v| v != rpc::PowerShelfComponent::Unknown as i32)
        .map(|&v| match rpc::PowerShelfComponent::try_from(v) {
            Ok(rpc::PowerShelfComponent::Pmc) => Ok(PowerShelfComponent::Pmc),
            Ok(rpc::PowerShelfComponent::Psu) => Ok(PowerShelfComponent::Psu),
            _ => Err(Status::invalid_argument(format!(
                "unknown power shelf component: {v}"
            ))),
        })
        .collect()
}

// ---- Endpoint resolution helpers ----

struct ResolvedSwitchEndpoints {
    endpoints: Vec<SwitchEndpoint>,
    mac_to_id: HashMap<MacAddress, SwitchId>,
}

struct SwitchEndpoints {
    resolved: ResolvedSwitchEndpoints,
    unresolved: Vec<SwitchId>,
}

async fn resolve_switch_endpoints(
    api: &Api,
    switch_ids: &[SwitchId],
) -> Result<SwitchEndpoints, Status> {
    let rows = db::switch::find_switch_endpoints_by_ids(&mut api.db_reader(), switch_ids)
        .await
        .map_err(|e| Status::internal(format!("db error resolving switch endpoints: {e}")))?;

    let mut endpoints = Vec::with_capacity(rows.len());
    let mut mac_to_id = HashMap::with_capacity(rows.len());
    let mut unresolved = Vec::new();
    let mut resolved_ids = HashSet::with_capacity(rows.len());

    for row in rows {
        let (Some(nvos_mac), Some(nvos_ip)) = (row.nvos_mac, row.nvos_ip) else {
            tracing::warn!(
                switch_id = %row.switch_id,
                "skipping switch: NVOS MAC or IP not available"
            );
            unresolved.push(row.switch_id);
            resolved_ids.insert(row.switch_id);
            continue;
        };
        resolved_ids.insert(row.switch_id);
        mac_to_id.insert(row.bmc_mac, row.switch_id);
        endpoints.push(SwitchEndpoint {
            bmc_ip: row.bmc_ip,
            bmc_mac: row.bmc_mac,
            nvos_ip,
            nvos_mac,
        });
    }

    for id in switch_ids {
        if !resolved_ids.contains(id) {
            tracing::warn!(switch_id = %id, "switch not found in expected_switches");
            unresolved.push(*id);
        }
    }

    if !unresolved.is_empty() {
        tracing::warn!(
            count = unresolved.len(),
            "some switches could not be resolved to endpoints"
        );
    }

    Ok(SwitchEndpoints {
        resolved: ResolvedSwitchEndpoints {
            endpoints,
            mac_to_id,
        },
        unresolved,
    })
}

struct ResolvedPowerShelfEndpoints {
    endpoints: Vec<PowerShelfEndpoint>,
    mac_to_id: HashMap<MacAddress, PowerShelfId>,
}

struct PowerShelfEndpoints {
    resolved: ResolvedPowerShelfEndpoints,
    unresolved: Vec<PowerShelfId>,
}

async fn resolve_power_shelf_endpoints(
    api: &Api,
    power_shelf_ids: &[PowerShelfId],
) -> Result<PowerShelfEndpoints, Status> {
    let rows =
        db::power_shelf::find_power_shelf_endpoints_by_ids(&mut api.db_reader(), power_shelf_ids)
            .await
            .map_err(|e| {
                Status::internal(format!("db error resolving power shelf endpoints: {e}"))
            })?;

    let mut endpoints = Vec::with_capacity(rows.len());
    let mut mac_to_id = HashMap::with_capacity(rows.len());
    let mut resolved_ids = HashSet::with_capacity(rows.len());

    for row in rows {
        resolved_ids.insert(row.power_shelf_id);
        mac_to_id.insert(row.pmc_mac, row.power_shelf_id);
        endpoints.push(PowerShelfEndpoint {
            pmc_ip: row.pmc_ip,
            pmc_mac: row.pmc_mac,
            // TODO: retrieve vendor from DB instead of using a hardcoded default
            pmc_vendor: PowerShelfVendor::DEFAULT,
        });
    }

    let mut unresolved = Vec::new();
    for id in power_shelf_ids {
        if !resolved_ids.contains(id) {
            tracing::warn!(power_shelf_id = %id, "power shelf not found in expected_power_shelves");
            unresolved.push(*id);
        }
    }

    if !unresolved.is_empty() {
        tracing::warn!(
            count = unresolved.len(),
            "some power shelves could not be resolved to endpoints"
        );
    }

    Ok(PowerShelfEndpoints {
        resolved: ResolvedPowerShelfEndpoints {
            endpoints,
            mac_to_id,
        },
        unresolved,
    })
}

fn switch_mac_to_id_str(mac: &MacAddress, mac_to_id: &HashMap<MacAddress, SwitchId>) -> String {
    mac_to_id
        .get(mac)
        .map(|id| id.to_string())
        .unwrap_or_else(|| mac.to_string())
}

fn ps_mac_to_id_str(mac: &MacAddress, mac_to_id: &HashMap<MacAddress, PowerShelfId>) -> String {
    mac_to_id
        .get(mac)
        .map(|id| id.to_string())
        .unwrap_or_else(|| mac.to_string())
}

fn map_fw_state(state: model::component_manager::FirmwareState) -> i32 {
    use model::component_manager::FirmwareState;
    match state {
        FirmwareState::Unknown => rpc::FirmwareUpdateState::FwStateUnknown as i32,
        FirmwareState::Queued => rpc::FirmwareUpdateState::FwStateQueued as i32,
        FirmwareState::InProgress => rpc::FirmwareUpdateState::FwStateInProgress as i32,
        FirmwareState::Verifying => rpc::FirmwareUpdateState::FwStateVerifying as i32,
        FirmwareState::Completed => rpc::FirmwareUpdateState::FwStateCompleted as i32,
        FirmwareState::Failed => rpc::FirmwareUpdateState::FwStateFailed as i32,
        FirmwareState::Cancelled => rpc::FirmwareUpdateState::FwStateCancelled as i32,
    }
}

// ---- Power Control ----

pub(crate) async fn component_power_control(
    api: &Api,
    request: Request<rpc::ComponentPowerControlRequest>,
) -> Result<Response<rpc::ComponentPowerControlResponse>, Status> {
    log_request_data(&request);
    let cm = require_component_manager(api)?;
    let req = request.into_inner();

    let action = map_power_action(req.action)?;

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let (results, exploration_ips) = match target {
        rpc::component_power_control_request::Target::SwitchIds(list) => {
            let endpoints = resolve_switch_endpoints(api, &list.ids).await?;

            let mut results: Vec<_> = endpoints
                .unresolved
                .iter()
                .map(|id| {
                    error_result(
                        &id.to_string(),
                        "could not resolve endpoint for switch".into(),
                    )
                })
                .collect();

            tracing::info!(
                backend = cm.nv_switch.name(),
                count = endpoints.resolved.endpoints.len(),
                ?action,
                "power control for switches"
            );
            let backend_results = cm
                .nv_switch
                .power_control(&endpoints.resolved.endpoints, action)
                .await
                .map_err(component_manager_error_to_status)?;
            results.extend(backend_results.into_iter().map(|r| {
                let id = switch_mac_to_id_str(&r.bmc_mac, &endpoints.resolved.mac_to_id);
                if r.success {
                    success_result(&id)
                } else {
                    error_result(&id, r.error.unwrap_or_default())
                }
            }));

            let ips: Vec<IpAddr> = endpoints
                .resolved
                .endpoints
                .iter()
                .map(|ep| ep.bmc_ip)
                .collect();

            (results, ips)
        }
        rpc::component_power_control_request::Target::PowerShelfIds(list) => {
            let endpoints = resolve_power_shelf_endpoints(api, &list.ids).await?;

            let mut results: Vec<_> = endpoints
                .unresolved
                .iter()
                .map(|id| {
                    error_result(
                        &id.to_string(),
                        "could not resolve endpoint for power shelf".into(),
                    )
                })
                .collect();

            tracing::info!(
                backend = cm.power_shelf.name(),
                count = endpoints.resolved.endpoints.len(),
                ?action,
                "power control for power shelves"
            );
            let backend_results = cm
                .power_shelf
                .power_control(&endpoints.resolved.endpoints, action)
                .await
                .map_err(component_manager_error_to_status)?;
            results.extend(backend_results.into_iter().map(|r| {
                let id = ps_mac_to_id_str(&r.pmc_mac, &endpoints.resolved.mac_to_id);
                if r.success {
                    success_result(&id)
                } else {
                    error_result(&id, r.error.unwrap_or_default())
                }
            }));

            let ips: Vec<IpAddr> = endpoints
                .resolved
                .endpoints
                .iter()
                .map(|ep| ep.pmc_ip)
                .collect();

            (results, ips)
        }
        rpc::component_power_control_request::Target::MachineIds(list) => {
            let mut txn = api.txn_begin().await?;
            let mut resolved = Vec::with_capacity(list.machine_ids.len());
            let mut results = Vec::with_capacity(list.machine_ids.len());
            let mut ips = Vec::new();

            for machine_id in &list.machine_ids {
                let id_str = machine_id.to_string();
                match crate::handlers::bmc_endpoint_explorer::validate_and_complete_bmc_endpoint_request(
                    &mut txn,
                    None,
                    Some(*machine_id),
                )
                .await
                {
                    Ok((req, _)) => resolved.push((*machine_id, req)),
                    Err(e) => results.push(error_result(&id_str, e.to_string())),
                }
            }

            if let Err(e) = txn.commit().await {
                tracing::warn!(
                    ?e,
                    "failed to commit read-only endpoint resolution txn; proceeding with already-resolved data"
                );
            }

            for (machine_id, bmc_endpoint_request) in resolved {
                let id_str = machine_id.to_string();

                if let Ok(ip) = bmc_endpoint_request.ip_address.parse() {
                    ips.push(ip);
                }

                let outcome =
                    compute_power_control(api, machine_id, bmc_endpoint_request, action).await;

                match outcome {
                    Ok(()) => results.push(success_result(&id_str)),
                    Err(e) => results.push(error_result(&id_str, e.message().to_string())),
                }
            }

            (results, ips)
        }
    };

    // request re-exploration for the BMC/PMC endpoints that had power control initiated against them
    // so that site explorer refreshes its data for the device. RLA will query the power state shortly
    // after initiating power control via this path. RLA queries the power state of a device via the site
    // exploration report data
    request_re_exploration(api, &exploration_ips).await;

    Ok(Response::new(rpc::ComponentPowerControlResponse {
        results,
    }))
}

async fn compute_power_control(
    api: &Api,
    machine_id: carbide_uuid::machine::MachineId,
    bmc_endpoint: BmcEndpointRequest,
    action: PowerAction,
) -> Result<(), Status> {
    let override_inserted = power_control_health_override(api, machine_id, true).await;

    let result = machine_power_control(api, machine_id, bmc_endpoint, action).await;

    if override_inserted {
        power_control_health_override(api, machine_id, false).await;
    }

    result
}

/// Best-effort insert or removal of the health report override used to
/// suppress external alerting during compute power control.
/// Returns `true` when the operation succeeded.
async fn power_control_health_override(
    api: &Api,
    machine_id: carbide_uuid::machine::MachineId,
    insert: bool,
) -> bool {
    let result = if insert {
        let req = rpc::InsertMachineHealthReportRequest {
            machine_id: Some(machine_id),
            health_report_entry: Some(rpc::HealthReportEntry {
                report: Some(::rpc::health::HealthReport {
                    source: MACHINE_POWER_OVERRIDE_SOURCE.to_string(),
                    triggered_by: None,
                    observed_at: None,
                    successes: vec![],
                    alerts: vec![::rpc::health::HealthProbeAlert {
                        id: health_report::HealthProbeId::internal_maintenance().to_string(),
                        target: None,
                        in_alert_since: None,
                        message: MACHINE_POWER_OVERRIDE_MESSAGE.to_string(),
                        tenant_message: None,
                        classifications: vec![
                            health_report::HealthAlertClassification::suppress_external_alerting()
                                .to_string(),
                        ],
                    }],
                }),
                mode: rpc::HealthReportApplyMode::Replace as i32,
            }),
        };
        crate::handlers::health::insert_machine_health_report(api, Request::new(req))
            .await
            .map(|_| ())
    } else {
        let req = rpc::RemoveMachineHealthReportRequest {
            machine_id: Some(machine_id),
            source: MACHINE_POWER_OVERRIDE_SOURCE.to_string(),
        };
        crate::handlers::health::remove_machine_health_report(api, Request::new(req))
            .await
            .map(|_| ())
    };

    if let Err(e) = &result {
        let action = if insert { "insert" } else { "remove" };
        tracing::warn!(
            %machine_id,
            error = %e,
            "failed to {action} health report override for power control"
        );
    }

    result.is_ok()
}

fn desired_power_state(action: PowerAction) -> rpc::PowerState {
    match action {
        PowerAction::On
        | PowerAction::ForceRestart
        | PowerAction::GracefulRestart
        | PowerAction::AcPowercycle => rpc::PowerState::On,
        PowerAction::GracefulShutdown | PowerAction::ForceOff => rpc::PowerState::Off,
    }
}

fn redfish_power_action(
    action: PowerAction,
) -> rpc::admin_power_control_request::SystemPowerControl {
    use rpc::admin_power_control_request::SystemPowerControl;
    match action {
        PowerAction::On => SystemPowerControl::On,
        PowerAction::ForceRestart => SystemPowerControl::ForceRestart,
        PowerAction::GracefulRestart => SystemPowerControl::GracefulRestart,
        PowerAction::AcPowercycle => SystemPowerControl::AcPowercycle,
        PowerAction::GracefulShutdown => SystemPowerControl::GracefulShutdown,
        PowerAction::ForceOff => SystemPowerControl::ForceOff,
    }
}

/*
machine_power_control facilitates power control against compute trays:
    1. Configures the desired power state for the machine in the power-manager
    2. Synchronously sends the redfish command to the compute tray's BMC to perform the action specified
On success, the power manager will have the desired power state set for the machine and the redfish command will have been successfully sent to the compute BMC
In the case of partial failure, the power manager may have the desired power state updated for the machine but the redfish command may have failed. We will leave reconvergence in this case to the power manager.
*/
async fn machine_power_control(
    api: &Api,
    machine_id: carbide_uuid::machine::MachineId,
    bmc_endpoint: BmcEndpointRequest,
    action: PowerAction,
) -> Result<(), Status> {
    let desired_power_state = desired_power_state(action) as i32;
    let redfish_action = redfish_power_action(action);

    let power_req = rpc::PowerOptionUpdateRequest {
        machine_id: Some(machine_id),
        power_state: desired_power_state,
    };
    match crate::handlers::power_options::update_power_option(api, Request::new(power_req)).await {
        Ok(_) => {}
        Err(e) if e.code() == Code::InvalidArgument && e.message().contains("already set as") => {
            tracing::debug!(
                %machine_id,
                desired_power_state,
                "power option already in desired state, skipping"
            );
        }
        Err(e) => return Err(e),
    }

    let admin_req = rpc::AdminPowerControlRequest {
        bmc_endpoint_request: Some(bmc_endpoint),
        machine_id: Some(machine_id.to_string()),
        action: redfish_action as i32,
    };
    crate::handlers::bmc_endpoint_explorer::admin_power_control(api, Request::new(admin_req))
        .await?;

    Ok(())
}

/// Best-effort: flag BMC/PMC endpoints for re-exploration so the site
/// explorer refreshes its cache before `VerifyPowerStatus` polls.
async fn request_re_exploration(api: &Api, ips: &[IpAddr]) {
    if ips.is_empty() {
        return;
    }
    let result = api
        .with_txn(|txn| {
            db::explored_endpoints::request_exploration_for_addresses(ips, txn.as_mut()).boxed()
        })
        .await;
    if let Err(e) | Ok(Err(e)) = result {
        tracing::warn!(?e, "failed to request re-exploration after power control");
    }
}

// ---- Inventory ----

pub(crate) async fn get_component_inventory(
    api: &Api,
    request: Request<rpc::GetComponentInventoryRequest>,
) -> Result<Response<rpc::GetComponentInventoryResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let entries = match target {
        rpc::get_component_inventory_request::Target::SwitchIds(list) => {
            let id_ip_pairs =
                db::switch::find_bmc_ips_by_switch_ids(&mut api.db_reader(), &list.ids)
                    .await
                    .map_err(|e| Status::internal(format!("db error: {e}")))?;

            let ip_to_id: HashMap<IpAddr, String> = id_ip_pairs
                .into_iter()
                .map(|(sid, ip)| (ip, sid.to_string()))
                .collect();

            let id_strings: Vec<String> = list.ids.iter().map(|id| id.to_string()).collect();
            let ips: Vec<IpAddr> = ip_to_id.keys().copied().collect();
            let endpoints = db::explored_endpoints::find_by_ips(&mut api.db_reader(), ips)
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?;

            let report_by_id: HashMap<String, _> = endpoints
                .into_iter()
                .filter_map(|ep| {
                    let id = ip_to_id.get(&ep.address)?;
                    Some((id.clone(), ep.report))
                })
                .collect();

            build_inventory_entries(&id_strings, &report_by_id)
        }
        rpc::get_component_inventory_request::Target::PowerShelfIds(list) => {
            let id_ip_pairs =
                db::power_shelf::find_bmc_ips_by_power_shelf_ids(&mut api.db_reader(), &list.ids)
                    .await
                    .map_err(|e| Status::internal(format!("db error: {e}")))?;

            let ip_to_id: HashMap<IpAddr, String> = id_ip_pairs
                .into_iter()
                .map(|(psid, ip)| (ip, psid.to_string()))
                .collect();

            let id_strings: Vec<String> = list.ids.iter().map(|id| id.to_string()).collect();
            let ips: Vec<IpAddr> = ip_to_id.keys().copied().collect();
            let endpoints = db::explored_endpoints::find_by_ips(&mut api.db_reader(), ips)
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?;

            let report_by_id: HashMap<String, _> = endpoints
                .into_iter()
                .filter_map(|ep| {
                    let id = ip_to_id.get(&ep.address)?;
                    Some((id.clone(), ep.report))
                })
                .collect();

            build_inventory_entries(&id_strings, &report_by_id)
        }
        rpc::get_component_inventory_request::Target::MachineIds(list) => {
            let id_strings: Vec<String> =
                list.machine_ids.iter().map(|id| id.to_string()).collect();

            let mut txn = api
                .txn_begin()
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?;

            let bmc_pairs = db::machine_topology::find_machine_bmc_pairs_by_machine_id(
                &mut txn,
                list.machine_ids.clone(),
            )
            .await
            .map_err(|e| Status::internal(format!("db error: {e}")))?;

            txn.commit()
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?;

            let ip_to_id: HashMap<IpAddr, String> = bmc_pairs
                .into_iter()
                .filter_map(|(mid, ip_str)| {
                    let ip: IpAddr = ip_str?.parse().ok()?;
                    Some((ip, mid.to_string()))
                })
                .collect();

            let ips: Vec<IpAddr> = ip_to_id.keys().copied().collect();
            let endpoints = db::explored_endpoints::find_by_ips(&mut api.db_reader(), ips)
                .await
                .map_err(|e| Status::internal(format!("db error: {e}")))?;

            let report_by_id: HashMap<String, _> = endpoints
                .into_iter()
                .filter_map(|ep| {
                    let id = ip_to_id.get(&ep.address)?;
                    Some((id.clone(), ep.report))
                })
                .collect();

            build_inventory_entries(&id_strings, &report_by_id)
        }
    };

    Ok(Response::new(rpc::GetComponentInventoryResponse {
        entries,
    }))
}

// ---- Firmware Update ----

pub(crate) async fn update_component_firmware(
    api: &Api,
    request: Request<rpc::UpdateComponentFirmwareRequest>,
) -> Result<Response<rpc::UpdateComponentFirmwareResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let mut rack_machine_ids: Vec<String> = Vec::new();
    let mut rack_switch_ids: Vec<String> = Vec::new();
    let mut rack_id: Option<carbide_uuid::rack::RackId> = None;
    let mut power_shelf_results: Option<Vec<rpc::ComponentResult>> = None;
    let mut rack_results: Option<Vec<rpc::ComponentResult>> = None;
    let mut component_names: Vec<String> = Vec::new();

    match target {
        rpc::update_component_firmware_request::Target::Switches(t) => {
            let list = t
                .switch_ids
                .ok_or_else(|| Status::invalid_argument("switch_ids is required"))?;
            if list.ids.is_empty() {
                return Err(Status::invalid_argument("switch_ids must not be empty"));
            }

            component_names = map_nv_switch_component_names(&t.components)?;

            let mut txn = api
                .database_connection
                .begin()
                .await
                .map_err(|e| Status::internal(format!("failed to begin transaction: {e}")))?;
            let switch = db::switch::find_by_id(&mut txn, &list.ids[0])
                .await
                .map_err(|e| Status::internal(format!("failed to look up switch: {e}")))?
                .ok_or_else(|| Status::not_found(format!("switch {} not found", list.ids[0])))?;
            drop(txn);

            rack_id = Some(switch.rack_id.ok_or_else(|| {
                Status::failed_precondition(format!(
                    "switch {} is not associated with a rack",
                    list.ids[0]
                ))
            })?);
            rack_switch_ids = list.ids.iter().map(|id| id.to_string()).collect();
        }
        rpc::update_component_firmware_request::Target::ComputeTrays(t) => {
            let list = t
                .machine_ids
                .ok_or_else(|| Status::invalid_argument("machine_ids is required"))?;
            if list.machine_ids.is_empty() {
                return Err(Status::invalid_argument("machine_ids must not be empty"));
            }

            component_names = map_compute_tray_component_names(&t.components)?;

            let machine = db::machine::find_one(
                api.db_reader().as_mut(),
                &list.machine_ids[0],
                Default::default(),
            )
            .await
            .map_err(|e| Status::internal(format!("failed to look up machine: {e}")))?
            .ok_or_else(|| {
                Status::not_found(format!("machine {} not found", list.machine_ids[0]))
            })?;

            rack_id = Some(machine.rack_id.ok_or_else(|| {
                Status::failed_precondition(format!(
                    "machine {} is not associated with a rack",
                    list.machine_ids[0]
                ))
            })?);
            rack_machine_ids = list.machine_ids.iter().map(|id| id.to_string()).collect();
        }
        rpc::update_component_firmware_request::Target::PowerShelves(t) => {
            let cm = require_component_manager(api)?;
            let list = t
                .power_shelf_ids
                .ok_or_else(|| Status::invalid_argument("power_shelf_ids is required"))?;
            let components = map_power_shelf_components(&t.components)?;
            let endpoints = resolve_power_shelf_endpoints(api, &list.ids).await?;

            let mut results: Vec<_> = endpoints
                .unresolved
                .iter()
                .map(|id| {
                    error_result(
                        &id.to_string(),
                        "could not resolve endpoint for power shelf".into(),
                    )
                })
                .collect();

            let backend_results = cm
                .power_shelf
                .update_firmware(
                    &endpoints.resolved.endpoints,
                    &req.target_version,
                    &components,
                )
                .await
                .map_err(component_manager_error_to_status)?;
            results.extend(backend_results.into_iter().map(|r| {
                let id = ps_mac_to_id_str(&r.pmc_mac, &endpoints.resolved.mac_to_id);
                if r.success {
                    success_result(&id)
                } else {
                    error_result(&id, r.error.unwrap_or_default())
                }
            }));
            power_shelf_results = Some(results);
        }
        rpc::update_component_firmware_request::Target::Racks(t) => {
            let list = t
                .rack_ids
                .ok_or_else(|| Status::invalid_argument("rack_ids is required"))?;
            if list.rack_ids.is_empty() {
                return Err(Status::invalid_argument("rack_ids must not be empty"));
            }

            let mut results = Vec::new();
            for rack_id in list.rack_ids {
                let rack_id_string = rack_id.to_string();
                let maintenance_req = Request::new(rpc::RackMaintenanceOnDemandRequest {
                    rack_id: Some(rack_id),
                    scope: Some(rpc::RackMaintenanceScope {
                        machine_ids: vec![],
                        switch_ids: vec![],
                        power_shelf_ids: vec![],
                        activities: vec![rpc::MaintenanceActivityConfig {
                            activity: Some(
                                rpc::maintenance_activity_config::Activity::FirmwareUpgrade(
                                    rpc::FirmwareUpgradeActivity {
                                        firmware_version: req.target_version.clone(),
                                        components: vec![],
                                    },
                                ),
                            ),
                        }],
                    }),
                });

                match crate::handlers::rack::on_demand_rack_maintenance(api, maintenance_req).await
                {
                    Ok(_) => results.push(success_result(&rack_id_string)),
                    Err(status) => results.push(status_result(&rack_id_string, status)),
                }
            }
            rack_results = Some(results);
        }
    }

    if let Some(results) = power_shelf_results {
        return Ok(Response::new(rpc::UpdateComponentFirmwareResponse {
            results,
        }));
    }

    if let Some(results) = rack_results {
        return Ok(Response::new(rpc::UpdateComponentFirmwareResponse {
            results,
        }));
    }

    let rack_id = rack_id.ok_or_else(|| {
        Status::invalid_argument("no machines or switches specified for firmware upgrade")
    })?;

    let maintenance_req = Request::new(rpc::RackMaintenanceOnDemandRequest {
        rack_id: Some(rack_id),
        scope: Some(rpc::RackMaintenanceScope {
            machine_ids: rack_machine_ids.clone(),
            switch_ids: rack_switch_ids.clone(),
            power_shelf_ids: vec![],
            activities: vec![rpc::MaintenanceActivityConfig {
                activity: Some(rpc::maintenance_activity_config::Activity::FirmwareUpgrade(
                    rpc::FirmwareUpgradeActivity {
                        firmware_version: req.target_version,
                        components: component_names,
                    },
                )),
            }],
        }),
    });

    crate::handlers::rack::on_demand_rack_maintenance(api, maintenance_req).await?;

    let results: Vec<_> = rack_machine_ids
        .iter()
        .chain(rack_switch_ids.iter())
        .map(|id| success_result(id))
        .collect();

    Ok(Response::new(rpc::UpdateComponentFirmwareResponse {
        results,
    }))
}

// ---- Firmware Status ----

pub(crate) async fn get_component_firmware_status(
    api: &Api,
    request: Request<rpc::GetComponentFirmwareStatusRequest>,
) -> Result<Response<rpc::GetComponentFirmwareStatusResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let statuses = match target {
        rpc::get_component_firmware_status_request::Target::SwitchIds(list) => {
            let cm = require_component_manager(api)?;
            let endpoints = resolve_switch_endpoints(api, &list.ids).await?;

            let mut statuses: Vec<_> = endpoints
                .unresolved
                .iter()
                .map(|id| rpc::FirmwareUpdateStatus {
                    result: Some(error_result(
                        &id.to_string(),
                        "could not resolve endpoint for switch".into(),
                    )),
                    state: rpc::FirmwareUpdateState::FwStateUnknown as i32,
                    target_version: String::new(),
                    updated_at: None,
                })
                .collect();

            let backend_statuses = cm
                .nv_switch
                .get_firmware_status(&endpoints.resolved.endpoints)
                .await
                .map_err(component_manager_error_to_status)?;
            statuses.extend(backend_statuses.into_iter().map(|s| {
                let id = switch_mac_to_id_str(&s.bmc_mac, &endpoints.resolved.mac_to_id);
                rpc::FirmwareUpdateStatus {
                    result: Some(if s.error.is_none() {
                        success_result(&id)
                    } else {
                        error_result(&id, s.error.unwrap_or_default())
                    }),
                    state: map_fw_state(s.state),
                    target_version: s.target_version,
                    updated_at: None,
                }
            }));
            statuses
        }
        rpc::get_component_firmware_status_request::Target::PowerShelfIds(list) => {
            let cm = require_component_manager(api)?;
            let endpoints = resolve_power_shelf_endpoints(api, &list.ids).await?;

            let mut statuses: Vec<_> = endpoints
                .unresolved
                .iter()
                .map(|id| rpc::FirmwareUpdateStatus {
                    result: Some(error_result(
                        &id.to_string(),
                        "could not resolve endpoint for power shelf".into(),
                    )),
                    state: rpc::FirmwareUpdateState::FwStateUnknown as i32,
                    target_version: String::new(),
                    updated_at: None,
                })
                .collect();

            let backend_statuses = cm
                .power_shelf
                .get_firmware_status(&endpoints.resolved.endpoints)
                .await
                .map_err(component_manager_error_to_status)?;
            statuses.extend(backend_statuses.into_iter().map(|s| {
                let id = ps_mac_to_id_str(&s.pmc_mac, &endpoints.resolved.mac_to_id);
                rpc::FirmwareUpdateStatus {
                    result: Some(if s.error.is_none() {
                        success_result(&id)
                    } else {
                        error_result(&id, s.error.unwrap_or_default())
                    }),
                    state: map_fw_state(s.state),
                    target_version: s.target_version,
                    updated_at: None,
                }
            }));
            statuses
        }
        rpc::get_component_firmware_status_request::Target::MachineIds(_) => {
            return Err(Status::unimplemented(
                "machine firmware status is not supported via this RPC",
            ));
        }
        rpc::get_component_firmware_status_request::Target::RackIds(list) => {
            if list.rack_ids.is_empty() {
                return Err(Status::invalid_argument("rack_ids must not be empty"));
            }

            let requested_rack_ids = list.rack_ids;
            let racks = db::rack::find_by(
                api.db_reader().as_mut(),
                db::ObjectColumnFilter::List(db::rack::IdColumn, &requested_rack_ids),
            )
            .await
            .map_err(|e| Status::internal(format!("failed to look up racks: {e}")))?;
            let rack_by_id: HashMap<_, _> = racks
                .into_iter()
                .map(|rack| (rack.id.clone(), rack))
                .collect();

            requested_rack_ids
                .iter()
                .map(|rack_id| {
                    rack_by_id.get(rack_id).map(rack_firmware_status).unwrap_or(
                        rpc::FirmwareUpdateStatus {
                            result: Some(not_found_component_result(
                                rack_id.as_ref(),
                                format!("rack {rack_id} not found"),
                            )),
                            state: rpc::FirmwareUpdateState::FwStateUnknown as i32,
                            target_version: String::new(),
                            updated_at: None,
                        },
                    )
                })
                .collect()
        }
    };

    Ok(Response::new(rpc::GetComponentFirmwareStatusResponse {
        statuses,
    }))
}

// ---- List Firmware Versions ----

pub(crate) async fn list_component_firmware_versions(
    api: &Api,
    request: Request<rpc::ListComponentFirmwareVersionsRequest>,
) -> Result<Response<rpc::ListComponentFirmwareVersionsResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    match target {
        rpc::list_component_firmware_versions_request::Target::SwitchIds(list) => {
            let cm = require_component_manager(api)?;
            let endpoints = resolve_switch_endpoints(api, &list.ids).await?;

            let mut devices: Vec<rpc::DeviceFirmwareVersions> = endpoints
                .unresolved
                .iter()
                .map(|id| rpc::DeviceFirmwareVersions {
                    result: Some(error_result(
                        &id.to_string(),
                        "could not resolve endpoint for switch".into(),
                    )),
                    versions: vec![],
                })
                .collect();

            let versions = cm
                .nv_switch
                .list_firmware_bundles()
                .await
                .map_err(component_manager_error_to_status)?;

            for ep in &endpoints.resolved.endpoints {
                let id = endpoints
                    .resolved
                    .mac_to_id
                    .get(&ep.bmc_mac)
                    .map(|id| id.to_string())
                    .unwrap_or_default();
                devices.push(rpc::DeviceFirmwareVersions {
                    result: Some(success_result(&id)),
                    versions: versions.clone(),
                });
            }

            Ok(Response::new(rpc::ListComponentFirmwareVersionsResponse {
                devices,
            }))
        }
        rpc::list_component_firmware_versions_request::Target::PowerShelfIds(list) => {
            let cm = require_component_manager(api)?;
            let endpoints = resolve_power_shelf_endpoints(api, &list.ids).await?;

            let mut devices: Vec<rpc::DeviceFirmwareVersions> = endpoints
                .unresolved
                .iter()
                .map(|id| rpc::DeviceFirmwareVersions {
                    result: Some(error_result(
                        &id.to_string(),
                        "could not resolve endpoint for power shelf".into(),
                    )),
                    versions: vec![],
                })
                .collect();

            let fw_results = cm
                .power_shelf
                .list_firmware(&endpoints.resolved.endpoints)
                .await
                .map_err(component_manager_error_to_status)?;

            for fv in fw_results {
                let id = endpoints
                    .resolved
                    .mac_to_id
                    .get(&fv.pmc_mac)
                    .map(|id| id.to_string())
                    .unwrap_or_default();
                let result = if let Some(err) = fv.error {
                    error_result(&id, err)
                } else {
                    success_result(&id)
                };
                devices.push(rpc::DeviceFirmwareVersions {
                    result: Some(result),
                    versions: fv.versions,
                });
            }

            Ok(Response::new(rpc::ListComponentFirmwareVersionsResponse {
                devices,
            }))
        }
        rpc::list_component_firmware_versions_request::Target::MachineIds(_) => Err(
            Status::unimplemented("machine firmware versions are not supported via this RPC"),
        ),
        rpc::list_component_firmware_versions_request::Target::RackIds(list) => {
            if list.rack_ids.is_empty() {
                return Err(Status::invalid_argument("rack_ids must not be empty"));
            }

            let requested_rack_ids = list.rack_ids;
            let racks = db::rack::find_by(
                api.db_reader().as_mut(),
                db::ObjectColumnFilter::List(db::rack::IdColumn, &requested_rack_ids),
            )
            .await
            .map_err(|e| Status::internal(format!("failed to look up racks: {e}")))?;
            let rack_by_id: HashMap<_, _> = racks
                .into_iter()
                .map(|rack| (rack.id.clone(), rack))
                .collect();

            let mut txn = api
                .database_connection
                .begin()
                .await
                .map_err(|e| Status::internal(format!("failed to begin transaction: {e}")))?;
            let firmwares = db::rack_firmware::list_all(
                &mut txn,
                model::rack_firmware::RackFirmwareSearchFilter {
                    only_available: true,
                    rack_hardware_type: None,
                },
            )
            .await
            .map_err(|e| Status::internal(format!("failed to list rack firmware: {e}")))?;
            txn.commit()
                .await
                .map_err(|e| Status::internal(format!("failed to commit transaction: {e}")))?;

            let devices = requested_rack_ids
                .iter()
                .map(|rack_id| {
                    let Some(rack) = rack_by_id.get(rack_id) else {
                        return rpc::DeviceFirmwareVersions {
                            result: Some(not_found_component_result(
                                rack_id.as_ref(),
                                format!("rack {rack_id} not found"),
                            )),
                            versions: vec![],
                        };
                    };

                    let Some(profile_id) = rack.rack_profile_id.as_ref() else {
                        return rpc::DeviceFirmwareVersions {
                            result: Some(invalid_argument_component_result(
                                rack_id.as_ref(),
                                format!("rack {rack_id} has no rack_profile_id"),
                            )),
                            versions: vec![],
                        };
                    };

                    let Some(profile) = api.runtime_config.rack_profiles.get(profile_id.as_str())
                    else {
                        return rpc::DeviceFirmwareVersions {
                            result: Some(not_found_component_result(
                                rack_id.as_ref(),
                                format!("rack profile {profile_id} not found"),
                            )),
                            versions: vec![],
                        };
                    };

                    let Some(rack_hardware_type) = profile.rack_hardware_type.as_ref() else {
                        return rpc::DeviceFirmwareVersions {
                            result: Some(invalid_argument_component_result(
                                rack_id.as_ref(),
                                format!(
                                    "rack profile {profile_id} does not define rack_hardware_type"
                                ),
                            )),
                            versions: vec![],
                        };
                    };

                    let versions = firmwares
                        .iter()
                        .filter(|firmware| {
                            firmware.rack_hardware_type.is_any()
                                || firmware.rack_hardware_type == *rack_hardware_type
                        })
                        .map(|firmware| firmware.id.clone())
                        .collect();

                    rpc::DeviceFirmwareVersions {
                        result: Some(success_result(rack_id.as_ref())),
                        versions,
                    }
                })
                .collect();

            Ok(Response::new(rpc::ListComponentFirmwareVersionsResponse {
                devices,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use config_version::{ConfigVersion, Versioned};
    use model::component_manager::FirmwareState;
    use model::metadata::Metadata;
    use model::rack::{Rack, RackConfig, RackState};
    use tonic::Code;

    use super::*;

    fn firmware_device(status: &str) -> model::rack::FirmwareUpgradeDeviceStatus {
        model::rack::FirmwareUpgradeDeviceStatus {
            node_id: String::new(),
            mac: "00:00:00:00:00:00".to_string(),
            bmc_ip: String::new(),
            status: status.to_string(),
            job_id: None,
            parent_job_id: None,
            error_message: None,
        }
    }

    fn test_rack_with_job(job: Option<FirmwareUpgradeJob>) -> Rack {
        Rack {
            id: Default::default(),
            rack_profile_id: None,
            config: RackConfig::default(),
            controller_state: Versioned::new(RackState::Ready, ConfigVersion::initial()),
            controller_state_outcome: None,
            firmware_upgrade_job: job,
            nvos_update_job: None,
            health_reports: Default::default(),
            created: chrono::Utc::now(),
            updated: chrono::Utc::now(),
            deleted: None,
            metadata: Metadata::default(),
            version: ConfigVersion::initial(),
        }
    }

    #[test]
    fn error_to_status_unavailable() {
        let st =
            component_manager_error_to_status(ComponentManagerError::Unavailable("gone".into()));
        assert_eq!(st.code(), Code::Unavailable);
        assert!(st.message().contains("gone"));
    }

    #[test]
    fn error_to_status_not_found() {
        let st =
            component_manager_error_to_status(ComponentManagerError::NotFound("missing".into()));
        assert_eq!(st.code(), Code::NotFound);
    }

    #[test]
    fn error_to_status_invalid_argument() {
        let st =
            component_manager_error_to_status(ComponentManagerError::InvalidArgument("bad".into()));
        assert_eq!(st.code(), Code::InvalidArgument);
    }

    #[test]
    fn error_to_status_internal() {
        let st = component_manager_error_to_status(ComponentManagerError::Internal("oops".into()));
        assert_eq!(st.code(), Code::Internal);
    }

    #[test]
    fn error_to_status_passthrough() {
        let original = Status::permission_denied("nope");
        let st = component_manager_error_to_status(ComponentManagerError::Status(original));
        assert_eq!(st.code(), Code::PermissionDenied);
    }

    #[test]
    fn power_action_on() {
        let action = map_power_action(SystemPowerControl::On as i32).unwrap();
        assert!(matches!(action, PowerAction::On));
    }

    #[test]
    fn power_action_graceful_shutdown() {
        let action = map_power_action(SystemPowerControl::GracefulShutdown as i32).unwrap();
        assert!(matches!(action, PowerAction::GracefulShutdown));
    }

    #[test]
    fn power_action_force_off() {
        let action = map_power_action(SystemPowerControl::ForceOff as i32).unwrap();
        assert!(matches!(action, PowerAction::ForceOff));
    }

    #[test]
    fn power_action_graceful_restart() {
        let action = map_power_action(SystemPowerControl::GracefulRestart as i32).unwrap();
        assert!(matches!(action, PowerAction::GracefulRestart));
    }

    #[test]
    fn power_action_force_restart() {
        let action = map_power_action(SystemPowerControl::ForceRestart as i32).unwrap();
        assert!(matches!(action, PowerAction::ForceRestart));
    }

    #[test]
    fn power_action_ac_powercycle() {
        let action = map_power_action(SystemPowerControl::AcPowercycle as i32).unwrap();
        assert!(matches!(action, PowerAction::AcPowercycle));
    }

    #[test]
    fn power_action_unknown_rejected() {
        let err = map_power_action(SystemPowerControl::Unknown as i32).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn power_action_unset_defaults_to_zero_and_is_rejected() {
        let req = rpc::ComponentPowerControlRequest::default();
        assert_eq!(req.action, 0);
        let err = map_power_action(req.action).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn power_action_invalid_value() {
        let err = map_power_action(9999).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn firmware_job_state_explicit_status_wins_for_empty_job() {
        let job = FirmwareUpgradeJob {
            status: Some("queued".to_string()),
            ..Default::default()
        };

        assert_eq!(
            firmware_job_state(&job),
            rpc::FirmwareUpdateState::FwStateQueued as i32
        );
    }

    #[test]
    fn firmware_job_state_empty_job_without_status_is_unknown() {
        assert_eq!(
            firmware_job_state(&FirmwareUpgradeJob::default()),
            rpc::FirmwareUpdateState::FwStateUnknown as i32
        );
    }

    #[test]
    fn firmware_job_state_all_completed_is_completed() {
        let job = FirmwareUpgradeJob {
            machines: vec![firmware_device("completed")],
            switches: vec![firmware_device("completed")],
            ..Default::default()
        };

        assert_eq!(
            firmware_job_state(&job),
            rpc::FirmwareUpdateState::FwStateCompleted as i32
        );
    }

    #[test]
    fn firmware_job_state_mixed_terminal_with_failure_is_failed() {
        let job = FirmwareUpgradeJob {
            machines: vec![firmware_device("completed")],
            switches: vec![firmware_device("failed")],
            ..Default::default()
        };

        assert_eq!(
            firmware_job_state(&job),
            rpc::FirmwareUpdateState::FwStateFailed as i32
        );
    }

    #[test]
    fn firmware_job_state_partial_terminal_is_in_progress() {
        let job = FirmwareUpgradeJob {
            machines: vec![firmware_device("completed")],
            switches: vec![firmware_device("pending")],
            ..Default::default()
        };

        assert_eq!(
            firmware_job_state(&job),
            rpc::FirmwareUpdateState::FwStateInProgress as i32
        );
    }

    #[test]
    fn firmware_job_state_all_pending_without_start_is_queued() {
        let job = FirmwareUpgradeJob {
            machines: vec![firmware_device("pending")],
            switches: vec![firmware_device("queued")],
            ..Default::default()
        };

        assert_eq!(
            firmware_job_state(&job),
            rpc::FirmwareUpdateState::FwStateQueued as i32
        );
    }

    #[test]
    fn firmware_job_state_unknown_device_status_is_unknown() {
        let job = FirmwareUpgradeJob {
            machines: vec![firmware_device("mystery")],
            ..Default::default()
        };

        assert_eq!(
            firmware_job_state(&job),
            rpc::FirmwareUpdateState::FwStateUnknown as i32
        );
    }

    #[test]
    fn rack_firmware_status_reports_retained_completed_job() {
        let job = FirmwareUpgradeJob {
            firmware_id: Some("fw-1".to_string()),
            status: Some("completed".to_string()),
            started_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
            completed_at: Some(chrono::Utc::now()),
            ..Default::default()
        };
        let rack = test_rack_with_job(Some(job));

        let status = rack_firmware_status(&rack);

        assert_eq!(
            status.state,
            rpc::FirmwareUpdateState::FwStateCompleted as i32
        );
        assert_eq!(status.target_version, "fw-1");
        assert!(status.updated_at.is_some());
    }

    #[test]
    fn rack_firmware_status_default_request_uses_job_firmware_id() {
        let job = FirmwareUpgradeJob {
            firmware_id: Some("fw-default".to_string()),
            status: Some("in_progress".to_string()),
            started_at: Some(chrono::Utc::now()),
            ..Default::default()
        };
        let mut rack = test_rack_with_job(Some(job));
        rack.config.maintenance_requested = Some(model::rack::MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: None,
                components: vec![],
            }],
            ..Default::default()
        });

        let status = rack_firmware_status(&rack);

        assert_eq!(
            status.state,
            rpc::FirmwareUpdateState::FwStateInProgress as i32
        );
        assert_eq!(status.target_version, "fw-default");
        assert!(status.updated_at.is_some());
    }

    #[test]
    fn rack_firmware_status_default_request_without_job_is_queued() {
        let mut rack = test_rack_with_job(None);
        rack.config.maintenance_requested = Some(model::rack::MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: None,
                components: vec![],
            }],
            ..Default::default()
        });

        let status = rack_firmware_status(&rack);

        assert_eq!(status.state, rpc::FirmwareUpdateState::FwStateQueued as i32);
        assert!(status.target_version.is_empty());
        assert!(status.updated_at.is_some());
    }

    #[test]
    fn fw_state_round_trip_all_variants() {
        let cases = [
            (
                FirmwareState::Unknown,
                rpc::FirmwareUpdateState::FwStateUnknown as i32,
            ),
            (
                FirmwareState::Queued,
                rpc::FirmwareUpdateState::FwStateQueued as i32,
            ),
            (
                FirmwareState::InProgress,
                rpc::FirmwareUpdateState::FwStateInProgress as i32,
            ),
            (
                FirmwareState::Verifying,
                rpc::FirmwareUpdateState::FwStateVerifying as i32,
            ),
            (
                FirmwareState::Completed,
                rpc::FirmwareUpdateState::FwStateCompleted as i32,
            ),
            (
                FirmwareState::Failed,
                rpc::FirmwareUpdateState::FwStateFailed as i32,
            ),
            (
                FirmwareState::Cancelled,
                rpc::FirmwareUpdateState::FwStateCancelled as i32,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(map_fw_state(input), expected, "mismatch for {input:?}");
        }
    }

    #[test]
    fn make_result_fields() {
        let r = make_result(
            "sw-1",
            rpc::ComponentManagerStatusCode::Success,
            Some("info".into()),
        );
        assert_eq!(r.component_id, "sw-1");
        assert_eq!(r.status, rpc::ComponentManagerStatusCode::Success as i32);
        assert_eq!(r.error, "info");
    }

    #[test]
    fn success_result_has_no_error() {
        let r = success_result("sw-2");
        assert_eq!(r.status, rpc::ComponentManagerStatusCode::Success as i32);
        assert!(r.error.is_empty());
    }

    #[test]
    fn not_found_result_has_error_message() {
        let r = not_found_result("sw-3");
        assert_eq!(r.status, rpc::ComponentManagerStatusCode::NotFound as i32);
        assert!(r.error.contains("sw-3"));
    }

    #[test]
    fn error_result_has_internal_error_status() {
        let r = error_result("sw-4", "boom".into());
        assert_eq!(
            r.status,
            rpc::ComponentManagerStatusCode::InternalError as i32,
        );
        assert_eq!(r.error, "boom");
    }

    fn test_switch_id() -> SwitchId {
        use carbide_uuid::switch::{SwitchIdSource, SwitchType};
        SwitchId::new(SwitchIdSource::Tpm, [0u8; 32], SwitchType::NvLink)
    }

    fn test_power_shelf_id() -> PowerShelfId {
        use carbide_uuid::power_shelf::{PowerShelfIdSource, PowerShelfType};
        PowerShelfId::new(PowerShelfIdSource::Tpm, [0u8; 32], PowerShelfType::Rack)
    }

    #[test]
    fn switch_mac_to_id_str_found() {
        let mac: MacAddress = "AA:BB:CC:DD:EE:01".parse().unwrap();
        let id = test_switch_id();
        let map = HashMap::from([(mac, id)]);
        assert_eq!(switch_mac_to_id_str(&mac, &map), id.to_string());
    }

    #[test]
    fn switch_mac_to_id_str_not_found_falls_back_to_mac() {
        let mac: MacAddress = "AA:BB:CC:DD:EE:01".parse().unwrap();
        let map = HashMap::new();
        assert_eq!(switch_mac_to_id_str(&mac, &map), mac.to_string());
    }

    #[test]
    fn ps_mac_to_id_str_found() {
        let mac: MacAddress = "AA:BB:CC:DD:EE:02".parse().unwrap();
        let id = test_power_shelf_id();
        let map = HashMap::from([(mac, id)]);
        assert_eq!(ps_mac_to_id_str(&mac, &map), id.to_string());
    }

    #[test]
    fn ps_mac_to_id_str_not_found_falls_back_to_mac() {
        let mac: MacAddress = "AA:BB:CC:DD:EE:02".parse().unwrap();
        let map = HashMap::new();
        assert_eq!(ps_mac_to_id_str(&mac, &map), mac.to_string());
    }

    #[test]
    fn unresolved_switch_produces_error_result() {
        let id = test_switch_id();
        let r = error_result(
            &id.to_string(),
            "could not resolve endpoint for switch".into(),
        );
        assert_eq!(r.component_id, id.to_string());
        assert_eq!(
            r.status,
            rpc::ComponentManagerStatusCode::InternalError as i32,
        );
        assert!(r.error.contains("could not resolve endpoint"));
    }

    #[test]
    fn unresolved_power_shelf_produces_error_result() {
        let id = test_power_shelf_id();
        let r = error_result(
            &id.to_string(),
            "could not resolve endpoint for power shelf".into(),
        );
        assert_eq!(r.component_id, id.to_string());
        assert_eq!(
            r.status,
            rpc::ComponentManagerStatusCode::InternalError as i32,
        );
        assert!(r.error.contains("could not resolve endpoint"));
    }

    #[test]
    fn desired_power_state_on_variants() {
        use super::desired_power_state;
        assert_eq!(
            desired_power_state(PowerAction::On),
            self::rpc::PowerState::On
        );
        assert_eq!(
            desired_power_state(PowerAction::ForceRestart),
            self::rpc::PowerState::On
        );
        assert_eq!(
            desired_power_state(PowerAction::GracefulRestart),
            self::rpc::PowerState::On
        );
        assert_eq!(
            desired_power_state(PowerAction::AcPowercycle),
            self::rpc::PowerState::On
        );
    }

    #[test]
    fn desired_power_state_off_variants() {
        use super::desired_power_state;
        assert_eq!(
            desired_power_state(PowerAction::GracefulShutdown),
            self::rpc::PowerState::Off
        );
        assert_eq!(
            desired_power_state(PowerAction::ForceOff),
            self::rpc::PowerState::Off
        );
    }

    #[test]
    fn redfish_power_action_mapping() {
        use self::rpc::admin_power_control_request::SystemPowerControl;
        use super::redfish_power_action;

        assert_eq!(
            redfish_power_action(PowerAction::On),
            SystemPowerControl::On
        );
        assert_eq!(
            redfish_power_action(PowerAction::ForceRestart),
            SystemPowerControl::ForceRestart
        );
        assert_eq!(
            redfish_power_action(PowerAction::GracefulRestart),
            SystemPowerControl::GracefulRestart
        );
        assert_eq!(
            redfish_power_action(PowerAction::AcPowercycle),
            SystemPowerControl::AcPowercycle
        );
        assert_eq!(
            redfish_power_action(PowerAction::GracefulShutdown),
            SystemPowerControl::GracefulShutdown
        );
        assert_eq!(
            redfish_power_action(PowerAction::ForceOff),
            SystemPowerControl::ForceOff
        );
    }
}
