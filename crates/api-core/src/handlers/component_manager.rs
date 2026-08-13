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
use ::rpc::forge::{self as rpc};
use carbide_rack::firmware_object::rms_access_token_or_noauth;
use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, Credentials,
};
use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::machine::MachineId;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use component_manager::component_manager::{ComponentManager, SwitchMaintenanceRequestResult};
use component_manager::compute_tray_manager::{
    ComputeTrayEndpoint, ComputeTrayManager, ComputeTrayVendor,
};
use component_manager::core_compute_manager::CoreComputeTrayManager;
use component_manager::error::ComponentManagerError;
use component_manager::nv_switch_manager::SwitchEndpoint;
use component_manager::power_shelf_manager::{PowerShelfEndpoint, PowerShelfVendor};
use component_manager::types::FirmwareUpdateOptions;
use db::{self, WithTransaction};
use futures_util::FutureExt;
use mac_address::MacAddress;
use model::component_manager::{
    ComputeTrayComponent as ModelComputeTrayComponent, NvSwitchComponent, PowerAction,
    PowerShelfComponent,
};
use model::firmware::FirmwareComponentType;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{Machine, MachineMaintenanceOperation};
use model::power_shelf::PowerShelfMaintenanceOperation;
use model::rack::{FirmwareUpgradeJob, MaintenanceActivity};
use model::switch::SwitchMaintenanceOperation;
use tonic::{Code, Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data, log_request_data_redacted};
use crate::handlers::firmware::load_desired_firmware_version_entries;

const MACHINE_POWER_OVERRIDE_SOURCE: &str = "component_power_control";
const MACHINE_POWER_OVERRIDE_MESSAGE: &str = "Compute-Tray component power control in progress";

fn require_component_manager(api: &Api) -> Result<&ComponentManager, Status> {
    api.component_manager
        .as_ref()
        .ok_or_else(|| Status::unimplemented("component manager is not configured"))
}

fn unsupported_from_json_firmware_versions(target: &str) -> Status {
    Status::unimplemented(format!(
        "listing {target} firmware versions is not supported for RMS firmware-object JSON updates; provide SOT JSON to UpdateComponentFirmware"
    ))
}

pub(super) fn component_manager_error_to_status(err: ComponentManagerError) -> Status {
    match err {
        ComponentManagerError::Unavailable(msg) => Status::unavailable(msg),
        ComponentManagerError::NotFound(msg) => Status::not_found(msg),
        ComponentManagerError::InvalidArgument(msg) => Status::invalid_argument(msg),
        ComponentManagerError::Unsupported(msg) => Status::unimplemented(msg),
        ComponentManagerError::RejectedBeforeDispatch(msg) => Status::failed_precondition(msg),
        ComponentManagerError::OperationOutcomeUnknown(msg) => Status::unavailable(msg),
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

fn safe_firmware_target_display(firmware_version: &str) -> String {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(firmware_version) else {
        return firmware_version.to_string();
    };

    json.get("Id")
        .or_else(|| json.get("object_id"))
        .and_then(serde_json::Value::as_str)
        .map_or_else(
            || "firmware_object_json".to_string(),
            |object_id| format!("firmware_object_json:{object_id}"),
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
            } if !firmware_version.is_empty() => {
                Some(safe_firmware_target_display(firmware_version))
            }
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

fn map_switch_maintenance_operation(action: PowerAction) -> SwitchMaintenanceOperation {
    match action {
        PowerAction::On => SwitchMaintenanceOperation::PowerOn,
        PowerAction::GracefulShutdown | PowerAction::ForceOff => {
            SwitchMaintenanceOperation::PowerOff
        }
        PowerAction::GracefulRestart | PowerAction::ForceRestart | PowerAction::AcPowercycle => {
            SwitchMaintenanceOperation::Reset
        }
    }
}

fn map_machine_maintenance_operation(action: PowerAction) -> MachineMaintenanceOperation {
    match action {
        PowerAction::On => MachineMaintenanceOperation::PowerOn,
        PowerAction::GracefulShutdown | PowerAction::ForceOff => {
            MachineMaintenanceOperation::PowerOff
        }
        PowerAction::GracefulRestart | PowerAction::ForceRestart | PowerAction::AcPowercycle => {
            MachineMaintenanceOperation::Reset
        }
    }
}

fn map_power_shelf_maintenance_operation(
    action: PowerAction,
) -> Result<PowerShelfMaintenanceOperation, &'static str> {
    match action {
        PowerAction::On => Ok(PowerShelfMaintenanceOperation::PowerOn),
        PowerAction::GracefulShutdown | PowerAction::ForceOff => {
            Ok(PowerShelfMaintenanceOperation::PowerOff)
        }
        PowerAction::GracefulRestart | PowerAction::ForceRestart | PowerAction::AcPowercycle => {
            Err("power shelf state controller supports PowerOn and PowerOff only")
        }
    }
}

async fn queue_switch_power_control_via_state_controller(
    api: &Api,
    cm: &ComponentManager,
    switch_ids: &[SwitchId],
    action: PowerAction,
) -> Result<Vec<rpc::ComponentResult>, Status> {
    let operation = map_switch_maintenance_operation(action);
    queue_switch_maintenance_via_state_controller(api, cm, switch_ids, operation).await
}

async fn queue_switch_maintenance_via_state_controller(
    api: &Api,
    cm: &ComponentManager,
    switch_ids: &[SwitchId],
    operation: SwitchMaintenanceOperation,
) -> Result<Vec<rpc::ComponentResult>, Status> {
    let results = cm
        .request_switch_maintenance_via_state_controller(
            &api.database_connection,
            switch_ids,
            operation,
            "component-manager",
        )
        .await
        .map_err(component_manager_error_to_status)?;

    Ok(results
        .iter()
        .map(switch_maintenance_request_result_to_component_result)
        .collect())
}

fn switch_maintenance_request_result_to_component_result(
    result: &SwitchMaintenanceRequestResult,
) -> rpc::ComponentResult {
    match &result.error {
        Some(error) => error_result(&result.switch_id.to_string(), error.clone()),
        None => success_result(&result.switch_id.to_string()),
    }
}

async fn queue_machine_power_control_via_state_controller(
    api: &Api,
    cm: &ComponentManager,
    machine_ids: &[carbide_uuid::machine::MachineId],
    action: PowerAction,
) -> Result<Vec<rpc::ComponentResult>, Status> {
    let operation = map_machine_maintenance_operation(action);
    queue_machine_maintenance_via_state_controller(api, cm, machine_ids, operation).await
}

async fn queue_machine_maintenance_via_state_controller(
    api: &Api,
    cm: &ComponentManager,
    machine_ids: &[carbide_uuid::machine::MachineId],
    operation: MachineMaintenanceOperation,
) -> Result<Vec<rpc::ComponentResult>, Status> {
    let results = cm
        .request_machine_maintenance_via_state_controller(
            &api.database_connection,
            machine_ids,
            operation,
            "component-manager",
        )
        .await
        .map_err(component_manager_error_to_status)?;

    Ok(results
        .iter()
        .map(machine_maintenance_request_result_to_component_result)
        .collect())
}

fn machine_maintenance_request_result_to_component_result(
    result: &component_manager::component_manager::MachineMaintenanceRequestResult,
) -> rpc::ComponentResult {
    match &result.error {
        Some(error) => error_result(&result.machine_id.to_string(), error.clone()),
        None => success_result(&result.machine_id.to_string()),
    }
}

async fn queue_power_shelf_power_control_via_state_controller(
    api: &Api,
    power_shelf_ids: &[PowerShelfId],
    action: PowerAction,
) -> Result<Vec<rpc::ComponentResult>, Status> {
    let operation = match map_power_shelf_maintenance_operation(action) {
        Ok(operation) => operation,
        Err(reason) => {
            return Ok(power_shelf_ids
                .iter()
                .map(|id| error_result(&id.to_string(), reason.to_string()))
                .collect());
        }
    };
    queue_power_shelf_maintenance_via_state_controller(api, power_shelf_ids, operation).await
}

async fn queue_power_shelf_maintenance_via_state_controller(
    api: &Api,
    power_shelf_ids: &[PowerShelfId],
    operation: PowerShelfMaintenanceOperation,
) -> Result<Vec<rpc::ComponentResult>, Status> {
    let mut txn = api.txn_begin().await?;
    let existing = db::power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::List(db::power_shelf::IdColumn, power_shelf_ids),
    )
    .await
    .map_err(CarbideError::from)?;

    let by_id: HashMap<PowerShelfId, model::power_shelf::PowerShelf> =
        existing.into_iter().map(|ps| (ps.id, ps)).collect();
    let mut results = Vec::with_capacity(power_shelf_ids.len());

    for power_shelf_id in power_shelf_ids {
        let Some(power_shelf) = by_id.get(power_shelf_id) else {
            results.push(not_found_result(&power_shelf_id.to_string()));
            continue;
        };

        if power_shelf.is_marked_as_deleted() {
            results.push(error_result(
                &power_shelf_id.to_string(),
                format!("power shelf {power_shelf_id} is marked for deletion"),
            ));
            continue;
        }

        db::power_shelf::set_power_shelf_maintenance_requested(
            &mut txn,
            *power_shelf_id,
            "component-manager",
            operation,
        )
        .await
        .map_err(CarbideError::from)?;

        results.push(success_result(&power_shelf_id.to_string()));
    }

    txn.commit().await?;
    Ok(results)
}

/// Maps raw proto `ComputeTrayComponent` values to display-name strings.
///
/// Keep in sync with `format_compute_tray_component` in
/// `admin-cli/src/component_manager/versions/cmd.rs`.
fn map_compute_tray_component_names(raw: &[i32]) -> Result<Vec<String>, Status> {
    raw.iter()
        .map(|&v| match rpc::ComputeTrayComponent::try_from(v) {
            Ok(rpc::ComputeTrayComponent::Bmc) => Ok("BMC".to_string()),
            Ok(rpc::ComputeTrayComponent::Bios) => Ok("BIOS".to_string()),
            Ok(rpc::ComputeTrayComponent::Cec) => Ok("CEC".to_string()),
            Ok(rpc::ComputeTrayComponent::Nic) => Ok("NIC".to_string()),
            Ok(rpc::ComputeTrayComponent::CpldMb) => Ok("CPLD_MB".to_string()),
            Ok(rpc::ComputeTrayComponent::CpldPdb) => Ok("CPLD_PDB".to_string()),
            Ok(rpc::ComputeTrayComponent::HgxBmc) => Ok("HGX_BMC".to_string()),
            Ok(rpc::ComputeTrayComponent::CombinedBmcUefi) => Ok("COMBINED_BMC_UEFI".to_string()),
            Ok(rpc::ComputeTrayComponent::Gpu) => Ok("GPU".to_string()),
            Ok(rpc::ComputeTrayComponent::Cx7) => Ok("CX7".to_string()),
            Ok(rpc::ComputeTrayComponent::Unknown) => Err(Status::invalid_argument(
                "compute tray component must not be unknown",
            )),
            Err(e) => Err(Status::invalid_argument(format!(
                "unrecognized compute tray component value {v}: {e}"
            ))),
        })
        .collect()
}

fn split_nv_switch_firmware_and_nvos_components(
    components: &[NvSwitchComponent],
) -> (Vec<String>, bool) {
    let mut firmware_components = Vec::new();
    let mut include_nvos = components.is_empty();

    for component in components {
        if *component == NvSwitchComponent::Nvos {
            include_nvos = true;
        } else {
            firmware_components.push(component.to_string());
        }
    }

    (firmware_components, include_nvos)
}

fn map_nv_switch_components(raw: &[i32]) -> Result<Vec<NvSwitchComponent>, Status> {
    raw.iter()
        .filter(|&&v| v != rpc::NvSwitchComponent::Unknown as i32)
        .map(|&v| match rpc::NvSwitchComponent::try_from(v) {
            Ok(rpc::NvSwitchComponent::Bmc) => Ok(NvSwitchComponent::Bmc),
            Ok(rpc::NvSwitchComponent::Cpld) => Ok(NvSwitchComponent::Cpld),
            Ok(rpc::NvSwitchComponent::Bios) => Ok(NvSwitchComponent::Bios),
            Ok(rpc::NvSwitchComponent::Nvos) => Ok(NvSwitchComponent::Nvos),
            _ => Err(Status::invalid_argument(format!(
                "unknown NV-switch component: {v}"
            ))),
        })
        .collect()
}

fn map_compute_tray_components(raw: &[i32]) -> Result<Vec<ModelComputeTrayComponent>, Status> {
    raw.iter()
        .map(|&v| match rpc::ComputeTrayComponent::try_from(v) {
            Ok(rpc::ComputeTrayComponent::Bmc) => Ok(ModelComputeTrayComponent::Bmc),
            Ok(rpc::ComputeTrayComponent::Bios) => Ok(ModelComputeTrayComponent::Bios),
            Ok(rpc::ComputeTrayComponent::CpldMb) => Ok(ModelComputeTrayComponent::Cpld),
            Ok(rpc::ComputeTrayComponent::Cx7) => Ok(ModelComputeTrayComponent::Cx7),
            Ok(rpc::ComputeTrayComponent::Unknown) => Err(Status::invalid_argument(
                "compute tray component must not be unknown",
            )),
            Ok(other) => Err(Status::invalid_argument(format!(
                "compute tray component {other:?} is not supported for direct dispatch"
            ))),
            Err(e) => Err(Status::invalid_argument(format!(
                "unrecognized compute tray component value {v}: {e}"
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

fn normalize_access_token(access_token: Option<String>) -> Option<String> {
    access_token.filter(|token| !token.trim().is_empty())
}

fn validate_firmware_object_json_request(target_version: &str) -> Result<(), Status> {
    if target_version.trim().is_empty() {
        return Err(Status::invalid_argument(
            "target_version must contain SOT JSON for firmware updates",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(target_version).map_err(|e| {
        Status::invalid_argument(format!(
            "target_version must contain valid SOT JSON for firmware updates: {e}"
        ))
    })?;
    if !value.is_object() {
        return Err(Status::invalid_argument(
            "target_version must contain a SOT JSON object for firmware updates",
        ));
    }
    Ok(())
}

fn reject_power_shelf_firmware_object_json(access_token: &Option<String>) -> Result<(), Status> {
    if access_token.is_some() {
        Err(Status::unimplemented(
            "firmware object JSON updates for power shelves are not implemented",
        ))
    } else {
        Ok(())
    }
}

fn require_firmware_object_json_for_rack_maintenance(
    _target: &str,
    access_token: &Option<String>,
    target_version: &str,
) -> Result<String, Status> {
    validate_firmware_object_json_request(target_version)?;
    Ok(rms_access_token_or_noauth(access_token.as_deref()))
}

fn require_firmware_object_json_for_direct_rms(
    _target: &str,
    access_token: &Option<String>,
    target_version: &str,
    force_update: bool,
) -> Result<FirmwareUpdateOptions, Status> {
    validate_firmware_object_json_request(target_version)?;
    Ok(FirmwareUpdateOptions {
        access_token: Some(rms_access_token_or_noauth(access_token.as_deref())),
        force_update,
    })
}

fn reject_firmware_object_json_for_direct_dispatch(
    target: &str,
    access_token: &Option<String>,
) -> Result<(), Status> {
    if access_token.is_some() {
        Err(Status::invalid_argument(format!(
            "access_token is only supported for {target} firmware updates routed through rack maintenance"
        )))
    } else {
        Ok(())
    }
}

struct RackFirmwareMaintenanceTarget {
    rack_id: RackId,
    machine_ids: Vec<String>,
    switch_ids: Vec<String>,
    power_shelf_ids: Vec<String>,
}

fn push_rack_firmware_target(
    targets: &mut Vec<RackFirmwareMaintenanceTarget>,
    rack_id: RackId,
    machine_id: Option<String>,
    switch_id: Option<String>,
    power_shelf_id: Option<String>,
) {
    let target = match targets.iter_mut().find(|target| target.rack_id == rack_id) {
        Some(target) => target,
        None => {
            targets.push(RackFirmwareMaintenanceTarget {
                rack_id,
                machine_ids: Vec::new(),
                switch_ids: Vec::new(),
                power_shelf_ids: Vec::new(),
            });
            targets.last_mut().expect("target was just pushed")
        }
    };

    if let Some(machine_id) = machine_id {
        target.machine_ids.push(machine_id);
    }
    if let Some(switch_id) = switch_id {
        target.switch_ids.push(switch_id);
    }
    if let Some(power_shelf_id) = power_shelf_id {
        target.power_shelf_ids.push(power_shelf_id);
    }
}

async fn group_machine_ids_by_rack(
    api: &Api,
    machine_ids: &[MachineId],
) -> Result<Vec<RackFirmwareMaintenanceTarget>, Status> {
    let machines = db::machine::find(
        api.db_reader().as_mut(),
        db::ObjectFilter::List(machine_ids),
        MachineSearchConfig::default(),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to look up machines: {e}")))?;
    let machines_by_id: HashMap<_, _> = machines
        .into_iter()
        .map(|machine| (machine.id, machine))
        .collect();

    let mut targets = Vec::new();
    for machine_id in machine_ids {
        let machine = machines_by_id
            .get(machine_id)
            .ok_or_else(|| Status::not_found(format!("machine {machine_id} not found")))?;
        let rack_id = machine.rack_id.clone().ok_or_else(|| {
            Status::failed_precondition(format!(
                "machine {machine_id} is not associated with a rack"
            ))
        })?;
        push_rack_firmware_target(
            &mut targets,
            rack_id,
            Some(machine_id.to_string()),
            None,
            None,
        );
    }

    Ok(targets)
}

/// Returns whether the machine is a rack-scale MNNVL server (GB200, GB300, etc.).
fn is_rack_scale_server(machine: &Machine) -> bool {
    machine
        .status
        .hardware_info
        .as_ref()
        .is_some_and(|hw| hw.is_mnnvl_capable())
}

/// Splits already-loaded compute machines into rack-scale and standalone lists.
/// Rack-scale systems go through the rack-level state controller maintenance flow.
/// Standalone servers use the existing host reprovisioning firmware path.
///
/// Unknown ids are a hard error here (firmware path); power control collects
/// them as per-machine results instead via [`machine_is_rack_scale`].
fn partition_loaded_compute_machines_by_rack_scale(
    machines_by_id: &HashMap<MachineId, Machine>,
    machine_ids: &[MachineId],
) -> Result<(Vec<MachineId>, Vec<MachineId>), Status> {
    let mut rack_scale = Vec::new();
    let mut standalone = Vec::new();
    for &machine_id in machine_ids {
        if machine_is_rack_scale(machines_by_id, machine_id)? {
            rack_scale.push(machine_id);
        } else {
            standalone.push(machine_id);
        }
    }
    Ok((rack_scale, standalone))
}

/// Load the requested machines keyed by id. A DB lookup failure is a hard
/// error, since nothing can be classified without it; ids that don't exist are
/// simply absent from the returned map, left for the caller to handle.
async fn load_machines_by_id(
    api: &Api,
    machine_ids: &[MachineId],
) -> Result<HashMap<MachineId, Machine>, Status> {
    let machines = db::machine::find(
        api.db_reader().as_mut(),
        db::ObjectFilter::List(machine_ids),
        MachineSearchConfig::default(),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to look up machines: {e}")))?;
    Ok(machines
        .into_iter()
        .map(|machine| (machine.id, machine))
        .collect())
}

/// Classify a single already-loaded machine as rack-scale (`true`) or
/// standalone (`false`), returning `Err(Status::not_found)` if the id is not in
/// the map. Callers decide whether an unknown id aborts the batch or is
/// collected as a per-machine error.
fn machine_is_rack_scale(
    machines_by_id: &HashMap<MachineId, Machine>,
    machine_id: MachineId,
) -> Result<bool, Status> {
    let machine = machines_by_id
        .get(&machine_id)
        .ok_or_else(|| Status::not_found(format!("machine {machine_id} not found")))?;
    Ok(is_rack_scale_server(machine))
}

/// Initiate a firmware upgrade for standalone (non rack-scale) servers
async fn schedule_host_reprovisioning_firmware_update(
    api: &Api,
    machine_ids: &[MachineId],
) -> Vec<rpc::ComponentResult> {
    let mut results = Vec::with_capacity(machine_ids.len());
    for machine_id in machine_ids {
        match schedule_one_host_reprovisioning_firmware_update(api, machine_id).await {
            Ok(()) => results.push(success_result(&machine_id.to_string())),
            Err(error) => results.push(error_result(&machine_id.to_string(), error)),
        }
    }
    results
}

async fn schedule_one_host_reprovisioning_firmware_update(
    api: &Api,
    machine_id: &MachineId,
) -> Result<(), String> {
    let mut txn = api
        .txn_begin()
        .await
        .map_err(|e| format!("failed to begin transaction: {e}"))?;

    db::machine::set_firmware_autoupdate(&mut txn, machine_id, Some(true))
        .await
        .map_err(|e| format!("failed to enable firmware auto-update: {e}"))?;

    let start = chrono::Utc::now();
    let end = start + chrono::Duration::hours(24);
    db::machine::update_firmware_update_time_window_start_end(
        std::slice::from_ref(machine_id),
        start,
        end,
        &mut txn,
    )
    .await
    .map_err(|e| format!("failed to set firmware update time window: {e}"))?;

    txn.commit()
        .await
        .map_err(|e| format!("failed to commit transaction: {e}"))?;

    Ok(())
}

async fn group_switch_ids_by_rack(
    api: &Api,
    switch_ids: &[SwitchId],
) -> Result<Vec<RackFirmwareMaintenanceTarget>, Status> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("failed to begin transaction: {e}")))?;
    let switches = db::switch::find_by(
        &mut txn,
        db::ObjectColumnFilter::List(db::switch::IdColumn, switch_ids),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to look up switches: {e}")))?;
    drop(txn);

    let switches_by_id: HashMap<_, _> = switches
        .into_iter()
        .map(|switch| (switch.id, switch))
        .collect();

    let mut targets = Vec::new();
    for switch_id in switch_ids {
        let switch = switches_by_id
            .get(switch_id)
            .ok_or_else(|| Status::not_found(format!("switch {switch_id} not found")))?;
        let rack_id = switch.rack_id.clone().ok_or_else(|| {
            Status::failed_precondition(format!("switch {switch_id} is not associated with a rack"))
        })?;
        push_rack_firmware_target(
            &mut targets,
            rack_id,
            None,
            Some(switch_id.to_string()),
            None,
        );
    }

    Ok(targets)
}

async fn group_power_shelf_ids_by_rack(
    api: &Api,
    power_shelf_ids: &[PowerShelfId],
) -> Result<Vec<RackFirmwareMaintenanceTarget>, Status> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("failed to begin transaction: {e}")))?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::List(db::power_shelf::IdColumn, power_shelf_ids),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to look up power shelves: {e}")))?;
    drop(txn);

    let power_shelves_by_id: HashMap<_, _> = power_shelves
        .into_iter()
        .map(|power_shelf| (power_shelf.id, power_shelf))
        .collect();

    let mut targets = Vec::new();
    for power_shelf_id in power_shelf_ids {
        let power_shelf = power_shelves_by_id
            .get(power_shelf_id)
            .ok_or_else(|| Status::not_found(format!("power shelf {power_shelf_id} not found")))?;
        let rack_id = power_shelf.rack_id.clone().ok_or_else(|| {
            Status::failed_precondition(format!(
                "power shelf {power_shelf_id} is not associated with a rack"
            ))
        })?;
        push_rack_firmware_target(
            &mut targets,
            rack_id,
            None,
            None,
            Some(power_shelf_id.to_string()),
        );
    }

    Ok(targets)
}

async fn submit_rack_firmware_maintenance_requests(
    api: &Api,
    targets: Vec<RackFirmwareMaintenanceTarget>,
    activities: Vec<rpc::MaintenanceActivityConfig>,
) -> Result<Vec<rpc::ComponentResult>, Status> {
    if targets.is_empty() {
        return Err(Status::invalid_argument(
            "no devices specified for firmware upgrade",
        ));
    }
    if activities.is_empty() {
        return Err(Status::invalid_argument(
            "no rack maintenance activities were selected for firmware upgrade",
        ));
    }

    let mut results = Vec::new();
    for target in targets {
        let affected_ids: Vec<_> = target
            .machine_ids
            .iter()
            .chain(target.switch_ids.iter())
            .chain(target.power_shelf_ids.iter())
            .cloned()
            .collect();
        let maintenance_req = Request::new(rpc::RackMaintenanceOnDemandRequest {
            rack_id: Some(target.rack_id),
            scope: Some(rpc::RackMaintenanceScope {
                machine_ids: target.machine_ids,
                switch_ids: target.switch_ids,
                power_shelf_ids: target.power_shelf_ids,
                activities: activities.clone(),
            }),
        });

        match crate::handlers::rack::on_demand_rack_maintenance(api, maintenance_req).await {
            Ok(_) => results.extend(affected_ids.iter().map(|id| success_result(id))),
            Err(status) => results.extend(
                affected_ids
                    .iter()
                    .map(|id| status_result(id, status.clone())),
            ),
        }
    }

    Ok(results)
}

fn firmware_upgrade_activity(
    firmware_version: String,
    components: Vec<String>,
    access_token: Option<String>,
    force_update: bool,
) -> rpc::MaintenanceActivityConfig {
    rpc::MaintenanceActivityConfig {
        activity: Some(rpc::maintenance_activity_config::Activity::FirmwareUpgrade(
            rpc::FirmwareUpgradeActivity {
                firmware_version,
                components,
                access_token,
                force_update,
            },
        )),
    }
}

fn nvos_update_activity(
    config_json: String,
    access_token: Option<String>,
) -> rpc::MaintenanceActivityConfig {
    rpc::MaintenanceActivityConfig {
        activity: Some(rpc::maintenance_activity_config::Activity::NvosUpdate(
            rpc::NvosUpdateActivity {
                config_json,
                access_token,
            },
        )),
    }
}

fn switch_firmware_maintenance_activities(
    config_json: &str,
    access_token: &str,
    components: &[NvSwitchComponent],
    force_update: bool,
) -> Vec<rpc::MaintenanceActivityConfig> {
    let (firmware_components, include_nvos) =
        split_nv_switch_firmware_and_nvos_components(components);
    let mut activities = Vec::new();

    if components.is_empty() || !firmware_components.is_empty() {
        activities.push(firmware_upgrade_activity(
            config_json.to_string(),
            firmware_components,
            Some(access_token.to_string()),
            force_update,
        ));
    }

    if include_nvos {
        activities.push(nvos_update_activity(
            config_json.to_string(),
            Some(access_token.to_string()),
        ));
    }

    activities
}

// ---- Endpoint resolution helpers ----

struct UnresolvedDevice<Id> {
    id: Id,
    reason: String,
}

impl<Id: std::fmt::Display> std::fmt::Display for UnresolvedDevice<Id> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.id, self.reason)
    }
}

struct ResolvedSwitchEndpoints {
    endpoints: Vec<SwitchEndpoint>,
    mac_to_id: HashMap<MacAddress, SwitchId>,
}

struct SwitchEndpoints {
    resolved: ResolvedSwitchEndpoints,
    unresolved: Vec<UnresolvedDevice<SwitchId>>,
}

async fn fetch_credentials(
    credential_manager: &dyn CredentialManager,
    key: CredentialKey,
) -> Result<Credentials, ComponentManagerError> {
    match credential_manager.get_credentials(&key).await {
        Ok(Some(c)) => Ok(c),
        Ok(None) => Err(ComponentManagerError::NotFound(format!(
            "no credentials found for {key:?}"
        ))),
        Err(e) => Err(ComponentManagerError::Internal(format!(
            "failed to fetch credentials for {key:?}: {e}"
        ))),
    }
}

async fn fetch_switch_bmc_credentials(
    credential_manager: &dyn CredentialManager,
    bmc_mac: MacAddress,
) -> Result<Credentials, ComponentManagerError> {
    let key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: bmc_mac,
        },
    };
    fetch_credentials(credential_manager, key).await
}

async fn fetch_compute_tray_bmc_credentials(
    credential_manager: &dyn CredentialManager,
    bmc_mac: MacAddress,
) -> Result<Credentials, ComponentManagerError> {
    let key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: bmc_mac,
        },
    };
    fetch_credentials(credential_manager, key).await
}

async fn fetch_switch_nvos_credentials(
    credential_manager: &dyn CredentialManager,
    bmc_mac: MacAddress,
) -> Result<Credentials, ComponentManagerError> {
    let key = CredentialKey::SwitchNvosAdmin {
        bmc_mac_address: bmc_mac,
    };
    fetch_credentials(credential_manager, key).await
}

async fn fetch_powershelf_pmc_credentials(
    credential_manager: &dyn CredentialManager,
    pmc_mac: MacAddress,
) -> Result<Credentials, ComponentManagerError> {
    let key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: pmc_mac,
        },
    };
    fetch_credentials(credential_manager, key).await
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
            let u = UnresolvedDevice {
                id: row.switch_id,
                reason: "NVOS MAC or IP not available".into(),
            };
            tracing::warn!(switch_id = %u.id, reason = %u.reason, "skipping switch");
            unresolved.push(u);
            resolved_ids.insert(row.switch_id);
            continue;
        };
        resolved_ids.insert(row.switch_id);

        let bmc_credentials = match fetch_switch_bmc_credentials(
            api.credential_manager.as_ref(),
            row.bmc_mac,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                let u = UnresolvedDevice {
                    id: row.switch_id,
                    reason: format!("BMC credentials unavailable: {e}"),
                };
                tracing::warn!(switch_id = %u.id, reason = %u.reason, "skipping switch");
                unresolved.push(u);
                continue;
            }
        };

        let nvos_credentials =
            match fetch_switch_nvos_credentials(api.credential_manager.as_ref(), row.bmc_mac).await
            {
                Ok(c) => c,
                Err(e) => {
                    let u = UnresolvedDevice {
                        id: row.switch_id,
                        reason: format!("NVOS credentials unavailable: {e}"),
                    };
                    tracing::warn!(switch_id = %u.id, reason = %u.reason, "skipping switch");
                    unresolved.push(u);
                    continue;
                }
            };

        mac_to_id.insert(row.bmc_mac, row.switch_id);
        endpoints.push(SwitchEndpoint {
            bmc_ip: row.bmc_ip,
            bmc_mac: row.bmc_mac,
            nvos_ip,
            nvos_mac,
            bmc_credentials,
            nvos_credentials,
            nvos_host_name: row.nvos_hostname.none_if_empty(),
        });
    }

    for id in switch_ids {
        if !resolved_ids.contains(id) {
            let u = UnresolvedDevice {
                id: *id,
                reason: "switch not found in database".into(),
            };
            tracing::warn!(switch_id = %u.id, reason = %u.reason, "skipping switch");
            unresolved.push(u);
        }
    }

    if !unresolved.is_empty() {
        tracing::warn!(
            unresolved_switch_count = unresolved.len(),
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
    unresolved: Vec<UnresolvedDevice<PowerShelfId>>,
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
    let mut unresolved = Vec::new();
    let mut resolved_ids = HashSet::with_capacity(rows.len());

    for row in rows {
        resolved_ids.insert(row.power_shelf_id);

        let pmc_credentials = match fetch_powershelf_pmc_credentials(
            api.credential_manager.as_ref(),
            row.pmc_mac,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                let u = UnresolvedDevice {
                    id: row.power_shelf_id,
                    reason: format!("PMC credentials unavailable: {e}"),
                };
                tracing::warn!(power_shelf_id = %u.id, reason = %u.reason, "skipping power shelf");
                unresolved.push(u);
                continue;
            }
        };

        mac_to_id.insert(row.pmc_mac, row.power_shelf_id);
        endpoints.push(PowerShelfEndpoint {
            pmc_ip: row.pmc_ip,
            pmc_mac: row.pmc_mac,
            // TODO: retrieve vendor from DB instead of using a hardcoded default
            pmc_vendor: PowerShelfVendor::DEFAULT,
            pmc_credentials,
        });
    }

    for id in power_shelf_ids {
        if !resolved_ids.contains(id) {
            let u = UnresolvedDevice {
                id: *id,
                reason: "power shelf not found in database".into(),
            };
            tracing::warn!(power_shelf_id = %u.id, reason = %u.reason, "skipping power shelf");
            unresolved.push(u);
        }
    }

    if !unresolved.is_empty() {
        tracing::warn!(
            unresolved_power_shelf_count = unresolved.len(),
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

struct ResolvedComputeTrayEndpoints {
    endpoints: Vec<ComputeTrayEndpoint>,
    ip_to_machine_id: HashMap<IpAddr, carbide_uuid::machine::MachineId>,
}

struct ComputeTrayEndpoints {
    resolved: ResolvedComputeTrayEndpoints,
    unresolved: Vec<UnresolvedDevice<carbide_uuid::machine::MachineId>>,
}

/// Resolve BMC endpoints from an already-loaded machine map.
///
/// Callers that previously loaded machines for classification (power / firmware
/// partition) reuse that map here so the machine table is not queried again.
async fn resolve_compute_tray_endpoints_from_machines(
    credential_manager: &dyn CredentialManager,
    machines_by_id: &HashMap<MachineId, Machine>,
    machine_ids: &[MachineId],
) -> ComputeTrayEndpoints {
    let mut endpoints = Vec::with_capacity(machine_ids.len());
    let mut ip_to_machine_id = HashMap::with_capacity(machine_ids.len());
    let mut unresolved = Vec::new();

    for &machine_id in machine_ids {
        let Some(machine) = machines_by_id.get(&machine_id) else {
            unresolved.push(UnresolvedDevice {
                id: machine_id,
                reason: "machine not found in database".into(),
            });
            continue;
        };

        let Some(bmc_mac) = machine.status.bmc_info.mac else {
            unresolved.push(UnresolvedDevice {
                id: machine_id,
                reason: "BMC MAC not available".into(),
            });
            continue;
        };

        let Some(bmc_ip) = machine.status.bmc_info.ip else {
            unresolved.push(UnresolvedDevice {
                id: machine_id,
                reason: "BMC IP not configured".into(),
            });
            continue;
        };

        let bmc_credentials =
            match fetch_compute_tray_bmc_credentials(credential_manager, bmc_mac).await {
                Ok(c) => c,
                Err(e) => {
                    unresolved.push(UnresolvedDevice {
                        id: machine_id,
                        reason: format!("BMC credentials unavailable: {e}"),
                    });
                    continue;
                }
            };

        let vendor = ComputeTrayVendor::from(machine.bmc_vendor());

        ip_to_machine_id.insert(bmc_ip, machine_id);
        endpoints.push(ComputeTrayEndpoint {
            vendor,
            bmc_ip,
            bmc_credentials,
        });
    }

    if !unresolved.is_empty() {
        tracing::warn!(
            unresolved_compute_tray_count = unresolved.len(),
            "some compute trays could not be resolved to endpoints"
        );
    }

    ComputeTrayEndpoints {
        resolved: ResolvedComputeTrayEndpoints {
            endpoints,
            ip_to_machine_id,
        },
        unresolved,
    }
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

/// Returns true when every key in `desired` exists in `actual` with the same
/// value (`desired` is treated as a subset of `actual`).
fn firmware_versions_match(
    desired: &HashMap<String, String>,
    actual: &HashMap<String, String>,
) -> bool {
    !desired.is_empty()
        && desired.iter().all(|(key, value)| {
            actual
                .get(key)
                .is_some_and(|actual_value| actual_value == value)
        })
}

fn matches_any_desired_firmware_entry(
    actual: &HashMap<String, String>,
    desired_entries: &[rpc::DesiredFirmwareVersionEntry],
) -> bool {
    desired_entries
        .iter()
        .any(|entry| firmware_versions_match(&entry.component_versions, actual))
}

fn exploration_report_firmware_versions(
    report: &model::site_explorer::EndpointExplorationReport,
) -> HashMap<String, String> {
    report
        .versions
        .iter()
        .filter(|(component, _)| **component != FirmwareComponentType::Unknown)
        .filter_map(|(component, version)| {
            let key = serde_json::to_value(component)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))?;
            Some((key, version.clone()))
        })
        .collect()
}

/// When explored firmware satisfies a desired entry, the update is complete
/// (or still verifying while the host reprovisions). Otherwise status is
/// inferred from `update_complete` and the machine's reprovision state.
fn derive_machine_firmware_update_status(
    machine_id: &str,
    machine: Option<&Machine>,
    actual_firmware: Option<&HashMap<String, String>>,
    desired_entries: &[rpc::DesiredFirmwareVersionEntry],
) -> rpc::FirmwareUpdateStatus {
    let Some(machine) = machine else {
        return rpc::FirmwareUpdateStatus {
            result: Some(error_result(
                machine_id,
                "machine not found in NICo".to_string(),
            )),
            state: rpc::FirmwareUpdateState::FwStateUnknown as i32,
            target_version: String::new(),
            updated_at: None,
        };
    };

    let state_str = machine.state.value.to_string();

    // On-host versions match site desired firmware: the flash succeeded.
    // Remain in Verifying until reprovision finishes.
    if let Some(actual) = actual_firmware
        && !desired_entries.is_empty()
        && matches_any_desired_firmware_entry(actual, desired_entries)
    {
        let state = if state_str.contains("HostReprovision") {
            rpc::FirmwareUpdateState::FwStateVerifying
        } else {
            rpc::FirmwareUpdateState::FwStateCompleted
        };
        return rpc::FirmwareUpdateStatus {
            result: Some(success_result(machine_id)),
            state: state as i32,
            target_version: String::new(),
            updated_at: None,
        };
    }

    // No version match (or no version data): use machine update/state signals.
    let state = if machine.status.update_complete {
        rpc::FirmwareUpdateState::FwStateCompleted
    } else if state_str.contains("HostReprovision") && state_str.contains("FailedFirmwareUpgrade") {
        rpc::FirmwareUpdateState::FwStateFailed
    } else if state_str.contains("HostReprovision") {
        rpc::FirmwareUpdateState::FwStateVerifying
    } else {
        rpc::FirmwareUpdateState::FwStateQueued
    };

    rpc::FirmwareUpdateStatus {
        result: Some(success_result(machine_id)),
        state: state as i32,
        target_version: String::new(),
        updated_at: None,
    }
}

async fn machine_firmware_statuses(
    api: &Api,
    machine_ids: &[MachineId],
) -> Result<Vec<rpc::FirmwareUpdateStatus>, Status> {
    let machines = db::machine::find(
        api.db_reader().as_mut(),
        db::ObjectFilter::List(machine_ids),
        MachineSearchConfig::default(),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to look up machines: {e}")))?;

    let machine_by_id: HashMap<MachineId, Machine> = machines
        .into_iter()
        .map(|machine| (machine.id, machine))
        .collect();

    let mut txn = api
        .txn_begin()
        .await
        .map_err(|e| Status::internal(format!("db error: {e}")))?;
    let bmc_pairs =
        db::machine_topology::find_machine_bmc_pairs_by_machine_id(&mut txn, machine_ids.to_vec())
            .await
            .map_err(|e| Status::internal(format!("db error: {e}")))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("db error: {e}")))?;

    let ip_to_machine_id: HashMap<IpAddr, MachineId> = bmc_pairs
        .into_iter()
        .filter_map(|(machine_id, ip_str)| {
            let ip: IpAddr = ip_str?.parse().ok()?;
            Some((ip, machine_id))
        })
        .collect();

    let ips: Vec<IpAddr> = ip_to_machine_id.keys().copied().collect();
    let endpoints = if ips.is_empty() {
        Vec::new()
    } else {
        db::explored_endpoints::find_by_ips(&mut api.db_reader(), ips)
            .await
            .map_err(|e| Status::internal(format!("db error: {e}")))?
    };

    let mut actual_firmware_by_machine: HashMap<MachineId, HashMap<String, String>> =
        HashMap::new();
    for endpoint in endpoints {
        let Some(machine_id) = ip_to_machine_id.get(&endpoint.address).copied() else {
            continue;
        };
        let versions = exploration_report_firmware_versions(&endpoint.report);
        if !versions.is_empty() {
            actual_firmware_by_machine.insert(machine_id, versions);
        }
    }

    let desired_entries = match load_desired_firmware_version_entries(api).await {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "failed to get desired firmware versions, falling back to state-based check"
            );
            Vec::new()
        }
    };

    Ok(machine_ids
        .iter()
        .map(|machine_id| {
            derive_machine_firmware_update_status(
                &machine_id.to_string(),
                machine_by_id.get(machine_id),
                actual_firmware_by_machine.get(machine_id),
                &desired_entries,
            )
        })
        .collect())
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
    let bypass_state_controller = req.bypass_state_controller;

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let (results, exploration_ips) = match target {
        rpc::component_power_control_request::Target::SwitchIds(list) => {
            if cm.nv_switch_use_state_controller && !bypass_state_controller {
                let results =
                    queue_switch_power_control_via_state_controller(api, cm, &list.ids, action)
                        .await?;
                (results, Vec::new())
            } else {
                let endpoints = resolve_switch_endpoints(api, &list.ids).await?;

                let mut results: Vec<_> = endpoints
                    .unresolved
                    .iter()
                    .map(|u| error_result(&u.id.to_string(), u.reason.clone()))
                    .collect();

                tracing::info!(
                    backend = cm.nv_switch.name(),
                    switch_count = endpoints.resolved.endpoints.len(),
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
        }
        rpc::component_power_control_request::Target::PowerShelfIds(list) => {
            if cm.power_shelf_use_state_controller && !bypass_state_controller {
                let results =
                    queue_power_shelf_power_control_via_state_controller(api, &list.ids, action)
                        .await?;
                (results, Vec::new())
            } else {
                let endpoints = resolve_power_shelf_endpoints(api, &list.ids).await?;

                let mut results: Vec<_> = endpoints
                    .unresolved
                    .iter()
                    .map(|u| error_result(&u.id.to_string(), u.reason.clone()))
                    .collect();

                tracing::info!(
                    backend = cm.power_shelf.name(),
                    power_shelf_count = endpoints.resolved.endpoints.len(),
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
        }
        rpc::component_power_control_request::Target::MachineIds(list) => {
            // Divide the requested machines the same way compute firmware
            // updates do: rack-scale (MNNVL) systems vs standalone servers. Only
            // rack-scale systems have a compute-tray backend (RMS) and a
            // state-controller maintenance flow; standalone servers are always
            // driven synchronously through NICo-core's Redfish stack, because
            // RMS cannot power-control them.
            //
            // Classify each machine and persist its power-manager desired state
            // in a single pass. A machine joins `rack_scale_ids`/`standalone_ids`
            // only after both steps succeed, so unknown ids and power-option
            // failures are reported per-machine and never dispatched (no
            // duplicate result, no actuation without a recorded intent).
            //
            // The state controller does not update the power manager today, so
            // the handler owns it regardless of which dispatch path (rack vs
            // standalone) a machine ultimately takes.
            //
            // The health override exists only to satisfy `update_power_option`'s
            // precondition for powering a host off (it requires an
            // `internal_maintenance` / `suppress_external_alerting` alert). The
            // Redfish dispatch does not need it, so it brackets just the
            // power-manager change. Durable alert suppression for an
            // intentionally-off host comes from `desired_power_state` itself.
            let machines_by_id = load_machines_by_id(api, &list.machine_ids).await?;
            let desired_state = desired_power_state(action) as i32;
            let mut results: Vec<rpc::ComponentResult> = Vec::new();
            let (mut rack_scale_ids, mut standalone_ids) = (Vec::new(), Vec::new());
            for &machine_id in &list.machine_ids {
                // Unknown ids are reported per-machine and never dispatched.
                let is_rack_scale = match machine_is_rack_scale(&machines_by_id, machine_id) {
                    Ok(v) => v,
                    Err(status) => {
                        // Preserve the tonic status code (NotFound for an unknown
                        // id) in the per-machine result instead of flattening it to
                        // InternalError.
                        results.push(status_result(&machine_id.to_string(), status));
                        continue;
                    }
                };

                let override_inserted = power_control_health_override(api, machine_id, true).await;

                let power_req = rpc::PowerOptionUpdateRequest {
                    machine_id: Some(machine_id),
                    power_state: desired_state,
                };
                let power_option_ok = match crate::handlers::power_options::update_power_option(
                    api,
                    Request::new(power_req),
                )
                .await
                {
                    Ok(_) => true,
                    Err(e)
                        if e.code() == Code::InvalidArgument
                            && e.message().contains("already set as") =>
                    {
                        tracing::debug!(
                            %machine_id,
                            desired_state,
                            "power option already in desired state, skipping"
                        );
                        true
                    }
                    Err(e) => {
                        results.push(error_result(
                            &machine_id.to_string(),
                            format!("failed to update power option: {e}"),
                        ));
                        false
                    }
                };

                if override_inserted {
                    power_control_health_override(api, machine_id, false).await;
                }

                // Only machines whose desired state was recorded proceed to
                // dispatch, so a power-option failure never actuates hardware
                // without a matching intent.
                if power_option_ok {
                    if is_rack_scale {
                        rack_scale_ids.push(machine_id);
                    } else {
                        standalone_ids.push(machine_id);
                    }
                }
            }

            let mut ips: Vec<IpAddr> = Vec::new();

            // Rack-scale systems: the state-controller maintenance flow when
            // enabled, otherwise a synchronous dispatch through the configured
            // backend (RMS).
            if !rack_scale_ids.is_empty() {
                if cm.compute_tray_use_state_controller && !bypass_state_controller {
                    match queue_machine_power_control_via_state_controller(
                        api,
                        cm,
                        &rack_scale_ids,
                        action,
                    )
                    .await
                    {
                        Ok(sc_results) => results.extend(sc_results),
                        Err(status) => {
                            results.extend(partition_error_results(&rack_scale_ids, &status))
                        }
                    }
                } else {
                    match dispatch_compute_tray_power_control(
                        api,
                        cm.compute_tray.as_ref(),
                        &machines_by_id,
                        &rack_scale_ids,
                        action,
                    )
                    .await
                    {
                        Ok((rack_results, rack_ips)) => {
                            results.extend(rack_results);
                            ips.extend(rack_ips);
                        }
                        Err(status) => {
                            results.extend(partition_error_results(&rack_scale_ids, &status))
                        }
                    }
                }
            }

            // Standalone servers: always synchronous, always NICo-core's Redfish
            // stack (never the state machine, which has no non-rack path), so
            // power control works even when the configured backend is RMS.
            if !standalone_ids.is_empty() {
                let core_backend = CoreComputeTrayManager::new(api.redfish_pool.clone());
                match dispatch_compute_tray_power_control(
                    api,
                    &core_backend,
                    &machines_by_id,
                    &standalone_ids,
                    action,
                )
                .await
                {
                    Ok((standalone_results, standalone_ips)) => {
                        results.extend(standalone_results);
                        ips.extend(standalone_ips);
                    }
                    Err(status) => {
                        results.extend(partition_error_results(&standalone_ids, &status))
                    }
                }
            }

            (results, ips)
        }
    };

    // request re-exploration for the BMC/PMC endpoints that had power control initiated against them
    // so that site explorer refreshes its data for the device. NICo Flow will query the power state
    // shortly after initiating power control via this path. NICo Flow queries the power state of a
    // device via the site exploration report data.
    request_re_exploration(api, &exploration_ips).await;

    Ok(Response::new(rpc::ComponentPowerControlResponse {
        results,
    }))
}

/// Fan a whole-partition dispatch failure out to one result per machine in that
/// partition, so a failure in one partition never discards results already
/// committed for the other partition or for the power-option updates. The tonic
/// status code is preserved per machine (e.g. `Unavailable` for a backend that
/// is down) rather than flattened to `InternalError`.
fn partition_error_results(
    machine_ids: &[MachineId],
    status: &Status,
) -> Vec<rpc::ComponentResult> {
    machine_ids
        .iter()
        .map(|id| status_result(&id.to_string(), status.clone()))
        .collect()
}

/// Resolve BMC endpoints for `machine_ids` from an already-loaded machine map,
/// issue power control through `backend`, and return per-machine results (keyed
/// by machine id via the resolved `ip_to_machine_id` map) alongside the BMC IPs
/// that were dispatched to, so the caller can request site re-exploration.
///
/// Shared by the rack-scale synchronous path (configured backend, e.g. RMS) and
/// the standalone path (always NICo-core's Redfish backend).
async fn dispatch_compute_tray_power_control(
    api: &Api,
    backend: &dyn ComputeTrayManager,
    machines_by_id: &HashMap<MachineId, Machine>,
    machine_ids: &[MachineId],
    action: PowerAction,
) -> Result<(Vec<rpc::ComponentResult>, Vec<IpAddr>), Status> {
    let resolved = resolve_compute_tray_endpoints_from_machines(
        api.credential_manager.as_ref(),
        machines_by_id,
        machine_ids,
    )
    .await;

    let mut results: Vec<rpc::ComponentResult> = resolved
        .unresolved
        .iter()
        .map(|u| error_result(&u.id.to_string(), u.reason.clone()))
        .collect();

    tracing::info!(
        backend = backend.name(),
        compute_tray_count = resolved.resolved.endpoints.len(),
        ?action,
        "power control for compute trays"
    );
    let backend_results = backend
        .power_control(&resolved.resolved.endpoints, action)
        .await
        .map_err(component_manager_error_to_status)?;

    let ips: Vec<IpAddr> = resolved
        .resolved
        .endpoints
        .iter()
        .map(|ep| ep.bmc_ip)
        .collect();

    results.extend(backend_results.into_iter().map(|r| {
        let id = resolved
            .resolved
            .ip_to_machine_id
            .get(&r.bmc_ip)
            .map(|id| id.to_string())
            .unwrap_or_else(|| r.bmc_ip.to_string());
        if r.success {
            success_result(&id)
        } else {
            error_result(&id, r.error.unwrap_or_default())
        }
    }));

    Ok((results, ips))
}

pub(crate) async fn component_configure_switch_certificate(
    api: &Api,
    request: Request<rpc::ComponentConfigureSwitchCertificateRequest>,
) -> Result<Response<rpc::ComponentConfigureSwitchCertificateResponse>, Status> {
    log_request_data(&request);
    let cm = require_component_manager(api)?;
    let req = request.into_inner();
    let bypass_state_controller = req.bypass_state_controller;
    let domain_name = req.domain_name.as_deref();
    let switch_ids = req
        .switch_ids
        .ok_or_else(|| Status::invalid_argument("switch_ids is required"))?;

    if cm.nv_switch_use_state_controller && !bypass_state_controller {
        let results = queue_switch_maintenance_via_state_controller(
            api,
            cm,
            &switch_ids.ids,
            SwitchMaintenanceOperation::ReconfigureCertificate,
        )
        .await?;
        return Ok(Response::new(
            rpc::ComponentConfigureSwitchCertificateResponse { results },
        ));
    }

    let endpoints = resolve_switch_endpoints(api, &switch_ids.ids).await?;
    let mut results: Vec<_> = endpoints
        .unresolved
        .iter()
        .map(|u| error_result(&u.id.to_string(), u.reason.clone()))
        .collect();

    tracing::info!(
        backend = cm.nv_switch.name(),
        switch_count = endpoints.resolved.endpoints.len(),
        "configure switch certificate for switches"
    );

    for endpoint in &endpoints.resolved.endpoints {
        let id = switch_mac_to_id_str(&endpoint.bmc_mac, &endpoints.resolved.mac_to_id);
        match cm
            .configure_switch_certificate(
                endpoint,
                domain_name,
                Some(
                    &api.runtime_config
                        .switch_state_controller
                        .effective_switch_mtls_services_as_i32(),
                ),
            )
            .await
            .map_err(component_manager_error_to_status)
        {
            Ok(job_id) => {
                tracing::info!(switch_id = %id, %job_id, "started switch certificate configuration");
                results.push(success_result(&id));
            }
            Err(status) => {
                results.push(error_result(&id, status.message().to_string()));
            }
        }
    }

    Ok(Response::new(
        rpc::ComponentConfigureSwitchCertificateResponse { results },
    ))
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
            action,
            "Failed to apply health report override for power control",
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
        tracing::warn!(error = ?e, "failed to request re-exploration after power control");
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
    log_request_data_redacted("UpdateComponentFirmwareRequest { redacted }");
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;
    let access_token = normalize_access_token(req.access_token);

    let force_update = req.force_update;
    let bypass_state_controller = req.bypass_state_controller;
    let mut rack_maintenance_targets: Vec<RackFirmwareMaintenanceTarget> = Vec::new();
    let mut power_shelf_results: Option<Vec<rpc::ComponentResult>> = None;
    let mut rack_results: Option<Vec<rpc::ComponentResult>> = None;
    let mut maintenance_activities: Vec<rpc::MaintenanceActivityConfig> = Vec::new();

    match target {
        rpc::update_component_firmware_request::Target::Switches(t) => {
            let list = t
                .switch_ids
                .ok_or_else(|| Status::invalid_argument("switch_ids is required"))?;
            if list.ids.is_empty() {
                return Err(Status::invalid_argument("switch_ids must not be empty"));
            }

            let cm = require_component_manager(api)?;
            let route_through_state_controller =
                cm.nv_switch_use_state_controller && !bypass_state_controller;
            let use_direct_rms_json =
                !route_through_state_controller && cm.nv_switch.supports_firmware_object_json();

            if route_through_state_controller {
                let token = require_firmware_object_json_for_rack_maintenance(
                    "switch",
                    &access_token,
                    &req.target_version,
                )?;
                let components = map_nv_switch_components(&t.components)?;
                maintenance_activities = switch_firmware_maintenance_activities(
                    &req.target_version,
                    &token,
                    &components,
                    force_update,
                );
                rack_maintenance_targets = group_switch_ids_by_rack(api, &list.ids).await?;
            } else {
                let options = if use_direct_rms_json {
                    require_firmware_object_json_for_direct_rms(
                        "switch",
                        &access_token,
                        &req.target_version,
                        force_update,
                    )?
                } else {
                    reject_firmware_object_json_for_direct_dispatch("switch", &access_token)?;
                    FirmwareUpdateOptions::default()
                };
                let components = map_nv_switch_components(&t.components)?;
                let endpoints = resolve_switch_endpoints(api, &list.ids).await?;

                let mut results: Vec<_> = endpoints
                    .unresolved
                    .iter()
                    .map(|u| error_result(&u.id.to_string(), u.reason.clone()))
                    .collect();

                let backend_results = cm
                    .nv_switch
                    .queue_firmware_updates(
                        &endpoints.resolved.endpoints,
                        &req.target_version,
                        &components,
                        &options,
                    )
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

                return Ok(Response::new(rpc::UpdateComponentFirmwareResponse {
                    results,
                }));
            }
        }
        rpc::update_component_firmware_request::Target::ComputeTrays(t) => {
            let list = t
                .machine_ids
                .ok_or_else(|| Status::invalid_argument("machine_ids is required"))?;
            if list.machine_ids.is_empty() {
                return Err(Status::invalid_argument("machine_ids must not be empty"));
            }

            let cm = require_component_manager(api)?;

            // Standalone (non-rack-scale) servers have no compute-tray backend
            // that can take a direct firmware dispatch, so they always go
            // through the host reprovisioning firmware flow. Only rack-scale
            // systems (currently GB200 NVL, backed by RMS via the
            // ComputeTrayManager interface) can choose between the rack-level
            // state controller maintenance flow and a direct backend dispatch.
            let machines_by_id = load_machines_by_id(api, &list.machine_ids).await?;
            let (rack_scale_ids, standalone_ids) = partition_loaded_compute_machines_by_rack_scale(
                &machines_by_id,
                &list.machine_ids,
            )?;

            let mut results = Vec::new();

            if !standalone_ids.is_empty() {
                results.extend(
                    schedule_host_reprovisioning_firmware_update(api, &standalone_ids).await,
                );
            }

            if !rack_scale_ids.is_empty() {
                if cm.compute_tray_use_state_controller && !bypass_state_controller {
                    let token = require_firmware_object_json_for_rack_maintenance(
                        "compute tray",
                        &access_token,
                        &req.target_version,
                    )?;
                    let component_names = map_compute_tray_component_names(&t.components)?;
                    let activities = vec![firmware_upgrade_activity(
                        req.target_version.clone(),
                        component_names,
                        Some(token),
                        force_update,
                    )];
                    let targets = group_machine_ids_by_rack(api, &rack_scale_ids).await?;
                    results.extend(
                        submit_rack_firmware_maintenance_requests(api, targets, activities).await?,
                    );
                } else {
                    reject_firmware_object_json_for_direct_dispatch("compute tray", &access_token)?;
                    let components = map_compute_tray_components(&t.components)?;
                    let resolved = resolve_compute_tray_endpoints_from_machines(
                        api.credential_manager.as_ref(),
                        &machines_by_id,
                        &rack_scale_ids,
                    )
                    .await;

                    results.extend(
                        resolved
                            .unresolved
                            .iter()
                            .map(|u| error_result(&u.id.to_string(), u.reason.clone())),
                    );

                    let backend_results = cm
                        .compute_tray
                        .update_firmware(
                            &resolved.resolved.endpoints,
                            &req.target_version,
                            &components,
                            &FirmwareUpdateOptions::default(),
                        )
                        .await
                        .map_err(component_manager_error_to_status)?;
                    results.extend(backend_results.into_iter().map(|r| {
                        if r.success {
                            success_result(&r.bmc_ip.to_string())
                        } else {
                            error_result(&r.bmc_ip.to_string(), r.error.unwrap_or_default())
                        }
                    }));
                }
            }

            return Ok(Response::new(rpc::UpdateComponentFirmwareResponse {
                results,
            }));
        }
        rpc::update_component_firmware_request::Target::PowerShelves(t) => {
            let list = t
                .power_shelf_ids
                .ok_or_else(|| Status::invalid_argument("power_shelf_ids is required"))?;
            if list.ids.is_empty() {
                return Err(Status::invalid_argument(
                    "power_shelf_ids must not be empty",
                ));
            }

            let cm = require_component_manager(api)?;
            let route_through_state_controller =
                cm.power_shelf_use_state_controller && !bypass_state_controller;
            if route_through_state_controller {
                let token = require_firmware_object_json_for_rack_maintenance(
                    "power shelf",
                    &access_token,
                    &req.target_version,
                )?;
                let components = map_power_shelf_components(&t.components)?;
                let component_names = components
                    .iter()
                    .map(|component| match component {
                        PowerShelfComponent::Pmc => "pmc".to_string(),
                        PowerShelfComponent::Psu => "psu".to_string(),
                    })
                    .collect();
                maintenance_activities = vec![firmware_upgrade_activity(
                    req.target_version.clone(),
                    component_names,
                    Some(token),
                    force_update,
                )];
                rack_maintenance_targets = group_power_shelf_ids_by_rack(api, &list.ids).await?;
            } else {
                let options = if cm.power_shelf.supports_firmware_object_json() {
                    require_firmware_object_json_for_direct_rms(
                        "power shelf",
                        &access_token,
                        &req.target_version,
                        force_update,
                    )?
                } else {
                    reject_power_shelf_firmware_object_json(&access_token)?;
                    FirmwareUpdateOptions {
                        force_update,
                        ..FirmwareUpdateOptions::default()
                    }
                };
                let components = map_power_shelf_components(&t.components)?;
                let endpoints = resolve_power_shelf_endpoints(api, &list.ids).await?;

                let mut results: Vec<_> = endpoints
                    .unresolved
                    .iter()
                    .map(|u| error_result(&u.id.to_string(), u.reason.clone()))
                    .collect();

                let backend_results = cm
                    .power_shelf
                    .update_firmware(
                        &endpoints.resolved.endpoints,
                        &req.target_version,
                        &components,
                        &options,
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
        }
        rpc::update_component_firmware_request::Target::Racks(t) => {
            if bypass_state_controller {
                // TODO: implement RMS backend direct dispatch for a full rack
                return Err(Status::invalid_argument(
                    "bypass_state_controller is not supported for rack-level firmware updates",
                ));
            }
            let list = t
                .rack_ids
                .ok_or_else(|| Status::invalid_argument("rack_ids is required"))?;
            if list.rack_ids.is_empty() {
                return Err(Status::invalid_argument("rack_ids must not be empty"));
            }
            let token = require_firmware_object_json_for_rack_maintenance(
                "rack",
                &access_token,
                &req.target_version,
            )?;

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
                                        access_token: Some(token.clone()),
                                        force_update: req.force_update,
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

    let results = submit_rack_firmware_maintenance_requests(
        api,
        rack_maintenance_targets,
        maintenance_activities,
    )
    .await?;

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
                .map(|u| rpc::FirmwareUpdateStatus {
                    result: Some(error_result(&u.id.to_string(), u.reason.clone())),
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
                .map(|u| rpc::FirmwareUpdateStatus {
                    result: Some(error_result(&u.id.to_string(), u.reason.clone())),
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
        rpc::get_component_firmware_status_request::Target::MachineIds(list) => {
            if list.machine_ids.is_empty() {
                return Err(Status::invalid_argument("machine_ids must not be empty"));
            }

            machine_firmware_statuses(api, &list.machine_ids).await?
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
            let Some(cm) = api.component_manager.as_ref() else {
                return Err(unsupported_from_json_firmware_versions("switch"));
            };
            if cm.nv_switch_use_state_controller {
                return Err(unsupported_from_json_firmware_versions("switch"));
            }
            let endpoints = resolve_switch_endpoints(api, &list.ids).await?;

            let mut devices: Vec<rpc::DeviceFirmwareVersions> = endpoints
                .unresolved
                .iter()
                .map(|u| rpc::DeviceFirmwareVersions {
                    result: Some(error_result(&u.id.to_string(), u.reason.clone())),
                    ..Default::default()
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
                    ..Default::default()
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
                .map(|u| rpc::DeviceFirmwareVersions {
                    result: Some(error_result(&u.id.to_string(), u.reason.clone())),
                    ..Default::default()
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
                    ..Default::default()
                });
            }

            Ok(Response::new(rpc::ListComponentFirmwareVersionsResponse {
                devices,
            }))
        }
        rpc::list_component_firmware_versions_request::Target::MachineIds(list) => {
            if list.machine_ids.is_empty() {
                return Err(Status::invalid_argument("machine_ids must not be empty"));
            }

            let Some(cm) = api.component_manager.as_ref() else {
                return Err(unsupported_from_json_firmware_versions("compute tray"));
            };
            if cm.compute_tray_use_state_controller {
                return Err(unsupported_from_json_firmware_versions("compute tray"));
            }

            let machines_by_id = load_machines_by_id(api, &list.machine_ids).await?;
            let resolved = resolve_compute_tray_endpoints_from_machines(
                api.credential_manager.as_ref(),
                &machines_by_id,
                &list.machine_ids,
            )
            .await;

            let mut devices: Vec<rpc::DeviceFirmwareVersions> = resolved
                .unresolved
                .iter()
                .map(|u| rpc::DeviceFirmwareVersions {
                    result: Some(error_result(&u.id.to_string(), u.reason.clone())),
                    ..Default::default()
                })
                .collect();

            let versions = cm
                .compute_tray
                .list_firmware_bundles()
                .await
                .map_err(component_manager_error_to_status)?;

            for ep in &resolved.resolved.endpoints {
                let id = resolved
                    .resolved
                    .ip_to_machine_id
                    .get(&ep.bmc_ip)
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| ep.bmc_ip.to_string());
                devices.push(rpc::DeviceFirmwareVersions {
                    result: Some(success_result(&id)),
                    versions: versions.clone(),
                    ..Default::default()
                });
            }

            Ok(Response::new(rpc::ListComponentFirmwareVersionsResponse {
                devices,
            }))
        }
        rpc::list_component_firmware_versions_request::Target::RackIds(list) => {
            if list.rack_ids.is_empty() {
                return Err(Status::invalid_argument("rack_ids must not be empty"));
            }

            Err(unsupported_from_json_firmware_versions("rack"))
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

    /// Yields a real `tonic::transport::Error` so the `Transport` arm can be
    /// exercised without a live connection: an invalid endpoint URI fails to parse
    /// synchronously into exactly that error type.
    fn transport_error() -> tonic::transport::Error {
        tonic::transport::Endpoint::new("not a valid uri")
            .expect_err("an invalid endpoint URI should fail to parse")
    }

    /// One `component_manager_error_to_status` mapping: the source error, the gRPC
    /// `Code` it must produce, and (where the message is part of the contract) a
    /// substring the propagated status message must contain.
    struct ErrorToStatusCase {
        scenario: &'static str,
        error: ComponentManagerError,
        expected_code: Code,
        message_contains: Option<&'static str>,
    }

    #[test]
    fn error_to_status_maps_each_variant() {
        let cases = [
            ErrorToStatusCase {
                scenario: "unavailable propagates its message",
                error: ComponentManagerError::Unavailable("gone".into()),
                expected_code: Code::Unavailable,
                message_contains: Some("gone"),
            },
            ErrorToStatusCase {
                scenario: "not found",
                error: ComponentManagerError::NotFound("missing".into()),
                expected_code: Code::NotFound,
                message_contains: None,
            },
            ErrorToStatusCase {
                scenario: "invalid argument",
                error: ComponentManagerError::InvalidArgument("bad".into()),
                expected_code: Code::InvalidArgument,
                message_contains: None,
            },
            ErrorToStatusCase {
                scenario: "unsupported operation",
                error: ComponentManagerError::Unsupported("not implemented".into()),
                expected_code: Code::Unimplemented,
                message_contains: Some("not implemented"),
            },
            ErrorToStatusCase {
                scenario: "operation rejected before dispatch",
                error: ComponentManagerError::RejectedBeforeDispatch("request rejected".into()),
                expected_code: Code::FailedPrecondition,
                message_contains: Some("request rejected"),
            },
            ErrorToStatusCase {
                scenario: "operation outcome unknown",
                error: ComponentManagerError::OperationOutcomeUnknown("lost job id".into()),
                expected_code: Code::Unavailable,
                message_contains: Some("lost job id"),
            },
            ErrorToStatusCase {
                scenario: "internal",
                error: ComponentManagerError::Internal("oops".into()),
                expected_code: Code::Internal,
                message_contains: None,
            },
            ErrorToStatusCase {
                scenario: "status passthrough preserves the original code",
                error: ComponentManagerError::Status(Status::permission_denied("nope")),
                expected_code: Code::PermissionDenied,
                message_contains: None,
            },
            ErrorToStatusCase {
                scenario: "transport maps to unavailable",
                error: ComponentManagerError::Transport(transport_error()),
                expected_code: Code::Unavailable,
                message_contains: Some("transport error"),
            },
            ErrorToStatusCase {
                scenario: "rms maps to internal",
                error: ComponentManagerError::Rms("rms boom".into()),
                expected_code: Code::Internal,
                message_contains: Some("RMS error"),
            },
        ];

        for case in cases {
            let status = component_manager_error_to_status(case.error);
            assert_eq!(status.code(), case.expected_code, "{}", case.scenario);
            if let Some(substring) = case.message_contains {
                assert!(
                    status.message().contains(substring),
                    "{}: message {:?} should contain {substring:?}",
                    case.scenario,
                    status.message(),
                );
            }
        }
    }

    #[test]
    fn firmware_object_json_request_requires_sot_json_in_target_version() {
        let err = validate_firmware_object_json_request("").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("target_version"));

        let err = validate_firmware_object_json_request("fw-1.0.0").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("valid SOT JSON"));

        let err = validate_firmware_object_json_request(r#""fw-1.0.0""#).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("SOT JSON object"));

        validate_firmware_object_json_request("{}").unwrap();
    }

    #[test]
    fn switch_firmware_maintenance_activities_split_nvos_component() {
        let activities = switch_firmware_maintenance_activities(
            r#"{"Id":"fw"}"#,
            "token",
            &[NvSwitchComponent::Bmc, NvSwitchComponent::Nvos],
            true,
        );

        assert_eq!(activities.len(), 2);
        assert!(matches!(
            activities[0].activity.as_ref(),
            Some(rpc::maintenance_activity_config::Activity::FirmwareUpgrade(
                activity
            )) if activity.components == vec!["BMC".to_string()] && activity.force_update
        ));
        assert!(matches!(
            activities[1].activity.as_ref(),
            Some(rpc::maintenance_activity_config::Activity::NvosUpdate(
                activity
            )) if activity.config_json == r#"{"Id":"fw"}"# && activity.access_token.as_deref() == Some("token")
        ));
    }

    #[test]
    fn switch_firmware_maintenance_activities_only_nvos_skips_firmware_activity() {
        let activities = switch_firmware_maintenance_activities(
            r#"{"Id":"fw"}"#,
            "token",
            &[NvSwitchComponent::Nvos],
            false,
        );

        assert_eq!(activities.len(), 1);
        assert!(matches!(
            activities[0].activity.as_ref(),
            Some(rpc::maintenance_activity_config::Activity::NvosUpdate(_))
        ));
    }

    #[test]
    fn rack_firmware_targets_are_grouped_by_rack() {
        let rack_a = RackId::new("rack-a".to_string());
        let rack_b = RackId::new("rack-b".to_string());
        let mut targets = Vec::new();

        push_rack_firmware_target(
            &mut targets,
            rack_a.clone(),
            Some("machine-a".into()),
            None,
            None,
        );
        push_rack_firmware_target(
            &mut targets,
            rack_b.clone(),
            None,
            Some("switch-b".into()),
            None,
        );
        push_rack_firmware_target(
            &mut targets,
            rack_a.clone(),
            Some("machine-c".into()),
            None,
            None,
        );

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].rack_id, rack_a);
        assert_eq!(targets[0].machine_ids, vec!["machine-a", "machine-c"]);
        assert!(targets[0].switch_ids.is_empty());
        assert!(targets[0].power_shelf_ids.is_empty());
        assert_eq!(targets[1].rack_id, rack_b);
        assert_eq!(targets[1].switch_ids, vec!["switch-b"]);
        assert!(targets[1].machine_ids.is_empty());
        assert!(targets[1].power_shelf_ids.is_empty());
    }

    #[test]
    fn power_shelf_firmware_object_json_is_unimplemented() {
        let access_token = Some("token".to_string());

        let err = reject_power_shelf_firmware_object_json(&access_token).unwrap_err();

        assert_eq!(err.code(), Code::Unimplemented);
        assert!(err.message().contains("power shelves"));
    }

    #[test]
    fn rack_maintenance_firmware_update_defaults_missing_access_token_to_noauth() {
        let token = require_firmware_object_json_for_rack_maintenance("rack", &None, "{}").unwrap();

        assert_eq!(
            token,
            carbide_rack::firmware_object::RMS_NOAUTH_ACCESS_TOKEN
        );
    }

    #[test]
    fn rack_maintenance_firmware_update_returns_access_token_when_valid() {
        let token = require_firmware_object_json_for_rack_maintenance(
            "switch",
            &Some("token".to_string()),
            "{}",
        )
        .unwrap();

        assert_eq!(token, "token");
    }

    #[test]
    fn rack_maintenance_firmware_update_defaults_empty_access_token_to_noauth() {
        let token =
            require_firmware_object_json_for_rack_maintenance("rack", &Some(String::new()), "{}")
                .unwrap();

        assert_eq!(
            token,
            carbide_rack::firmware_object::RMS_NOAUTH_ACCESS_TOKEN
        );
    }

    #[test]
    fn direct_rms_firmware_update_defaults_missing_access_token_to_noauth() {
        let options =
            require_firmware_object_json_for_direct_rms("switch", &None, "{}", false).unwrap();

        assert_eq!(
            options.access_token.as_deref(),
            Some(carbide_rack::firmware_object::RMS_NOAUTH_ACCESS_TOKEN)
        );
    }

    #[test]
    fn direct_rms_firmware_update_returns_options_when_valid() {
        let options = require_firmware_object_json_for_direct_rms(
            "switch",
            &Some("token".to_string()),
            "{}",
            true,
        )
        .unwrap();

        assert_eq!(options.access_token.as_deref(), Some("token"));
        assert!(options.force_update);
    }

    #[test]
    fn non_rms_direct_firmware_update_rejects_access_token() {
        let err =
            reject_firmware_object_json_for_direct_dispatch("switch", &Some("token".to_string()))
                .unwrap_err();

        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(err.message().contains("rack maintenance"));
    }

    #[test]
    fn power_action_maps_each_control() {
        use carbide_test_support::Outcome::*;
        // Map the rejection error to its `Code` so rows share one comparable error
        // type; every row here is a successful control-to-action mapping.
        carbide_test_support::scenarios!(run = |raw| map_power_action(raw).map_err(|s| s.code());
            "control maps to action" {
                SystemPowerControl::On as i32 => Yields(PowerAction::On),
                SystemPowerControl::GracefulShutdown as i32 => Yields(PowerAction::GracefulShutdown),
                SystemPowerControl::ForceOff as i32 => Yields(PowerAction::ForceOff),
                SystemPowerControl::GracefulRestart as i32 => Yields(PowerAction::GracefulRestart),
                SystemPowerControl::ForceRestart as i32 => Yields(PowerAction::ForceRestart),
                SystemPowerControl::AcPowercycle as i32 => Yields(PowerAction::AcPowercycle),
            }
        );
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
                force_update: false,
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
                force_update: false,
            }],
            ..Default::default()
        });

        let status = rack_firmware_status(&rack);

        assert_eq!(status.state, rpc::FirmwareUpdateState::FwStateQueued as i32);
        assert!(status.target_version.is_empty());
        assert!(status.updated_at.is_some());
    }

    #[test]
    fn rack_firmware_status_redacts_sot_json_target_version() {
        let mut rack = test_rack_with_job(None);
        rack.config.maintenance_requested = Some(model::rack::MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: Some(
                    r#"{"Id":"fw-123","Locations":["https://internal.example/artifact"]}"#
                        .to_string(),
                ),
                components: vec![],
                force_update: false,
            }],
            ..Default::default()
        });

        let status = rack_firmware_status(&rack);

        assert_eq!(status.target_version, "firmware_object_json:fw-123");
        assert!(!status.target_version.contains("Locations"));
        assert!(!status.target_version.contains("internal.example"));
    }

    #[test]
    fn rack_firmware_status_redacts_sot_json_without_object_id() {
        let mut rack = test_rack_with_job(None);
        rack.config.maintenance_requested = Some(model::rack::MaintenanceScope {
            activities: vec![MaintenanceActivity::FirmwareUpgrade {
                firmware_version: Some(
                    r#"{"Locations":["https://internal.example/artifact"]}"#.to_string(),
                ),
                components: vec![],
                force_update: false,
            }],
            ..Default::default()
        });

        let status = rack_firmware_status(&rack);

        assert_eq!(status.target_version, "firmware_object_json");
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

    #[test]
    fn status_result_maps_tonic_codes_and_defaults_to_internal_error() {
        use super::status_result;

        let cases = [
            (
                Status::not_found("missing"),
                rpc::ComponentManagerStatusCode::NotFound,
            ),
            (
                Status::invalid_argument("bad"),
                rpc::ComponentManagerStatusCode::InvalidArgument,
            ),
            (
                Status::failed_precondition("precondition"),
                rpc::ComponentManagerStatusCode::InvalidArgument,
            ),
            (
                Status::already_exists("dup"),
                rpc::ComponentManagerStatusCode::AlreadyExists,
            ),
            (
                Status::unavailable("down"),
                rpc::ComponentManagerStatusCode::Unavailable,
            ),
            // Codes without an explicit arm collapse to InternalError.
            (
                Status::internal("boom"),
                rpc::ComponentManagerStatusCode::InternalError,
            ),
            (
                Status::permission_denied("nope"),
                rpc::ComponentManagerStatusCode::InternalError,
            ),
        ];

        for (status, expected) in cases {
            let message = status.message().to_string();
            let r = status_result("machine-1", status);
            assert_eq!(r.component_id, "machine-1");
            assert_eq!(
                r.status, expected as i32,
                "unexpected mapping for {message:?}"
            );
            assert_eq!(r.error, message);
        }
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
    fn unresolved_switch_produces_error_result_with_reason() {
        let id = test_switch_id();
        let u = UnresolvedDevice {
            id,
            reason: "BMC credentials unavailable: no BMC credentials found".into(),
        };
        let r = error_result(&u.id.to_string(), u.reason);
        assert_eq!(r.component_id, id.to_string());
        assert_eq!(
            r.status,
            rpc::ComponentManagerStatusCode::InternalError as i32,
        );
        assert!(r.error.contains("BMC credentials unavailable"));
    }

    #[test]
    fn unresolved_power_shelf_produces_error_result_with_reason() {
        let id = test_power_shelf_id();
        let u = UnresolvedDevice {
            id,
            reason: "PMC credentials unavailable: no PMC credentials found".into(),
        };
        let r = error_result(&u.id.to_string(), u.reason);
        assert_eq!(r.component_id, id.to_string());
        assert_eq!(
            r.status,
            rpc::ComponentManagerStatusCode::InternalError as i32,
        );
        assert!(r.error.contains("PMC credentials unavailable"));
    }

    #[test]
    fn unresolved_device_display() {
        let id = test_switch_id();
        let u = UnresolvedDevice {
            id,
            reason: "NVOS MAC or IP not available".into(),
        };
        let display = u.to_string();
        assert!(display.contains(&id.to_string()));
        assert!(display.contains("NVOS MAC or IP not available"));
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
    fn map_switch_maintenance_operation_variants() {
        use model::switch::SwitchMaintenanceOperation;

        use super::map_switch_maintenance_operation;

        assert_eq!(
            map_switch_maintenance_operation(PowerAction::On),
            SwitchMaintenanceOperation::PowerOn,
        );
        assert_eq!(
            map_switch_maintenance_operation(PowerAction::ForceOff),
            SwitchMaintenanceOperation::PowerOff,
        );
        assert_eq!(
            map_switch_maintenance_operation(PowerAction::GracefulShutdown),
            SwitchMaintenanceOperation::PowerOff,
        );
        assert_eq!(
            map_switch_maintenance_operation(PowerAction::ForceRestart),
            SwitchMaintenanceOperation::Reset,
        );
    }

    #[test]
    fn map_machine_maintenance_operation_variants() {
        use model::machine::MachineMaintenanceOperation;

        use super::map_machine_maintenance_operation;

        assert_eq!(
            map_machine_maintenance_operation(PowerAction::On),
            MachineMaintenanceOperation::PowerOn,
        );
        assert_eq!(
            map_machine_maintenance_operation(PowerAction::ForceOff),
            MachineMaintenanceOperation::PowerOff,
        );
        assert_eq!(
            map_machine_maintenance_operation(PowerAction::GracefulShutdown),
            MachineMaintenanceOperation::PowerOff,
        );
        assert_eq!(
            map_machine_maintenance_operation(PowerAction::ForceRestart),
            MachineMaintenanceOperation::Reset,
        );
    }

    #[test]
    fn map_power_shelf_maintenance_operation_variants() {
        use model::power_shelf::PowerShelfMaintenanceOperation;

        use super::map_power_shelf_maintenance_operation;

        assert_eq!(
            map_power_shelf_maintenance_operation(PowerAction::On).unwrap(),
            PowerShelfMaintenanceOperation::PowerOn,
        );
        assert_eq!(
            map_power_shelf_maintenance_operation(PowerAction::ForceOff).unwrap(),
            PowerShelfMaintenanceOperation::PowerOff,
        );
        assert_eq!(
            map_power_shelf_maintenance_operation(PowerAction::GracefulShutdown).unwrap(),
            PowerShelfMaintenanceOperation::PowerOff,
        );
        assert!(map_power_shelf_maintenance_operation(PowerAction::ForceRestart).is_err());
        assert!(map_power_shelf_maintenance_operation(PowerAction::AcPowercycle).is_err());
    }

    #[test]
    fn firmware_versions_match_requires_non_empty_desired_subset() {
        use super::firmware_versions_match;

        let desired = HashMap::from([("bmc".to_string(), "1.0".to_string())]);
        let actual = HashMap::from([("bmc".to_string(), "1.0".to_string())]);
        assert!(firmware_versions_match(&desired, &actual));

        let superset = HashMap::from([
            ("bmc".to_string(), "1.0".to_string()),
            ("uefi".to_string(), "2.0".to_string()),
        ]);
        assert!(firmware_versions_match(&desired, &superset));

        let mismatch = HashMap::from([("bmc".to_string(), "0.9".to_string())]);
        assert!(!firmware_versions_match(&desired, &mismatch));

        assert!(!firmware_versions_match(&HashMap::new(), &actual));
    }

    #[test]
    fn derive_machine_firmware_update_status_unknown_when_machine_missing() {
        use super::derive_machine_firmware_update_status;

        let status = derive_machine_firmware_update_status("machine-1", None, None, &[]);

        assert_eq!(
            status.state,
            rpc::FirmwareUpdateState::FwStateUnknown as i32
        );
        assert!(
            status
                .result
                .as_ref()
                .is_some_and(|result| result.error.contains("machine not found"))
        );
    }

    // ---- compute power-control (MachineIds) decision logic ----

    use carbide_secrets::credentials::Credentials;
    use carbide_secrets::test_support::credentials::TestCredentialManager;
    use model::hardware_info::{Gpu, GpuPlatformInfo, HardwareInfo};
    use model::test_support::machine_snapshot::{dpu_machine_id, host_machine, host_machine_id};

    /// A GPU carrying NVLink platform metadata and an MNNVL family name — what
    /// `is_mnnvl_capable` keys off of to flag a rack-scale (GB200) server.
    fn mnnvl_gpu() -> Gpu {
        Gpu {
            name: "NVIDIA GB200".to_string(),
            serial: String::new(),
            driver_version: String::new(),
            vbios_version: String::new(),
            inforom_version: String::new(),
            total_memory: String::new(),
            frequency: String::new(),
            pci_bus_id: String::new(),
            platform_info: Some(GpuPlatformInfo {
                chassis_serial: "CHASSIS-1".to_string(),
                slot_number: 1,
                tray_index: 1,
                host_id: 1,
                module_id: 1,
                fabric_guid: String::new(),
            }),
        }
    }

    fn machine_with_hardware(hardware_info: Option<HardwareInfo>) -> Machine {
        let mut machine = host_machine();
        machine.status.hardware_info = hardware_info;
        machine
    }

    fn machine_with_id(mut machine: Machine, id: MachineId) -> Machine {
        machine.id = id;
        machine
    }

    /// Rack-scale: at least one MNNVL-capable GPU.
    fn rack_scale_machine() -> Machine {
        machine_with_hardware(Some(HardwareInfo {
            gpus: vec![mnnvl_gpu()],
            ..Default::default()
        }))
    }

    /// Standalone: no MNNVL-capable GPU.
    fn standalone_machine() -> Machine {
        machine_with_hardware(Some(HardwareInfo::default()))
    }

    /// Mirror the MachineIds power path's classify → power-option gate → partition
    /// loop without a database: unknown ids become per-machine NotFound results,
    /// and only machines with a successful power-option update join a partition.
    fn prepare_dispatch_lists(
        machines_by_id: &HashMap<MachineId, Machine>,
        machine_ids: &[MachineId],
        power_option_ok: &HashMap<MachineId, bool>,
    ) -> (Vec<MachineId>, Vec<MachineId>, Vec<rpc::ComponentResult>) {
        let mut results = Vec::new();
        let mut rack_scale_ids = Vec::new();
        let mut standalone_ids = Vec::new();
        for &machine_id in machine_ids {
            let is_rack_scale = match machine_is_rack_scale(machines_by_id, machine_id) {
                Ok(v) => v,
                Err(status) => {
                    results.push(status_result(&machine_id.to_string(), status));
                    continue;
                }
            };
            let ok = power_option_ok.get(&machine_id).copied().unwrap_or(true);
            if !ok {
                results.push(error_result(
                    &machine_id.to_string(),
                    "failed to update power option: precondition".into(),
                ));
                continue;
            }
            if is_rack_scale {
                rack_scale_ids.push(machine_id);
            } else {
                standalone_ids.push(machine_id);
            }
        }
        (rack_scale_ids, standalone_ids, results)
    }

    #[test]
    fn machine_is_rack_scale_classifies_rack_standalone_and_unknown() {
        let id = host_machine_id();

        let rack_map = HashMap::from([(id, rack_scale_machine())]);
        assert!(
            machine_is_rack_scale(&rack_map, id).unwrap(),
            "MNNVL hardware should classify as rack-scale"
        );

        let standalone_map = HashMap::from([(id, standalone_machine())]);
        assert!(
            !machine_is_rack_scale(&standalone_map, id).unwrap(),
            "non-MNNVL hardware should classify as standalone"
        );

        // Unknown id (absent from the map) is a per-machine NotFound carrying the id.
        let err = machine_is_rack_scale(&HashMap::new(), id).unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        assert!(err.message().contains(&id.to_string()));
    }

    #[test]
    fn mixed_batch_routes_rack_to_rack_partition_and_standalone_to_core_partition() {
        let rack_id = host_machine_id();
        let standalone_id = dpu_machine_id(0);
        let machines = HashMap::from([
            (rack_id, machine_with_id(rack_scale_machine(), rack_id)),
            (
                standalone_id,
                machine_with_id(standalone_machine(), standalone_id),
            ),
        ]);

        let (rack, standalone, results) =
            prepare_dispatch_lists(&machines, &[rack_id, standalone_id], &HashMap::new());

        assert!(results.is_empty());
        assert_eq!(rack, vec![rack_id]);
        assert_eq!(standalone, vec![standalone_id]);
    }

    #[test]
    fn all_rack_scale_batch_uses_only_rack_partition() {
        let id = host_machine_id();
        let machines = HashMap::from([(id, rack_scale_machine())]);
        let (rack, standalone, results) = prepare_dispatch_lists(&machines, &[id], &HashMap::new());
        assert!(results.is_empty());
        assert_eq!(rack, vec![id]);
        assert!(standalone.is_empty());
    }

    #[test]
    fn all_standalone_batch_uses_only_standalone_partition() {
        let id = host_machine_id();
        let machines = HashMap::from([(id, standalone_machine())]);
        let (rack, standalone, results) = prepare_dispatch_lists(&machines, &[id], &HashMap::new());
        assert!(results.is_empty());
        assert!(rack.is_empty());
        assert_eq!(standalone, vec![id]);
    }

    #[test]
    fn unknown_machine_id_is_not_found_and_does_not_abort_rest_of_batch() {
        let known = host_machine_id();
        let unknown = dpu_machine_id(1);
        let machines = HashMap::from([(known, standalone_machine())]);

        let (rack, standalone, results) =
            prepare_dispatch_lists(&machines, &[unknown, known], &HashMap::new());

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].component_id, unknown.to_string());
        assert_eq!(
            results[0].status,
            rpc::ComponentManagerStatusCode::NotFound as i32
        );
        assert!(rack.is_empty());
        assert_eq!(standalone, vec![known]);
    }

    #[test]
    fn power_option_failure_is_not_dispatched_while_siblings_are() {
        let ok_id = host_machine_id();
        let fail_id = dpu_machine_id(0);
        let machines = HashMap::from([
            (ok_id, machine_with_id(rack_scale_machine(), ok_id)),
            (fail_id, machine_with_id(standalone_machine(), fail_id)),
        ]);
        let power_ok = HashMap::from([(ok_id, true), (fail_id, false)]);

        let (rack, standalone, results) =
            prepare_dispatch_lists(&machines, &[ok_id, fail_id], &power_ok);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].component_id, fail_id.to_string());
        assert!(results[0].error.contains("failed to update power option"));
        assert_eq!(rack, vec![ok_id]);
        assert!(
            standalone.is_empty(),
            "power-option failure must not join a dispatch partition"
        );
    }

    #[test]
    fn partition_error_results_reports_one_error_per_machine() {
        let ids = [host_machine_id(), dpu_machine_id(0)];
        let status = Status::unavailable("backend down");

        let results = partition_error_results(&ids, &status);

        assert_eq!(results.len(), ids.len());
        for (result, id) in results.iter().zip(ids) {
            assert_eq!(result.component_id, id.to_string());
            // The dispatch status code is preserved per machine, not flattened.
            assert_eq!(
                result.status,
                rpc::ComponentManagerStatusCode::Unavailable as i32
            );
            assert!(result.error.contains("backend down"));
        }
    }

    #[tokio::test]
    async fn resolve_from_machines_reports_missing_id_and_bmc_gaps() {
        let missing_id = dpu_machine_id(0);
        let no_mac_id = host_machine_id();
        let no_ip_id = dpu_machine_id(1);

        let mut no_mac = standalone_machine();
        no_mac.id = no_mac_id;
        no_mac.status.bmc_info.mac = None;

        let mut no_ip = standalone_machine();
        no_ip.id = no_ip_id;
        no_ip.status.bmc_info.ip = None;

        let machines = HashMap::from([(no_mac_id, no_mac), (no_ip_id, no_ip)]);
        let creds = TestCredentialManager::new(Credentials::UsernamePassword {
            username: "u".into(),
            password: "p".into(),
        });

        let resolved = resolve_compute_tray_endpoints_from_machines(
            &creds,
            &machines,
            &[missing_id, no_mac_id, no_ip_id],
        )
        .await;

        assert!(resolved.resolved.endpoints.is_empty());
        assert_eq!(resolved.unresolved.len(), 3);
        assert!(
            resolved
                .unresolved
                .iter()
                .any(|u| u.id == missing_id && u.reason.contains("machine not found"))
        );
        assert!(
            resolved
                .unresolved
                .iter()
                .any(|u| u.id == no_mac_id && u.reason.contains("BMC MAC"))
        );
        assert!(
            resolved
                .unresolved
                .iter()
                .any(|u| u.id == no_ip_id && u.reason.contains("BMC IP"))
        );
    }

    #[tokio::test]
    async fn resolve_from_machines_builds_endpoint_when_bmc_and_creds_present() {
        let id = host_machine_id();
        let machine = standalone_machine();
        let bmc_ip = machine.status.bmc_info.ip.expect("fixture has BMC IP");
        let machines = HashMap::from([(id, machine)]);
        let creds = TestCredentialManager::new(Credentials::UsernamePassword {
            username: "root".into(),
            password: "secret".into(),
        });

        let resolved = resolve_compute_tray_endpoints_from_machines(&creds, &machines, &[id]).await;

        assert!(resolved.unresolved.is_empty());
        assert_eq!(resolved.resolved.endpoints.len(), 1);
        assert_eq!(resolved.resolved.endpoints[0].bmc_ip, bmc_ip);
        assert_eq!(resolved.resolved.ip_to_machine_id.get(&bmc_ip), Some(&id));
    }
}
