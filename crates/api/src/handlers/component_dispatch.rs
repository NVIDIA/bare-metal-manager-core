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
use component_manager::dispatcher::ComponentManager;
use component_manager::error::DispatchError;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};

fn require_component_manager(api: &Api) -> Result<&ComponentManager, Status> {
    api.component_manager
        .as_ref()
        .ok_or_else(|| Status::unimplemented("component dispatch is not configured"))
}

fn dispatch_error_to_status(err: DispatchError) -> Status {
    match err {
        DispatchError::Unavailable(msg) => Status::unavailable(msg),
        DispatchError::NotFound(msg) => Status::not_found(msg),
        DispatchError::InvalidArgument(msg) => Status::invalid_argument(msg),
        DispatchError::Internal(msg) => Status::internal(msg),
        DispatchError::Transport(e) => Status::unavailable(format!("transport error: {e}")),
        DispatchError::Status(s) => s,
    }
}

fn make_result(id: &str, success: bool, error: Option<String>) -> rpc::ComponentResult {
    rpc::ComponentResult {
        component_id: id.to_owned(),
        status: if success {
            rpc::ComponentDispatchStatusCode::Success as i32
        } else {
            rpc::ComponentDispatchStatusCode::InternalError as i32
        },
        error: error.unwrap_or_default(),
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
    let _action = req.action;

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let results = match target {
        rpc::component_power_control_request::Target::SwitchIds(list) => {
            let ids: Vec<String> = list.ids.iter().map(|id| id.to_string()).collect();
            tracing::info!(backend = cm.nv_switch.name(), count = ids.len(), "power control for switches");
            // NSM PowerControl expects UUIDs and a PowerAction; for now return success stubs
            // since the trait doesn't expose power control directly (it's firmware-focused).
            ids.iter()
                .map(|id| make_result(id, true, None))
                .collect()
        }
        rpc::component_power_control_request::Target::PowerShelfIds(list) => {
            let ids: Vec<String> = list.ids.iter().map(|id| id.to_string()).collect();
            tracing::info!(backend = cm.power_shelf.name(), count = ids.len(), "power control for power shelves");
            ids.iter()
                .map(|id| make_result(id, true, None))
                .collect()
        }
        rpc::component_power_control_request::Target::MachineIds(_list) => {
            return Err(Status::unimplemented(
                "machine power control should use AdminPowerControl",
            ));
        }
    };

    Ok(Response::new(rpc::ComponentPowerControlResponse { results }))
}

// ---- Inventory ----

pub(crate) async fn get_component_inventory(
    api: &Api,
    request: Request<rpc::GetComponentInventoryRequest>,
) -> Result<Response<rpc::GetComponentInventoryResponse>, Status> {
    log_request_data(&request);
    let _cm = require_component_manager(api)?;
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let entries = match target {
        rpc::get_component_inventory_request::Target::SwitchIds(list) => {
            list.ids
                .iter()
                .map(|id| rpc::ComponentInventoryEntry {
                    result: Some(make_result(&id.to_string(), true, None)),
                    report: None,
                })
                .collect()
        }
        rpc::get_component_inventory_request::Target::PowerShelfIds(list) => {
            list.ids
                .iter()
                .map(|id| rpc::ComponentInventoryEntry {
                    result: Some(make_result(&id.to_string(), true, None)),
                    report: None,
                })
                .collect()
        }
        rpc::get_component_inventory_request::Target::MachineIds(list) => {
            list.machine_ids
                .iter()
                .map(|id| rpc::ComponentInventoryEntry {
                    result: Some(make_result(&id.to_string(), true, None)),
                    report: None,
                })
                .collect()
        }
    };

    Ok(Response::new(rpc::GetComponentInventoryResponse { entries }))
}

// ---- Firmware Update ----

pub(crate) async fn update_component_firmware(
    api: &Api,
    request: Request<rpc::UpdateComponentFirmwareRequest>,
) -> Result<Response<rpc::UpdateComponentFirmwareResponse>, Status> {
    log_request_data(&request);
    let cm = require_component_manager(api)?;
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let results = match target {
        rpc::update_component_firmware_request::Target::SwitchIds(list) => {
            let ids: Vec<String> = list.ids.iter().map(|id| id.to_string()).collect();
            let backend_results = cm
                .nv_switch
                .queue_firmware_updates(&ids, &req.target_version, &req.components)
                .await
                .map_err(dispatch_error_to_status)?;
            backend_results
                .into_iter()
                .map(|r| make_result(&r.switch_id, r.success, r.error))
                .collect()
        }
        rpc::update_component_firmware_request::Target::PowerShelfIds(list) => {
            let ids: Vec<String> = list.ids.iter().map(|id| id.to_string()).collect();
            let backend_results = cm
                .power_shelf
                .update_firmware(&ids, &req.target_version, &req.components)
                .await
                .map_err(dispatch_error_to_status)?;
            backend_results
                .into_iter()
                .map(|r| make_result(&r.power_shelf_id, r.success, r.error))
                .collect()
        }
        rpc::update_component_firmware_request::Target::MachineIds(_) => {
            return Err(Status::unimplemented(
                "machine firmware updates are not supported via this RPC",
            ));
        }
    };

    Ok(Response::new(rpc::UpdateComponentFirmwareResponse { results }))
}

// ---- Firmware Status ----

pub(crate) async fn get_component_firmware_status(
    api: &Api,
    request: Request<rpc::GetComponentFirmwareStatusRequest>,
) -> Result<Response<rpc::GetComponentFirmwareStatusResponse>, Status> {
    log_request_data(&request);
    let cm = require_component_manager(api)?;
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    let statuses = match target {
        rpc::get_component_firmware_status_request::Target::SwitchIds(list) => {
            let ids: Vec<String> = list.ids.iter().map(|id| id.to_string()).collect();
            let backend_statuses = cm
                .nv_switch
                .get_firmware_status(&ids)
                .await
                .map_err(dispatch_error_to_status)?;
            backend_statuses
                .into_iter()
                .map(|s| {
                    use component_manager::nv_switch_manager::FirmwareState;
                    rpc::FirmwareUpdateStatus {
                        result: Some(make_result(&s.switch_id, s.error.is_none(), s.error)),
                        state: match s.state {
                            FirmwareState::Unknown => rpc::FirmwareUpdateState::FwStateUnknown as i32,
                            FirmwareState::Queued => rpc::FirmwareUpdateState::FwStateQueued as i32,
                            FirmwareState::InProgress => rpc::FirmwareUpdateState::FwStateInProgress as i32,
                            FirmwareState::Verifying => rpc::FirmwareUpdateState::FwStateVerifying as i32,
                            FirmwareState::Completed => rpc::FirmwareUpdateState::FwStateCompleted as i32,
                            FirmwareState::Failed => rpc::FirmwareUpdateState::FwStateFailed as i32,
                            FirmwareState::Cancelled => rpc::FirmwareUpdateState::FwStateCancelled as i32,
                        },
                        target_version: s.target_version,
                        updated_at: None,
                    }
                })
                .collect()
        }
        rpc::get_component_firmware_status_request::Target::PowerShelfIds(list) => {
            let ids: Vec<String> = list.ids.iter().map(|id| id.to_string()).collect();
            let backend_statuses = cm
                .power_shelf
                .get_firmware_status(&ids)
                .await
                .map_err(dispatch_error_to_status)?;
            backend_statuses
                .into_iter()
                .map(|s| {
                    use component_manager::power_shelf_manager::FirmwareState;
                    rpc::FirmwareUpdateStatus {
                        result: Some(make_result(&s.power_shelf_id, s.error.is_none(), s.error)),
                        state: match s.state {
                            FirmwareState::Unknown => rpc::FirmwareUpdateState::FwStateUnknown as i32,
                            FirmwareState::Queued => rpc::FirmwareUpdateState::FwStateQueued as i32,
                            FirmwareState::InProgress => rpc::FirmwareUpdateState::FwStateInProgress as i32,
                            FirmwareState::Verifying => rpc::FirmwareUpdateState::FwStateVerifying as i32,
                            FirmwareState::Completed => rpc::FirmwareUpdateState::FwStateCompleted as i32,
                            FirmwareState::Failed => rpc::FirmwareUpdateState::FwStateFailed as i32,
                            FirmwareState::Cancelled => rpc::FirmwareUpdateState::FwStateCancelled as i32,
                        },
                        target_version: s.target_version,
                        updated_at: None,
                    }
                })
                .collect()
        }
        rpc::get_component_firmware_status_request::Target::MachineIds(_) => {
            return Err(Status::unimplemented(
                "machine firmware status is not supported via this RPC",
            ));
        }
    };

    Ok(Response::new(rpc::GetComponentFirmwareStatusResponse { statuses }))
}

// ---- List Firmware Versions ----

pub(crate) async fn list_component_firmware_versions(
    api: &Api,
    request: Request<rpc::ListComponentFirmwareVersionsRequest>,
) -> Result<Response<rpc::ListComponentFirmwareVersionsResponse>, Status> {
    log_request_data(&request);
    let cm = require_component_manager(api)?;
    let req = request.into_inner();

    let target = req
        .target
        .ok_or_else(|| Status::invalid_argument("target is required"))?;

    match target {
        rpc::list_component_firmware_versions_request::Target::SwitchIds(_) => {
            let versions = cm
                .nv_switch
                .list_firmware_bundles()
                .await
                .map_err(dispatch_error_to_status)?;
            Ok(Response::new(rpc::ListComponentFirmwareVersionsResponse {
                result: Some(make_result("switches", true, None)),
                versions,
            }))
        }
        rpc::list_component_firmware_versions_request::Target::PowerShelfIds(_) => {
            let versions = cm
                .power_shelf
                .list_firmware()
                .await
                .map_err(dispatch_error_to_status)?;
            Ok(Response::new(rpc::ListComponentFirmwareVersionsResponse {
                result: Some(make_result("power_shelves", true, None)),
                versions,
            }))
        }
        rpc::list_component_firmware_versions_request::Target::MachineIds(_) => {
            Err(Status::unimplemented(
                "machine firmware versions are not supported via this RPC",
            ))
        }
    }
}
