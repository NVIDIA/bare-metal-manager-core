/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;

use crate::json::JsonExt;
use crate::mock_machine_router::MockWrapperState;
use crate::{DpuMachineInfo, MachineInfo, redfish};

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(
        "/redfish/v1/UpdateService/FirmwareInventory/DPU_SYS_IMAGE",
        get(get_dpu_sys_image),
    )
    .route(
        "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate",
        post(update_firmware_simple_update),
    )
    .route(
        "/redfish/v1/UpdateService/FirmwareInventory/BMC_Firmware",
        get(get_dpu_bmc_firmware),
    )
    .route(
        "/redfish/v1/UpdateService/FirmwareInventory/Bluefield_FW_ERoT",
        get(get_dpu_erot_firmware),
    )
    .route(
        "/redfish/v1/UpdateService/FirmwareInventory/DPU_UEFI",
        get(get_dpu_uefi_firmware),
    )
    .route(
        "/redfish/v1/UpdateService/FirmwareInventory/DPU_NIC",
        get(get_dpu_nic_firmware),
    )
}

async fn get_dpu_sys_image(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> Response {
    state
        .call_inner_router(request)
        .await
        .map(|json| {
            // We only rewrite this line if it's a DPU we're mocking
            match state.machine_info {
                MachineInfo::Dpu(dpu) => {
                    let base_mac = dpu.host_mac_address.to_string().replace(':', "");
                    let version = format!(
                        "{}:{}00:00{}:{}",
                        &base_mac[0..4],
                        &base_mac[4..6],
                        &base_mac[6..8],
                        &base_mac[8..12]
                    );
                    json.patch(json!({ "Version": version }))
                }
                _ => json,
            }
            .into_ok_response()
        })
        .unwrap_or_else(|err| err.into_response())
}

async fn update_firmware_simple_update() -> Response {
    redfish::task_service::update_firmware_simple_update_task()
}

async fn get_dpu_firmware(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
    fw_name: &str,
    version: impl FnOnce(&DpuMachineInfo) -> Option<&String>,
) -> Response {
    state
        .call_inner_router(request)
        .await
        .map(|json| {
            match state.machine_info {
                MachineInfo::Dpu(dpu_machine) => {
                    match version(&dpu_machine) {
                        Some(desired_version) => {
                            json.patch(json!({"Version": desired_version }))
                        }
                        None => {
                            tracing::debug!(
                                "Unknown desired {fw_name} firmware version for {}, not rewriting response",
                                dpu_machine.serial
                            );
                            json
                        }
                    }
                }
                _ => json
            }.into_ok_response()
        })
        .unwrap_or_else(|err| err.into_response())
}

async fn get_dpu_bmc_firmware(state: State<MockWrapperState>, request: Request<Body>) -> Response {
    get_dpu_firmware(state, request, "BMC", |m| m.firmware_versions.bmc.as_ref()).await
}

async fn get_dpu_erot_firmware(state: State<MockWrapperState>, request: Request<Body>) -> Response {
    get_dpu_firmware(state, request, "CEC", |m| m.firmware_versions.cec.as_ref()).await
}

async fn get_dpu_uefi_firmware(state: State<MockWrapperState>, request: Request<Body>) -> Response {
    get_dpu_firmware(state, request, "UEFI", |m| {
        m.firmware_versions.uefi.as_ref()
    })
    .await
}

async fn get_dpu_nic_firmware(state: State<MockWrapperState>, request: Request<Body>) -> Response {
    get_dpu_firmware(state, request, "NIC", |m| m.firmware_versions.nic.as_ref()).await
}
