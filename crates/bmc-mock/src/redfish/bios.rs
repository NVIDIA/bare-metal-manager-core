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
use axum::extract::{Json, Path, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use serde_json::json;

use crate::json::JsonExt;
use crate::mock_machine_router::MockWrapperState;
use crate::{MachineInfo, redfish};

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(
        "/redfish/v1/Systems/{system_id}/Bios/Actions/Bios.ChangePassword",
        post(change_password_action),
    )
    .route("/redfish/v1/Systems/Bluefield/Bios", get(get_dpu_bios))
    .route("/redfish/v1/Systems/{system_id}/Bios", get(get_bios))
    .route(
        "/redfish/v1/Systems/Bluefield/Bios/Settings",
        patch(patch_dpu_bios),
    )
    .route(
        "/redfish/v1/Systems/{system_id}/Bios/Settings",
        patch(patch_bios_settings),
    )
}

async fn change_password_action(Path(_system_id): Path<String>) -> Response {
    json!({}).into_ok_response()
}

async fn get_dpu_bios(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> Response {
    state
        .call_inner_router(request)
        .await
        .map(|inner_bios| {
            // We only rewrite this line if it's a DPU we're mocking
            let MachineInfo::Dpu(dpu) = state.machine_info else {
                return inner_bios.into_ok_response();
            };
            let patched_bios = state.bmc_state.get_bios(inner_bios);
            // For DPUs in NicMode, rewrite the BIOS attributes to reflect as such
            let mode = if dpu.nic_mode { "NicMode" } else { "DpuMode" };
            patched_bios
                .patch(json!({"Attributes": {"NicMode": mode}}))
                .into_ok_response()
        })
        .unwrap_or_else(|err| err.into_response())
}

async fn get_bios(State(mut state): State<MockWrapperState>, request: Request<Body>) -> Response {
    state
        .call_inner_router(request)
        .await
        .map(|inner_bios| state.bmc_state.get_bios(inner_bios).into_ok_response())
        .unwrap_or_else(|err| err.into_response())
}

async fn patch_bios_settings(
    State(mut state): State<MockWrapperState>,
    Json(patch_bios_request): Json<serde_json::Value>,
) -> Response {
    // TODO: this is Dell-specific implementation. Need to be
    // refactoried to be generic.
    // Clear is transformed to Enabled state after reboot. Check if we
    // need to apply this logic here.
    const TPM2_HIERARCHY: &str = "Tpm2Hierarchy";
    const ATTRIBUTES: &str = "Attributes";
    let tpm2_clear_to_enabled = patch_bios_request
        .as_object()
        .and_then(|obj| obj.get(ATTRIBUTES))
        .and_then(|v| v.as_object())
        .and_then(|obj| obj.get(TPM2_HIERARCHY))
        .and_then(|v| v.as_str())
        .is_some_and(|v| v == "Clear");
    let patch_bios_request = if tpm2_clear_to_enabled {
        patch_bios_request.patch(json!({ATTRIBUTES: {
            TPM2_HIERARCHY: "Enabled"
        }}))
    } else {
        patch_bios_request
    };
    state.bmc_state.update_bios(patch_bios_request);
    redfish::oem::dell::idrac::create_job_with_location(state)
}

async fn patch_dpu_bios(
    State(mut state): State<MockWrapperState>,
    Json(patch_bios_request): Json<serde_json::Value>,
) -> Response {
    state.bmc_state.update_bios(patch_bios_request);
    json!({}).into_ok_response()
}
