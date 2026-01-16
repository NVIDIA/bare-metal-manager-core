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
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::HeaderValue;
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use http_body_util::BodyExt;
use serde_json::json;

use crate::MachineInfo;
use crate::json::{JsonExt, json_patch};
use crate::mock_machine_router::{MockWrapperError, MockWrapperResult, MockWrapperState};

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

async fn change_password_action(Path(_system_id): Path<String>) -> impl IntoResponse {
    json!({}).into_ok_response()
}

async fn get_dpu_bios(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    // We only rewrite this line if it's a DPU we're mocking
    let MachineInfo::Dpu(dpu) = state.machine_info else {
        return Ok(inner_response);
    };
    let inner_bios = serde_json::from_slice(inner_response.as_ref())?;
    let patched_bios = state.bmc_state.get_bios(inner_bios);

    // For DPUs in NicMode, rewrite the BIOS attributes to reflect as such
    if dpu.nic_mode {
        let serde_json::Value::Object(mut bios) = patched_bios else {
            tracing::error!(
                "Invalid JSON response, expected object, got {:?}",
                inner_response
            );
            return Ok(inner_response);
        };

        let Some(serde_json::Value::Object(attributes)) = bios.get_mut("Attributes") else {
            tracing::error!(
                "Invalid Attributes, expected object, got {:?}",
                inner_response
            );
            return Ok(inner_response);
        };

        if attributes.get("NicMode").is_none() {
            tracing::warn!(
                "DPU BIOS Attributes.NicMode is not present: {:?}",
                inner_response
            )
        }

        attributes.insert(
            "NicMode".to_string(),
            serde_json::Value::String("NicMode".to_string()),
        );
        Ok(Bytes::from(serde_json::to_string(&bios)?))
    } else {
        Ok(Bytes::from(serde_json::to_string(&patched_bios)?))
    }
}

async fn get_bios(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let inner_bios = serde_json::from_slice(inner_response.as_ref())?;
    let patched_bios = state.bmc_state.get_bios(inner_bios);
    Ok(Bytes::from(serde_json::to_string(&patched_bios)?))
}

async fn patch_bios_settings(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> impl IntoResponse {
    // TODO: this is Dell-specific implementation. Need to be
    // refactoried to be generic.

    // Dell password change, needs a job ID to be returned in the Location: header
    let body = match request.into_body().collect().await.map(|v| v.to_bytes()) {
        Ok(v) => v,
        Err(err) => return MockWrapperError::from(err).into_response(),
    };
    let mut patch_bios_request: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(err) => return MockWrapperError::from(err).into_response(),
    };
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
    if tpm2_clear_to_enabled {
        json_patch(
            &mut patch_bios_request,
            serde_json::json!({ATTRIBUTES: {
                TPM2_HIERARCHY: "Enabled"
            }}),
        );
    }
    state.bmc_state.update_bios(patch_bios_request);
    json!({}).into_ok_response_with_location(HeaderValue::from_static(
        "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/JID_00000000001",
    ))
}

async fn patch_dpu_bios(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> MockWrapperResult {
    let body = request.into_body().collect().await?.to_bytes();
    let patch_bios_request: serde_json::Value = serde_json::from_slice(&body)?;
    state.bmc_state.update_bios(patch_bios_request);
    Ok(Bytes::from(""))
}
