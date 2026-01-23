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

use std::sync::atomic::Ordering;

use axum::Router;
use axum::extract::{Json, State};
use axum::response::Response;
use axum::routing::get;
use serde_json::json;

use crate::json::JsonExt;
use crate::mock_machine_router::MockWrapperState;

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(
        "/redfish/v1/Systems/Bluefield/SecureBoot",
        get(get_dpu_secure_boot).patch(patch_dpu_secure_boot),
    )
}

async fn patch_dpu_secure_boot(
    State(mut state): State<MockWrapperState>,
    Json(secure_boot_request): Json<serde_json::Value>,
) -> Response {
    if let Some(v) = secure_boot_request
        .get("SecureBootEnable")
        .and_then(serde_json::Value::as_bool)
    {
        state.bmc_state.set_secure_boot_enabled(v);
    }
    json!({}).into_ok_response()
}

async fn get_dpu_secure_boot(State(state): State<MockWrapperState>) -> Response {
    let secure_boot_enabled = state.bmc_state.secure_boot_enabled.load(Ordering::Relaxed);
    json!(
        {
            "@odata.context": "/redfish/v1/$metadata#SecureBoot.SecureBoot",
            "@odata.id": "/redfish/v1/Systems/Bluefield/SecureBoot",
            "@odata.type": "#SecureBoot.v1_6_0.SecureBoot",
            "Id": "SecureBoot",
            "Name": "UEFI Secure Boot",
            "SecureBootEnable": secure_boot_enabled,
            "SecureBootMode": "UserMode",
            "SecureBootCurrentBoot": if secure_boot_enabled {
                "Enabled"
            } else {
                "Disabled"
            },
        }
    )
    .into_ok_response()
}
