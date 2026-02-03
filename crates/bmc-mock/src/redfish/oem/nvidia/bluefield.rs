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

use std::borrow::Cow;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, patch, post};
use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::mock_machine_router::MockWrapperState;
use crate::{MachineInfo, redfish};

pub fn resource() -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1/Systems/Bluefield/Oem/Nvidia"),
        odata_type: Cow::Borrowed("#NvidiaComputerSystem.v1_0_0.NvidiaComputerSystem"),
        // Neither BF2 nor BF-3 provide Id & Name in the resource We
        // simulate this behavior by removing these fields from final answer.
        id: Cow::Borrowed(""),
        name: Cow::Borrowed(""),
    }
}
const SYSTEMS_OEM_RESOURCE_DELETE_FIELDS: &[&str] = &["Id", "Name"];

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(&resource().odata_id, get(get_oem_nvidia))
        .route(
            // TODO: This is BF-3 only.
            &format!("{}/Actions/HostRshim.Set", resource().odata_id),
            post(hostrshim_set),
        )
        .route(
            "/redfish/v1/Managers/Bluefield_BMC/Oem/Nvidia",
            patch(patch_managers_oem_nvidia),
        )
}

async fn hostrshim_set() -> Response {
    json!({}).into_ok_response()
}

async fn get_oem_nvidia(State(state): State<MockWrapperState>) -> Response {
    let MachineInfo::Dpu(dpu_machine) = state.machine_info else {
        return json!({}).into_response(StatusCode::NOT_FOUND);
    };
    let mode = if dpu_machine.nic_mode {
        "NicMode"
    } else {
        "DpuMode"
    };
    resource()
        .json_patch()
        .patch(json!({"Mode": mode}))
        .delete_fields(SYSTEMS_OEM_RESOURCE_DELETE_FIELDS)
        .into_ok_response()
}

async fn patch_managers_oem_nvidia() -> Response {
    // This is used by enable_rshim_bmc() of libredfish client.
    json!({}).into_ok_response()
}
