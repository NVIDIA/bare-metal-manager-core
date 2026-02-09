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

use std::borrow::Cow;

use axum::Router;
use axum::extract::State;
use axum::response::Response;
use axum::routing::{get, patch, post};
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::{http, redfish};

#[derive(Clone)]
pub struct BluefieldState {
    nic_mode: bool,
}

impl BluefieldState {
    pub fn new(nic_mode: bool) -> Self {
        Self { nic_mode }
    }
}

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

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
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

async fn get_oem_nvidia(State(state): State<BmcState>) -> Response {
    let redfish::oem::State::NvidiaBluefield(state) = state.oem_state else {
        return http::not_found();
    };
    let mode = if state.nic_mode { "NicMode" } else { "DpuMode" };
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
