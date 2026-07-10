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
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Json, Path, State};
use axum::response::Response;
use axum::routing::get;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::{http, redfish};

#[derive(Clone)]
pub struct SupermicroState {
    kcs_interface: Arc<Mutex<serde_json::Value>>,
    sys_lockdown: Arc<Mutex<serde_json::Value>>,
}

impl Default for SupermicroState {
    fn default() -> Self {
        Self {
            kcs_interface: Arc::new(Mutex::new(json!({
                "Privilege": "Administrator",
            }))),
            sys_lockdown: Arc::new(Mutex::new(json!({
                "SysLockdownEnabled": false,
            }))),
        }
    }
}

impl SupermicroState {
    fn kcs_interface(&self, base: serde_json::Value) -> serde_json::Value {
        base.patch(self.kcs_interface.lock().expect("mutex poisoned").clone())
    }

    fn patch_kcs_interface(&self, patch: serde_json::Value) {
        let mut current = self.kcs_interface.lock().expect("mutex poisoned");
        *current = current.clone().patch(patch);
    }

    fn sys_lockdown(&self, base: serde_json::Value) -> serde_json::Value {
        base.patch(self.sys_lockdown.lock().expect("mutex poisoned").clone())
    }

    fn patch_sys_lockdown(&self, patch: serde_json::Value) {
        let mut current = self.sys_lockdown.lock().expect("mutex poisoned");
        *current = current.clone().patch(patch);
    }
}

pub fn kcs_interface_resource(manager_id: &str) -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Owned(format!(
            "/redfish/v1/Managers/{manager_id}/Oem/Supermicro/KCSInterface"
        )),
        odata_type: Cow::Borrowed("#KCSInterface.v1_0_0.KCSInterface"),
        id: Cow::Borrowed("KCSInterface"),
        name: Cow::Borrowed("KCS Interface"),
    }
}

pub fn sys_lockdown_resource(manager_id: &str) -> redfish::Resource<'static> {
    redfish::Resource {
        odata_id: Cow::Owned(format!(
            "/redfish/v1/Managers/{manager_id}/Oem/Supermicro/SysLockdown"
        )),
        odata_type: Cow::Borrowed("#SysLockdown.v1_0_0.SysLockdown"),
        id: Cow::Borrowed("SysLockdown"),
        name: Cow::Borrowed("System Lockdown"),
    }
}

pub fn manager_oem_patch(manager_id: &str) -> serde_json::Value {
    json!({
        "Oem": {
            "Supermicro": {
                "KCSInterface": kcs_interface_resource(manager_id).entity_ref(),
                "SysLockdown": sys_lockdown_resource(manager_id).entity_ref(),
            }
        }
    })
}

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    r.route(
        "/redfish/v1/Managers/{manager_id}/Oem/Supermicro/KCSInterface",
        get(get_kcs_interface).patch(patch_kcs_interface),
    )
    .route(
        "/redfish/v1/Managers/{manager_id}/Oem/Supermicro/SysLockdown",
        get(get_sys_lockdown).patch(patch_sys_lockdown),
    )
}

async fn get_kcs_interface(
    State(state): State<BmcState>,
    Path(manager_id): Path<String>,
) -> Response {
    let redfish::oem::State::Supermicro(supermicro) = state.oem_state else {
        return http::not_found();
    };
    if state.manager.find(&manager_id).is_none() {
        return http::not_found();
    }
    supermicro
        .kcs_interface(kcs_interface_resource(&manager_id).json_patch())
        .into_ok_response()
}

async fn patch_kcs_interface(
    State(state): State<BmcState>,
    Path(manager_id): Path<String>,
    Json(patch): Json<serde_json::Value>,
) -> Response {
    let redfish::oem::State::Supermicro(supermicro) = state.oem_state else {
        return http::not_found();
    };
    if state.manager.find(&manager_id).is_none() {
        return http::not_found();
    }
    supermicro.patch_kcs_interface(patch);
    http::ok_no_content()
}

async fn get_sys_lockdown(
    State(state): State<BmcState>,
    Path(manager_id): Path<String>,
) -> Response {
    let redfish::oem::State::Supermicro(supermicro) = state.oem_state else {
        return http::not_found();
    };
    if state.manager.find(&manager_id).is_none() {
        return http::not_found();
    }
    supermicro
        .sys_lockdown(sys_lockdown_resource(&manager_id).json_patch())
        .into_ok_response()
}

async fn patch_sys_lockdown(
    State(state): State<BmcState>,
    Path(manager_id): Path<String>,
    Json(patch): Json<serde_json::Value>,
) -> Response {
    let redfish::oem::State::Supermicro(supermicro) = state.oem_state else {
        return http::not_found();
    };
    if state.manager.find(&manager_id).is_none() {
        return http::not_found();
    }
    supermicro.patch_sys_lockdown(patch);
    http::ok_no_content()
}
