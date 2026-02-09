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
use std::sync::{Arc, atomic};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::redfish::Builder;
use crate::{http, redfish};

pub fn collection() -> redfish::Collection<'static> {
    redfish::Collection {
        odata_id: Cow::Borrowed("/redfish/v1/Managers"),
        odata_type: Cow::Borrowed("#ManagerCollection.ManagerCollection"),
        name: Cow::Borrowed("Manager"),
    }
}

pub fn resource<'a>(manager_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("/redfish/v1/Managers/{manager_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#Manager.v1_12_0.Manager"),
        id: Cow::Borrowed(manager_id),
        name: Cow::Borrowed("Manager"),
    }
}

pub fn reset_target(manager_id: &str) -> String {
    format!("{}/Actions/Manager.Reset", resource(manager_id).odata_id)
}

pub fn builder(resource: &redfish::Resource<'_>) -> ManagerBuilder {
    let reset_target = reset_target(&resource.id);
    ManagerBuilder {
        reset_target,
        value: resource.json_patch(),
    }
}

pub struct ManagerBuilder {
    reset_target: String,
    value: serde_json::Value,
}

impl Builder for ManagerBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            reset_target: self.reset_target,
        }
    }
}

impl ManagerBuilder {
    pub fn ethernet_interfaces(self, collection: redfish::Collection<'_>) -> Self {
        self.apply_patch(collection.nav_property("EthernetInterfaces"))
    }

    pub fn enable_reset_action(self) -> Self {
        let patch = json!({
            "Actions": {
                "#Manager.Reset": {
                    "target": &self.reset_target
                }
            }
        });
        self.apply_patch(patch)
    }

    pub fn log_services(self, collection: redfish::Collection<'_>) -> Self {
        self.apply_patch(collection.nav_property("LogServices"))
    }

    pub fn firmware_version(self, v: &str) -> Self {
        self.add_str_field("FirmwareVersion", v)
    }

    pub fn manager_type(self, v: &str) -> Self {
        self.add_str_field("ManagerType", v)
    }

    pub fn network_protocol(self, resource: redfish::Resource<'_>) -> Self {
        self.apply_patch(resource.nav_property("NetworkProtocol"))
    }

    // TODO: we can use typed UUID here, but all these fields are
    // really not used it just requirements of libredfish model added
    // "just in case"...
    pub fn uuid(self, v: &str) -> Self {
        self.add_str_field("UUID", v)
    }

    pub fn date_time(self, v: DateTime<Utc>) -> Self {
        let current_time = v.format("%Y-%m-%dT%H:%M:%S+00:00").to_string();
        self.add_str_field("DateTime", &current_time)
    }

    pub fn status(self, status: redfish::resource::Status) -> Self {
        self.apply_patch(json!({"Status": status.into_json()}))
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }
}

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    const MGR_ID: &str = "{manager_id}";
    const ETH_ID: &str = "{ethernet_id}";
    r.route(&collection().odata_id, get(get_manager_collection))
        .route(&resource(MGR_ID).odata_id, get(get_manager))
        .route(
            &redfish::ethernet_interface::manager_collection(MGR_ID).odata_id,
            get(get_ethernet_interface_collection),
        )
        .route(
            &redfish::ethernet_interface::manager_resource(MGR_ID, ETH_ID).odata_id,
            get(get_ethernet_interface),
        )
        .route(
            &redfish::manager_network_protocol::manager_resource(MGR_ID).odata_id,
            get(get_network_protocol).patch(patch_network_protocol),
        )
        .route(
            &redfish::log_services::manager_collection(MGR_ID).odata_id,
            get(get_log_services),
        )
}

pub struct Config {
    pub managers: Vec<SingleConfig>,
}

pub struct SingleConfig {
    pub id: &'static str,
    pub eth_interfaces: Vec<redfish::ethernet_interface::EthernetInterface>,
    pub firmware_version: &'static str,
}

pub struct ManagerState {
    managers: Vec<SingleManagerState>,
}

impl ManagerState {
    pub fn new(config: &Config) -> Self {
        Self {
            managers: config
                .managers
                .iter()
                .map(SingleManagerState::new)
                .collect(),
        }
    }

    pub fn find(&self, manager_id: &str) -> Option<&SingleManagerState> {
        self.managers.iter().find(|c| c.id == manager_id)
    }
}

pub struct SingleManagerState {
    id: &'static str,
    eth_interfaces: Vec<redfish::ethernet_interface::EthernetInterface>,
    firmware_version: String,
    ipmi_enabled: Arc<atomic::AtomicBool>,
}

impl SingleManagerState {
    pub fn new(config: &SingleConfig) -> Self {
        Self {
            id: config.id,
            eth_interfaces: config.eth_interfaces.clone(),
            firmware_version: config.firmware_version.to_string(),
            ipmi_enabled: Arc::new(false.into()),
        }
    }
}

async fn get_manager_collection(State(state): State<BmcState>) -> Response {
    collection()
        .with_members(
            &state
                .manager
                .managers
                .iter()
                .map(|manager| resource(manager.id).entity_ref())
                .collect::<Vec<_>>(),
        )
        .into_ok_response()
}

async fn get_manager(State(state): State<BmcState>, Path(manager_id): Path<String>) -> Response {
    let Some(this) = state.manager.find(&manager_id) else {
        return http::not_found();
    };

    builder(&resource(&manager_id))
        .manager_type("BMC")
        .network_protocol(redfish::manager_network_protocol::manager_resource(
            &manager_id,
        ))
        .ethernet_interfaces(redfish::ethernet_interface::manager_collection(&manager_id))
        .enable_reset_action()
        .firmware_version(&this.firmware_version)
        .log_services(redfish::log_services::manager_collection(&manager_id))
        .status(redfish::resource::Status::Ok)
        .uuid("3347314f-c0c6-5080-3410-00354c4c4544")
        .date_time(Utc::now())
        .build()
        .into_ok_response()
}

async fn get_ethernet_interface_collection(
    State(state): State<BmcState>,
    Path(manager_id): Path<String>,
) -> Response {
    let Some(this) = state.manager.find(&manager_id) else {
        return http::not_found();
    };

    let members = this
        .eth_interfaces
        .iter()
        .map(|eth| redfish::ethernet_interface::manager_resource(&manager_id, &eth.id).entity_ref())
        .collect::<Vec<_>>();
    redfish::ethernet_interface::manager_collection(&manager_id)
        .with_members(&members)
        .into_ok_response()
}

async fn get_ethernet_interface(
    State(state): State<BmcState>,
    Path((manager_id, eth_id)): Path<(String, String)>,
) -> Response {
    let Some(this) = state.manager.find(&manager_id) else {
        return http::not_found();
    };
    this.eth_interfaces
        .iter()
        .find(|eth| eth.id == eth_id)
        .map(|eth| eth.to_json().into_ok_response())
        .unwrap_or_else(http::not_found)
}

async fn get_network_protocol(
    State(state): State<BmcState>,
    Path(manager_id): Path<String>,
) -> Response {
    let Some(this) = state.manager.find(&manager_id) else {
        return http::not_found();
    };
    let resource = redfish::manager_network_protocol::manager_resource(&manager_id);
    redfish::manager_network_protocol::builder(&resource)
        .ipmi_enabled(this.ipmi_enabled.load(atomic::Ordering::Relaxed))
        .build()
        .into_ok_response()
}

async fn patch_network_protocol(
    State(state): State<BmcState>,
    Path(manager_id): Path<String>,
    Json(json): Json<serde_json::Value>,
) -> Response {
    let Some(this) = state.manager.find(&manager_id) else {
        return http::not_found();
    };
    if let Some(v) = json
        .get("IPMI")
        .and_then(|v| v.get("ProtocolEnabled"))
        .and_then(serde_json::Value::as_bool)
    {
        this.ipmi_enabled.store(v, atomic::Ordering::Relaxed)
    }
    json!({}).into_ok_response()
}

async fn get_log_services() -> Response {
    not_implemented()
}

fn not_implemented() -> Response {
    json!("").into_response(StatusCode::NOT_IMPLEMENTED)
}
