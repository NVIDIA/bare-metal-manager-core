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
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::redfish::Builder;
use crate::{http, redfish};

pub fn resource<'a>() -> redfish::Resource<'a> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1/UpdateService"),
        odata_type: Cow::Borrowed("#UpdateService.v1_9_0.UpdateService"),
        id: Cow::Borrowed("UpdateService"),
        name: Cow::Borrowed("Update Service"),
    }
}

pub fn builder(resource: &redfish::Resource) -> UpdateServiceBuilder {
    UpdateServiceBuilder {
        value: resource.json_patch(),
    }
}

pub fn simple_update_target() -> String {
    format!("{}/Actions/UpdateService.SimpleUpdate", resource().odata_id)
}

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    const FW_INVENTORY_ID: &str = "{fw_inventory_id}";
    r.route(&resource().odata_id, get(get_update_service))
        .route(&simple_update_target(), post(update_firmware_simple_update))
        .route(
            &redfish::software_inventory::firmware_inventory_collection().odata_id,
            get(get_firmware_inventory_collection),
        )
        .route(
            &redfish::software_inventory::firmware_inventory_resource(FW_INVENTORY_ID).odata_id,
            get(get_firmware_inventory_resource),
        )
}

pub struct UpdateServiceConfig {
    pub firmware_inventory: Vec<redfish::software_inventory::SoftwareInventory>,
}

pub struct UpdateServiceState {
    firmware_inventory: Vec<redfish::software_inventory::SoftwareInventory>,
}

impl UpdateServiceState {
    pub fn from_config(config: UpdateServiceConfig) -> Self {
        Self {
            firmware_inventory: config.firmware_inventory,
        }
    }

    pub fn find_firmware_inventory(
        &self,
        id: &str,
    ) -> Option<&redfish::software_inventory::SoftwareInventory> {
        self.firmware_inventory.iter().find(|v| v.id == id)
    }
}

async fn get_update_service() -> Response {
    builder(&resource())
        .firmware_inventory(&redfish::software_inventory::firmware_inventory_collection())
        .build()
        .into_ok_response()
}

async fn update_firmware_simple_update() -> Response {
    redfish::task_service::update_firmware_simple_update_task()
}

async fn get_firmware_inventory_collection(State(state): State<BmcState>) -> Response {
    let members = state
        .update_service_state
        .firmware_inventory
        .iter()
        .map(|sw| redfish::software_inventory::firmware_inventory_resource(&sw.id).entity_ref())
        .collect::<Vec<_>>();
    redfish::software_inventory::firmware_inventory_collection()
        .with_members(&members)
        .into_ok_response()
}

async fn get_firmware_inventory_resource(
    State(state): State<BmcState>,
    Path(fw_inventory_id): Path<String>,
) -> Response {
    state
        .update_service_state
        .find_firmware_inventory(&fw_inventory_id)
        .map(|fw_inv| fw_inv.to_json().into_ok_response())
        .unwrap_or_else(http::not_found)
}

pub struct UpdateServiceBuilder {
    value: serde_json::Value,
}

impl Builder for UpdateServiceBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}

impl UpdateServiceBuilder {
    pub fn build(self) -> serde_json::Value {
        self.value
    }

    pub fn firmware_inventory(self, v: &redfish::Collection<'_>) -> Self {
        self.apply_patch(v.nav_property("FirmwareInventory"))
    }
}
