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
use axum::routing::get;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::redfish;

pub fn resource<'a>() -> redfish::Resource<'a> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1"),
        odata_type: Cow::Borrowed("#ServiceRoot.v1_10_0.ServiceRoot"),
        id: Cow::Borrowed("RootService"),
        name: Cow::Borrowed("Root Service"),
    }
}

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    r.route(&resource().odata_id, get(get_service_root))
}

pub fn builder(resource: &redfish::Resource) -> ServiceRootBuilder {
    ServiceRootBuilder {
        value: resource.json_patch(),
    }
}

async fn get_service_root(State(state): State<BmcState>) -> Response {
    builder(&resource())
        .redfish_version("1.13.1")
        .vendor(state.bmc_vendor.service_root_value())
        .account_service(&redfish::account_service::resource())
        .chassis_collection(&redfish::chassis::collection())
        .system_collection(&redfish::computer_system::collection())
        .update_service(&redfish::update_service::resource())
        .build()
        .into_ok_response()
}

pub struct ServiceRootBuilder {
    value: serde_json::Value,
}

impl ServiceRootBuilder {
    pub fn build(self) -> serde_json::Value {
        self.value
    }

    pub fn redfish_version(self, v: &str) -> Self {
        self.add_str_field("RedfishVersion", v)
    }

    pub fn vendor(self, v: &str) -> Self {
        self.add_str_field("Vendor", v)
    }

    pub fn account_service(self, v: &redfish::Resource<'_>) -> Self {
        self.apply_patch(v.nav_property("AccountService"))
    }

    pub fn chassis_collection(self, v: &redfish::Collection<'_>) -> Self {
        self.apply_patch(v.nav_property("Chassis"))
    }

    pub fn system_collection(self, v: &redfish::Collection<'_>) -> Self {
        self.apply_patch(v.nav_property("Systems"))
    }

    pub fn update_service(self, v: &redfish::Resource<'_>) -> Self {
        self.apply_patch(v.nav_property("UpdateService"))
    }

    fn add_str_field(self, name: &str, value: &str) -> Self {
        self.apply_patch(json!({ name: value }))
    }

    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}
