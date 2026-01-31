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
use axum::response::Response;
use axum::routing::get;
use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::mock_machine_router::MockWrapperState;
use crate::redfish;

pub fn resource<'a>() -> redfish::Resource<'a> {
    redfish::Resource {
        odata_id: Cow::Borrowed("/redfish/v1"),
        odata_type: Cow::Borrowed("#ServiceRoot.v1_10_0.ServiceRoot"),
        id: Cow::Borrowed("RootService"),
        name: Cow::Borrowed("Root Service"),
    }
}

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    r.route(&resource().odata_id, get(get_service_root))
}

pub fn builder(resource: &redfish::Resource) -> ServiceRootBuilder {
    ServiceRootBuilder {
        value: resource.json_patch(),
    }
}

async fn get_service_root(State(state): State<MockWrapperState>) -> Response {
    builder(&resource())
        .redfish_version("1.13.1")
        .vendor(state.bmc_state.bmc_vendor.service_root_value())
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
