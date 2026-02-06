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

use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;

const NETWORK_ADAPTER_TYPE: &str = "#NetworkAdapter.v1_7_0.NetworkAdapter";
const NETWORK_ADAPTER_NAME: &str = "Network Adapter";

pub fn chassis_resource(chassis_id: &str, adapter_id: &str) -> redfish::Resource<'static> {
    let odata_id = format!("/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/{adapter_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed(NETWORK_ADAPTER_TYPE),
        id: Cow::Owned(adapter_id.into()),
        name: Cow::Borrowed(NETWORK_ADAPTER_NAME),
    }
}

pub fn chassis_collection(chassis_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Chassis/{chassis_id}/NetworkAdapters");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#NetworkAdapterCollection.NetworkAdapterCollection"),
        name: Cow::Borrowed("Network Adapter Collection"),
    }
}

pub struct NetworkAdapter {
    pub id: Cow<'static, str>,
    value: serde_json::Value,
    pub functions: Vec<redfish::network_device_function::NetworkDeviceFunction>,
}

impl NetworkAdapter {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
    pub fn find_function(
        &self,
        function_id: &str,
    ) -> Option<&redfish::network_device_function::NetworkDeviceFunction> {
        self.functions.iter().find(|f| f.id.as_ref() == function_id)
    }
}

/// Get builder of the network adapter.
pub fn builder(resource: &redfish::Resource) -> NetworkAdapterBuilder {
    NetworkAdapterBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
        functions: Vec::new(),
    }
}

pub struct NetworkAdapterBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
    functions: Vec<redfish::network_device_function::NetworkDeviceFunction>,
}

impl NetworkAdapterBuilder {
    pub fn manufacturer(self, value: &str) -> Self {
        self.add_str_field("Manufacturer", value)
    }

    pub fn model(self, value: &str) -> Self {
        self.add_str_field("Model", value)
    }

    pub fn part_number(self, value: &str) -> Self {
        self.add_str_field("PartNumber", value)
    }

    pub fn serial_number(self, value: &str) -> Self {
        self.add_str_field("SerialNumber", value)
    }

    pub fn sku(self, value: &str) -> Self {
        self.add_str_field("SKU", value)
    }

    pub fn network_device_functions(
        self,
        collection: &redfish::Collection<'_>,
        functions: Vec<redfish::network_device_function::NetworkDeviceFunction>,
    ) -> Self {
        let mut v = self.apply_patch(collection.nav_property("NetworkDeviceFunctions"));
        v.functions = functions;
        v
    }

    pub fn status(self, status: redfish::resource::Status) -> Self {
        self.apply_patch(json!({
            "Status": status.into_json()
        }))
    }

    pub fn build(self) -> NetworkAdapter {
        NetworkAdapter {
            id: self.id,
            value: self.value,
            functions: self.functions,
        }
    }

    fn add_str_field(self, name: &str, value: &str) -> Self {
        self.apply_patch(json!({ name: value }))
    }

    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
            functions: self.functions,
        }
    }
}
