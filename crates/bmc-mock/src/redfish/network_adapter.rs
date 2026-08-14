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
use crate::redfish::Builder;
use crate::{hw, redfish};

const NETWORK_ADAPTER_TYPE: &str = "#NetworkAdapter.v1_7_0.NetworkAdapter";
const NETWORK_ADAPTER_NAME: &str = "Network Adapter";

pub(crate) fn chassis_resource(chassis_id: &str, adapter_id: &str) -> redfish::Resource<'static> {
    let odata_id = format!("/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/{adapter_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed(NETWORK_ADAPTER_TYPE),
        id: Cow::Owned(adapter_id.into()),
        name: Cow::Borrowed(NETWORK_ADAPTER_NAME),
    }
}

pub(crate) fn port_resource(
    chassis_id: &str,
    adapter_id: &str,
    port_id: &str,
) -> redfish::Resource<'static> {
    let odata_id =
        format!("/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/{adapter_id}/Ports/{port_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#Port.v1_6_0.Port"),
        id: Cow::Owned(port_id.into()),
        name: Cow::Borrowed("Port"),
    }
}

pub(crate) fn port_collection(chassis_id: &str, adapter_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Chassis/{chassis_id}/NetworkAdapters/{adapter_id}/Ports");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#PortCollection.PortCollection"),
        name: Cow::Borrowed("Port Collection"),
    }
}

pub(super) fn chassis_collection(chassis_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Chassis/{chassis_id}/NetworkAdapters");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#NetworkAdapterCollection.NetworkAdapterCollection"),
        name: Cow::Borrowed("Network Adapter Collection"),
    }
}

pub(crate) struct NetworkAdapter {
    pub(crate) id: Cow<'static, str>,
    value: serde_json::Value,
    pub(crate) functions: Vec<redfish::network_device_function::NetworkDeviceFunction>,
    pub(crate) ports: Vec<Port>,
}

impl NetworkAdapter {
    pub(crate) fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
    pub(crate) fn find_function(
        &self,
        function_id: &str,
    ) -> Option<&redfish::network_device_function::NetworkDeviceFunction> {
        self.functions.iter().find(|f| f.id.as_ref() == function_id)
    }

    pub(crate) fn find_port(&self, port_id: &str) -> Option<&Port> {
        self.ports.iter().find(|port| port.id.as_ref() == port_id)
    }
}

pub(crate) struct Port {
    pub(crate) id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Port {
    pub(crate) fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub(crate) fn port_builder(resource: &redfish::Resource) -> PortBuilder {
    PortBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
    }
}

pub(crate) struct PortBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Builder for PortBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            id: self.id,
            value: self.value.patch(patch),
        }
    }
}

impl PortBuilder {
    pub(crate) fn lenovo_physical_mac_address(self, mac_address: mac_address::MacAddress) -> Self {
        self.apply_patch(json!({
            "Oem": {
                "Lenovo": {
                    "PhysicalPortMacAddress": mac_address,
                }
            }
        }))
    }

    pub(crate) fn build(self) -> Port {
        Port {
            id: self.id,
            value: self.value,
        }
    }
}

/// Get builder of the network adapter.
pub(crate) fn builder(resource: &redfish::Resource) -> NetworkAdapterBuilder {
    NetworkAdapterBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
        functions: Vec::new(),
        ports: Vec::new(),
    }
}

pub(crate) fn builder_from_nic(
    resource: &redfish::Resource,
    nic: &hw::nic::Nic,
) -> NetworkAdapterBuilder {
    builder(resource)
        .maybe_with(NetworkAdapterBuilder::serial_number, &nic.serial_number)
        .maybe_with(NetworkAdapterBuilder::description, &nic.description)
        .maybe_with(NetworkAdapterBuilder::manufacturer, &nic.manufacturer)
        .maybe_with(NetworkAdapterBuilder::model, &nic.model)
        .maybe_with(NetworkAdapterBuilder::part_number, &nic.part_number)
}

pub(crate) struct NetworkAdapterBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
    functions: Vec<redfish::network_device_function::NetworkDeviceFunction>,
    ports: Vec<Port>,
}

impl Builder for NetworkAdapterBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
            functions: self.functions,
            ports: self.ports,
        }
    }
}

impl NetworkAdapterBuilder {
    pub(crate) fn manufacturer(self, value: &str) -> Self {
        self.add_str_field("Manufacturer", value)
    }

    pub(crate) fn model(self, value: &str) -> Self {
        self.add_str_field("Model", value)
    }

    pub(crate) fn part_number(self, value: &str) -> Self {
        self.add_str_field("PartNumber", value)
    }

    pub(crate) fn serial_number(self, value: &str) -> Self {
        self.add_str_field("SerialNumber", value)
    }

    pub(crate) fn description(self, value: &str) -> Self {
        self.add_str_field("Description", value)
    }

    pub(crate) fn network_device_functions(
        self,
        collection: &redfish::Collection<'_>,
        functions: Vec<redfish::network_device_function::NetworkDeviceFunction>,
    ) -> Self {
        let mut v = self.apply_patch(collection.nav_property("NetworkDeviceFunctions"));
        v.functions = functions;
        v
    }

    pub(crate) fn ports(self, collection: &redfish::Collection<'_>, ports: Vec<Port>) -> Self {
        let mut value = self.apply_patch(collection.nav_property("Ports"));
        value.ports = ports;
        value
    }

    pub(crate) fn status(self, status: redfish::resource::Status) -> Self {
        self.apply_patch(json!({
            "Status": status.into_json()
        }))
    }

    pub(crate) fn build(self) -> NetworkAdapter {
        NetworkAdapter {
            id: self.id,
            value: self.value,
            functions: self.functions,
            ports: self.ports,
        }
    }
}
