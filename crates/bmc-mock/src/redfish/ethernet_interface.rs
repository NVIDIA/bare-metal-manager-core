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

use mac_address::MacAddress;
use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;
use crate::redfish::Builder;

pub fn manager_collection(manager_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Managers/{manager_id}/EthernetInterfaces");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#EthernetInterfaceCollection.EthernetInterfaceCollection"),
        name: Cow::Borrowed("Ethernet Network Interface Collection"),
    }
}

pub fn manager_resource<'a>(manager_id: &'a str, iface_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("/redfish/v1/Managers/{manager_id}/EthernetInterfaces/{iface_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#EthernetInterface.v1_6_0.EthernetInterface"),
        id: Cow::Borrowed(iface_id),
        name: Cow::Borrowed("Manager Ethernet Interface"),
    }
}

pub fn system_collection(system_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}/EthernetInterfaces");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#EthernetInterfaceCollection.EthernetInterfaceCollection"),
        name: Cow::Borrowed("Ethernet Network Interface Collection"),
    }
}

pub fn system_resource<'a>(system_id: &str, iface_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}/EthernetInterfaces/{iface_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#EthernetInterface.v1_6_0.EthernetInterface"),
        id: Cow::Borrowed(iface_id),
        name: Cow::Borrowed("System Ethernet Interface"),
    }
}

pub fn builder(resource: &redfish::Resource) -> EthernetInterfaceBuilder {
    EthernetInterfaceBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
    }
}

#[derive(Clone)]
pub struct EthernetInterface {
    pub id: Cow<'static, str>,
    value: serde_json::Value,
}

impl EthernetInterface {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub struct EthernetInterfaceBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Builder for EthernetInterfaceBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
        }
    }
}

impl EthernetInterfaceBuilder {
    pub fn mac_address(self, addr: MacAddress) -> Self {
        self.add_str_field("MACAddress", &addr.to_string())
    }

    pub fn interface_enabled(self, v: bool) -> Self {
        self.apply_patch(json!({ "InterfaceEnabled": v }))
    }

    pub fn description(self, v: &str) -> Self {
        self.add_str_field("Description", v)
    }

    pub fn build(self) -> EthernetInterface {
        EthernetInterface {
            id: self.id,
            value: self.value,
        }
    }
}
