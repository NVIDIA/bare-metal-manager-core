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
use crate::redfish::Builder;

pub fn manager_collection(manager_id: &str) -> redfish::Collection<'static> {
    redfish::Collection {
        odata_id: Cow::Owned(format!(
            "/redfish/v1/Managers/{manager_id}/SerialInterfaces"
        )),
        odata_type: Cow::Borrowed("#SerialInterfaceCollection.SerialInterfaceCollection"),
        name: Cow::Borrowed("Serial Interface Collection"),
    }
}

pub fn manager_resource<'a>(manager_id: &'a str, interface_id: &'a str) -> redfish::Resource<'a> {
    redfish::Resource {
        odata_id: Cow::Owned(format!(
            "/redfish/v1/Managers/{manager_id}/SerialInterfaces/{interface_id}"
        )),
        odata_type: Cow::Borrowed("#SerialInterface.v1_1_7.SerialInterface"),
        id: Cow::Borrowed(interface_id),
        name: Cow::Borrowed("SerialInterface"),
    }
}

#[derive(Clone)]
pub struct SerialInterface {
    pub id: Cow<'static, str>,
    value: serde_json::Value,
}

impl SerialInterface {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub fn builder(resource: &redfish::Resource) -> SerialInterfaceBuilder {
    SerialInterfaceBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
    }
}

pub struct SerialInterfaceBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Builder for SerialInterfaceBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            id: self.id,
            value: self.value.patch(patch),
        }
    }
}

impl SerialInterfaceBuilder {
    pub fn description(self, value: &str) -> Self {
        self.add_str_field("Description", value)
    }

    pub fn interface_enabled(self, value: bool) -> Self {
        self.apply_patch(json!({ "InterfaceEnabled": value }))
    }

    pub fn signal_type(self, value: &str) -> Self {
        self.add_str_field("SignalType", value)
    }

    pub fn bit_rate(self, value: &str) -> Self {
        self.add_str_field("BitRate", value)
    }

    pub fn parity(self, value: &str) -> Self {
        self.add_str_field("Parity", value)
    }

    pub fn data_bits(self, value: &str) -> Self {
        self.add_str_field("DataBits", value)
    }

    pub fn stop_bits(self, value: &str) -> Self {
        self.add_str_field("StopBits", value)
    }

    pub fn flow_control(self, value: &str) -> Self {
        self.add_str_field("FlowControl", value)
    }

    pub fn connector_type(self, value: &str) -> Self {
        self.add_str_field("ConnectorType", value)
    }

    pub fn pin_out(self, value: &str) -> Self {
        self.add_str_field("PinOut", value)
    }

    pub fn build(self) -> SerialInterface {
        SerialInterface {
            id: self.id,
            value: self.value,
        }
    }
}
