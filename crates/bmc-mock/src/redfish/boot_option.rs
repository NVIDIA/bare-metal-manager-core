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

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;
use crate::redfish::Builder;

pub fn collection(system_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!(
        "{}/BootOptions",
        redfish::computer_system::resource(system_id).odata_id
    );
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#BootOptionCollection.BootOptionCollection"),
        name: Cow::Borrowed("Boot Options Collection"),
    }
}

pub fn resource<'a>(system_id: &str, boot_option_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("{}/{boot_option_id}", collection(system_id).odata_id);
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#BootOption.v1_0_4.BootOption"),
        name: Cow::Borrowed("Uefi Boot Option"),
        id: Cow::Borrowed(boot_option_id),
    }
}

pub fn builder(resource: &redfish::Resource) -> BootOptionBuilder {
    BootOptionBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
    }
}

pub struct BootOption {
    pub id: Cow<'static, str>,
    value: serde_json::Value,
}

impl BootOption {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub struct BootOptionBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Builder for BootOptionBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
        }
    }
}

impl BootOptionBuilder {
    pub fn display_name(self, value: &str) -> Self {
        self.add_str_field("DisplayName", value)
    }

    pub fn boot_option_reference(self, value: &str) -> Self {
        self.add_str_field("BootOptionReference", value)
    }

    pub fn uefi_device_path(self, value: &str) -> Self {
        self.add_str_field("UefiDevicePath", value)
    }

    pub fn build(self) -> BootOption {
        BootOption {
            id: self.id,
            value: self.value,
        }
    }
}
