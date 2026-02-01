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

use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;

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

    fn add_str_field(self, name: &str, value: &str) -> Self {
        self.apply_patch(json!({ name: value }))
    }

    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
        }
    }
}
