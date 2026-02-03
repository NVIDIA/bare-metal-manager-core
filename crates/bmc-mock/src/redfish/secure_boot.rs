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

pub fn resource<'a>(system_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!(
        "{}/SecureBoot",
        redfish::computer_system::resource(system_id).odata_id
    );
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#SecureBoot.v1_1_0.SecureBoot"),
        id: Cow::Borrowed("SecureBoot"),
        name: Cow::Borrowed("UEFI Secure Boot"),
    }
}

pub fn builder(resource: &redfish::Resource) -> SecureBootBuilder {
    SecureBootBuilder {
        value: resource.json_patch(),
    }
}

pub struct SecureBootBuilder {
    value: serde_json::Value,
}

impl SecureBootBuilder {
    pub fn secure_boot_enable(self, v: bool) -> Self {
        self.apply_patch(json!({"SecureBootEnable": v}))
    }

    pub fn secure_boot_current_boot(self, enabled: bool) -> Self {
        if enabled {
            self.add_str_field("SecureBootCurrentBoot", "Enabled")
        } else {
            self.add_str_field("SecureBootCurrentBoot", "Disabled")
        }
    }

    pub fn build(self) -> serde_json::Value {
        self.value
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
