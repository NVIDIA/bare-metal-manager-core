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

pub fn resource<'a>(system_id: &str) -> redfish::Resource<'a> {
    let odata_id = format!(
        "{}/Bios",
        redfish::computer_system::resource(system_id).odata_id
    );
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#Bios.v1_2_0.Bios"),
        name: Cow::Borrowed("BIOS Configuration"),
        id: Cow::Borrowed("BIOS"),
    }
}

pub fn change_password_target(resource: &redfish::Resource<'_>) -> String {
    format!("{}/Actions/Bios.ChangePassword", resource.odata_id)
}

pub fn builder(resource: &redfish::Resource) -> BiosBuilder {
    BiosBuilder {
        value: resource.json_patch(),
    }
}

pub struct BiosBuilder {
    value: serde_json::Value,
}

impl BiosBuilder {
    pub fn attributes(self, value: serde_json::Value) -> Self {
        self.apply_patch(json!({"Attributes": value}))
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }

    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}
