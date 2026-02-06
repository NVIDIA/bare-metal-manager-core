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

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;
use crate::redfish::Builder;

pub fn firmware_inventory_collection() -> redfish::Collection<'static> {
    let odata_id = format!(
        "{}/FirmwareInventory",
        redfish::update_service::resource().odata_id
    );
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#SoftwareInventoryCollection.SoftwareInventoryCollection"),
        name: Cow::Borrowed("Collection of Firmware Inventory"),
    }
}

pub fn firmware_inventory_resource<'a>(id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("{}/{id}", firmware_inventory_collection().odata_id);
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#SoftwareInventory.v1_4_0.SoftwareInventory"),
        name: Cow::Borrowed("Firmware Inventory Item"),
        id: Cow::Borrowed(id),
    }
}

/// Generate resource bound to chassis.
pub fn builder(resource: &redfish::Resource) -> SoftwareInventoryBuilder {
    SoftwareInventoryBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
    }
}

pub struct SoftwareInventory {
    pub id: Cow<'static, str>,
    value: serde_json::Value,
}

impl SoftwareInventory {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub struct SoftwareInventoryBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Builder for SoftwareInventoryBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
        }
    }
}

impl SoftwareInventoryBuilder {
    pub fn version(self, value: &str) -> Self {
        self.add_str_field("Version", value)
    }

    pub fn build(self) -> SoftwareInventory {
        SoftwareInventory {
            id: self.id,
            value: self.value,
        }
    }
}
