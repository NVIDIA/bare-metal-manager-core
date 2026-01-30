/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/// Get builder of the network adapter.
pub fn builder(resource: &redfish::Resource) -> NetworkAdapterBuilder {
    NetworkAdapterBuilder {
        value: resource.json_patch(),
    }
}

pub struct NetworkAdapterBuilder {
    value: serde_json::Value,
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

    pub fn network_device_functions(self, collection: &redfish::Collection<'_>) -> Self {
        Self {
            value: self
                .value
                .patch(collection.nav_property("NetworkDeviceFunctions")),
        }
    }

    pub fn status(self, status: redfish::resource::Status) -> Self {
        Self {
            value: self.value.patch(json!({
                "Status": status.into_json()
            })),
        }
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }

    fn add_str_field(self, name: &str, value: &str) -> Self {
        Self {
            value: self.value.patch(json!({ name: value })),
        }
    }
}
