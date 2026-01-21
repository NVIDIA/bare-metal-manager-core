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

const PCIE_DEVICE_TYPE: &str = "#PCIeDevice.v1_5_0.PCIeDevice";

pub fn chassis_resource(chassis_id: &str, dev_id: &str) -> redfish::Resource<'static> {
    let odata_id = format!("/redfish/v1/Chassis/{chassis_id}/PCIeDevices/{dev_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed(PCIE_DEVICE_TYPE),
        id: Cow::Owned(dev_id.into()),
        name: Cow::Borrowed("PCIe Device"),
    }
}

pub fn chassis_collection(chassis_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Chassis/{chassis_id}/PCIeDevices");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#PCIeDeviceCollection.PCIeDeviceCollection"),
        name: Cow::Borrowed("PCIeDevice Collection"),
    }
}

/// Generate resource bound to chassis.
pub fn builder(resource: &redfish::Resource) -> PcieDeviceBuilder {
    PcieDeviceBuilder {
        value: resource.json_patch(),
    }
}

pub struct PcieDeviceBuilder {
    value: serde_json::Value,
}

impl PcieDeviceBuilder {
    pub fn description(self, value: &str) -> Self {
        self.add_str_field("Description", value)
    }

    pub fn firmware_version(self, value: &str) -> Self {
        self.add_str_field("FirmwareVersion", value)
    }

    pub fn manufacturer(self, value: &str) -> Self {
        self.add_str_field("Manufacturer", value)
    }

    pub fn part_number(self, value: &str) -> Self {
        self.add_str_field("PartNumber", value)
    }

    pub fn serial_number(self, value: &str) -> Self {
        self.add_str_field("SerialNumber", value)
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }

    pub fn status(self, status: redfish::resource::Status) -> Self {
        Self {
            value: self.value.patch(json!({
                "Status": status.into_json()
            })),
        }
    }

    fn add_str_field(self, name: &str, value: &str) -> Self {
        Self {
            value: self.value.patch(json!({ name: value })),
        }
    }
}
