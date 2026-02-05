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
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch(),
        mat_dpu: false,
    }
}

pub fn builder_from_nic(resource: &redfish::Resource, nic: &hw::nic::Nic) -> PcieDeviceBuilder {
    let b = builder(resource).serial_number(&nic.serial_number);
    let b = if nic.is_mat_dpu { b.mat_dpu() } else { b };
    b.maybe_with(PcieDeviceBuilder::description, &nic.description)
        .maybe_with(PcieDeviceBuilder::manufacturer, &nic.manufacturer)
        .maybe_with(PcieDeviceBuilder::model, &nic.model)
        .maybe_with(PcieDeviceBuilder::part_number, &nic.part_number)
        .maybe_with(PcieDeviceBuilder::firmware_version, &nic.firmware_version)
}

pub struct PCIeDevice {
    pub id: Cow<'static, str>,
    pub is_mat_dpu: bool,
    value: serde_json::Value,
}

impl PCIeDevice {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub struct PcieDeviceBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
    mat_dpu: bool,
}

impl Builder for PcieDeviceBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
            mat_dpu: self.mat_dpu,
        }
    }
}

impl PcieDeviceBuilder {
    pub fn description(self, value: &str) -> Self {
        self.add_str_field("Description", value)
    }

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

    pub fn firmware_version(self, value: &str) -> Self {
        self.add_str_field("FirmwareVersion", value)
    }

    pub fn mat_dpu(mut self) -> Self {
        self.mat_dpu = true;
        self
    }

    pub fn status(self, status: redfish::resource::Status) -> Self {
        self.apply_patch(json!({
            "Status": status.into_json()
        }))
    }

    pub fn build(self) -> PCIeDevice {
        PCIeDevice {
            id: self.id,
            value: self.value,
            is_mat_dpu: self.mat_dpu,
        }
    }
}
