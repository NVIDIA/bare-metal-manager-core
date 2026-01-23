/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

// MlxDeviceInfo represents detailed information about a Mellanox
// network device. Most fields are optional, because when querying
// with mlxfwmanager, a device that is in lockdown won't return
// all data (just pci_name and device_type), which can be the case
// with DPUs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MlxDeviceInfo {
    // pci_name is the PCI address or MST device
    // path for the device.
    pub pci_name: String,
    // device_type identifies the specific
    // Mellanox device model.
    pub device_type: String,
    // psid (Parameter-Set IDentification) is a 16-ASCII character
    // string embedded in the firmware image which provides a unique
    // identification for the configuration of the firmware.
    pub psid: Option<String>,
    // device_description provides a human-readable
    // description of the device.
    pub device_description: Option<String>,
    // part_number is the manufacturer part number
    // for the device.
    pub part_number: Option<String>,
    // fw_version_current is the currently
    // installed firmware version.
    pub fw_version_current: Option<String>,
    // pxe_version_current is the currently installed
    // PXE boot version.
    pub pxe_version_current: Option<String>,
    // uefi_version_current is the currently installed
    // UEFI boot version.
    pub uefi_version_current: Option<String>,
    // uefi_version_virtio_blk_current is the currently
    // installed UEFI VirtIO block driver version.
    pub uefi_version_virtio_blk_current: Option<String>,
    // uefi_version_virtio_net_current is the currently
    // installed UEFI VirtIO network driver version.
    pub uefi_version_virtio_net_current: Option<String>,
    // base_mac is the base MAC address for the device.
    pub base_mac: Option<MacAddress>,
    // status is the "status" of the device that is
    // returned. Sometimes there's useful stuff, other
    // times there isn't.
    pub status: Option<String>,
}

impl MlxDeviceInfo {
    pub fn pci_name_pretty(&self) -> String {
        self.pci_name.clone()
    }

    pub fn device_type_pretty(&self) -> String {
        self.device_type.clone()
    }

    pub fn psid_pretty(&self) -> String {
        self.psid.as_deref().unwrap_or("--").to_string()
    }

    pub fn device_description_pretty(&self) -> String {
        self.device_description
            .as_deref()
            .unwrap_or("--")
            .to_string()
    }

    pub fn part_number_pretty(&self) -> String {
        self.part_number.as_deref().unwrap_or("--").to_string()
    }

    pub fn fw_version_current_pretty(&self) -> String {
        self.fw_version_current
            .as_deref()
            .unwrap_or("--")
            .to_string()
    }

    pub fn pxe_version_current_pretty(&self) -> String {
        self.pxe_version_current
            .as_deref()
            .unwrap_or("--")
            .to_string()
    }

    pub fn uefi_version_current_pretty(&self) -> String {
        self.uefi_version_current
            .as_deref()
            .unwrap_or("--")
            .to_string()
    }

    pub fn uefi_version_virtio_blk_current_pretty(&self) -> String {
        self.uefi_version_virtio_blk_current
            .as_deref()
            .unwrap_or("--")
            .to_string()
    }

    pub fn uefi_version_virtio_net_current_pretty(&self) -> String {
        self.uefi_version_virtio_net_current
            .as_deref()
            .unwrap_or("--")
            .to_string()
    }

    pub fn base_mac_pretty(&self) -> String {
        self.base_mac
            .map(|mac| mac.to_string())
            .unwrap_or_else(|| "--".to_string())
    }

    pub fn status_pretty(&self) -> String {
        self.status.as_deref().unwrap_or("--").to_string()
    }

    // get_field_value returns the value of a field by name for
    // display purposes, used by the CLI cmd module, and
    // anything else that wants a "pretty" string representation.
    pub fn get_field_value(&self, field_name: &str) -> String {
        match field_name {
            "pci_name" => self.pci_name_pretty(),
            "device_type" => self.device_type_pretty(),
            "psid" => self.psid_pretty(),
            "device_description" => self.device_description_pretty(),
            "part_number" => self.part_number_pretty(),
            "fw_version_current" => self.fw_version_current_pretty(),
            "pxe_version_current" => self.pxe_version_current_pretty(),
            "uefi_version_current" => self.uefi_version_current_pretty(),
            "uefi_version_virtio_blk_current" => self.uefi_version_virtio_blk_current_pretty(),
            "uefi_version_virtio_net_current" => self.uefi_version_virtio_net_current_pretty(),
            "base_mac" => self.base_mac_pretty(),
            "status" => self.status_pretty(),
            _ => "<unknown-field>".to_string(),
        }
    }
    // get_all_fields returns a vector of all field names for this struct.
    pub fn get_all_fields() -> Vec<&'static str> {
        vec![
            "pci_name",
            "base_mac",
            "psid",
            "device_type",
            "part_number",
            "device_description",
            "fw_version_current",
            "pxe_version_current",
            "uefi_version_current",
            "uefi_version_virtio_blk_current",
            "uefi_version_virtio_net_current",
            "status",
        ]
    }
}
