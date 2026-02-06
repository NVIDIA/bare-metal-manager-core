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

use std::process::Command;
use std::str::FromStr;

use mac_address::MacAddress;
use quick_xml::de::from_str;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::filters::DeviceFilter;
use crate::info::MlxDeviceInfo;

// DevicesXml represents the root XML structure
// from mlxfwmanager output.
#[derive(Debug, Deserialize)]
struct DevicesXml {
    #[serde(rename = "Device")]
    devices: Vec<DeviceXml>,
}

// DeviceXml represents a single device entry from
// mlxfwmanager XML output.
#[derive(Debug, Deserialize)]
struct DeviceXml {
    #[serde(rename = "@pciName")]
    pci_name: String,
    #[serde(rename = "@type")]
    device_type: String,
    #[serde(rename = "@psid")]
    psid: String,
    #[serde(rename = "@partNumber")]
    part_number: String,
    #[serde(rename = "Versions")]
    versions: VersionsXml,
    #[serde(rename = "MACs")]
    macs: MacsXml,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Status", default)]
    status: String,
}

// VersionsXml represents the version information section
// from mlxfwmanager XML.
#[derive(Debug, Deserialize)]
struct VersionsXml {
    #[serde(rename = "FW", default)]
    fw: Option<VersionXml>,
    #[serde(rename = "PXE", default)]
    pxe: Option<VersionXml>,
    #[serde(rename = "UEFI", default)]
    uefi: Option<VersionXml>,
    #[serde(rename = "UEFI_Virtio_blk", default)]
    uefi_virtio_blk: Option<VersionXml>,
    #[serde(rename = "UEFI_Virtio_net", default)]
    uefi_virtio_net: Option<VersionXml>,
}

// VersionXml represents current and available version
// information for a component.
#[derive(Debug, Deserialize)]
struct VersionXml {
    #[serde(rename = "@current")]
    current: String,
    #[serde(rename = "@available")]
    #[allow(dead_code)]
    available: String,
}

// MacsXml represents MAC address information from
// mlxfwmanager XML.
#[derive(Debug, Deserialize)]
struct MacsXml {
    #[serde(rename = "@Base_Mac")]
    base_mac: String,
}

// discover_devices finds all devices using mlxfwmanager.
pub fn discover_devices() -> Result<Vec<MlxDeviceInfo>, String> {
    debug!("Running mlxfwmanager to discover devices");

    let output = Command::new("mlxfwmanager")
        .args(["--query-format", "xml"])
        .output()
        .map_err(|e| format!("failed to build cmd: {e}"))?;

    // In cases where DPUs are returned, it looks like DPUs that are
    // currently in lockdown won't return data to mlxfwmanager. The
    // XML is still generated, just with some empty fields, and all
    // of the SuperNIC XML data is unaffected. The problem, though,
    // is that even though the full set of XML is returned, the
    // command itself returns exit code 1, so we need to allow that
    // here, and then just deal with issues as part of attempting
    // to parse the XML output.
    if !matches!(output.status.code(), Some(0) | Some(1)) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "mlxfwmanager failed with unexpected exit code: {stderr}"
        ));
    }

    {
        let xml_content = String::from_utf8_lossy(&output.stdout);
        warn!("mlxfwmanager XML output: {}", xml_content);
        parse_mlxfwmanager_xml(&xml_content)
    }
}

// discover_device loads a specific device using mlxfwmanager.
// The actual XML returned is still "devices", but will only
// contain the target device.
pub fn discover_device(device: &str) -> Result<MlxDeviceInfo, String> {
    debug!("Running mlxfwmanager to discover device: {device}");

    let output = Command::new("mlxfwmanager")
        .args(["--dev", device, "--query-format", "xml"])
        .output()
        .map_err(|e| format!("failed to build cmd: {e}"))?;

    // In cases where DPUs are returned, it looks like DPUs that are
    // currently in lockdown won't return data to mlxfwmanager. The
    // XML is still generated, just with some empty fields, and all
    // of the SuperNIC XML data is unaffected. The problem, though,
    // is that even though the full set of XML is returned, the
    // command itself returns exit code 1, so we need to allow that
    // here, and then just deal with issues as part of attempting
    // to parse the XML output.
    if !matches!(output.status.code(), Some(0) | Some(1)) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "mlxfwmanager failed with unexpected exit code: {stderr}"
        ));
    }

    let xml_content = String::from_utf8_lossy(&output.stdout);
    debug!("mlxfwmanager XML output: {}", xml_content);

    let devices = parse_mlxfwmanager_xml(&xml_content)?;
    if devices.len() > 1 {
        return Err(format!(
            "only expected a single device returned for device: {device}"
        ));
    }
    if devices.is_empty() {
        return Err(format!("no devices returned for device: {device}"));
    }
    Ok(devices.into_iter().next().unwrap())
}

// discover_devices_with_filters finds devices that match
// the specified filters.
pub fn discover_devices_with_filters(filter: DeviceFilter) -> Result<Vec<MlxDeviceInfo>, String> {
    let all_devices = discover_devices()?;

    let filtered_devices: Vec<MlxDeviceInfo> = all_devices
        .into_iter()
        .filter(|device| {
            let matches = filter.matches(device);
            debug!(
                "Device {} (type: {}, part: {}, fw: {}) matches filter: {}",
                device.pci_name_pretty(),
                device.device_type_pretty(),
                device.part_number_pretty(),
                device.fw_version_current_pretty(),
                matches
            );
            matches
        })
        .collect();

    debug!(
        "Found {} devices matching filter: [{filter}]",
        filtered_devices.len()
    );

    Ok(filtered_devices)
}

// parse_mlxfwmanager_xml converts XML output from mlxfwmanager
// into device info structs.
pub fn parse_mlxfwmanager_xml(xml_content: &str) -> Result<Vec<MlxDeviceInfo>, String> {
    let devices_xml: DevicesXml =
        from_str(xml_content).map_err(|e| format!("Failed to parse mlxfwmanager XML: {e}"))?;

    let mut devices = Vec::new();

    for device_xml in devices_xml.devices {
        let pci_name = convert_pci_name_to_address(&device_xml.pci_name)?;

        // If the MAC fails to parse, just return None.
        let base_mac = MacAddress::from_str(&device_xml.macs.base_mac).ok();
        // ...and if any of the "optional" fields look to have been
        // excluded by mlxfwmanager, parse it into None.
        let device_info = MlxDeviceInfo {
            pci_name,
            device_type: device_xml.device_type,
            psid: parse_optional_xml_field(&device_xml.psid),
            device_description: parse_optional_xml_field(&device_xml.description),
            part_number: parse_optional_xml_field(&device_xml.part_number),
            status: parse_optional_xml_field(&device_xml.status),
            fw_version_current: device_xml
                .versions
                .fw
                .as_ref()
                .and_then(|fw| parse_optional_xml_field(&fw.current)),
            pxe_version_current: device_xml
                .versions
                .pxe
                .as_ref()
                .and_then(|pxe| parse_optional_xml_field(&pxe.current)),
            uefi_version_current: device_xml
                .versions
                .uefi
                .as_ref()
                .and_then(|uefi| parse_optional_xml_field(&uefi.current)),
            uefi_version_virtio_blk_current: device_xml
                .versions
                .uefi_virtio_blk
                .as_ref()
                .and_then(|virtio_blk| parse_optional_xml_field(&virtio_blk.current)),
            uefi_version_virtio_net_current: device_xml
                .versions
                .uefi_virtio_net
                .as_ref()
                .and_then(|virtio_net| parse_optional_xml_field(&virtio_net.current)),
            base_mac,
        };
        devices.push(device_info);
    }

    debug!("Discovered {} MLX devices", devices.len());
    Ok(devices)
}

// parse_optional_xml_field converts common "missing" indicators to None
// for optional fields.
fn parse_optional_xml_field(value: &str) -> Option<String> {
    if value.is_empty() || value == "--" || value == "N/A" {
        None
    } else {
        Some(value.to_string())
    }
}

// convert_pci_name_to_address converts PCI device name from
// mlxfwmanager format to mlxconfig format.
pub fn convert_pci_name_to_address(pci_name: &str) -> Result<String, String> {
    // Clean up the PCI address format if needed
    let cleaned_address = if pci_name.starts_with("0000:") {
        // Remove leading domain if present: "0000:01:00.0" -> "01:00.0".
        pci_name
            .strip_prefix("0000:")
            .unwrap_or(pci_name)
            .to_string()
    } else {
        // Pass through MST device paths or already-clean PCI addresses.
        pci_name.to_string()
    };

    debug!(
        "Converted PCI name '{}' to address '{}'",
        pci_name, cleaned_address
    );
    Ok(cleaned_address)
}
