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
use carbide_test_support::Outcome::*;
use carbide_test_support::{scenarios, value_scenarios};
use libmlx::device::discovery::{convert_pci_name_to_address, parse_mlxfwmanager_xml};

// Test XML to use for a single DPU with failed access due to lockdown.
const DPU_FAILED_XML: &str = r#"
    <Devices>
        <Device pciName="0000:b4:00.0" type="BlueField3" psid="" partNumber="--">
          <Versions>
            <FW current="--" available=""/>
          </Versions>
          <MACs Base_Mac="N/A" />
          <Status>Failed to open device</Status>
          <Description></Description>
        </Device>
    </Devices>
    "#;

// More test XML for DPUs with failed access. Depending on
// whatever, mlxfwmanager can decide to do different things.
const DPU_FAILED_XML2: &str = r#"
    <Devices>
        <Device pciName="0000:9d:00.0" type="BlueField3" psid="" partNumber="--">
          <Versions>
            <FW current="--" available=""/>
            <PXE current="--" available=""/>
            <UEFI current="--" available=""/>
            <UEFI_Virtio_blk current="--" available=""/>
            <UEFI_Virtio_net current="--" available=""/>
          </Versions>
          <MACs Base_Mac="N/A" />
          <Status>Failed to open device</Status>
          <Description></Description>
        </Device>
    </Devices>
    "#;

// Test XML to use for mixed accessible SuperNICs and a locked down DPU.
const MIXED_DEVICES_XML: &str = r#"
    <Devices>
        <Device pciName="0000:dc:00.0" type="BlueField3" psid="MT_0000001010" partNumber="900-9D3B4-00EN-E_Ax">
          <Versions>
            <FW current="32.42.1000" available="N/A"/>
            <PXE current="3.7.0500" available="N/A"/>
            <UEFI current="14.35.0015" available="N/A"/>
            <UEFI_Virtio_blk current="22.4.0013" available="N/A"/>
            <UEFI_Virtio_net current="21.4.0013" available="N/A"/>
          </Versions>
          <MACs Base_Mac="c470bd31eb46" />
          <Status>No matching image found</Status>
          <Description>NVIDIA BlueField-3 B3140L E-Series FHHL SuperNIC; 400GbE / NDR IB (default mode); Single-port QSFP112; PCIe Gen5.0 x16; 8 Arm cores; 16GB on-board DDR; integrated BMC; Crypto Enabled</Description>
        </Device>
        <Device pciName="0000:9d:00.0" type="BlueField3" psid="" partNumber="--">
          <Versions>
            <FW current="--" available=""/>
            <PXE current="--" available=""/>
            <UEFI current="--" available=""/>
            <UEFI_Virtio_blk current="--" available=""/>
            <UEFI_Virtio_net current="--" available=""/>
          </Versions>
          <MACs Base_Mac="N/A" />
          <Status>Failed to open device</Status>
          <Description></Description>
        </Device>
        <Device pciName="0000:9c:00.0" type="BlueField3" psid="MT_0000001010" partNumber="900-9D3B4-00EN-E_Ax">
          <Versions>
            <FW current="32.42.1000" available="N/A"/>
            <PXE current="3.7.0500" available="N/A"/>
            <UEFI current="14.35.0015" available="N/A"/>
            <UEFI_Virtio_blk current="22.4.0013" available="N/A"/>
            <UEFI_Virtio_net current="21.4.0013" available="N/A"/>
          </Versions>
          <MACs Base_Mac="c470bd31ea12" />
          <Status>No matching image found</Status>
          <Description>NVIDIA BlueField-3 B3140L E-Series FHHL SuperNIC; 400GbE / NDR IB (default mode); Single-port QSFP112; PCIe Gen5.0 x16; 8 Arm cores; 16GB on-board DDR; integrated BMC; Crypto Enabled</Description>
        </Device>
    </Devices>
    "#;

#[test]
fn test_parse_dpu_failed_device() {
    let devices = parse_mlxfwmanager_xml(DPU_FAILED_XML).unwrap();

    assert_eq!(devices.len(), 1);
    let device = &devices[0];

    // Basic fields should be present
    assert_eq!(device.pci_name, "b4:00.0"); // Domain prefix removed
    assert_eq!(device.device_type, "BlueField3");

    // Optional fields should be None for failed devices
    assert_eq!(device.psid, None);
    assert_eq!(device.part_number, None);
    assert_eq!(device.fw_version_current, None); // "--" becomes None
    assert_eq!(device.base_mac, None); // "N/A" becomes None
    assert_eq!(device.device_description, None); // Empty becomes None

    // Status should be captured
    assert_eq!(device.status, Some("Failed to open device".to_string()));
}

#[test]
fn test_parse_dpu_failed_device2() {
    let devices = parse_mlxfwmanager_xml(DPU_FAILED_XML2).unwrap();

    assert_eq!(devices.len(), 1);
    let device = &devices[0];

    // Basic fields should be present
    assert_eq!(device.pci_name, "9d:00.0"); // Domain prefix removed
    assert_eq!(device.device_type, "BlueField3");

    // All version fields should be None since they contain "--"
    assert_eq!(device.fw_version_current, None);
    assert_eq!(device.pxe_version_current, None);
    assert_eq!(device.uefi_version_current, None);
    assert_eq!(device.uefi_version_virtio_blk_current, None);
    assert_eq!(device.uefi_version_virtio_net_current, None);

    // Status should be captured
    assert_eq!(device.status, Some("Failed to open device".to_string()));
}

#[test]
fn test_parse_mixed_devices() {
    let devices = parse_mlxfwmanager_xml(MIXED_DEVICES_XML).unwrap();

    assert_eq!(devices.len(), 3);

    // First device should be a working SuperNIC
    let working_device = &devices[0];
    assert_eq!(working_device.pci_name, "dc:00.0");
    assert_eq!(working_device.psid, Some("MT_0000001010".to_string()));
    assert_eq!(
        working_device.part_number,
        Some("900-9D3B4-00EN-E_Ax".to_string())
    );
    assert_eq!(
        working_device.fw_version_current,
        Some("32.42.1000".to_string())
    );
    assert!(working_device.base_mac.is_some());
    assert_eq!(
        working_device.status,
        Some("No matching image found".to_string())
    );

    // Second device should be a failed DPU
    let failed_device = &devices[1];
    assert_eq!(failed_device.pci_name, "9d:00.0");
    assert_eq!(failed_device.psid, None);
    assert_eq!(failed_device.part_number, None);
    assert_eq!(failed_device.fw_version_current, None);
    assert_eq!(failed_device.base_mac, None);
    assert_eq!(
        failed_device.status,
        Some("Failed to open device".to_string())
    );

    // Third device should be another working SuperNIC
    let third_device = &devices[2];
    assert_eq!(third_device.pci_name, "9c:00.0");
    assert_eq!(third_device.psid, Some("MT_0000001010".to_string()));
    assert_eq!(
        third_device.part_number,
        Some("900-9D3B4-00EN-E_Ax".to_string())
    );
    assert!(third_device.base_mac.is_some());
}

// convert_pci_name_to_address strips a single leading "0000:" domain prefix from a
// PCI name and passes everything else (clean addresses, mst paths, arbitrary
// strings) through untouched.
#[test]
fn test_convert_pci_name_to_address() {
    scenarios!(
        run = convert_pci_name_to_address;
        "removes domain prefix" {
            "0000:01:00.0" => Yields("01:00.0".to_string()),
        }

        "passes through a clean address" {
            "01:00.0" => Yields("01:00.0".to_string()),
        }

        "passes through an mst path" {
            "/dev/mst/mt41692_pciconf0" => Yields("/dev/mst/mt41692_pciconf0".to_string()),
        }

        "passes through an unrelated format" {
            "custom_device_path" => Yields("custom_device_path".to_string()),
        }

        "removes only the first of multiple domain prefixes" {
            "0000:0000:01:00.0" => Yields("0000:01:00.0".to_string()),
        }

        "passes through an empty string" {
            "" => Yields("".to_string()),
        }
    );
}

#[test]
fn test_mac_address_parsing() {
    // Test that valid MAC addresses parse correctly
    let devices = parse_mlxfwmanager_xml(MIXED_DEVICES_XML).unwrap();
    let working_device = &devices[0];

    // Should successfully parse the MAC address
    assert!(working_device.base_mac.is_some());
    assert_eq!(
        working_device.base_mac.unwrap().to_string(),
        "c4:70:bd:31:eb:46".to_uppercase()
    );
}

// get_field_value renders a None optional field as "--" and returns the value of a
// present field. Exercised against the failed-DPU device, whose optionals are all
// absent while pci_name/device_type/status are set.
#[test]
fn test_optional_field_handling() {
    let devices = parse_mlxfwmanager_xml(DPU_FAILED_XML).unwrap();
    let device = &devices[0];

    value_scenarios!(
        run = |field| device.get_field_value(field);
        "None psid renders as --" {
            "psid" => "--".to_string(),
        }

        "None part_number renders as --" {
            "part_number" => "--".to_string(),
        }

        "None base_mac renders as --" {
            "base_mac" => "--".to_string(),
        }

        "None fw_version_current renders as --" {
            "fw_version_current" => "--".to_string(),
        }

        "present pci_name" {
            "pci_name" => "b4:00.0".to_string(),
        }

        "present device_type" {
            "device_type" => "BlueField3".to_string(),
        }

        "present status" {
            "status" => "Failed to open device".to_string(),
        }
    );
}
