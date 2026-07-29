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
use carbide_libmlx_model::device::info::MlxDeviceInfo;
use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;
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

const MISSING_OPTIONALS_XML: &str = r#"
    <Devices>
        <Device pciName="0000:01:00.0" type="ConnectX-6" psid="N/A" partNumber="N/A">
          <Versions></Versions>
          <MACs Base_Mac="N/A" />
          <Description>N/A</Description>
        </Device>
    </Devices>
    "#;

const EMPTY_DEVICES_XML: &str = "<Devices></Devices>";
const MALFORMED_XML: &str = "<Devices><Device";

fn device_with_missing_optionals(
    pci_name: &str,
    device_type: &str,
    status: Option<&str>,
) -> MlxDeviceInfo {
    MlxDeviceInfo {
        pci_name: pci_name.to_string(),
        device_type: device_type.to_string(),
        psid: None,
        device_description: None,
        part_number: None,
        fw_version_current: None,
        pxe_version_current: None,
        uefi_version_current: None,
        uefi_version_virtio_blk_current: None,
        uefi_version_virtio_net_current: None,
        base_mac: None,
        status: status.map(str::to_string),
    }
}

fn failed_device(pci_name: &str) -> MlxDeviceInfo {
    device_with_missing_optionals(pci_name, "BlueField3", Some("Failed to open device"))
}

fn accessible_device(pci_name: &str, base_mac: &str) -> MlxDeviceInfo {
    MlxDeviceInfo {
        pci_name: pci_name.to_string(),
        device_type: "BlueField3".to_string(),
        psid: Some("MT_0000001010".to_string()),
        device_description: Some(
            "NVIDIA BlueField-3 B3140L E-Series FHHL SuperNIC; 400GbE / NDR IB \
             (default mode); Single-port QSFP112; PCIe Gen5.0 x16; 8 Arm cores; \
             16GB on-board DDR; integrated BMC; Crypto Enabled"
                .to_string(),
        ),
        part_number: Some("900-9D3B4-00EN-E_Ax".to_string()),
        fw_version_current: Some("32.42.1000".to_string()),
        pxe_version_current: Some("3.7.0500".to_string()),
        uefi_version_current: Some("14.35.0015".to_string()),
        uefi_version_virtio_blk_current: Some("22.4.0013".to_string()),
        uefi_version_virtio_net_current: Some("21.4.0013".to_string()),
        base_mac: Some(base_mac.parse().unwrap()),
        status: Some("No matching image found".to_string()),
    }
}

#[test]
fn parse_mlxfwmanager_xml_cases() {
    scenarios!(
        run = parse_mlxfwmanager_xml;
        "failed DPU normalizes omitted and placeholder values" {
            DPU_FAILED_XML => Yields(vec![failed_device("b4:00.0")]),
        }

        "mixed devices preserve every parsed field" {
            MIXED_DEVICES_XML => Yields(vec![
                accessible_device("dc:00.0", "c4:70:bd:31:eb:46"),
                failed_device("9d:00.0"),
                accessible_device("9c:00.0", "c4:70:bd:31:ea:12"),
            ]),
        }

        "missing sections and placeholders become absent values" {
            MISSING_OPTIONALS_XML => Yields(vec![
                device_with_missing_optionals("01:00.0", "ConnectX-6", None),
            ]),
        }

        "empty device lists are rejected" {
            EMPTY_DEVICES_XML => Fails,
        }

        "malformed XML is rejected" {
            MALFORMED_XML => Fails,
        }
    );
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
