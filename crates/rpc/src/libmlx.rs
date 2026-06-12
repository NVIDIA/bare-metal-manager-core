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

use std::str::FromStr;

use carbide_libmlx_model::device::info::MlxDeviceInfo;
use carbide_libmlx_model::firmware::result::FirmwareFlashReport;
use mac_address::MacAddress;

use crate::protos::mlx_device::{
    FirmwareFlashReport as FirmwareFlashReportPb, MlxDeviceInfo as MlxDeviceInfoPb,
};

// Implement conversion from Rust MlxDeviceInfo to protobuf.
impl From<MlxDeviceInfo> for MlxDeviceInfoPb {
    fn from(info: MlxDeviceInfo) -> Self {
        MlxDeviceInfoPb {
            pci_name: info.pci_name,
            device_type: info.device_type,
            psid: info.psid.unwrap_or_default(),
            device_description: info.device_description.unwrap_or_default(),
            part_number: info.part_number.unwrap_or_default(),
            fw_version_current: info.fw_version_current.unwrap_or_default(),
            pxe_version_current: info.pxe_version_current.unwrap_or_default(),
            uefi_version_current: info.uefi_version_current.unwrap_or_default(),
            uefi_version_virtio_blk_current: info
                .uefi_version_virtio_blk_current
                .unwrap_or_default(),
            uefi_version_virtio_net_current: info
                .uefi_version_virtio_net_current
                .unwrap_or_default(),
            base_mac: info.base_mac.map(|mac| mac.to_string()).unwrap_or_default(),
            status: info.status.unwrap_or_default(),
        }
    }
}

// Implement conversion from protobuf MlxDeviceInfo to Rust.
impl TryFrom<MlxDeviceInfoPb> for MlxDeviceInfo {
    type Error = String;

    fn try_from(proto: MlxDeviceInfoPb) -> Result<Self, Self::Error> {
        let base_mac = if proto.base_mac.is_empty() {
            None
        } else {
            Some(
                MacAddress::from_str(&proto.base_mac)
                    .map_err(|e| format!("Invalid MAC address '{}': {}", proto.base_mac, e))?,
            )
        };

        // Similar to parse_optional_xml_field, have a little helper
        // for handling it with Rust <-> proto type conversion as well.
        let parse_optional_field = |s: String| if s.is_empty() { None } else { Some(s) };

        Ok(MlxDeviceInfo {
            pci_name: proto.pci_name,
            device_type: proto.device_type,
            psid: parse_optional_field(proto.psid),
            device_description: parse_optional_field(proto.device_description),
            part_number: parse_optional_field(proto.part_number),
            fw_version_current: parse_optional_field(proto.fw_version_current),
            pxe_version_current: parse_optional_field(proto.pxe_version_current),
            uefi_version_current: parse_optional_field(proto.uefi_version_current),
            uefi_version_virtio_blk_current: parse_optional_field(
                proto.uefi_version_virtio_blk_current,
            ),
            uefi_version_virtio_net_current: parse_optional_field(
                proto.uefi_version_virtio_net_current,
            ),
            status: parse_optional_field(proto.status),
            base_mac,
        })
    }
}

// From implementations for converting FirmwareFlashReport
// to/from a FirmwareFlashReportPb protobuf message and back.
impl From<FirmwareFlashReport> for FirmwareFlashReportPb {
    fn from(result: FirmwareFlashReport) -> Self {
        FirmwareFlashReportPb {
            flashed: result.flashed,
            reset: result.reset,
            verified_image: result.verified_image,
            verified_version: result.verified_version,
            observed_version: result.observed_version,
            expected_version: result.expected_version,
        }
    }
}

impl From<FirmwareFlashReportPb> for FirmwareFlashReport {
    fn from(proto: FirmwareFlashReportPb) -> Self {
        FirmwareFlashReport {
            flashed: proto.flashed,
            reset: proto.reset,
            verified_image: proto.verified_image,
            verified_version: proto.verified_version,
            observed_version: proto.observed_version,
            expected_version: proto.expected_version,
        }
    }
}

#[cfg(test)]
mod test {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    // Proto -> model `TryFrom`: every input proto should convert back to the
    // expected `MlxDeviceInfo`, with empty proto strings (and an empty MAC)
    // becoming `None`. The roundtrip rows feed a model through its own
    // `Into<MlxDeviceInfoPb>` first.
    #[test]
    fn device_info_proto_to_model() {
        check_cases(
            [
                Case {
                    scenario: "full device roundtrips",
                    input: MlxDeviceInfo::create_test_device().into(),
                    expect: Yields(MlxDeviceInfo::create_test_device()),
                },
                Case {
                    scenario: "missing-data device roundtrips",
                    input: MlxDeviceInfo::create_test_device_with_missing_data().into(),
                    expect: Yields(MlxDeviceInfo::create_test_device_with_missing_data()),
                },
                Case {
                    scenario: "empty string fields become none",
                    input: MlxDeviceInfoPb {
                        pci_name: "01:00.0".to_string(),
                        device_type: "BlueField3".to_string(),
                        psid: "".to_string(), // Empty string should become None
                        device_description: "".to_string(),
                        part_number: "".to_string(),
                        fw_version_current: "".to_string(),
                        pxe_version_current: "".to_string(),
                        uefi_version_current: "".to_string(),
                        uefi_version_virtio_blk_current: "".to_string(),
                        uefi_version_virtio_net_current: "".to_string(),
                        base_mac: "".to_string(), // Empty MAC becomes None
                        status: "".to_string(),
                    },
                    expect: Yields(MlxDeviceInfo {
                        pci_name: "01:00.0".to_string(),
                        device_type: "BlueField3".to_string(),
                        psid: None,
                        device_description: None,
                        part_number: None,
                        fw_version_current: None,
                        pxe_version_current: None,
                        uefi_version_current: None,
                        uefi_version_virtio_blk_current: None,
                        uefi_version_virtio_net_current: None,
                        base_mac: None,
                        status: None,
                    }),
                },
                Case {
                    scenario: "populated mac parses",
                    input: MlxDeviceInfoPb {
                        pci_name: "01:00.0".to_string(),
                        device_type: "BlueField3".to_string(),
                        psid: "".to_string(),
                        device_description: "".to_string(),
                        part_number: "".to_string(),
                        fw_version_current: "".to_string(),
                        pxe_version_current: "".to_string(),
                        uefi_version_current: "".to_string(),
                        uefi_version_virtio_blk_current: "".to_string(),
                        uefi_version_virtio_net_current: "".to_string(),
                        base_mac: "b8:3f:d2:12:34:56".to_string(),
                        status: "".to_string(),
                    },
                    expect: Yields(MlxDeviceInfo {
                        pci_name: "01:00.0".to_string(),
                        device_type: "BlueField3".to_string(),
                        psid: None,
                        device_description: None,
                        part_number: None,
                        fw_version_current: None,
                        pxe_version_current: None,
                        uefi_version_current: None,
                        uefi_version_virtio_blk_current: None,
                        uefi_version_virtio_net_current: None,
                        base_mac: Some(MacAddress::from_str("b8:3f:d2:12:34:56").unwrap()),
                        status: None,
                    }),
                },
                Case {
                    scenario: "every optional string field present",
                    input: MlxDeviceInfoPb {
                        pci_name: "01:00.0".to_string(),
                        device_type: "ConnectX-6 Dx".to_string(),
                        psid: "MT_00000055".to_string(),
                        device_description: "desc".to_string(),
                        part_number: "MCX623106AN-CDAT".to_string(),
                        fw_version_current: "22.32.1010".to_string(),
                        pxe_version_current: "3.6.0502".to_string(),
                        uefi_version_current: "14.25.1020".to_string(),
                        uefi_version_virtio_blk_current: "1.0.0".to_string(),
                        uefi_version_virtio_net_current: "1.0.0".to_string(),
                        base_mac: "".to_string(),
                        status: "ok".to_string(),
                    },
                    expect: Yields(MlxDeviceInfo {
                        pci_name: "01:00.0".to_string(),
                        device_type: "ConnectX-6 Dx".to_string(),
                        psid: Some("MT_00000055".to_string()),
                        device_description: Some("desc".to_string()),
                        part_number: Some("MCX623106AN-CDAT".to_string()),
                        fw_version_current: Some("22.32.1010".to_string()),
                        pxe_version_current: Some("3.6.0502".to_string()),
                        uefi_version_current: Some("14.25.1020".to_string()),
                        uefi_version_virtio_blk_current: Some("1.0.0".to_string()),
                        uefi_version_virtio_net_current: Some("1.0.0".to_string()),
                        base_mac: None,
                        status: Some("ok".to_string()),
                    }),
                },
                Case {
                    scenario: "malformed mac fails",
                    input: MlxDeviceInfoPb {
                        pci_name: "01:00.0".to_string(),
                        device_type: "BlueField3".to_string(),
                        psid: "".to_string(),
                        device_description: "".to_string(),
                        part_number: "".to_string(),
                        fw_version_current: "".to_string(),
                        pxe_version_current: "".to_string(),
                        uefi_version_current: "".to_string(),
                        uefi_version_virtio_blk_current: "".to_string(),
                        uefi_version_virtio_net_current: "".to_string(),
                        base_mac: "not-a-mac".to_string(),
                        status: "".to_string(),
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "mac with too few octets fails",
                    input: MlxDeviceInfoPb {
                        pci_name: "01:00.0".to_string(),
                        device_type: "BlueField3".to_string(),
                        psid: "".to_string(),
                        device_description: "".to_string(),
                        part_number: "".to_string(),
                        fw_version_current: "".to_string(),
                        pxe_version_current: "".to_string(),
                        uefi_version_current: "".to_string(),
                        uefi_version_virtio_blk_current: "".to_string(),
                        uefi_version_virtio_net_current: "".to_string(),
                        base_mac: "b8:3f:d2".to_string(),
                        status: "".to_string(),
                    },
                    expect: Fails,
                },
            ],
            |proto: MlxDeviceInfoPb| MlxDeviceInfo::try_from(proto).map_err(drop),
        );
    }

    // Model -> proto `From`: the total mapping that fills each absent
    // `Option` with the proto's empty-string default and renders the MAC via
    // `to_string`. Each row pins the produced proto fields as one tuple.
    #[test]
    fn device_info_model_to_proto() {
        type Fields = (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        );
        let project = |info: MlxDeviceInfo| -> Fields {
            let pb: MlxDeviceInfoPb = info.into();
            (
                pb.pci_name,
                pb.device_type,
                pb.psid,
                pb.device_description,
                pb.part_number,
                pb.fw_version_current,
                pb.pxe_version_current,
                pb.uefi_version_current,
                pb.uefi_version_virtio_blk_current,
                pb.uefi_version_virtio_net_current,
                pb.base_mac,
                pb.status,
            )
        };
        check_values(
            [
                Check {
                    scenario: "fully populated model maps every field",
                    input: MlxDeviceInfo::create_test_device(),
                    expect: (
                        "01:00.0".to_string(),
                        "ConnectX-6 Dx".to_string(),
                        "MT_00000055".to_string(),
                        "Mellanox ConnectX-6 Dx EN 100GbE dual port".to_string(),
                        "MCX623106AN-CDAT".to_string(),
                        "22.32.1010".to_string(),
                        "3.6.0502".to_string(),
                        "14.25.1020".to_string(),
                        "1.0.0".to_string(),
                        "1.0.0".to_string(),
                        "B8:3F:D2:12:34:56".to_string(),
                        // status is None on the test device -> empty string
                        "".to_string(),
                    ),
                },
                Check {
                    scenario: "missing-data model defaults absent options to empty",
                    input: MlxDeviceInfo::create_test_device_with_missing_data(),
                    expect: (
                        "b4:00.0".to_string(),
                        "BlueField3".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        "".to_string(),
                        // base_mac is None -> empty string
                        "".to_string(),
                        "Failed to open device".to_string(),
                    ),
                },
            ],
            project,
        );
    }

    // `FirmwareFlashReport` -> proto -> `FirmwareFlashReport` roundtrip. The
    // report isn't `PartialEq`, so project to the tuple of fields the originals
    // asserted; the conversions are total (`From`), hence `check_values`.
    #[test]
    fn firmware_flash_report_roundtrip() {
        check_values(
            [
                Check {
                    scenario: "all steps success",
                    input: FirmwareFlashReport {
                        flashed: true,
                        reset: Some(true),
                        verified_image: Some(true),
                        verified_version: Some(true),
                        observed_version: Some("32.43.1014".to_string()),
                        expected_version: Some("32.43.1014".to_string()),
                    },
                    expect: (
                        true,
                        Some(true),
                        Some(true),
                        Some(true),
                        Some("32.43.1014".to_string()),
                        Some("32.43.1014".to_string()),
                    ),
                },
                Check {
                    scenario: "flash only",
                    input: FirmwareFlashReport {
                        flashed: true,
                        reset: None,
                        verified_image: None,
                        verified_version: None,
                        observed_version: None,
                        expected_version: None,
                    },
                    expect: (true, None, None, None, None, None),
                },
                Check {
                    scenario: "partial failure",
                    input: FirmwareFlashReport {
                        flashed: true,
                        reset: Some(false),
                        verified_image: Some(false),
                        verified_version: Some(false),
                        observed_version: Some("32.42.900".to_string()),
                        expected_version: Some("32.43.1014".to_string()),
                    },
                    expect: (
                        true,
                        Some(false),
                        Some(false),
                        Some(false),
                        Some("32.42.900".to_string()),
                        Some("32.43.1014".to_string()),
                    ),
                },
            ],
            |original: FirmwareFlashReport| {
                let proto: FirmwareFlashReportPb = original.into();
                let converted: FirmwareFlashReport = proto.into();
                (
                    converted.flashed,
                    converted.reset,
                    converted.verified_image,
                    converted.verified_version,
                    converted.observed_version,
                    converted.expected_version,
                )
            },
        );
    }

    // Proto -> model `From` for `FirmwareFlashReport`, exercised directly
    // (not via the roundtrip above). The report isn't `PartialEq`, so project
    // to its field tuple; the conversion is total, hence `check_values`.
    #[test]
    fn firmware_flash_report_proto_to_model() {
        type Fields = (
            bool,
            Option<bool>,
            Option<bool>,
            Option<bool>,
            Option<String>,
            Option<String>,
        );
        let project = |proto: FirmwareFlashReportPb| -> Fields {
            let model: FirmwareFlashReport = proto.into();
            (
                model.flashed,
                model.reset,
                model.verified_image,
                model.verified_version,
                model.observed_version,
                model.expected_version,
            )
        };
        check_values(
            [
                Check {
                    scenario: "every field populated",
                    input: FirmwareFlashReportPb {
                        flashed: true,
                        reset: Some(true),
                        verified_image: Some(true),
                        verified_version: Some(true),
                        observed_version: Some("32.43.1014".to_string()),
                        expected_version: Some("32.43.1014".to_string()),
                    },
                    expect: (
                        true,
                        Some(true),
                        Some(true),
                        Some(true),
                        Some("32.43.1014".to_string()),
                        Some("32.43.1014".to_string()),
                    ),
                },
                Check {
                    scenario: "all optionals absent",
                    input: FirmwareFlashReportPb {
                        flashed: false,
                        reset: None,
                        verified_image: None,
                        verified_version: None,
                        observed_version: None,
                        expected_version: None,
                    },
                    expect: (false, None, None, None, None, None),
                },
                Check {
                    scenario: "false flags pass through distinct from none",
                    input: FirmwareFlashReportPb {
                        flashed: true,
                        reset: Some(false),
                        verified_image: Some(false),
                        verified_version: Some(false),
                        observed_version: Some("32.42.900".to_string()),
                        expected_version: Some("32.43.1014".to_string()),
                    },
                    expect: (
                        true,
                        Some(false),
                        Some(false),
                        Some(false),
                        Some("32.42.900".to_string()),
                        Some("32.43.1014".to_string()),
                    ),
                },
            ],
            project,
        );
    }

    // Model -> proto `From` for `FirmwareFlashReport`, exercised directly. The
    // proto carries the same field shape, so the mapping is a straight copy.
    #[test]
    fn firmware_flash_report_model_to_proto() {
        type Fields = (
            bool,
            Option<bool>,
            Option<bool>,
            Option<bool>,
            Option<String>,
            Option<String>,
        );
        let project = |model: FirmwareFlashReport| -> Fields {
            let pb: FirmwareFlashReportPb = model.into();
            (
                pb.flashed,
                pb.reset,
                pb.verified_image,
                pb.verified_version,
                pb.observed_version,
                pb.expected_version,
            )
        };
        check_values(
            [
                Check {
                    scenario: "fully populated report",
                    input: FirmwareFlashReport {
                        flashed: true,
                        reset: Some(true),
                        verified_image: Some(true),
                        verified_version: Some(true),
                        observed_version: Some("32.43.1014".to_string()),
                        expected_version: Some("32.43.1014".to_string()),
                    },
                    expect: (
                        true,
                        Some(true),
                        Some(true),
                        Some(true),
                        Some("32.43.1014".to_string()),
                        Some("32.43.1014".to_string()),
                    ),
                },
                Check {
                    scenario: "default report maps to all-absent proto",
                    input: FirmwareFlashReport::default(),
                    expect: (false, None, None, None, None, None),
                },
            ],
            project,
        );
    }

    #[test]
    fn test_flasher_result_default() {
        let report = FirmwareFlashReport::default();
        assert!(!report.flashed);
        assert!(report.reset.is_none());
        assert!(report.verified_image.is_none());
        assert!(report.verified_version.is_none());
        assert!(report.observed_version.is_none());
        assert!(report.expected_version.is_none());
    }
}
