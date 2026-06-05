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
    use super::*;

    #[test]
    fn test_device_info_roundtrip_conversion() {
        let original = MlxDeviceInfo::create_test_device();
        let proto: MlxDeviceInfoPb = original.clone().into();
        let converted: MlxDeviceInfo = proto.try_into().unwrap();
        assert_eq!(original, converted);
    }

    #[test]
    fn test_device_info_with_missing_data_conversion() {
        let original = MlxDeviceInfo::create_test_device_with_missing_data();
        let proto: MlxDeviceInfoPb = original.clone().into();
        let converted: MlxDeviceInfo = proto.try_into().unwrap();

        // Required fields should be preserved
        assert_eq!(original.pci_name, converted.pci_name);
        assert_eq!(original.device_type, converted.device_type);

        // Optional fields should become None
        assert_eq!(converted.psid, None);
        assert_eq!(converted.part_number, None);
        assert_eq!(converted.base_mac, None);
        assert_eq!(converted.status, Some("Failed to open device".to_string()));
    }

    #[test]
    fn test_empty_string_fields_become_none() {
        let proto = MlxDeviceInfoPb {
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
        };

        let converted: MlxDeviceInfo = proto.try_into().unwrap();

        assert_eq!(converted.psid, None);
        assert_eq!(converted.part_number, None);
        assert_eq!(converted.base_mac, None);
        assert_eq!(converted.fw_version_current, None);
        assert_eq!(converted.status, None);
    }

    #[test]
    fn test_flasher_result_all_steps_success() {
        let original = FirmwareFlashReport {
            flashed: true,
            reset: Some(true),
            verified_image: Some(true),
            verified_version: Some(true),
            observed_version: Some("32.43.1014".to_string()),
            expected_version: Some("32.43.1014".to_string()),
        };
        let proto: FirmwareFlashReportPb = original.clone().into();
        let converted: FirmwareFlashReport = proto.into();

        assert_eq!(original.flashed, converted.flashed);
        assert_eq!(original.reset, converted.reset);
        assert_eq!(original.verified_image, converted.verified_image);
        assert_eq!(original.verified_version, converted.verified_version);
        assert_eq!(original.observed_version, converted.observed_version);
        assert_eq!(original.expected_version, converted.expected_version);
    }

    #[test]
    fn test_flasher_result_flash_only() {
        let original = FirmwareFlashReport {
            flashed: true,
            reset: None,
            verified_image: None,
            verified_version: None,
            observed_version: None,
            expected_version: None,
        };
        let proto: FirmwareFlashReportPb = original.into();
        let converted: FirmwareFlashReport = proto.into();

        assert!(converted.flashed);
        assert!(converted.reset.is_none());
        assert!(converted.verified_image.is_none());
        assert!(converted.verified_version.is_none());
        assert!(converted.observed_version.is_none());
    }

    #[test]
    fn test_flasher_result_partial_failure() {
        let original = FirmwareFlashReport {
            flashed: true,
            reset: Some(false),
            verified_image: Some(false),
            verified_version: Some(false),
            observed_version: Some("32.42.900".to_string()),
            expected_version: Some("32.43.1014".to_string()),
        };
        let proto: FirmwareFlashReportPb = original.into();
        let converted: FirmwareFlashReport = proto.into();

        assert!(converted.flashed);
        assert_eq!(converted.reset, Some(false));
        assert_eq!(converted.verified_image, Some(false));
        assert_eq!(converted.verified_version, Some(false));
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
