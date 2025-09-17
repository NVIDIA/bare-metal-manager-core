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

use crate::filters::{DeviceField, DeviceFilter, DeviceFilterSet, MatchMode};
use crate::info::MlxDeviceInfo;
use crate::report::MlxDeviceReport;
use chrono::{DateTime, Utc};
use mac_address::MacAddress;
use std::str::FromStr;

use rpc::protos::mlx_device::{
    DeviceField as DeviceFieldPb, DeviceFilter as DeviceFilterPb,
    DeviceFilterSet as DeviceFilterSetPb, MatchMode as MatchModePb,
    MlxDeviceInfo as MlxDeviceInfoPb, MlxDeviceReport as MlxDeviceReportPb,
};
use rpc::Timestamp;

// Convert chrono DateTime to RPC Timestamp.
fn datetime_to_timestamp(dt: DateTime<Utc>) -> Timestamp {
    Timestamp::from(prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    })
}

// Convert RPC Timestamp to chrono DateTime.
fn timestamp_to_datetime(ts: Timestamp) -> Result<DateTime<Utc>, String> {
    let prost_ts: prost_types::Timestamp = ts.into();
    DateTime::from_timestamp(prost_ts.seconds, prost_ts.nanos as u32).ok_or_else(|| {
        format!(
            "Invalid timestamp: {} seconds, {} nanos",
            prost_ts.seconds, prost_ts.nanos
        )
    })
}

// Implement conversion from Rust MlxDeviceReport to protobuf.
impl From<MlxDeviceReport> for MlxDeviceReportPb {
    fn from(report: MlxDeviceReport) -> Self {
        MlxDeviceReportPb {
            hostname: report.hostname,
            timestamp: Some(datetime_to_timestamp(report.timestamp)),
            devices: report.devices.into_iter().map(|d| d.into()).collect(),
            filters: report.filters.map(|f| f.into()),
        }
    }
}

// Implement conversion from protobuf MlxDeviceReport to Rust.
impl TryFrom<MlxDeviceReportPb> for MlxDeviceReport {
    type Error = String;

    fn try_from(proto: MlxDeviceReportPb) -> Result<Self, Self::Error> {
        let timestamp = proto
            .timestamp
            .ok_or("Missing timestamp in protobuf message")?;

        let devices: Result<Vec<_>, _> = proto.devices.into_iter().map(|d| d.try_into()).collect();

        let filters: Option<Result<DeviceFilterSet, String>> = proto.filters.map(|f| f.try_into());

        let filters = match filters {
            Some(Ok(f)) => Some(f),
            Some(Err(e)) => return Err(e),
            None => None,
        };

        Ok(MlxDeviceReport {
            hostname: proto.hostname,
            timestamp: timestamp_to_datetime(timestamp)?,
            devices: devices?,
            filters,
        })
    }
}

// Implement conversion from Rust MlxDeviceInfo to protobuf.
impl From<MlxDeviceInfo> for MlxDeviceInfoPb {
    fn from(info: MlxDeviceInfo) -> Self {
        MlxDeviceInfoPb {
            pci_name: info.pci_name,
            device_type: info.device_type,
            psid: info.psid,
            device_description: info.device_description,
            part_number: info.part_number,
            fw_version_current: info.fw_version_current,
            pxe_version_current: info.pxe_version_current,
            uefi_version_current: info.uefi_version_current,
            uefi_version_virtio_blk_current: info.uefi_version_virtio_blk_current,
            uefi_version_virtio_net_current: info.uefi_version_virtio_net_current,
            base_mac: info.base_mac.to_string(),
        }
    }
}

// Implement conversion from protobuf MlxDeviceInfo to Rust.
impl TryFrom<MlxDeviceInfoPb> for MlxDeviceInfo {
    type Error = String;

    fn try_from(proto: MlxDeviceInfoPb) -> Result<Self, Self::Error> {
        let base_mac = MacAddress::from_str(&proto.base_mac)
            .map_err(|e| format!("Invalid MAC address '{}': {}", proto.base_mac, e))?;

        Ok(MlxDeviceInfo {
            pci_name: proto.pci_name,
            device_type: proto.device_type,
            psid: proto.psid,
            device_description: proto.device_description,
            part_number: proto.part_number,
            fw_version_current: proto.fw_version_current,
            pxe_version_current: proto.pxe_version_current,
            uefi_version_current: proto.uefi_version_current,
            uefi_version_virtio_blk_current: proto.uefi_version_virtio_blk_current,
            uefi_version_virtio_net_current: proto.uefi_version_virtio_net_current,
            base_mac,
        })
    }
}

// Implement conversion from Rust DeviceFilterSet to protobuf.
impl From<DeviceFilterSet> for DeviceFilterSetPb {
    fn from(filter_set: DeviceFilterSet) -> Self {
        DeviceFilterSetPb {
            filters: filter_set.filters.into_iter().map(|f| f.into()).collect(),
        }
    }
}

// Implement conversion from protobuf DeviceFilterSet to Rust.
impl TryFrom<DeviceFilterSetPb> for DeviceFilterSet {
    type Error = String;

    fn try_from(proto: DeviceFilterSetPb) -> Result<Self, Self::Error> {
        let filters: Result<Vec<_>, _> = proto.filters.into_iter().map(|f| f.try_into()).collect();

        Ok(DeviceFilterSet { filters: filters? })
    }
}

// Implement conversion from Rust DeviceFilter to protobuf.
impl From<DeviceFilter> for DeviceFilterPb {
    fn from(filter: DeviceFilter) -> Self {
        DeviceFilterPb {
            field: device_field_to_proto(filter.field) as i32,
            values: filter.values,
            match_mode: match_mode_to_proto(filter.match_mode) as i32,
        }
    }
}

// Implement conversion from protobuf DeviceFilter to Rust.
impl TryFrom<DeviceFilterPb> for DeviceFilter {
    type Error = String;

    fn try_from(proto: DeviceFilterPb) -> Result<Self, Self::Error> {
        let field = proto_device_field_to_rust(proto.field)?;
        let match_mode = proto_match_mode_to_rust(proto.match_mode)?;

        Ok(DeviceFilter {
            field,
            values: proto.values,
            match_mode,
        })
    }
}

// Convert Rust DeviceField to protobuf enum.
fn device_field_to_proto(field: DeviceField) -> DeviceFieldPb {
    match field {
        DeviceField::DeviceType => DeviceFieldPb::DeviceType,
        DeviceField::PartNumber => DeviceFieldPb::PartNumber,
        DeviceField::FirmwareVersion => DeviceFieldPb::FirmwareVersion,
        DeviceField::MacAddress => DeviceFieldPb::MacAddress,
        DeviceField::Description => DeviceFieldPb::Description,
        DeviceField::PciName => DeviceFieldPb::PciName,
    }
}

// Convert protobuf DeviceField to Rust enum.
fn proto_device_field_to_rust(field: i32) -> Result<DeviceField, String> {
    match DeviceFieldPb::try_from(field) {
        Ok(DeviceFieldPb::DeviceType) => Ok(DeviceField::DeviceType),
        Ok(DeviceFieldPb::PartNumber) => Ok(DeviceField::PartNumber),
        Ok(DeviceFieldPb::FirmwareVersion) => Ok(DeviceField::FirmwareVersion),
        Ok(DeviceFieldPb::MacAddress) => Ok(DeviceField::MacAddress),
        Ok(DeviceFieldPb::Description) => Ok(DeviceField::Description),
        Ok(DeviceFieldPb::PciName) => Ok(DeviceField::PciName),
        Ok(DeviceFieldPb::Unspecified) => {
            Err("Unspecified device field is not allowed".to_string())
        }
        Err(_) => Err(format!("Invalid device field value: {field}")),
    }
}

// Convert Rust MatchMode to protobuf enum.
fn match_mode_to_proto(mode: MatchMode) -> MatchModePb {
    match mode {
        MatchMode::Regex => MatchModePb::Regex,
        MatchMode::Exact => MatchModePb::Exact,
        MatchMode::Prefix => MatchModePb::Prefix,
    }
}

// Convert protobuf MatchMode to Rust enum.
fn proto_match_mode_to_rust(mode: i32) -> Result<MatchMode, String> {
    match MatchModePb::try_from(mode) {
        Ok(MatchModePb::Regex) => Ok(MatchMode::Regex),
        Ok(MatchModePb::Exact) => Ok(MatchMode::Exact),
        Ok(MatchModePb::Prefix) => Ok(MatchMode::Prefix),
        Ok(MatchModePb::Unspecified) => {
            // Default to regex when unspecified for backward compatibility.
            Ok(MatchMode::Regex)
        }
        Err(_) => Err(format!("Invalid match mode value: {mode}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // create_test_device creates a sample device for testing purposes.
    fn create_test_device() -> MlxDeviceInfo {
        MlxDeviceInfo {
            pci_name: "01:00.0".to_string(),
            device_type: "ConnectX-6".to_string(),
            psid: "MT_0000055".to_string(),
            device_description: "Mellanox ConnectX-6 Dx EN 100GbE".to_string(),
            part_number: "MCX623106AN-CDAT_A1".to_string(),
            fw_version_current: "22.32.1010".to_string(),
            pxe_version_current: "3.6.0502".to_string(),
            uefi_version_current: "14.25.1020".to_string(),
            uefi_version_virtio_blk_current: "1.0.0".to_string(),
            uefi_version_virtio_net_current: "1.0.0".to_string(),
            base_mac: "b8:3f:d2:12:34:56".parse().unwrap(),
        }
    }

    #[test]
    fn test_device_info_roundtrip_conversion() {
        let original = create_test_device();
        let proto: MlxDeviceInfoPb = original.clone().into();
        let converted: MlxDeviceInfo = proto.try_into().unwrap();

        assert_eq!(original, converted);
    }

    #[test]
    fn test_device_report_roundtrip_conversion() {
        let original = MlxDeviceReport {
            hostname: "test-host".to_string(),
            timestamp: Utc::now(),
            devices: vec![create_test_device()],
            filters: None,
        };

        let proto: MlxDeviceReportPb = original.clone().into();
        let converted: MlxDeviceReport = proto.try_into().unwrap();

        assert_eq!(original.hostname, converted.hostname);
        assert_eq!(original.devices.len(), converted.devices.len());
        // Timestamp comparison with some tolerance due to precision differences.
        let time_diff = (original.timestamp - converted.timestamp)
            .num_milliseconds()
            .abs();
        assert!(time_diff < 1000); // Within 1 second
    }

    #[test]
    fn test_match_mode_conversion() {
        let modes = vec![MatchMode::Regex, MatchMode::Exact, MatchMode::Prefix];

        for mode in modes {
            let proto = match_mode_to_proto(mode.clone());
            let converted = proto_match_mode_to_rust(proto as i32).unwrap();
            assert_eq!(mode, converted);
        }
    }

    #[test]
    fn test_device_field_conversion() {
        let fields = vec![
            DeviceField::DeviceType,
            DeviceField::PartNumber,
            DeviceField::FirmwareVersion,
            DeviceField::MacAddress,
            DeviceField::Description,
            DeviceField::PciName,
        ];

        for field in fields {
            let proto = device_field_to_proto(field.clone());
            let converted = proto_device_field_to_rust(proto as i32).unwrap();
            assert_eq!(field, converted);
        }
    }

    #[test]
    fn test_filter_set_conversion() {
        let mut original_filter_set = DeviceFilterSet::new();
        original_filter_set.add_filter(DeviceFilter::device_type(
            vec!["ConnectX-6".to_string()],
            MatchMode::Prefix,
        ));
        original_filter_set.add_filter(DeviceFilter::part_number(
            vec!["MCX623".to_string()],
            MatchMode::Exact,
        ));

        let proto: DeviceFilterSetPb = original_filter_set.clone().into();
        let converted: DeviceFilterSet = proto.try_into().unwrap();

        assert_eq!(original_filter_set.filters.len(), converted.filters.len());
        assert_eq!(original_filter_set.summary(), converted.summary());
    }
}
