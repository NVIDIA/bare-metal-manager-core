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

use libmlx::device::filters::{DeviceField, DeviceFilter, DeviceFilterSet, MatchMode};
use libmlx::device::info::MlxDeviceInfo;
use mac_address::MacAddress;

/// create_test_device creates a sample device for testing purposes.
fn create_test_device() -> MlxDeviceInfo {
    MlxDeviceInfo {
        pci_name: "01:00.0".to_string(),
        device_type: "ConnectX-6 Dx".to_string(),
        psid: Some("MT_00000055".to_string()),
        device_description: Some("Mellanox ConnectX-6 Dx EN 100GbE dual port".to_string()),
        part_number: Some("MCX623106AN-CDAT".to_string()),
        fw_version_current: Some("22.32.1010".to_string()),
        pxe_version_current: Some("3.6.0502".to_string()),
        uefi_version_current: Some("14.25.1020".to_string()),
        uefi_version_virtio_blk_current: Some("1.0.0".to_string()),
        uefi_version_virtio_net_current: Some("1.0.0".to_string()),
        base_mac: Some(MacAddress::from_str("b8:3f:d2:12:34:56").unwrap()),
        status: None,
    }
}

/// create_test_device_with_missing_data creates a device with partial data (like a DPU).
fn create_test_device_with_missing_data() -> MlxDeviceInfo {
    MlxDeviceInfo {
        pci_name: "b4:00.0".to_string(),
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
        status: Some("Failed to open device".to_string()),
    }
}

#[test]
fn test_device_filter_set_no_filters_matches_all() {
    let device = create_test_device();
    let filter_set = DeviceFilterSet::new();

    assert!(filter_set.matches(&device));
    assert!(!filter_set.has_filters());
}

#[test]
fn test_device_filter_device_type_exact_match() {
    let device = create_test_device();
    let filter = DeviceFilter::device_type(vec!["ConnectX-6 Dx".to_string()], MatchMode::Exact);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_device_type_prefix_match() {
    let device = create_test_device();
    let filter = DeviceFilter::device_type(vec!["ConnectX".to_string()], MatchMode::Prefix);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_device_type_regex_match() {
    let device = create_test_device();
    let filter = DeviceFilter::device_type(vec!["Connect.*".to_string()], MatchMode::Regex);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_device_type_complex_regex() {
    let device = create_test_device();
    let filter = DeviceFilter::device_type(vec![".*X-6.*".to_string()], MatchMode::Regex);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_part_number_match() {
    let device = create_test_device();
    let filter = DeviceFilter::part_number(vec!["MCX623".to_string()], MatchMode::Prefix);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_firmware_version_match() {
    let device = create_test_device();
    let filter = DeviceFilter::firmware_version(vec!["22.32".to_string()], MatchMode::Prefix);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_mac_address_match() {
    let device = create_test_device();
    let filter = DeviceFilter::mac_address(vec!["b8:3f:d2".to_string()], MatchMode::Prefix);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_description_substring_match() {
    let device = create_test_device();
    let filter = DeviceFilter::description(vec![".*100GbE.*".to_string()], MatchMode::Regex);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_description_case_insensitive() {
    let device = create_test_device();
    let filter = DeviceFilter::description(vec!["mellanox".to_string()], MatchMode::Prefix);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_status_match() {
    let device = create_test_device_with_missing_data();
    let filter = DeviceFilter::status(vec!["Failed to open device".to_string()], MatchMode::Exact);

    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_set_multiple_criteria_all_match() {
    let device = create_test_device();
    let mut filter_set = DeviceFilterSet::new();

    filter_set.add_filter(DeviceFilter::device_type(
        vec!["ConnectX".to_string()],
        MatchMode::Prefix,
    ));
    filter_set.add_filter(DeviceFilter::part_number(
        vec!["MCX".to_string()],
        MatchMode::Prefix,
    ));
    filter_set.add_filter(DeviceFilter::firmware_version(
        vec!["22".to_string()],
        MatchMode::Prefix,
    ));

    assert!(filter_set.matches(&device));
    assert!(filter_set.has_filters());
}

#[test]
fn test_device_filter_set_multiple_criteria_one_fails() {
    let device = create_test_device();
    let mut filter_set = DeviceFilterSet::new();

    filter_set.add_filter(DeviceFilter::device_type(
        vec!["ConnectX".to_string()],
        MatchMode::Prefix,
    ));
    filter_set.add_filter(DeviceFilter::part_number(
        vec!["WRONG".to_string()],
        MatchMode::Prefix,
    ));

    assert!(!filter_set.matches(&device));
}

#[test]
fn test_device_filter_set_summary_empty() {
    let filter_set = DeviceFilterSet::new();
    let summary = filter_set.to_string();

    assert_eq!(summary, "No filters");
}

#[test]
fn test_device_filter_set_summary_with_filters() {
    let mut filter_set = DeviceFilterSet::new();

    filter_set.add_filter(DeviceFilter::device_type(
        vec!["ConnectX".to_string()],
        MatchMode::Prefix,
    ));
    filter_set.add_filter(DeviceFilter::part_number(
        vec!["MCX".to_string()],
        MatchMode::Prefix,
    ));

    let summary_vec = filter_set.summary();

    assert_eq!(summary_vec.len(), 2);
    assert!(summary_vec.iter().any(|s| s.contains("device_type")));
    assert!(summary_vec.iter().any(|s| s.contains("part_number")));
}

#[test]
fn test_device_filter_from_str_simple() {
    let filter_str = "device_type:ConnectX";
    let filter = DeviceFilter::from_str(filter_str).unwrap();

    assert_eq!(filter.field, DeviceField::DeviceType);
    assert_eq!(filter.values, vec!["ConnectX".to_string()]);
    assert_eq!(filter.match_mode, MatchMode::Regex);
}

#[test]
fn test_device_filter_from_str_with_match_mode() {
    let filter_str = "part_number:MCX623:exact";
    let filter = DeviceFilter::from_str(filter_str).unwrap();

    assert_eq!(filter.field, DeviceField::PartNumber);
    assert_eq!(filter.values, vec!["MCX623".to_string()]);
    assert_eq!(filter.match_mode, MatchMode::Exact);
}

#[test]
fn test_device_filter_from_str_multiple_values() {
    let filter_str = "device_type:ConnectX-6,ConnectX-7:prefix";
    let filter = DeviceFilter::from_str(filter_str).unwrap();

    assert_eq!(filter.field, DeviceField::DeviceType);
    assert_eq!(
        filter.values,
        vec!["ConnectX-6".to_string(), "ConnectX-7".to_string()]
    );
    assert_eq!(filter.match_mode, MatchMode::Prefix);
}

#[test]
fn test_device_filter_multiple_values_or_logic() {
    let device = create_test_device();
    let filter = DeviceFilter::device_type(
        vec!["ConnectX-7".to_string(), "ConnectX-6 Dx".to_string()],
        MatchMode::Exact,
    );

    // Should match because one of the values matches (ConnectX-6 Dx)
    assert!(filter.matches(&device));
}

#[test]
fn test_device_filter_with_missing_data() {
    let device = create_test_device_with_missing_data();

    // Filtering on missing data should not match
    let part_filter = DeviceFilter::part_number(vec!["MCX".to_string()], MatchMode::Prefix);
    assert!(!part_filter.matches(&device));

    // But filtering on device type should still work
    let type_filter = DeviceFilter::device_type(vec!["BlueField".to_string()], MatchMode::Prefix);
    assert!(type_filter.matches(&device));

    // Status filtering should work
    let status_filter = DeviceFilter::status(vec!["Failed".to_string()], MatchMode::Prefix);
    assert!(status_filter.matches(&device));
}

#[test]
fn test_match_mode_from_str() {
    assert_eq!(MatchMode::from_str("regex").unwrap(), MatchMode::Regex);
    assert_eq!(MatchMode::from_str("exact").unwrap(), MatchMode::Exact);
    assert_eq!(MatchMode::from_str("prefix").unwrap(), MatchMode::Prefix);
    assert_eq!(MatchMode::from_str("REGEX").unwrap(), MatchMode::Regex);
    assert!(MatchMode::from_str("invalid").is_err());
}

#[test]
fn test_device_field_from_str() {
    assert_eq!(
        DeviceField::from_str("device_type").unwrap(),
        DeviceField::DeviceType
    );
    assert_eq!(
        DeviceField::from_str("type").unwrap(),
        DeviceField::DeviceType
    );
    assert_eq!(
        DeviceField::from_str("part_number").unwrap(),
        DeviceField::PartNumber
    );
    assert_eq!(
        DeviceField::from_str("part").unwrap(),
        DeviceField::PartNumber
    );
    assert_eq!(
        DeviceField::from_str("firmware_version").unwrap(),
        DeviceField::FirmwareVersion
    );
    assert_eq!(
        DeviceField::from_str("fw").unwrap(),
        DeviceField::FirmwareVersion
    );
    assert_eq!(
        DeviceField::from_str("status").unwrap(),
        DeviceField::Status
    );
    assert!(DeviceField::from_str("invalid").is_err());
}

#[test]
fn test_empty_field_filtering() {
    let device = create_test_device_with_missing_data();

    // Test that empty fields don't match regular filters
    let fw_filter = DeviceFilter::firmware_version(vec!["22.32".to_string()], MatchMode::Prefix);
    assert!(!fw_filter.matches(&device));

    let mac_filter = DeviceFilter::mac_address(vec!["b8:3f".to_string()], MatchMode::Prefix);
    assert!(!mac_filter.matches(&device));

    // But device type should still match since it's always present
    let type_filter = DeviceFilter::device_type(vec!["BlueField".to_string()], MatchMode::Prefix);
    assert!(type_filter.matches(&device));
}

#[test]
fn test_mixed_device_filtering() {
    let complete_device = create_test_device();
    let partial_device = create_test_device_with_missing_data();

    // Filter that should match only complete devices
    let part_filter = DeviceFilter::part_number(vec!["MCX".to_string()], MatchMode::Prefix);
    assert!(part_filter.matches(&complete_device));
    assert!(!part_filter.matches(&partial_device));

    // Filter that should match both
    let type_filter = DeviceFilter::device_type(vec![".*".to_string()], MatchMode::Regex);
    assert!(type_filter.matches(&complete_device)); // ConnectX-6 Dx
    assert!(type_filter.matches(&partial_device)); // BlueField3 -> no match actually

    // Actually fix the regex to match both
    let broad_filter =
        DeviceFilter::device_type(vec!["Connect.*|Blue.*".to_string()], MatchMode::Regex);
    assert!(broad_filter.matches(&complete_device));
    assert!(broad_filter.matches(&partial_device));
}
