use mac_address::MacAddress;
use mlxconfig_device::filters::{DeviceField, DeviceFilter, DeviceFilterSet, MatchMode};
use mlxconfig_device::info::MlxDeviceInfo;
use std::str::FromStr;

/// create_test_device creates a sample device for testing purposes.
fn create_test_device() -> MlxDeviceInfo {
    MlxDeviceInfo {
        pci_name: "01:00.0".to_string(),
        device_type: "ConnectX-6 Dx".to_string(),
        psid: "MT_00000055".to_string(),
        device_description: "Mellanox ConnectX-6 Dx EN 100GbE dual port".to_string(),
        part_number: "MCX623106AN-CDAT".to_string(),
        fw_version_current: "22.32.1010".to_string(),
        pxe_version_current: "3.6.0502".to_string(),
        uefi_version_current: "14.25.1020".to_string(),
        uefi_version_virtio_blk_current: "1.0.0".to_string(),
        uefi_version_virtio_net_current: "1.0.0".to_string(),
        base_mac: MacAddress::from_str("b8:3f:d2:12:34:56").unwrap(),
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

    assert_eq!(summary, "No filters".to_string());
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

    let filters = filter_set.filters;

    assert_eq!(filters.len(), 2);
    assert!(filters
        .iter()
        .any(|s| s.to_string().contains("device_type")));
    assert!(filters
        .iter()
        .any(|s| s.to_string().contains("part_number")));
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
    assert!(DeviceField::from_str("invalid").is_err());
}
