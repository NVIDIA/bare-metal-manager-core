use mlxconfig_device::discovery::convert_pci_name_to_address;

#[test]
fn test_convert_pci_name_removes_domain_prefix() {
    let input = "0000:01:00.0";
    let result = convert_pci_name_to_address(input).unwrap();
    assert_eq!(result, "01:00.0");
}

#[test]
fn test_convert_pci_name_passthrough_clean_address() {
    let input = "01:00.0";
    let result = convert_pci_name_to_address(input).unwrap();
    assert_eq!(result, "01:00.0");
}

#[test]
fn test_convert_pci_name_passthrough_mst_path() {
    let input = "/dev/mst/mt41692_pciconf0";
    let result = convert_pci_name_to_address(input).unwrap();
    assert_eq!(result, "/dev/mst/mt41692_pciconf0");
}

#[test]
fn test_convert_pci_name_passthrough_other_format() {
    let input = "custom_device_path";
    let result = convert_pci_name_to_address(input).unwrap();
    assert_eq!(result, "custom_device_path");
}

#[test]
fn test_convert_pci_name_multiple_domain_prefixes() {
    let input = "0000:0000:01:00.0";
    let result = convert_pci_name_to_address(input).unwrap();
    // Should only remove the first "0000:" prefix
    assert_eq!(result, "0000:01:00.0");
}

#[test]
fn test_convert_pci_name_empty_string() {
    let input = "";
    let result = convert_pci_name_to_address(input).unwrap();
    assert_eq!(result, "");
}
