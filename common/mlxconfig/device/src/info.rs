use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

// MlxDeviceInfo represents detailed information
// about a Mellanox network device.
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
    pub psid: String,
    // device_description provides a human-readable
    // description of the device.
    pub device_description: String,
    // part_number is the manufacturer part number
    // for the device.
    pub part_number: String,
    // fw_version_current is the currently
    // installed firmware version.
    pub fw_version_current: String,
    // pxe_version_current is the currently installed
    // PXE boot version.
    pub pxe_version_current: String,
    // uefi_version_current is the currently installed
    // UEFI boot version.
    pub uefi_version_current: String,
    // uefi_version_virtio_blk_current is the currently
    // installed UEFI VirtIO block driver version.
    pub uefi_version_virtio_blk_current: String,
    // uefi_version_virtio_net_current is the currently
    // installed UEFI VirtIO network driver version.
    pub uefi_version_virtio_net_current: String,
    // base_mac is the base MAC address for the device.
    pub base_mac: MacAddress,
}

impl MlxDeviceInfo {
    // get_field_value returns the value of a field by name for display purposes.
    pub fn get_field_value(&self, field_name: &str) -> String {
        match field_name {
            "pci_name" => self.pci_name.clone(),
            "device_type" => self.device_type.clone(),
            "psid" => self.psid.clone(),
            "device_description" => self.device_description.clone(),
            "part_number" => self.part_number.clone(),
            "fw_version_current" => self.fw_version_current.clone(),
            "pxe_version_current" => self.pxe_version_current.clone(),
            "uefi_version_current" => self.uefi_version_current.clone(),
            "uefi_version_virtio_blk_current" => self.uefi_version_virtio_blk_current.clone(),
            "uefi_version_virtio_net_current" => self.uefi_version_virtio_net_current.clone(),
            "base_mac" => self.base_mac.to_string(),
            _ => "".to_string(),
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
        ]
    }
}
