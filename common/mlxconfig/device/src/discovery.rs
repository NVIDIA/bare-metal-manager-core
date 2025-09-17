use crate::filters::DeviceFilter;
use crate::info::MlxDeviceInfo;
use mac_address::MacAddress;
use quick_xml::de::from_str;
use serde::Deserialize;
use std::process::Command;
use std::str::FromStr;
use tracing::debug;

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
}

// VersionsXml represents the version information section
// from mlxfwmanager XML.
#[derive(Debug, Deserialize)]
struct VersionsXml {
    #[serde(rename = "FW")]
    fw: VersionXml,
    #[serde(rename = "PXE")]
    pxe: VersionXml,
    #[serde(rename = "UEFI")]
    uefi: VersionXml,
    #[serde(rename = "UEFI_Virtio_blk")]
    uefi_virtio_blk: VersionXml,
    #[serde(rename = "UEFI_Virtio_net")]
    uefi_virtio_net: VersionXml,
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

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("mlxfwmanager failed: {stderr}"));
    }

    let xml_content = String::from_utf8_lossy(&output.stdout);
    debug!("mlxfwmanager XML output: {}", xml_content);

    parse_mlxfwmanager_xml(&xml_content)
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

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("mlxfwmanager failed: {stderr}"));
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
                device.pci_name,
                device.device_type,
                device.part_number,
                device.fw_version_current,
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
fn parse_mlxfwmanager_xml(xml_content: &str) -> Result<Vec<MlxDeviceInfo>, String> {
    let devices_xml: DevicesXml =
        from_str(xml_content).map_err(|e| format!("Failed to parse mlxfwmanager XML: {e}"))?;

    let mut devices = Vec::new();

    for device_xml in devices_xml.devices {
        let pci_name = convert_pci_name_to_address(&device_xml.pci_name)?;
        let base_mac = MacAddress::from_str(&device_xml.macs.base_mac)
            .map_err(|e| format!("Invalid MAC address '{}': {}", device_xml.macs.base_mac, e))?;
        let device_info = MlxDeviceInfo {
            pci_name,
            device_type: device_xml.device_type,
            psid: device_xml.psid,
            device_description: device_xml.description,
            part_number: device_xml.part_number,
            fw_version_current: device_xml.versions.fw.current,
            pxe_version_current: device_xml.versions.pxe.current,
            uefi_version_current: device_xml.versions.uefi.current,
            uefi_version_virtio_blk_current: device_xml.versions.uefi_virtio_blk.current,
            uefi_version_virtio_net_current: device_xml.versions.uefi_virtio_net.current,
            base_mac,
        };
        devices.push(device_info);
    }

    debug!("Discovered {} MLX devices", devices.len());
    Ok(devices)
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
