use ::utils::cmd::Cmd;

use super::PciDevicePropertiesExt;

const LINK_TYPE_P1: &str = "LINK_TYPE_P1";

// This function decides on well known Mellanox PCI ids taken from the https://pci-ids.ucw.cz/read/PC/15b3
// all BF DPUs start with 0xa2xx or 0xc2xx
pub fn is_dpu(device_id: &str) -> bool {
    device_id.starts_with("0xa2") || device_id.starts_with("0xc2")
}

//pub fn mlnx_ib_capable(device: &str, pci_subclass: &str, vendor: &str) -> bool {
pub fn mlnx_ib_capable(properties: &PciDevicePropertiesExt) -> bool {
    // TODO: Check whether the device exists.
    // only check Mellanox devices
    if let Some(device) = &properties.pci_properties.slot {
        if !device.is_empty()
            && properties
                .pci_properties
                .vendor
                .eq_ignore_ascii_case("Mellanox Technologies")
        {
            // there are three types of devices: VPI, IB-only and Eth-only
            // VPI and IB-only device are ib capable
            // VPI device has LINK_TYPE_P1 parameters. IB-only and Eth-only devices do not have these parameters.
            // IB-only device has Infiniband controller sub class.
            return check_link_type(device, LINK_TYPE_P1)
                || properties
                    .sub_class
                    .eq_ignore_ascii_case("Infiniband controller");
        }
    }
    false
}

fn check_link_type(device: &str, port: &str) -> bool {
    match Cmd::new("mstconfig")
        .args(vec!["-d", device, "q", port])
        .output()
    {
        Ok(_) => {
            tracing::info!("Device {} is IB capable", device,);
            true
        }
        Err(e) => {
            tracing::trace!("Device {} is not IB capable, result {} ", device, e,);
            false
        }
    }
}
