use rpc::forge::DhcpRecord;

use crate::{
    errors::DhcpError,
    vendor_class::{MachineArchitecture, VendorClass},
    Config,
};

pub fn u8_to_mac(data: &[u8]) -> String {
    data.iter()
        .map(|x| format!("{:x}", x))
        .collect::<Vec<String>>()
        .join(":")
}

pub fn u8_to_hex_string(data: &[u8]) -> Result<String, DhcpError> {
    Ok(std::str::from_utf8(data)?.to_string())
}

pub fn machine_get_filename(
    dhcp_response: &DhcpRecord,
    vendor_class: &VendorClass,
    config: &Config,
) -> Vec<u8> {
    // If the API sent us the URL we should boot from, just use it.
    let url = if let Some(url) = &dhcp_response.booturl {
        url.to_string()
    } else {
        if !vendor_class.is_netboot() {
            return vec![];
        }

        let VendorClass { arch, .. } = vendor_class;

        let base_url = config.dhcp_config.carbide_provisioning_server_ipv4;
        match arch {
            MachineArchitecture::EfiX64 => format!(
                "http://{}:8080/public/blobs/internal/x86_64/ipxe.efi",
                base_url
            ),
            MachineArchitecture::Arm64 => format!(
                "http://{}:8080/public/blobs/internal/aarch64/ipxe.efi",
                base_url
            ),
            MachineArchitecture::BiosX86 => {
                tracing::warn!(
                    "Matched an HTTP client on a Legacy BIOS client, cannot provide HTTP boot URL"
                );
                return vec![];
            }
            MachineArchitecture::Unknown => {
                tracing::warn!("Matched an unknown architecture, cannot provide HTTP boot URL",);
                return vec![];
            }
        }
    };

    url.into_bytes().to_vec()
}
