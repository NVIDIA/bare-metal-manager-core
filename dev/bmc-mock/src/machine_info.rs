use mac_address::MacAddress;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_MAC_ADDRESS: AtomicU32 = AtomicU32::new(1);

/// Represents static information we know ahead of time about a host or DPU (independent of any
/// state we get from carbide like IP addresses or machine ID's.) Intended to be immutable and
/// easily cloneable.
#[derive(Debug, Clone)]
pub enum MachineInfo {
    Host(HostMachineInfo),
    Dpu(DpuMachineInfo),
}

#[derive(Debug, Clone)]
pub struct HostMachineInfo {
    pub bmc_mac_address: MacAddress,
    pub serial: String,
    pub dpus: Vec<DpuMachineInfo>,
    pub non_dpu_mac_address: Option<MacAddress>,
}

#[derive(Debug, Clone)]
pub struct DpuMachineInfo {
    pub bmc_mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub oob_mac_address: MacAddress,
    pub serial: String,
    pub nic_mode: bool,
}

impl Default for DpuMachineInfo {
    fn default() -> Self {
        Self::new(false)
    }
}

impl DpuMachineInfo {
    pub fn new(nic_mode: bool) -> Self {
        let bmc_mac_address = next_mac();
        let host_mac_address = next_mac();
        let oob_mac_address = next_mac();
        Self {
            bmc_mac_address,
            host_mac_address,
            oob_mac_address,
            nic_mode,
            serial: format!("MT{}", oob_mac_address.to_string().replace(':', "")),
        }
    }
}

impl HostMachineInfo {
    pub fn new(dpus: Vec<DpuMachineInfo>) -> Self {
        let bmc_mac_address = next_mac();
        Self {
            bmc_mac_address,
            serial: bmc_mac_address.to_string().replace(':', ""),
            non_dpu_mac_address: if dpus.is_empty() {
                Some(next_mac())
            } else {
                None
            },
            dpus,
        }
    }

    pub fn primary_dpu(&self) -> Option<&DpuMachineInfo> {
        self.dpus.first()
    }

    pub fn system_mac_address(&self) -> Option<MacAddress> {
        self.primary_dpu()
            .map(|d| d.host_mac_address)
            .or(self.non_dpu_mac_address)
    }
}

impl MachineInfo {
    pub fn chassis_serial(&self) -> Option<String> {
        match self {
            Self::Host(h) => Some(h.serial.clone()),
            Self::Dpu(_) => None,
        }
    }

    pub fn product_serial(&self) -> Option<String> {
        match self {
            Self::Host(h) => Some(h.serial.clone()),
            Self::Dpu(d) => Some(d.serial.clone()),
        }
    }

    pub fn bmc_mac_address(&self) -> MacAddress {
        match self {
            Self::Host(h) => h.bmc_mac_address,
            Self::Dpu(d) => d.bmc_mac_address,
        }
    }

    /// Returns the mac addresses this system would use to request DHCP on boot
    pub fn dhcp_mac_addresses(&self) -> Vec<MacAddress> {
        match self {
            Self::Host(h) => {
                if h.dpus.is_empty() {
                    h.non_dpu_mac_address.map(|m| vec![m]).unwrap_or_default()
                } else {
                    h.dpus.iter().map(|d| d.host_mac_address).collect()
                }
            }
            Self::Dpu(d) => vec![d.oob_mac_address],
        }
    }

    // If this is a DPU, return its host mac address
    pub fn host_mac_address(&self) -> Option<MacAddress> {
        if let Self::Dpu(d) = self {
            Some(d.host_mac_address)
        } else {
            None
        }
    }
}

fn next_mac() -> MacAddress {
    let next_mac_num = NEXT_MAC_ADDRESS.fetch_add(1, Ordering::Acquire);

    let bytes: Vec<u8> = [0x02u8, 0x01]
        .into_iter()
        .chain(next_mac_num.to_be_bytes())
        .collect();

    let mac_bytes = <[u8; 6]>::try_from(bytes).unwrap();

    MacAddress::from(mac_bytes)
}
