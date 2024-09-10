use std::{
    collections::{BTreeMap, HashMap},
    fs,
    net::Ipv4Addr,
    str::FromStr,
};

use forge_network::virtualization::{get_svi_prefix, VpcVirtualizationType};
use ipnetwork::{IpNetwork, Ipv4Network};
use rpc::forge::ManagedHostNetworkConfigResponse;
use serde::{Deserialize, Serialize};

/// This structure is used in dhcp-server and dpu-agent. dpu-agent passes these information to
/// dhcp-server. dhcp-server uses it for handling packet.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DhcpConfig {
    pub lease_time_secs: u32,
    pub renewal_time_secs: u32,
    pub rebinding_time_secs: u32,
    pub carbide_nameservers: Vec<Ipv4Addr>,
    // Mandatory for Controller mode.
    pub carbide_api_url: Option<String>,
    pub carbide_ntpservers: Vec<Ipv4Addr>,
    pub carbide_provisioning_server_ipv4: Ipv4Addr,
    pub carbide_dhcp_server: Ipv4Addr,
}

#[derive(thiserror::Error, Debug)]
pub enum DhcpDataError {
    #[error("DhcpDataError: AddressParseError: {0}")]
    AddressParseError(#[from] std::net::AddrParseError),
    #[error("DhcpDataError: Missing: {0}")]
    ParameterMissing(&'static str),
    #[error("DhcpDataError: IpNetworkError: {0}")]
    IpNetworkError(#[from] ipnetwork::IpNetworkError),
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            // Use some sane defaults
            lease_time_secs: 604800,
            renewal_time_secs: 3600,
            rebinding_time_secs: 432000,
            carbide_nameservers: vec![],
            carbide_api_url: None,
            carbide_ntpservers: vec![],

            // These two must be updated with valid values.
            carbide_provisioning_server_ipv4: Ipv4Addr::from([127, 0, 0, 1]),
            carbide_dhcp_server: Ipv4Addr::from([127, 0, 0, 1]),
        }
    }
}

impl DhcpConfig {
    pub fn from_forge_dhcp_config(
        carbide_provisioning_server_ipv4: Ipv4Addr,
        carbide_ntpservers: Vec<Ipv4Addr>,
        carbide_nameservers: Vec<Ipv4Addr>,
        loopback_ip: Ipv4Addr,
    ) -> Result<Self, DhcpDataError> {
        Ok(DhcpConfig {
            carbide_nameservers,
            carbide_ntpservers,
            carbide_provisioning_server_ipv4,
            carbide_dhcp_server: loopback_ip,
            ..Default::default()
        })
    }
}

type CircuitId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub host_interface_id: String,
    // BTreeMap is needed because we want ordered map. Due to unordered nature of HashMap, the
    // serialized output was changing very frequently and it was causing dpu-agent to restart dhcp-server
    // very frequently although no config was changed.
    pub host_ip_addresses: BTreeMap<CircuitId, InterfaceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub address: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub prefix: String,
    pub fqdn: String,
    pub booturl: Option<String>,
}

impl TryFrom<ManagedHostNetworkConfigResponse> for HostConfig {
    type Error = DhcpDataError;
    fn try_from(value: ManagedHostNetworkConfigResponse) -> Result<Self, Self::Error> {
        let mut host_ip_addresses = BTreeMap::new();

        let interface_configs = if value.use_admin_network {
            let Some(interface_config) = value.admin_interface else {
                return Err(DhcpDataError::ParameterMissing("AdminInterface"));
            };
            vec![interface_config]
        } else {
            value.tenant_interfaces
        };

        // If the host is part of an FNN L3 virtualized VPC, then the DHCP prefix
        // should be the gateway interface prefix, which is the second /31 of
        // the /30 allocated to the DPU interface for FNN.
        //
        // Among other things, the prefix here is used to derive the subnet mask
        // set in the DHCP reply packet (where a /31 will result in a .254 mask),
        // so it needs to be set accordingly.
        //
        // If it's not FNN-L3, just use the prefix that comes with the
        // corresponding network segment (defaulting to ETV if needed, since
        // ETV will also just do what we want here).
        let vpc_virtualization_type =
            if let Some(virtualization_i32) = value.network_virtualization_type {
                VpcVirtualizationType::try_from(virtualization_i32)
                    .map_err(|_| DhcpDataError::ParameterMissing("vpc_virtualization_type"))?
            } else {
                VpcVirtualizationType::EthernetVirtualizer
            };

        for interface in interface_configs {
            match vpc_virtualization_type {
                VpcVirtualizationType::FnnL3 => {
                    host_ip_addresses.insert(
                        format!("vlan{}", interface.vlan_id),
                        InterfaceInfo::try_from_fnn_l3(interface)?,
                    );
                }
                _ => {
                    host_ip_addresses.insert(
                        format!("vlan{}", interface.vlan_id),
                        InterfaceInfo::try_from(interface)?,
                    );
                }
            }
        }

        Ok(HostConfig {
            host_interface_id: value
                .host_interface_id
                .ok_or(DhcpDataError::ParameterMissing("HostInterfaceId"))?,
            host_ip_addresses,
        })
    }
}

impl InterfaceInfo {
    /// try_from_fnn_l3 takes a FlatInterfaceConfig and converts it into an
    /// InterfaceInfo, with the assumption the FlatInterfaceConfig is part
    /// of a machine allocated into an FNN-L3 VPC. In this mode, the network
    /// prefix (and corresponding subnet mask) are derived from the second
    /// /31 of the allocated /30 for the DPU, and not from the wider network
    /// the /30 is being allocated from.
    pub fn try_from_fnn_l3(
        value: ::rpc::forge::FlatInterfaceConfig,
    ) -> Result<Self, DhcpDataError> {
        let gateway = Ipv4Network::from_str(&value.gateway)?.ip();

        let dpu_prefix: IpNetwork = value
            .interface_prefix
            .parse()
            .map_err(|_| DhcpDataError::ParameterMissing("dpu_prefix"))?;
        let svi_prefix = get_svi_prefix(&dpu_prefix)
            .map_err(|_| DhcpDataError::ParameterMissing("svi_prefix"))?
            .map_or(value.prefix, |svi_prefix| svi_prefix.to_string());

        Ok(InterfaceInfo {
            address: value.ip.parse()?,
            gateway,
            prefix: svi_prefix,
            fqdn: value.fqdn,
            booturl: value.booturl,
        })
    }
}

impl TryFrom<::rpc::forge::FlatInterfaceConfig> for InterfaceInfo {
    type Error = DhcpDataError;
    fn try_from(value: ::rpc::forge::FlatInterfaceConfig) -> Result<Self, Self::Error> {
        let gateway = Ipv4Network::from_str(&value.gateway)?.ip();

        Ok(InterfaceInfo {
            address: value.ip.parse()?,
            gateway,
            prefix: value.prefix,
            fqdn: value.fqdn,
            booturl: value.booturl,
        })
    }
}

const DHCP_TIMESTAMP_FILE_HBN: &str = "/var/support/forge-dhcp/logs/dhcp_timestamps.json";
const DHCP_TIMESTAMP_FILE_HBN_TMP: &str = "/var/support/forge-dhcp/logs/dhcp_timestamps.json.tmp";
const DHCP_TIMESTAMP_FILE_DPU: &str =
    "/var/lib/hbn/var/support/forge-dhcp/logs/dhcp_timestamps.json";
const DHCP_TIMESTAMP_FILE_TEST: &str = "/tmp/timestamps.json";
#[derive(Serialize, Deserialize)]
pub struct DhcpTimestamps {
    timestamps: HashMap<String, String>,

    #[serde(skip)]
    path: DhcpTimestampsFilePath,
}

pub enum DhcpTimestampsFilePath {
    Hbn,
    Dpu,
    Test,
    NotSet,
}

impl DhcpTimestampsFilePath {
    pub fn path_str(&self) -> &str {
        match self {
            Self::Hbn => DHCP_TIMESTAMP_FILE_HBN_TMP,
            Self::Dpu => DHCP_TIMESTAMP_FILE_DPU,
            Self::Test => DHCP_TIMESTAMP_FILE_TEST,
            Self::NotSet => "Not set",
        }
    }
}

impl Default for DhcpTimestampsFilePath {
    fn default() -> Self {
        Self::NotSet
    }
}

impl DhcpTimestamps {
    pub fn new(filepath: DhcpTimestampsFilePath) -> Self {
        Self {
            timestamps: HashMap::new(),
            path: filepath,
        }
    }

    pub fn add_timestamp(&mut self, host_id: String, timestamp: String) {
        self.timestamps.insert(host_id, timestamp);
    }

    pub fn get_timestamp(&self, host_id: &String) -> Option<&String> {
        self.timestamps.get(host_id)
    }

    pub fn write(&self) -> eyre::Result<()> {
        if let DhcpTimestampsFilePath::NotSet = self.path {
            // No-op
            return Ok(());
        }
        let timestamp_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.path.path_str())?;

        serde_json::to_writer(timestamp_file, self)?;
        if let DhcpTimestampsFilePath::Hbn = self.path {
            // Rename the file.
            fs::rename(DHCP_TIMESTAMP_FILE_HBN_TMP, DHCP_TIMESTAMP_FILE_HBN)?;
        }
        Ok(())
    }

    pub fn read(&mut self) -> eyre::Result<()> {
        if let DhcpTimestampsFilePath::NotSet = self.path {
            // No-op
            return Ok(());
        }
        let timestamp_file = fs::OpenOptions::new()
            .read(true)
            .open(self.path.path_str())?;
        *self = serde_json::from_reader(timestamp_file)?;
        Ok(())
    }
}

impl Default for DhcpTimestamps {
    fn default() -> Self {
        Self::new(DhcpTimestampsFilePath::default())
    }
}

impl IntoIterator for DhcpTimestamps {
    type Item = (String, String);
    type IntoIter = std::collections::hash_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.timestamps.into_iter()
    }
}
