use std::{collections::BTreeMap, net::Ipv4Addr, str::FromStr};

use ipnetwork::Ipv4Network;
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
    pub carbide_ntpserver: Option<Ipv4Addr>,
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
            carbide_ntpserver: None,

            // These two must be updated with valid values.
            carbide_provisioning_server_ipv4: Ipv4Addr::from([127, 0, 0, 1]),
            carbide_dhcp_server: Ipv4Addr::from([127, 0, 0, 1]),
        }
    }
}

impl DhcpConfig {
    pub fn from_forge_dhcp_config(
        carbide_provisioning_server_ipv4: Ipv4Addr,
        carbide_ntpserver: Option<Ipv4Addr>,
        carbide_nameservers: Vec<Ipv4Addr>,
        loopback_ip: Ipv4Addr,
    ) -> Result<Self, DhcpDataError> {
        Ok(DhcpConfig {
            carbide_nameservers,
            carbide_ntpserver,
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

        for interface in interface_configs {
            host_ip_addresses.insert(
                format!("vlan{}", interface.vlan_id),
                InterfaceInfo::try_from(interface)?,
            );
        }

        Ok(HostConfig {
            host_interface_id: value
                .host_interface_id
                .ok_or(DhcpDataError::ParameterMissing("HostInterfaceId"))?,
            host_ip_addresses,
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
