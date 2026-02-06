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
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::Ipv4Addr;
use std::str::FromStr;

use carbide_uuid::UuidConversionError;
use carbide_uuid::machine::MachineInterfaceId;
use ipnetwork::Ipv4Network;
use rpc::InterfaceFunctionType;
use rpc::errors::RpcDataConversionError;
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
    #[error("DhcpDataError: RpcDataConversionError: {0}")]
    RpcConversion(#[from] RpcDataConversionError),
    #[error("DhcpDataError: UuidConversionError: {0}")]
    UuidConversion(#[from] UuidConversionError),
    #[error("DhcpDataError: UuidParseError: {0}")]
    UuidParseError(#[from] carbide_uuid::typed_uuids::UuidError),
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
    pub host_interface_id: MachineInterfaceId,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
}
impl Default for InterfaceInfo {
    fn default() -> Self {
        InterfaceInfo {
            address: Ipv4Addr::UNSPECIFIED,
            gateway: Ipv4Addr::UNSPECIFIED,
            prefix: Default::default(),
            fqdn: Default::default(),
            booturl: None,
            mtu: None,
        }
    }
}
impl HostConfig {
    pub fn try_from(
        value: ManagedHostNetworkConfigResponse,
        physical_rep: &str,
        virt_rep_begin: &str,
        sf_id: &str,
    ) -> Result<Self, DhcpDataError> {
        let mut host_ip_addresses = BTreeMap::new();
        let virtualization_type = value.network_virtualization_type();

        let interface_configs = if value.use_admin_network {
            let Some(interface_config) = value.admin_interface else {
                return Err(DhcpDataError::ParameterMissing("AdminInterface"));
            };
            vec![interface_config]
        } else {
            value.tenant_interfaces
        };

        for interface in interface_configs {
            let interface_name = if virtualization_type == ::rpc::forge::VpcVirtualizationType::Fnn
                && !interface.is_l2_segment
            {
                if interface.function_type() == InterfaceFunctionType::Physical {
                    // pf0hpf_sf/if
                    physical_rep.to_string()
                } else {
                    // pf0vf{0-15}_sf/if
                    format!(
                        "{}{}{}",
                        virt_rep_begin,
                        interface.virtual_function_id(),
                        sf_id
                    )
                }
            } else {
                format!("vlan{}", interface.vlan_id)
            };
            host_ip_addresses.insert(interface_name, InterfaceInfo::try_from(interface)?);
        }

        Ok(HostConfig {
            host_interface_id: value
                .host_interface_id
                .ok_or(DhcpDataError::ParameterMissing("HostInterfaceId"))?
                .parse()?,
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
            mtu: value.mtu,
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
    timestamps: HashMap<MachineInterfaceId, String>,

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

    pub fn add_timestamp(&mut self, host_id: MachineInterfaceId, timestamp: String) {
        self.timestamps.insert(host_id, timestamp);
    }

    pub fn get_timestamp(&self, host_id: &MachineInterfaceId) -> Option<&String> {
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
    type Item = (MachineInterfaceId, String);
    type IntoIter = std::collections::hash_map::IntoIter<MachineInterfaceId, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.timestamps.into_iter()
    }
}
