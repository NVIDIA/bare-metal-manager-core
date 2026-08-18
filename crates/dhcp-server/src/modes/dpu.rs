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
use carbide_rpc_utils::dhcp::InterfaceInfo;
use carbide_uuid::machine::MachineInterfaceId;
use lru::LruCache;
use rpc::forge::{DhcpDiscovery, DhcpRecord};
use tonic::async_trait;

use super::DhcpMode;
use crate::cache::CacheEntry;
use crate::errors::DhcpError;
use crate::packet_handler::DecodedPacket;
use crate::{Config, HostConfig};

#[derive(Debug)]
pub(crate) struct Dpu {}

fn from_host_conf(
    value: &InterfaceInfo,
    interface_id: MachineInterfaceId,
) -> Result<DhcpRecord, DhcpError> {
    let address = value
        .address
        .ok_or_else(|| DhcpError::InvalidInput("IPv4 address is not configured".to_string()))?;
    let gateway = value
        .gateway
        .ok_or_else(|| DhcpError::InvalidInput("IPv4 gateway is not configured".to_string()))?;
    let prefix = value
        .prefix
        .clone()
        .ok_or_else(|| DhcpError::InvalidInput("IPv4 prefix is not configured".to_string()))?;

    // Fill only needed fields. Rest are left empty or none.
    Ok(DhcpRecord {
        machine_id: None,
        machine_interface_id: Some(interface_id),
        segment_id: None,
        subdomain_id: None,
        fqdn: value.fqdn.clone(),
        mac_address: "dummy".to_string(),
        address: address.to_string(),
        mtu: 0,
        prefix,
        gateway: Some(gateway.to_string()),
        booturl: value.booturl.clone(),
        last_invalidation_time: None,
        ntp_servers: vec![],
    })
}

#[async_trait]
impl DhcpMode for Dpu {
    async fn discover_dhcp(
        &self,
        discovery_request: DhcpDiscovery,
        config: &Config,
        _machine_cache: &mut std::sync::Arc<tokio::sync::Mutex<LruCache<String, CacheEntry>>>,
    ) -> Result<DhcpRecord, DhcpError> {
        let Some(circuit_id) = discovery_request.circuit_id else {
            return Err(DhcpError::MissingArgument(
                "Missing circuit id.".to_string(),
            ));
        };

        let ip_details = config
            .host_config
            .as_ref()
            .ok_or_else(|| DhcpError::InvalidInput("host input is invalid.".to_string()))?
            .host_ip_addresses
            .get(&circuit_id)
            .ok_or_else(|| {
                DhcpError::MissingArgument(format!("Could not find IP details for {circuit_id}"))
            })?;

        let Some(host_config) = &config.host_config else {
            return Err(DhcpError::MissingArgument(
                "host_config is missing.".to_string(),
            ));
        };

        from_host_conf(ip_details, host_config.host_interface_id)
    }

    /// Here circuit is interface name. This is what dhcp-relay used to fill.
    fn get_circuit_id(&self, _packet: &DecodedPacket, circuit_id: &str) -> Option<String> {
        Some(circuit_id.to_string())
    }

    fn should_be_relayed(&self) -> bool {
        false
    }
}

fn validate_host_config(host_config: &HostConfig) -> Result<(), DhcpError> {
    for (circuit_id, interface) in &host_config.host_ip_addresses {
        if !matches!(
            (&interface.address, &interface.gateway, &interface.prefix),
            (Some(_), Some(_), Some(_)) | (None, None, None)
        ) {
            return Err(DhcpError::InvalidInput(format!(
                "IPv4 address, gateway, and prefix for {circuit_id} must be configured together"
            )));
        }
    }

    Ok(())
}

/// This config is fetched by dpu-agent from controller periodically. In case of any change in
/// this configuration, dpu-agent MUST restart dhcp-server.
pub(crate) async fn get_host_config(
    host_config_path: Option<String>,
) -> Result<Option<HostConfig>, DhcpError> {
    let Some(host_config) = host_config_path else {
        return Err(DhcpError::MissingArgument(
            "--host_config is missing.".to_string(),
        ));
    };

    let f = tokio::fs::read_to_string(host_config).await?;
    let host_config: HostConfig = serde_yaml::from_str(&f)?;
    validate_host_config(&host_config)?;

    Ok(Some(host_config))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use carbide_rpc_utils::dhcp::InterfaceInfoV6;
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

    use super::*;

    fn summarize_ipv4_config(
        interface: InterfaceInfo,
    ) -> Result<(String, Option<String>, String), ()> {
        let interface_id = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        from_host_conf(&interface, interface_id)
            .map(|record| (record.address, record.gateway, record.prefix))
            .map_err(drop)
    }

    fn validate_interface_presence(interface: InterfaceInfo) -> Result<(), ()> {
        let host_config = HostConfig {
            host_interface_id: "11111111-1111-1111-1111-111111111111".parse().unwrap(),
            host_ip_addresses: [("vlan100".to_string(), interface)].into(),
        };
        validate_host_config(&host_config).map_err(drop)
    }

    #[test]
    fn host_config_requires_ipv4_for_dhcpv4() {
        scenarios!(run = summarize_ipv4_config;
            "complete IPv4 configuration" {
                InterfaceInfo {
                    address: Some(Ipv4Addr::new(192, 0, 2, 10)),
                    gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    prefix: Some("192.0.2.0/24".to_string()),
                    ..Default::default()
                } => Yields((
                    "192.0.2.10".to_string(),
                    Some("192.0.2.1".to_string()),
                    "192.0.2.0/24".to_string(),
                )),
            }
            "IPv6-only configuration" {
                InterfaceInfo {
                    ipv6: Some(InterfaceInfoV6 {
                        address: Some("2001:db8::10".parse().unwrap()),
                        prefix: "2001:db8::/64".to_string(),
                    }),
                    ..Default::default()
                } => Fails,
            }
            "missing IPv4 gateway" {
                InterfaceInfo {
                    address: Some(Ipv4Addr::new(192, 0, 2, 10)),
                    prefix: Some("192.0.2.0/24".to_string()),
                    ..Default::default()
                } => Fails,
            }
            "missing IPv4 prefix" {
                InterfaceInfo {
                    address: Some(Ipv4Addr::new(192, 0, 2, 10)),
                    gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    ..Default::default()
                } => Fails,
            }
        );
    }

    #[test]
    fn host_config_rejects_partial_ipv4_configuration() {
        scenarios!(run = validate_interface_presence;
            "complete IPv4 configuration" {
                InterfaceInfo {
                    address: Some(Ipv4Addr::new(192, 0, 2, 10)),
                    gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    prefix: Some("192.0.2.0/24".to_string()),
                    ..Default::default()
                } => Yields(()),
            }
            "IPv6-only configuration" {
                InterfaceInfo {
                    ipv6: Some(InterfaceInfoV6 {
                        address: Some("2001:db8::10".parse().unwrap()),
                        prefix: "2001:db8::/64".to_string(),
                    }),
                    ..Default::default()
                } => Yields(()),
            }
            "missing IPv4 address" {
                InterfaceInfo {
                    gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    prefix: Some("192.0.2.0/24".to_string()),
                    ..Default::default()
                } => Fails,
            }
            "missing IPv4 gateway" {
                InterfaceInfo {
                    address: Some(Ipv4Addr::new(192, 0, 2, 10)),
                    prefix: Some("192.0.2.0/24".to_string()),
                    ..Default::default()
                } => Fails,
            }
            "missing IPv4 prefix" {
                InterfaceInfo {
                    address: Some(Ipv4Addr::new(192, 0, 2, 10)),
                    gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
                    ..Default::default()
                } => Fails,
            }
        );
    }
}
