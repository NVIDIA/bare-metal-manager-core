/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::machine::MachineInterfaceId;
use lru::LruCache;
use rpc::forge::{DhcpDiscovery, DhcpRecord};
use tonic::async_trait;
use utils::models::dhcp::InterfaceInfo;

use super::DhcpMode;
use crate::cache::CacheEntry;
use crate::errors::DhcpError;
use crate::packet_handler::DecodedPacket;
use crate::{Config, HostConfig};

#[derive(Debug)]
pub struct Dpu {}

fn from_host_conf(value: &InterfaceInfo, interface_id: MachineInterfaceId) -> DhcpRecord {
    // Fill only needed fields. Rest are left empty or none.
    DhcpRecord {
        machine_id: None,
        machine_interface_id: Some(interface_id),
        segment_id: None,
        subdomain_id: None,
        fqdn: value.fqdn.clone(),
        mac_address: "dummy".to_string(),
        address: value.address.to_string(),
        mtu: 0,
        prefix: value.prefix.clone(),
        gateway: Some(value.gateway.to_string()),
        booturl: value.booturl.clone(),
        last_invalidation_time: None,
    }
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

        Ok(from_host_conf(ip_details, host_config.host_interface_id))
    }

    /// Here circuit is interface name. This is what dhcp-relay used to fill.
    fn get_circuit_id(&self, _packet: &DecodedPacket, circuit_id: &str) -> Option<String> {
        Some(circuit_id.to_string())
    }

    fn should_be_relayed(&self) -> bool {
        false
    }
}

/// This config is fetched by dpu-agent from controller periodically. In case of any change in
/// this configuration, dpu-agent MUST restart dhcp-server.
pub async fn get_host_config(
    host_config_path: Option<String>,
) -> Result<Option<HostConfig>, DhcpError> {
    let Some(host_config) = host_config_path else {
        return Err(DhcpError::MissingArgument(
            "--host_config is missing.".to_string(),
        ));
    };

    let f = tokio::fs::read_to_string(host_config).await?;
    let host_config: HostConfig = serde_yaml::from_str(&f)?;

    Ok(Some(host_config))
}
