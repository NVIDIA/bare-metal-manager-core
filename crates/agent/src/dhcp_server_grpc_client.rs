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

pub mod proto {
    tonic::include_proto!("dhcp_server_control");
}

use carbide_uuid::machine::MachineInterfaceId;
use proto::dhcp_server_control_client::DhcpServerControlClient;
use utils::models::dhcp::{
    DhcpConfig as ModelDhcpConfig, HostConfig as ModelHostConfig,
    InterfaceInfo as ModelInterfaceInfo,
};

// ── Model → proto conversions ─────────────────────────────────────────────────

impl From<ModelDhcpConfig> for proto::DhcpConfig {
    fn from(c: ModelDhcpConfig) -> Self {
        proto::DhcpConfig {
            lease_time_secs: c.lease_time_secs,
            renewal_time_secs: c.renewal_time_secs,
            rebinding_time_secs: c.rebinding_time_secs,
            carbide_nameservers: c
                .carbide_nameservers
                .iter()
                .map(|ip| ip.to_string())
                .collect(),
            carbide_api_url: c.carbide_api_url,
            carbide_ntpservers: c
                .carbide_ntpservers
                .iter()
                .map(|ip| ip.to_string())
                .collect(),
            carbide_provisioning_server_ipv4: c.carbide_provisioning_server_ipv4.to_string(),
            carbide_dhcp_server: c.carbide_dhcp_server.to_string(),
        }
    }
}

impl From<ModelInterfaceInfo> for proto::InterfaceInfo {
    fn from(i: ModelInterfaceInfo) -> Self {
        proto::InterfaceInfo {
            address: i.address.to_string(),
            gateway: i.gateway.to_string(),
            prefix: i.prefix,
            fqdn: i.fqdn,
            booturl: i.booturl,
            mtu: i.mtu,
        }
    }
}

impl From<ModelHostConfig> for proto::HostConfig {
    fn from(h: ModelHostConfig) -> Self {
        proto::HostConfig {
            host_interface_id: h.host_interface_id.to_string(),
            host_ip_addresses: h
                .host_ip_addresses
                .into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect(),
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Fetches last DHCP request timestamps from the dhcp-server control service.
///
/// Used when the DHCP server runs in a separate container where the timestamps
/// file is not directly accessible on the DPU filesystem.  Each entry carries
/// the host interface UUID and the timestamp of the last DHCP request seen for
/// that interface.  Returns an empty `Vec` (with a warning) if the call fails,
/// so the caller can degrade gracefully.
pub async fn get_dhcp_timestamps(
    grpc_addr: &str,
) -> eyre::Result<Vec<::rpc::forge::LastDhcpRequest>> {
    let channel = tonic::transport::Endpoint::new(grpc_addr.to_string())?
        .connect()
        .await?;
    let mut client = DhcpServerControlClient::new(channel);

    let entries = client
        .get_dhcp_timestamps(proto::GetDhcpTimestampsRequest {})
        .await
        .map_err(|s| eyre::eyre!("GetDhcpTimestamps gRPC failed: {s}"))?
        .into_inner()
        .entries;

    let requests = entries
        .into_iter()
        .filter_map(|e| {
            let id = e
                .host_interface_id
                .parse::<MachineInterfaceId>()
                .map_err(|err| tracing::warn!("Skipping unparseable host_interface_id: {err}"))
                .ok()?;
            Some(::rpc::forge::LastDhcpRequest {
                host_interface_id: Some(id),
                timestamp: e.timestamp,
            })
        })
        .collect();

    Ok(requests)
}

/// Sends a stop request to the dhcp-server control service.
///
/// The gRPC control server remains running after this call so that a future
/// [`update_and_reload`] call can restart the DHCP process.
pub async fn stop_server(grpc_addr: &str) -> eyre::Result<()> {
    let channel = tonic::transport::Endpoint::new(grpc_addr.to_string())?
        .connect()
        .await?;
    let mut client = DhcpServerControlClient::new(channel);

    client
        .stop_server(proto::StopServerRequest {})
        .await
        .map_err(|s| eyre::eyre!("StopServer gRPC failed: {s}"))?;

    Ok(())
}

/// Pushes new DHCP config to the dhcp-server control service and triggers an
/// immediate reload in a single RPC.
///
/// The server only restarts the DHCP process if the incoming config differs
/// from what is already active, so this function is safe to call on every
/// agent tick.
pub async fn update_and_reload(
    grpc_addr: &str,
    dhcp_config: ModelDhcpConfig,
    host_config: Option<ModelHostConfig>,
    interfaces: Vec<String>,
) -> eyre::Result<()> {
    let channel = tonic::transport::Endpoint::new(grpc_addr.to_string())?
        .connect()
        .await?;
    let mut client = DhcpServerControlClient::new(channel);

    client
        .update_and_reload_config(proto::UpdateAndReloadConfigRequest {
            dhcp_config: Some(dhcp_config.into()),
            host_config: host_config.map(Into::into),
            interfaces,
        })
        .await
        .map_err(|s| eyre::eyre!("UpdateAndReloadConfig gRPC failed: {s}"))?;

    Ok(())
}
