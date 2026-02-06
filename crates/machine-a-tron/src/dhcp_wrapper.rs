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
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::sync::Arc;

use carbide_uuid::machine::MachineInterfaceId;
use mac_address::MacAddress;
use rpc::forge::ManagedHostNetworkConfigResponse;
use tokio::sync::{RwLock, mpsc, oneshot};

use crate::api_client::{ApiClient, ClientApiError};

pub type DhcpRelayResult<T> = Result<T, DhcpRelayError>;

#[derive(Debug)]
pub struct DhcpRequestInfo {
    pub mac_address: MacAddress,
    pub relay_address: Ipv4Addr,
    pub template_dir: String,
}

#[derive(Clone, Debug)]
pub struct DhcpResponseInfo {
    pub interface_id: Option<MachineInterfaceId>,
    pub ip_address: Ipv4Addr,
}

pub async fn request_ip(
    api_client: ApiClient,
    request_info: DhcpRequestInfo,
) -> DhcpRelayResult<DhcpResponseInfo> {
    tracing::debug!("requesting ip for mac: {}", request_info.mac_address);

    let dhcp_record = api_client
        .discover_dhcp(
            request_info.mac_address,
            request_info.template_dir.clone(),
            request_info.relay_address.to_string(),
            None,
        )
        .await
        .inspect_err(|e| {
            tracing::warn!("discover_dhcp failed: {e}");
        })?;

    tracing::info!(
        "dhcp request for {} through relay {} got address {} (machine id {:?})",
        request_info.mac_address,
        request_info.relay_address,
        dhcp_record.address,
        dhcp_record.machine_id,
    );

    let interface_uuid = dhcp_record.machine_interface_id.ok_or_else(|| {
        DhcpRelayError::InvalidDhcpRecord("missing machine_interface_id".to_string())
    })?;

    let response_info = DhcpResponseInfo {
        interface_id: Some(interface_uuid),
        ip_address: dhcp_record.address.parse::<Ipv4Addr>().map_err(|e| {
            DhcpRelayError::InvalidDhcpRecord(format!(
                "{} is not an IPv4 address: {}",
                dhcp_record.address, e
            ))
        })?,
    };

    Ok(response_info)
}

#[derive(thiserror::Error, Debug)]
pub enum DhcpRelayError {
    #[error("Client API error: {0}")]
    ClientApiError(#[from] ClientApiError),
    #[error("Invalid DHCP record: {0}")]
    InvalidDhcpRecord(String),
    #[error("Cannot send host DHCP from DPU as relay: {0}")]
    DpuRelayError(String),
}

impl From<tonic::Status> for DhcpRelayError {
    fn from(s: tonic::Status) -> Self {
        Self::ClientApiError(ClientApiError::from(s))
    }
}

/// A DpuDhcpRelay forms a channel that links between a HostMachine and the DpuMachine which is
/// performing DHCP requests on its behalf. It's a PCIe bus in a tokio channel. :-D
///
/// A DPU synthesizes DHCP responses from its managed host network config, so it doesn't need any
/// additional API calls (since it should already have the config cached when it's booted.)
///
/// HostMachines can use HostEnd to send requests (no info needed) to which the DpuEnd will reply.
/// DpuMachines are expected to call [`DpuDhcpRelayServer::spawn`] from the DpuEnd when they are in
/// a steady (booted) state (and have a ManagedHostNetworkConfig.)
#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)] // Dumb lint. "End" is a semantically important suffix here.
pub enum DpuDhcpRelay {
    HostEnd(mpsc::UnboundedSender<DhcpRelayReply>),
    DpuEnd(DpuDhcpRelayServer),
}

pub type DhcpRelayReply = oneshot::Sender<DhcpRelayResult<DhcpResponseInfo>>;

#[derive(Debug, Clone)]
pub struct DpuDhcpRelayServer {
    request_rx: Arc<RwLock<mpsc::UnboundedReceiver<DhcpRelayReply>>>,
}

impl DpuDhcpRelayServer {
    pub fn new(reply_rx: mpsc::UnboundedReceiver<DhcpRelayReply>) -> Self {
        Self {
            request_rx: Arc::new(RwLock::new(reply_rx)),
        }
    }

    /// Run a DHCP server that replies to requests by vending IP's from the given
    /// [`ManagedHostNetworkConfigResponse`], in a background task, and return a stop handle. The
    /// service will stop once the stop handle is dropped.
    ///
    /// Only one service will run at a time, so if a prior call to spawn() is still running, this
    /// task will not start accepting requests until the prior task is complete.
    ///
    /// The caller, [`MachineStateMachine`], stores the stop handle in the MachineUp state, so it is
    /// implicitly dropped (and this task stopped) when the mock DPU is rebooted.
    pub fn spawn(&self, network_config: ManagedHostNetworkConfigResponse) -> oneshot::Sender<()> {
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let request_rx = self.request_rx.clone();
        tokio::spawn(async move {
            // Only one dhcp relay at a time can respond to requests.
            let mut request_rx = request_rx.write().await;
            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        tracing::info!("DPU shutting down, not serving DHCP requests from host");
                        break;
                    }
                    result = request_rx.recv() => {
                        let Some(reply) = result else {
                            tracing::info!("DpuDhcpRelay request channel closed, shutting down");
                            break;
                        };
                        reply.send(synthesize_dhcp_response_for_host(&network_config)).ok();
                    }
                }
            }
        });
        stop_tx
    }
}

// Synthesize a DHCP response given the provided ManagedHostNetworkConfigResponse
fn synthesize_dhcp_response_for_host(
    managed_host_config: &ManagedHostNetworkConfigResponse,
) -> DhcpRelayResult<DhcpResponseInfo> {
    let interface = if managed_host_config.use_admin_network {
        vec![managed_host_config.admin_interface.clone().ok_or_else(|| {
            DhcpRelayError::InvalidDhcpRecord("Admin interface is invalid.".to_string())
        })?]
    } else {
        // TODO: As of now MAT does not support VF, so assuming that only one interface is present
        // in tenant interface.
        managed_host_config.tenant_interfaces.clone()
    };

    let ip = interface[0]
        .ip
        .parse::<Ipv4Addr>()
        .map_err(|x| DhcpRelayError::InvalidDhcpRecord(x.to_string()))?;

    Ok(DhcpResponseInfo {
        interface_id: managed_host_config
            .host_interface_id
            .as_ref()
            .and_then(|x| x.parse().ok()),
        ip_address: ip,
    })
}
