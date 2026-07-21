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

use bmc_mock::{HostHardwareType, MachineInfo};
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
    pub vendor_class: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DhcpRequester {
    Bmc,
    System,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DhcpMachine {
    Dpu,
    Host(HostHardwareType),
}

impl From<&MachineInfo> for DhcpMachine {
    fn from(machine_info: &MachineInfo) -> Self {
        match machine_info {
            MachineInfo::Dpu(_) => Self::Dpu,
            MachineInfo::Host(host) => Self::Host(host.hw_type),
        }
    }
}

pub(crate) fn vendor_class(
    machine_info: &MachineInfo,
    requester: DhcpRequester,
) -> Option<&'static str> {
    vendor_class_for(DhcpMachine::from(machine_info), requester)
}

fn vendor_class_for(machine: DhcpMachine, requester: DhcpRequester) -> Option<&'static str> {
    match (machine, requester) {
        (DhcpMachine::Dpu, DhcpRequester::Bmc) => Some("NVIDIA/BF/BMC"),
        (DhcpMachine::Dpu, DhcpRequester::System) => Some("NVIDIA/BF/OOB"),
        (
            DhcpMachine::Host(
                HostHardwareType::DellPowerEdgeR750 | HostHardwareType::DellPowerEdgeR760Bf4,
            ),
            DhcpRequester::Bmc,
        ) => Some("iDRAC"),
        (DhcpMachine::Host(HostHardwareType::HpeProliantDl380aGen11), DhcpRequester::Bmc) => {
            Some("CPQRIB3")
        }
        // These BMCs have no verified DHCP vendor class, so omit option 60 rather than
        // reporting a value that may cause Carbide to misidentify the requester.
        (
            DhcpMachine::Host(
                HostHardwareType::WiwynnGB200Nvl
                | HostHardwareType::LenovoGB300Nvl
                | HostHardwareType::NvidiaDgxGb300
                | HostHardwareType::SupermicroGb300Nvl
                | HostHardwareType::NvidiaDgxVr
                | HostHardwareType::LiteOnPowerShelf
                | HostHardwareType::DeltaPowerShelf
                | HostHardwareType::NvidiaSwitchNd5200Ld
                | HostHardwareType::NvidiaDgxH100
                | HostHardwareType::GenericAmi
                | HostHardwareType::GenericSupermicro,
            ),
            DhcpRequester::Bmc,
        ) => None,
        (
            DhcpMachine::Host(
                HostHardwareType::DellPowerEdgeR750
                | HostHardwareType::DellPowerEdgeR760Bf4
                | HostHardwareType::WiwynnGB200Nvl
                | HostHardwareType::LenovoGB300Nvl
                | HostHardwareType::NvidiaDgxGb300
                | HostHardwareType::SupermicroGb300Nvl
                | HostHardwareType::NvidiaDgxVr
                | HostHardwareType::LiteOnPowerShelf
                | HostHardwareType::DeltaPowerShelf
                | HostHardwareType::NvidiaSwitchNd5200Ld
                | HostHardwareType::NvidiaDgxH100
                | HostHardwareType::GenericAmi
                | HostHardwareType::HpeProliantDl380aGen11
                | HostHardwareType::GenericSupermicro,
            ),
            DhcpRequester::System,
        ) => Some("PXEClient:Arch:00007:UNDI:003000"),
    }
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
    tracing::debug!(
        mac_address = %request_info.mac_address,
        "Requesting IP address",
    );

    let dhcp_record = api_client
        .discover_dhcp(
            request_info.mac_address,
            request_info.relay_address.to_string(),
            None,
            request_info.vendor_class,
        )
        .await
        .inspect_err(|e| {
            tracing::warn!(
                error = %e,
                "discover_dhcp failed",
            );
        })?;

    tracing::info!(
        mac_address = %request_info.mac_address,
        relay_address = %request_info.relay_address,
        assigned_address = %dhcp_record.address,
        machine_id = ?dhcp_record.machine_id,
        "DHCP request received an address",
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
    #[error("client API error: {0}")]
    ClientApiError(#[from] ClientApiError),
    #[error("invalid DHCP record: {0}")]
    InvalidDhcpRecord(String),
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

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;

    #[test]
    fn derives_vendor_class_from_requester_and_machine() {
        check_values(
            [
                Check {
                    scenario: "DPU BMC",
                    input: (DhcpMachine::Dpu, DhcpRequester::Bmc),
                    expect: Some("NVIDIA/BF/BMC"),
                },
                Check {
                    scenario: "DPU system OOB interface",
                    input: (DhcpMachine::Dpu, DhcpRequester::System),
                    expect: Some("NVIDIA/BF/OOB"),
                },
                Check {
                    scenario: "Dell R750 BMC",
                    input: (
                        DhcpMachine::Host(HostHardwareType::DellPowerEdgeR750),
                        DhcpRequester::Bmc,
                    ),
                    expect: Some("iDRAC"),
                },
                Check {
                    scenario: "Dell R760 BMC",
                    input: (
                        DhcpMachine::Host(HostHardwareType::DellPowerEdgeR760Bf4),
                        DhcpRequester::Bmc,
                    ),
                    expect: Some("iDRAC"),
                },
                Check {
                    scenario: "HPE BMC",
                    input: (
                        DhcpMachine::Host(HostHardwareType::HpeProliantDl380aGen11),
                        DhcpRequester::Bmc,
                    ),
                    expect: Some("CPQRIB3"),
                },
                Check {
                    scenario: "unrecognized host BMC",
                    input: (
                        DhcpMachine::Host(HostHardwareType::GenericAmi),
                        DhcpRequester::Bmc,
                    ),
                    expect: None,
                },
                Check {
                    scenario: "host system PXE client",
                    input: (
                        DhcpMachine::Host(HostHardwareType::GenericAmi),
                        DhcpRequester::System,
                    ),
                    expect: Some("PXEClient:Arch:00007:UNDI:003000"),
                },
            ],
            |(machine, requester)| vendor_class_for(machine, requester),
        );
    }
}
