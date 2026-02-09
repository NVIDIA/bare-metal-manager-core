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
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use rpc::forge;
use rpc::forge_api_client::ForgeApiClient;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::bmc::client_pool::BmcPoolMetrics;
use crate::bmc::connection_impl;
use crate::bmc::connection_impl::{ipmi, ssh};
use crate::bmc::message_proxy::{ToBmcMessage, ToFrontendMessage};
use crate::bmc::vendor::{BmcVendor, BmcVendorDetectionError, SshBmcVendor};
use crate::config::{Config, ConfigError};
use crate::shutdown_handle::ShutdownHandle;

pub async fn spawn(
    connection_details: ConnectionDetails,
    broadcast_to_frontend_tx: broadcast::Sender<ToFrontendMessage>,
    metrics: Arc<BmcPoolMetrics>,
    config: Arc<Config>,
) -> Result<Handle, SpawnError> {
    let handle = match connection_details {
        ConnectionDetails::Ssh(ssh_connection_details) => {
            ssh::spawn(ssh_connection_details, broadcast_to_frontend_tx, metrics)
                .await?
                .into()
        }
        ConnectionDetails::Ipmi(ipmi_connection_details) => ipmi::spawn(
            ipmi_connection_details,
            broadcast_to_frontend_tx,
            config,
            metrics,
        )
        .await?
        .into(),
    };

    Ok(handle)
}

#[derive(thiserror::Error, Debug)]
pub enum SpawnError {
    #[error(transparent)]
    Ssh(#[from] connection_impl::ssh::SpawnError),
    #[error(transparent)]
    Ipmi(#[from] connection_impl::ipmi::SpawnError),
}

/// Get the address and auth details to use for a connection to a given machine or instance ID.
///
/// This information is normally gotten by calling GetBMCMetadData on carbide-api, but it can
/// also obey overridden information from ssh-console's config.
pub async fn lookup(
    machine_or_instance_id: &str,
    config: &Config,
    forge_api_client: &ForgeApiClient,
) -> Result<ConnectionDetails, LookupError> {
    if let Some(override_bmc) = config.override_bmcs.as_ref().and_then(|override_bmcs| {
        override_bmcs
            .iter()
            .find(|bmc| {
                bmc.machine_id == machine_or_instance_id
                    || bmc
                        .instance_id
                        .as_ref()
                        .is_some_and(|i| i.as_str() == machine_or_instance_id)
            })
            .cloned()
    }) {
        let machine_id = MachineId::from_str(&override_bmc.machine_id)
            .map_err(|e| LookupError::Config(ConfigError::InvalidBmcOverrideMachineId(e)))?;
        let connection_details = match override_bmc.bmc_vendor {
            BmcVendor::Ssh(ssh_bmc_vendor) => {
                ConnectionDetails::Ssh(Arc::new(ssh::ConnectionDetails {
                    machine_id,
                    addr: config
                        .override_bmc_ssh_addr(override_bmc.addr().port())
                        .await?
                        .unwrap_or(override_bmc.addr()),
                    user: override_bmc.user,
                    password: override_bmc.password,
                    ssh_key_path: override_bmc.ssh_key_path,
                    bmc_vendor: ssh_bmc_vendor,
                }))
            }
            BmcVendor::Ipmi(_) => ConnectionDetails::Ipmi(Arc::new(ipmi::ConnectionDetails {
                machine_id,
                addr: override_bmc.addr(),
                user: override_bmc.user,
                password: override_bmc.password,
            })),
        };
        tracing::info!(
            "Overriding bmc connection to {machine_or_instance_id} with {connection_details:?}"
        );
        return Ok(connection_details);
    }

    let machine_id: MachineId = if let Ok(id) = machine_or_instance_id.parse() {
        id
    } else if let Ok(instance_id) = InstanceId::from_str(machine_or_instance_id) {
        forge_api_client
            .find_instances_by_ids(forge::InstancesByIdsRequest {
                instance_ids: vec![instance_id],
            })
            .await
            .map_err(|e| LookupError::InstanceIdLookup {
                instance_id,
                tonic_status: e,
            })?
            .instances
            .into_iter()
            .next()
            .ok_or_else(|| LookupError::CouldNotFindInstance { instance_id })?
            .machine_id
            .ok_or_else(|| LookupError::InstanceHasNoMachineId { instance_id })?
    } else {
        return Err(LookupError::CouldNotParseId {
            machine_or_instance_id: machine_or_instance_id.to_owned(),
        });
    };

    let machines = forge_api_client
        .find_machines_by_ids(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine_id],
            include_history: false,
        })
        .await
        .map_err(|tonic_status| LookupError::MachineIdLookup {
            machine_id: machine_id.to_string(),
            tonic_status,
        })?
        .machines;
    let machine = machines
        .into_iter()
        .next()
        .ok_or_else(|| LookupError::MachineIdLookup {
            machine_id: machine_id.to_string(),
            tonic_status: tonic::Status::not_found("Response did not contain machine"),
        })?;

    let machine_id = machine
        .id
        .ok_or_else(|| LookupError::MachineMissingId { machine_id })?;

    let bmc_vendor = if machine_id.machine_type().is_dpu() {
        BmcVendor::Ssh(SshBmcVendor::Dpu)
    } else {
        BmcVendor::detect_from_api_machine(&machine)
            .map_err(|error| LookupError::BmcVendorDetection { machine_id, error })?
    };

    let forge::BmcMetaDataGetResponse {
        ip,
        user,
        password,
        mac: _,
        port: _,
        ssh_port,
        ipmi_port,
    } = forge_api_client
        .get_bmc_meta_data(forge::BmcMetaDataGetRequest {
            machine_id: Some(machine_id),
            role: 0,
            request_type: forge::BmcRequestType::Ipmi.into(),
            bmc_endpoint_request: None,
        })
        .await
        .map_err(|tonic_status| LookupError::BmcMetaDataLookup {
            machine_id: machine_id.to_string(),
            tonic_status,
        })?;

    let ip: IpAddr = ip.parse().map_err(|e| LookupError::InvalidBmcMetadata {
        reason: format!("Error parsing IP address {ip:?}: {e:?}"),
    })?;

    let port = match &bmc_vendor {
        BmcVendor::Ssh(ssh_bmc_vendor) => ssh_port
            .map(u16::try_from)
            .transpose()
            .map_err(|e| LookupError::InvalidBmcMetadata {
                reason: format!("invalid ssh port: {e:?}"),
            })?
            .or(config.override_bmc_ssh_port)
            .unwrap_or(match ssh_bmc_vendor {
                SshBmcVendor::Dpu => 2200,
                _ => 22,
            }),
        BmcVendor::Ipmi(_) => ipmi_port
            .map(u16::try_from)
            .transpose()
            .map_err(|e| LookupError::InvalidBmcMetadata {
                reason: format!("invalid ipmi port: {e:?}"),
            })?
            .or(config.override_ipmi_port)
            .unwrap_or(623),
    };

    let addr = if let Some(override_ssh_addr) = config.override_bmc_ssh_addr(port).await? {
        tracing::info!(
            "Overriding bmc connection to {ip} with {override_ssh_addr} per configuration"
        );
        override_ssh_addr
    } else {
        SocketAddr::new(ip, port)
    };

    let connection_details = match bmc_vendor {
        BmcVendor::Ssh(ssh_bmc_vendor) => {
            ConnectionDetails::Ssh(Arc::new(ssh::ConnectionDetails {
                machine_id,
                addr,
                user,
                password,
                ssh_key_path: None,
                bmc_vendor: ssh_bmc_vendor,
            }))
        }
        BmcVendor::Ipmi(_) => ConnectionDetails::Ipmi(Arc::new(ipmi::ConnectionDetails {
            machine_id,
            addr,
            user,
            password,
        })),
    };

    Ok(connection_details)
}

#[derive(thiserror::Error, Debug)]
pub enum LookupError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("Error looking up instance ID {instance_id}: {tonic_status}")]
    InstanceIdLookup {
        instance_id: InstanceId,
        tonic_status: tonic::Status,
    },
    #[error("Could not find instance with id {instance_id}")]
    CouldNotFindInstance { instance_id: InstanceId },
    #[error("Instance {instance_id} has no machine_id")]
    InstanceHasNoMachineId { instance_id: InstanceId },
    #[error("Could not parse {machine_or_instance_id} into a machine ID or instance ID")]
    CouldNotParseId { machine_or_instance_id: String },
    #[error("Error getting machine {machine_id}: {tonic_status}")]
    MachineIdLookup {
        machine_id: String,
        tonic_status: tonic::Status,
    },
    #[error("API machine has no id? (looked up via machine_id={machine_id})")]
    MachineMissingId { machine_id: MachineId },
    #[error("Cannot detect BMC vendor for machine: {machine_id}: {error}")]
    BmcVendorDetection {
        machine_id: MachineId,
        error: BmcVendorDetectionError,
    },
    #[error("Error calling forge.GetBmcMetaData for {machine_id}: {tonic_status}")]
    BmcMetaDataLookup {
        machine_id: String,
        tonic_status: tonic::Status,
    },
    #[error("BMC metadata is invalid: {reason}")]
    InvalidBmcMetadata { reason: String },
}

/// A handle to a BMC connection, which will shut down when dropped.
pub struct Handle {
    pub to_bmc_msg_tx: mpsc::Sender<ToBmcMessage>,
    pub shutdown_tx: oneshot::Sender<()>,
    pub join_handle: JoinHandle<Result<(), SpawnError>>,
}

impl From<ipmi::Handle> for Handle {
    fn from(handle: ipmi::Handle) -> Self {
        Self {
            to_bmc_msg_tx: handle.to_bmc_msg_tx,
            shutdown_tx: handle.shutdown_tx,
            join_handle: tokio::spawn(async move {
                handle
                    .join_handle
                    .await
                    .expect("task panicked")
                    .map_err(Into::into)
            }),
        }
    }
}

impl From<ssh::Handle> for Handle {
    fn from(handle: ssh::Handle) -> Self {
        Self {
            to_bmc_msg_tx: handle.to_bmc_msg_tx,
            shutdown_tx: handle.shutdown_tx,
            join_handle: tokio::spawn(async move {
                handle
                    .join_handle
                    .await
                    .expect("task panicked")
                    .map_err(Into::into)
            }),
        }
    }
}

impl ShutdownHandle<Result<(), SpawnError>> for Handle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<Result<(), SpawnError>>) {
        (self.shutdown_tx, self.join_handle)
    }
}

#[derive(Debug, Clone)]
pub enum ConnectionDetails {
    Ssh(Arc<ssh::ConnectionDetails>),
    Ipmi(Arc<ipmi::ConnectionDetails>),
}

impl ConnectionDetails {
    pub fn addr(&self) -> SocketAddr {
        match self {
            ConnectionDetails::Ssh(s) => s.addr,
            ConnectionDetails::Ipmi(i) => i.addr,
        }
    }

    pub fn machine_id(&self) -> MachineId {
        match self {
            ConnectionDetails::Ssh(s) => s.machine_id,
            ConnectionDetails::Ipmi(i) => i.machine_id,
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            ConnectionDetails::Ssh(_) => Kind::Ssh,
            ConnectionDetails::Ipmi(_) => Kind::Ipmi,
        }
    }
}

#[derive(Copy, Clone)]
pub enum Kind {
    Ssh,
    Ipmi,
}

/// Represents the state of a connection to a BMC
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    ConnectionError = 3,
}

impl From<State> for u8 {
    fn from(state: State) -> u8 {
        state as u8
    }
}

impl TryFrom<u8> for State {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(State::Disconnected),
            1 => Ok(State::Connecting),
            2 => Ok(State::Connected),
            3 => Ok(State::ConnectionError),
            _ => Err(()),
        }
    }
}

/// Wrapper for an AtomicU8 representing a [`State`], so that the state can be shared
/// between threads.
#[derive(Debug)]
pub struct AtomicConnectionState(AtomicU8);

impl AtomicConnectionState {
    #[inline]
    pub fn new(state: State) -> Self {
        Self(AtomicU8::new(state.into()))
    }

    #[inline]
    pub fn load(&self) -> State {
        State::try_from(self.0.load(Ordering::SeqCst)).expect("BUG: connection state corrupted")
    }

    #[inline]
    pub fn store(&self, state: State) {
        self.0.store(state.into(), Ordering::SeqCst);
    }
}

impl Default for AtomicConnectionState {
    fn default() -> Self {
        AtomicConnectionState::new(State::Disconnected)
    }
}
