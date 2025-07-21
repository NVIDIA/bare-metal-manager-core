/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
pub(crate) mod ipmi;
mod ssh;

use crate::bmc_vendor::{BmcVendor, SshBmcVendor};
use crate::config::Config;
use eyre::{Context, ContextCompat};
use forge_uuid::machine::{MachineId, MachineType};
use rpc::forge;
use rpc::forge_api_client::ForgeApiClient;
use russh::ChannelMsg;
use std::borrow::Cow;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

#[derive(Debug)]
pub struct BackendHandle {
    /// Writer to send messages (including data) to backend
    pub to_backend_msg_tx: mpsc::Sender<ChannelMsg>,
    /// For informational purposes: the actuall address of the backend
    pub addr: SocketAddr,
    // Hold a copy of the tx for broadcasting to frontends, so that we can subscribe to it multiple
    // times. This must be a WeakSender so it can be properly dropped when the backend dies
    broadcast_to_frontend_weak_tx: broadcast::WeakSender<Arc<ChannelMsg>>,
}

impl BackendHandle {
    pub fn subscribe(&self) -> Option<broadcast::Receiver<Arc<ChannelMsg>>> {
        self.broadcast_to_frontend_weak_tx
            .upgrade()
            .map(|tx| tx.subscribe())
    }
}

pub async fn spawn(
    connection_details: &ConnectionDetails,
    config: &Config,
) -> eyre::Result<Arc<BackendHandle>> {
    let (broadcast_to_frontend_tx, _broadcast_to_frontend_rx) =
        broadcast::channel::<Arc<ChannelMsg>>(4096);

    // Frontends will call .subscribe on this: It must be a WeakSender so that the channel can close
    // properly when the backend dies.
    let broadcast_to_frontend_weak_tx = broadcast_to_frontend_tx.downgrade();

    let to_backend_msg_tx = match connection_details {
        ConnectionDetails::Ssh(ssh_connection_details) => {
            ssh::spawn(ssh_connection_details, broadcast_to_frontend_tx)
                .await
                .context("error spawning SSH backend connection")?
        }
        ConnectionDetails::Ipmi(ipmi_connection_details) => {
            ipmi::spawn(ipmi_connection_details, broadcast_to_frontend_tx, config)
                .await
                .context("error spawning IPMI backend connection")?
        }
    };

    Ok(Arc::new(BackendHandle {
        to_backend_msg_tx,
        broadcast_to_frontend_weak_tx,
        addr: connection_details.addr(),
    }))
}

/// Get the address and auth details to use for a connection to a given machine or instance ID.
///
/// This information is normally gotten by calling GetBMCMetadData on carbide-api, but it can
/// also obey overridden information from ssh-console's config.
pub async fn lookup_connection_details(
    machine_or_instance_id: &str,
    config: &Config,
    forge_api_client: &ForgeApiClient,
) -> eyre::Result<ConnectionDetails> {
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
        let machine_id = MachineId::from_str(&override_bmc.machine_id).with_context(|| {
            format!(
                "Invalid machine_id in BMC override config: {}",
                &override_bmc.machine_id
            )
        })?;
        let connection_details = match override_bmc.bmc_vendor {
            BmcVendor::Ssh(ssh_bmc_vendor) => ConnectionDetails::Ssh(SshConnectionDetails {
                machine_id,
                addr: config
                    .override_bmc_ssh_addr(override_bmc.addr().port())
                    .await
                    .context("error looking up override_bmc_ssh_addr")?
                    .unwrap_or(override_bmc.addr()),
                user: override_bmc.user,
                password: override_bmc.password,
                ssh_key_path: override_bmc.ssh_key_path,
                bmc_vendor: ssh_bmc_vendor,
            }),
            BmcVendor::Ipmi(_) => ConnectionDetails::Ipmi(IpmiConnectionDetails {
                machine_id,
                addr: override_bmc.addr(),
                user: override_bmc.user,
                password: override_bmc.password,
            }),
        };
        tracing::info!(
            "Overriding bmc connection to {machine_or_instance_id} with {connection_details:?}"
        );
        return Ok(connection_details);
    }

    let maybe_machine_id = MachineId::from_str(machine_or_instance_id).ok();

    let machine_id_str = if maybe_machine_id.is_some() {
        Cow::Borrowed(machine_or_instance_id)
    } else if let Ok(uuid) = Uuid::from_str(machine_or_instance_id) {
        Cow::Owned(
            forge_api_client
                .find_instances(forge::InstanceSearchQuery {
                    id: Some(rpc::Uuid {
                        value: uuid.to_string(),
                    }),
                    label: None,
                })
                .await
                .with_context(|| format!("Error looking up instance ID {uuid}"))?
                .instances
                .into_iter()
                .next()
                .with_context(|| format!("Could not find instance with id {uuid}"))?
                .machine_id
                .with_context(|| format!("Instance {uuid} has no machine_id"))?
                .id,
        )
    } else {
        return Err(eyre::format_err!(
            "Could not parse {machine_or_instance_id} into a machine ID or instance ID"
        ));
    };

    let machine = forge_api_client
        .get_machine(&*machine_id_str)
        .await
        .with_context(|| format!("Error getting machine {machine_id_str}"))?;
    let is_dpu =
        maybe_machine_id.is_some_and(|machine_id| machine_id.machine_type() == MachineType::Dpu);

    let machine_id: MachineId = machine
        .id
        .as_ref()
        .with_context(|| {
            format!(
                "API machine has no id? (looked up via machine_id={:?})",
                machine_id_str
            )
        })?
        .id
        .parse()
        .with_context(|| {
            format!(
                "Invalid machine ID returned by GetMachines: {}",
                machine_id_str
            )
        })?;

    let bmc_vendor = if is_dpu {
        BmcVendor::Ssh(SshBmcVendor::Dpu)
    } else {
        BmcVendor::detect_from_api_machine(&machine)
            .with_context(|| format!("Cannot detect BMC vendor for machine: {machine_id_str}"))?
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
            machine_id: Some(rpc::MachineId {
                id: machine_id_str.into_owned(),
            }),
            role: 0,
            request_type: forge::BmcRequestType::Ipmi.into(),
            bmc_endpoint_request: None,
        })
        .await
        .context("Error calling forge.GetBmcMetaData")?;

    let ip: IpAddr = ip
        .parse()
        .with_context(|| format!("Error parsing IP address from forge.GetBmcMetaData: {}", ip))?;

    let port = match &bmc_vendor {
        BmcVendor::Ssh(ssh_bmc_vendor) => ssh_port
            .map(u16::try_from)
            .transpose()
            .context("invalid ssh port from forge.GetBmcMetaData")?
            .or(config.override_bmc_ssh_port)
            .unwrap_or(match ssh_bmc_vendor {
                SshBmcVendor::Dpu => 2200,
                _ => 22,
            }),
        BmcVendor::Ipmi(_) => ipmi_port
            .map(u16::try_from)
            .transpose()
            .context("invalid IPMI port from forge.GetBmcMetaData")?
            .or(config.override_ipmi_port)
            .unwrap_or(623),
    };

    let addr = if let Some(override_ssh_addr) = config
        .override_bmc_ssh_addr(port)
        .await
        .context("error looking up override_bmc_ssh_ip")?
    {
        tracing::info!(
            "Overriding bmc connection to {ip} with {override_ssh_addr} per configuration"
        );
        override_ssh_addr
    } else {
        SocketAddr::new(ip, port)
    };

    let connection_details = match bmc_vendor {
        BmcVendor::Ssh(ssh_bmc_vendor) => ConnectionDetails::Ssh(SshConnectionDetails {
            machine_id,
            addr,
            user,
            password,
            ssh_key_path: None,
            bmc_vendor: ssh_bmc_vendor,
        }),
        BmcVendor::Ipmi(_) => ConnectionDetails::Ipmi(IpmiConnectionDetails {
            machine_id,
            addr,
            user,
            password,
        }),
    };

    Ok(connection_details)
}

#[derive(Debug, Clone)]
pub enum ConnectionDetails {
    Ssh(SshConnectionDetails),
    Ipmi(IpmiConnectionDetails),
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
}

#[derive(Clone)]
pub struct SshConnectionDetails {
    machine_id: MachineId,
    addr: SocketAddr,
    user: String,
    password: String,
    ssh_key_path: Option<PathBuf>,
    bmc_vendor: SshBmcVendor,
}

impl Debug for SshConnectionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Skip writing the password
        f.debug_struct("SshConnectionDetails")
            .field("addr", &self.addr)
            .field("user", &self.user)
            .field("ssh_key_path", &self.ssh_key_path)
            .field("bmc_vendor", &self.bmc_vendor)
            .field("machine_id", &self.machine_id.to_string())
            .finish()
    }
}

#[derive(Clone)]
pub struct IpmiConnectionDetails {
    machine_id: MachineId,
    addr: SocketAddr,
    user: String,
    password: String,
}

impl Debug for IpmiConnectionDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Skip writing the password
        f.debug_struct("IpmiConnectionDetails")
            .field("addr", &self.addr)
            .field("user", &self.user)
            .field("machine_id", &self.machine_id.to_string())
            .finish()
    }
}
