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

use crate::config::Config;
use crate::ssh_server::backend_connection::lookup_connection_details;
use crate::ssh_server::backend_session;
use crate::ssh_server::backend_session::{BackendSessionConnectionHandle, BackendSessionHandle};
use crate::{ReadyHandle, ShutdownHandle};
use eyre::{Context, ContextCompat};
use forge_uuid::machine::MachineId;
use futures_util::future::join_all;
use rpc::forge;
use rpc::forge_api_client::ForgeApiClient;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::oneshot::Receiver;
use tokio::sync::{RwLock, oneshot};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use uuid::Uuid;

/// Spawn a background task that connects to all BMC's in the environment, reconnecting if they fail.
pub fn spawn(config: Arc<Config>, forge_api_client: ForgeApiClient) -> BackendPoolHandle {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let (ready_tx, ready_rx) = oneshot::channel();
    let members: Arc<RwLock<HashMap<MachineId, BackendSessionHandle>>> = Default::default();
    let join_handle = tokio::spawn(
        BackendPool {
            members: members.clone(),
            shutdown_rx,
            config,
            forge_api_client,
        }
        .run_loop(ready_tx),
    );

    BackendPoolHandle {
        shutdown_tx,
        members,
        ready_rx: Some(ready_rx),
        join_handle,
    }
}

/// A owned handle to the entire backend pool background task. The pool will shut down when this is
/// dropped.
pub struct BackendPoolHandle {
    members: Arc<RwLock<HashMap<MachineId, BackendSessionHandle>>>,
    shutdown_tx: oneshot::Sender<()>,
    ready_rx: Option<oneshot::Receiver<()>>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl ShutdownHandle<()> for BackendPoolHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

impl ReadyHandle for BackendPoolHandle {
    fn take_ready_rx(&mut self) -> Option<Receiver<()>> {
        self.ready_rx.take()
    }
}

impl BackendPoolHandle {
    /// Return a connection store for the backends in this pool, which can be used by an individual frontend
    /// connection to find the correct backend.
    pub fn get_connection_store(&self) -> BackendConnectionStore {
        BackendConnectionStore {
            members: self.members.clone(),
        }
    }
}

/// An Arc reference to the available backend connections in this pool
pub struct BackendConnectionStore {
    members: Arc<RwLock<HashMap<MachineId, BackendSessionHandle>>>,
}

impl BackendConnectionStore {
    pub async fn get_connection(
        &self,
        machine_or_instance_id: &str,
        config: &Config,
        forge_api_client: &ForgeApiClient,
    ) -> eyre::Result<Arc<BackendSessionConnectionHandle>> {
        if let Ok(machine_id) = MachineId::from_str(machine_or_instance_id) {
            self.members
                .read()
                .await
                .get(&machine_id)
                .map(|session_handle| session_handle.connection_handle.clone())
                .with_context(|| format!("unknown machine id {machine_id}"))
        } else if let Ok(instance_id) = Uuid::from_str(machine_or_instance_id) {
            let machine_id_candidate = if let Some(machine_id) =
                config.override_bmcs.iter().flatten().find_map(|bmc| {
                    if bmc
                        .instance_id
                        .as_ref()
                        .is_some_and(|i| i.eq(machine_or_instance_id))
                    {
                        bmc.machine_id
                            .parse()
                            .inspect_err(|error| {
                                tracing::warn!(
                                    machine_id = bmc.machine_id,
                                    ?error,
                                    "invalid machine_id in bmc override config"
                                );
                            })
                            .ok()
                    } else {
                        None
                    }
                }) {
                machine_id
            } else {
                forge_api_client
                    .find_instances(forge::InstanceSearchQuery {
                        id: Some(rpc::Uuid {
                            value: instance_id.to_string(),
                        }),
                        label: None,
                    })
                    .await
                    .with_context(|| format!("Error looking up instance ID {instance_id}"))?
                    .instances
                    .into_iter()
                    .next()
                    .with_context(|| format!("Could not find instance with id {instance_id}"))?
                    .machine_id
                    .with_context(|| format!("Instance {instance_id} has no machine_id"))?
                    .id
                    .parse()
                    .with_context(|| format!("Instance {instance_id} has an invalid machine_id"))?
            };

            self.members
                .read()
                .await
                .get(&machine_id_candidate)
                .map(|session_handle| session_handle.connection_handle.clone())
                .with_context(|| format!("no machine with instance_id {instance_id}"))
        } else {
            return Err(eyre::format_err!(
                "{machine_or_instance_id} is not a valid machine_id or instance ID"
            ));
        }
    }
}

/// A BackendPool runs in a background Task and maintains a single BackendSession handle to each
/// backend
struct BackendPool {
    members: Arc<RwLock<HashMap<MachineId, BackendSessionHandle>>>,
    shutdown_rx: oneshot::Receiver<()>,
    config: Arc<Config>,
    forge_api_client: ForgeApiClient,
}

impl BackendPool {
    /// Run a loop which refreshes the list backends from the API and ensures we have a running
    /// connection to each one.
    async fn run_loop(mut self, ready_tx: oneshot::Sender<()>) {
        let mut api_refresh = tokio::time::interval(self.config.api_poll_interval);
        // Don't try to catch up if for some reason api refresh takes forever (ie. if the connection
        // is down and we have to retry a long time.)
        api_refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut ready_tx = Some(ready_tx);

        loop {
            tokio::select! {
                _ = &mut self.shutdown_rx => {
                    tracing::info!("shutting down BackendPool");
                    break;
                }
                _ = api_refresh.tick() => {
                    if let Err(error) = self.refresh_backends().await {
                        tracing::error!(?error, "error refreshing backend list from API");
                    }
                    // Inform callers that we're ready once the first API refresh happens.
                    ready_tx.take().map(|ch| ch.send(()).ok());
                }
            }
        }

        // Shutdown each backend
        join_all(
            self.members
                .write()
                .await
                .drain()
                .map(|(_machine_id, handle)| handle.shutdown_and_wait()),
        )
        .await;
    }

    async fn refresh_backends(&mut self) -> eyre::Result<()> {
        // Get all machine ID's from forge, parsing them into forge_uuid::MachineId.
        let machine_ids: HashSet<MachineId> = match &self.config.override_bmcs {
                Some(override_bmcs) => {
                    override_bmcs
                        .iter()
                        .filter_map(|b| {
                            b.machine_id
                                .parse()
                                .inspect_err(|error| {
                                    tracing::error!(
                                    ?error,
                                    machine_id = %b.machine_id,
                                    "invalid machine ID in config, will not do console logging on this machine"
                                )
                                }).ok()
                        })
                        .collect()
                }
                None => {
                    self.forge_api_client
                        .find_machine_ids(forge::MachineSearchConfig {
                            include_dpus: self.config.dpus,
                            ..Default::default()
                        })
                        .await
                        .context("error fetching machine ids")?
                        .machine_ids
                        .into_iter()
                        .filter_map(|rpc_machine_id| {
                            rpc_machine_id
                                .id
                                .parse()
                                .inspect_err(|error| {
                                    tracing::error!(
                                    ?error,
                                    machine_id = rpc_machine_id.id,
                                    "invalid machine ID, will not do console logging on this machine"
                                )
                                })
                                .ok()
                        })
                        .collect()
                }
            };

        // -- Reconcile our list with the running tasks
        let mut guard = self.members.write().await;

        // Remove any machines that are no longer monitored
        let to_remove = guard
            .keys()
            .filter(|&machine_id| !machine_ids.contains(machine_id))
            .copied()
            .collect::<Vec<_>>();
        for machine_id in to_remove {
            tracing::info!(%machine_id, "removing machine from console logging, no longer found in carbide");
            guard.remove(&machine_id);
        }

        // Add any machines that need to be monitored
        let to_add = machine_ids
            .iter()
            .filter(|id| !guard.contains_key(id))
            .copied()
            .collect::<Vec<_>>();

        // For each one we want to add, get the connection details. Skip any machines which fail
        // here.
        let all_connection_details = join_all(to_add.into_iter().map(|machine_id| {
            let config = self.config.clone();
            let forge_api_client = self.forge_api_client.clone();
            async move {
                match lookup_connection_details(
                    &machine_id.to_string(),
                    &config,
                    &forge_api_client,
                )
                    .await
                {
                    Ok(connection_details) => Some((machine_id, connection_details)),
                    Err(error) => {
                        tracing::error!(%machine_id, ?error, "error looking up connection details, excluding from backend list");
                        None
                    }
                }
            }
        })).await.into_iter().flatten().collect::<Vec<_>>();

        for (machine_id, connection_details) in all_connection_details {
            if guard.contains_key(&machine_id) {
                continue;
            }
            tracing::info!(%machine_id, "begin connection to machine");
            let backend_session_handle =
                backend_session::spawn(connection_details, self.config.clone());
            guard.insert(machine_id, backend_session_handle);
        }

        Ok(())
    }
}

/// Newtype wrpper around Arc<eyre::Error> to make it clone-able for use in a future::Shared.
#[derive(Debug, Clone)]
struct ConnectionError(Arc<eyre::Error>);

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.as_ref(), f)
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<eyre::Error> for ConnectionError {
    fn from(eyre_error: eyre::Error) -> Self {
        ConnectionError(eyre_error.into())
    }
}
