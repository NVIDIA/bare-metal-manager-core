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

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use opentelemetry::metrics::{Counter, Meter, ObservableGauge, UpDownCounter};
use rpc::forge_api_client::ForgeApiClient;
use russh::server::{Server as RusshServer, run_stream};
use russh::{MethodKind, MethodSet};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;

use crate::bmc::client_pool::BmcConnectionStore;
use crate::config::Config;
use crate::frontend::{Handler, HandlerError};
use crate::shutdown_handle::ShutdownHandle;

pub async fn spawn(
    config: Arc<Config>,
    forge_api_client: ForgeApiClient,
    bmc_connection_store: BmcConnectionStore,
    meter: &Meter,
) -> Result<Handle, SpawnError> {
    let metrics = Arc::new(ServerMetrics::new(meter, &config));
    let listen_address = config.listen_address;
    use SpawnError::*;

    let host_key =
        russh::keys::PrivateKey::read_openssh_file(&config.host_key_path).map_err(|error| {
            ReadingHostKeyFile {
                path: config.host_key_path.as_path().to_string_lossy().to_string(),
                error,
            }
        })?;

    let russh_config = Arc::new(russh::server::Config {
        keys: vec![host_key],
        // We only accept PublicKey auth (certificates are a kind of PublicKey auth)
        methods: MethodSet::from([MethodKind::PublicKey].as_slice()),
        nodelay: true,
        auth_rejection_time: Duration::from_millis(30),
        ..Default::default()
    });

    let server = SshServer {
        config,
        forge_api_client,
        bmc_connection_store,
        russh_config,
        metrics,
    };

    let listener = TcpListener::bind(listen_address)
        .await
        .map_err(|error| Listening {
            addr: listen_address,
            error,
        })?;
    tracing::info!("listening on {}", listen_address);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join_handle = tokio::spawn(server.run(listener, shutdown_rx));

    Ok(Handle {
        shutdown_tx,
        join_handle,
    })
}

#[derive(thiserror::Error, Debug)]
pub enum SpawnError {
    #[error("Error reading host key file at {path}: {error}")]
    ReadingHostKeyFile {
        path: String,
        error: russh::keys::ssh_key::Error,
    },
    #[error("Error listening on {addr}: {error}")]
    Listening {
        addr: SocketAddr,
        error: std::io::Error,
    },
}

pub struct Handle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ShutdownHandle<()> for Handle {
    fn into_parts(self) -> (Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

struct SshServer {
    config: Arc<Config>,
    russh_config: Arc<russh::server::Config>,
    forge_api_client: ForgeApiClient,
    bmc_connection_store: BmcConnectionStore,
    metrics: Arc<ServerMetrics>,
}

impl SshServer {
    /// Run an instance of ssh-console on the given socket, looping forever until `shutdown` is
    /// received (or if the sending end of `shutdown` is dropped.)
    pub async fn run(mut self, socket: TcpListener, mut shutdown: oneshot::Receiver<()>) {
        loop {
            tokio::select! {
                accept_result = socket.accept() => {
                    match accept_result {
                        Ok((socket, _)) => {
                            let russh_config = self.russh_config.clone();
                            let handler = self.new_client(socket.peer_addr().ok());

                            tokio::spawn(async move {
                                if russh_config.nodelay
                                    && let Err(error) = socket.set_nodelay(true) {
                                        tracing::warn!(%error, "set_nodelay() failed");
                                    }

                                let session = match run_stream(russh_config, socket, handler).await {
                                    Ok(s) => s,
                                    Err(HandlerError::Russh(russh::Error::Disconnect)) => {
                                        // If it was a simple disconnect, don't log a scary looking
                                        // error.
                                        tracing::debug!("client disconnected");
                                        return;
                                    }
                                    Err(HandlerError::Russh(russh::Error::ConnectionTimeout)) => {
                                        // ditto connection timeout
                                        tracing::debug!("client connection timeout");
                                        return;
                                    }
                                    Err(HandlerError::Russh(error)) => {
                                        tracing::warn!(%error, "Connection setup failed with internal russh error");
                                        return;
                                    }
                                    Err(error) => {
                                        // I think this is impossible, none of our code is run yet.
                                        tracing::warn!(%error, "Connection setup failed");
                                        return;
                                    }
                                };

                                match session.await {
                                    Ok(_) => tracing::debug!("Connection closed"),
                                    Err(HandlerError::Russh(russh::Error::IO(io_error))) => {
                                        match io_error.kind() {
                                            io::ErrorKind::UnexpectedEof => {
                                                tracing::debug!("eof from client");
                                            }
                                            error => {
                                                tracing::warn!(%error, "Connection closed with error");
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(%error, "Connection closed with error");
                                    }
                                }
                            });
                        }

                        Err(error) => {
                            tracing::error!(%error, "Error accepting SSH connection from socket");
                            break;
                        },
                    }
                },

                _ = &mut shutdown => break,
            }
        }
    }
}

pub struct ServerMetrics {
    pub total_clients: UpDownCounter<i64>,
    pub client_auth_failures_total: Counter<u64>,
    _auth_enforced: ObservableGauge<u64>,
    _include_dpus: ObservableGauge<u64>,

    // per-BMC stats
    pub bmc_clients: UpDownCounter<i64>,
}

impl ServerMetrics {
    fn new(meter: &Meter, config: &Config) -> ServerMetrics {
        Self {
            total_clients: meter
                .i64_up_down_counter("ssh_console_total_clients")
                .with_description("The number of SSH clients currently connected to the service")
                .build(),
            client_auth_failures_total: meter
                .u64_counter("ssh_console_client_auth_failures")
                .with_description("The number of SSH clients authentication attempts denied")
                .build(),
            _auth_enforced: meter
                .u64_observable_gauge("ssh_console_auth_enforced")
                .with_description("Whether authentication for clients is being enforced, 1 = enforced, 0 = disabled")
                .with_callback({
                    let auth_enforced = !config.insecure;
                    move |observer| {
                        observer.observe(
                            if auth_enforced { 1 } else { 0 },
                            &[]
                        );
                    }
                })
                .build(),
            _include_dpus: meter
                .u64_observable_gauge("ssh_console_include_dpus")
                .with_description("Whether DPU serial consoles are included by the SSH Console service")
                .with_callback({
                    let dpus = config.dpus;
                    move |observer| {
                        observer.observe(
                            if dpus { 1 } else { 0 },
                            &[]
                        );
                    }
                })
                .build(),
            bmc_clients: meter
                .i64_up_down_counter("ssh_console_bmc_clients")
                .with_description("Number of active client SSH sessions to this host")
                .build(),
        }
    }
}

impl russh::server::Server for SshServer {
    type Handler = Handler;

    fn new_client(&mut self, addr: Option<std::net::SocketAddr>) -> Self::Handler {
        Self::Handler::new(
            self.bmc_connection_store.clone(),
            self.config.clone(),
            self.forge_api_client.clone(),
            self.metrics.clone(),
            addr,
        )
    }
}
