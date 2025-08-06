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

use crate::bmc::client_pool::BmcConnectionStore;
use crate::config::Config;
use crate::frontend::{Handler, RusshOrEyreError};
use crate::shutdown_handle::ShutdownHandle;
use eyre::Context;
use opentelemetry::metrics::{Counter, Meter, ObservableGauge, UpDownCounter};
use rpc::forge_api_client::ForgeApiClient;
use russh::server::{Server as RusshServer, run_stream};
use russh::{MethodKind, MethodSet};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;

pub async fn spawn(
    config: Arc<Config>,
    forge_api_client: ForgeApiClient,
    bmc_connection_store: BmcConnectionStore,
    meter: &Meter,
) -> eyre::Result<Handle> {
    let metrics = Arc::new(ServerMetrics::new(meter, &config));
    let listen_address = config.listen_address;

    let host_key =
        russh::keys::PrivateKey::read_openssh_file(&config.host_key_path).with_context(|| {
            format!(
                "Error reading host key file at {}",
                config.host_key_path.display()
            )
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
        .with_context(|| format!("Error listening on {listen_address}"))?;
    tracing::info!("listening on {}", listen_address);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join_handle = tokio::spawn(server.run(listener, shutdown_rx));

    Ok(Handle {
        shutdown_tx,
        join_handle,
    })
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
                                if russh_config.nodelay {
                                    if let Err(e) = socket.set_nodelay(true) {
                                        tracing::warn!("set_nodelay() failed: {e:?}");
                                    }
                                }

                                // Failures here are all from russh, but the error type is
                                // Handler::Error, which is *our* error type. So we have go to
                                // through this RusshOrEyreError hoops to track down what the actual
                                // error was.
                                let session = match run_stream(russh_config, socket, handler).await {
                                    Ok(s) => s,
                                    Err(RusshOrEyreError::Russh(russh::Error::Disconnect)) => {
                                        // If it was a simple disconnect, don't log a scary looking
                                        // error.
                                        tracing::debug!("client disconnected");
                                        return;
                                    }
                                    Err(RusshOrEyreError::Russh(russh::Error::ConnectionTimeout)) => {
                                        // ditto connection timeout
                                        tracing::debug!("client connection timeout");
                                        return;
                                    }
                                    Err(RusshOrEyreError::Eyre(error)) => {
                                        // I think this is impossible, none of our code is run yet.
                                        tracing::warn!(?error, "Connection setup failed");
                                        return;
                                    }
                                    Err(RusshOrEyreError::Russh(error)) => {
                                        tracing::warn!(?error, "Connection setup failed with internal russh error");
                                        return;
                                    }
                                };

                                match session.await {
                                    Ok(_) => tracing::debug!("Connection closed"),
                                    Err(RusshOrEyreError::Russh(russh::Error::IO(io_error))) => {
                                        match io_error.kind() {
                                            io::ErrorKind::UnexpectedEof => {
                                                tracing::debug!("eof from client");
                                            }
                                            error => {
                                                tracing::warn!(?error, "Connection closed with error");
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        tracing::warn!(?error, "Connection closed with error");
                                    }
                                }
                            });
                        }

                        Err(error) => {
                            tracing::error!(?error, "Error accepting SSH connection from socket");
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
