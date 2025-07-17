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
use crate::ShutdownHandle;
use crate::config::Config;
use crate::ssh_server::backend_pool::BackendPool;
use crate::ssh_server::console_logging;
use crate::ssh_server::console_logging::ConsoleLoggerPoolHandle;
use crate::ssh_server::frontend::RusshOrEyreError;
use forge_tls::client_config::ClientCert;
use rpc::forge_api_client::ForgeApiClient;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use russh::server::Server as _;
use russh::server::run_stream;
use std::io;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Construct a new [`Server`]
pub fn new(config: Arc<Config>) -> Server {
    let forge_api_client = config.make_forge_api_client();
    let backend_pool = Arc::new(BackendPool::default());
    let console_logger_pool_handle = if config.console_logging_enabled {
        Some(console_logging::spawn(
            config.clone(),
            forge_api_client.clone(),
            backend_pool.clone(),
        ))
    } else {
        None
    };
    Server {
        config,
        forge_api_client,
        backend_pool,
        console_logger_pool_handle,
    }
}

pub struct Server {
    config: Arc<Config>,
    forge_api_client: ForgeApiClient,
    backend_pool: Arc<BackendPool>,
    console_logger_pool_handle: Option<ConsoleLoggerPoolHandle>,
}

impl Server {
    /// Run an instance of ssh-console on the given socket, looping forever until `shutdown` is
    /// received (or if the sending end of `shutdown` is dropped.)
    pub async fn run(
        mut self,
        config: Arc<russh::server::Config>,
        socket: TcpListener,
        mut shutdown: oneshot::Receiver<()>,
    ) -> eyre::Result<()> {
        loop {
            tokio::select! {
                accept_result = socket.accept() => {
                    match accept_result {
                        Ok((socket, _)) => {
                            let config = config.clone();
                            let handler = self.new_client(socket.peer_addr().ok());

                            tokio::spawn(async move {
                                if config.nodelay {
                                    if let Err(e) = socket.set_nodelay(true) {
                                        tracing::warn!("set_nodelay() failed: {e:?}");
                                    }
                                }

                                // Failures here are all from russh, but the error type is
                                // Handler::Error, which is *our* error type. So we have go to
                                // through this RusshOrEyreError hoops to track down what the actual
                                // error was.
                                let session = match run_stream(config, socket, handler).await {
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

        if let Some(console_logger_pool_handle) = self.console_logger_pool_handle.take() {
            console_logger_pool_handle.shutdown_and_wait().await;
        }

        Ok(())
    }
}

impl russh::server::Server for Server {
    type Handler = super::frontend::Handler;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        Self::Handler::new(
            self.backend_pool.clone(),
            self.config.clone(),
            self.forge_api_client.clone(),
        )
    }
}

impl Config {
    fn make_forge_api_client(&self) -> ForgeApiClient {
        let carbide_uri_string = self.carbide_uri.to_string();
        tracing::info!("carbide_uri_string: {}", carbide_uri_string);

        // TODO: The API's for ClientCert/ForgeClientConfig/etc really ought to take PathBufs, not Strings.
        let client_cert = ClientCert {
            cert_path: self
                .client_cert_path
                .to_str()
                .expect("Invalid utf-8 in client_cert_path")
                .to_string(),
            key_path: self
                .client_key_path
                .to_str()
                .expect("Invalid utf-8 in client_key_path")
                .to_string(),
        };
        let client_config = ForgeClientConfig::new(
            self.forge_root_ca_path
                .to_str()
                .expect("Invalid utf-8 in forge_root_ca_path")
                .to_string(),
            Some(client_cert),
        );

        let api_config = ApiConfig::new(&carbide_uri_string, &client_config);
        ForgeApiClient::new(&api_config)
    }
}
