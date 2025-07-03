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
use forge_tls::client_config::ClientCert;
use rpc::forge_api_client::ForgeApiClient;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use russh::server::Server as _;
use russh::server::run_stream;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Construct a new [`Server`]
pub fn new(config: Arc<Config>) -> Server {
    Server {
        forge_api_client: config.make_forge_api_client(),
        config,
    }
}

pub struct Server {
    config: Arc<Config>,
    forge_api_client: ForgeApiClient,
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

                                let session = match run_stream(config, socket, handler).await {
                                    Ok(s) => s,
                                    Err(error) => {
                                        tracing::warn!(?error, "Connection setup failed");
                                        return
                                    }
                                };

                                match session.await {
                                    Ok(_) => tracing::debug!("Connection closed"),
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

        Ok(())
    }
}

impl russh::server::Server for Server {
    type Handler = super::frontend::Handler;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        Self::Handler::new(self.config.clone(), self.forge_api_client.clone())
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
