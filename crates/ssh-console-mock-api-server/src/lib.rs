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
mod api;
#[allow(dead_code)]
mod generated;

use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use api_test_helper::utils::LOCALHOST_CERTS;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use uuid::Uuid;

use crate::generated::forge::forge_server::ForgeServer;
use crate::generated::forge::{self};
use crate::generated::{common, machine_discovery};

#[derive(Debug, Clone)]
pub struct MockHost {
    pub machine_id: carbide_uuid::machine::MachineId,
    pub instance_id: Uuid,
    pub tenant_public_key: String,
    pub sys_vendor: &'static str,
    pub bmc_ip: IpAddr,
    pub bmc_ssh_port: Option<u16>,
    pub ipmi_port: Option<u16>,
    pub bmc_user: String,
    pub bmc_password: String,
}

impl From<MockHost> for forge::Machine {
    fn from(value: MockHost) -> Self {
        Self {
            id: Some(value.machine_id),
            discovery_info: Some(machine_discovery::DiscoveryInfo {
                dmi_data: Some(machine_discovery::DmiData {
                    sys_vendor: value.sys_vendor.to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl From<MockHost> for forge::Instance {
    fn from(value: MockHost) -> Self {
        Self {
            id: Some(common::InstanceId {
                value: value.instance_id.to_string(),
            }),
            machine_id: Some(value.machine_id),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct MockApiServer {
    pub mock_hosts: Arc<Vec<MockHost>>,
}

pub struct MockApiServerHandle {
    pub addr: SocketAddr,
    _shutdown_tx: oneshot::Sender<()>,
}

impl MockApiServer {
    pub async fn spawn(self) -> eyre::Result<MockApiServerHandle> {
        let cert = fs::read(&LOCALHOST_CERTS.server_cert)?;
        let key = fs::read(&LOCALHOST_CERTS.server_key)?;
        let identity = Identity::from_pem(cert, key);
        let tls = ServerTlsConfig::new().identity(identity);
        rustls::crypto::ring::default_provider()
            .install_default()
            .inspect_err(|crypto_provider| {
                tracing::warn!("Crypto provider already configured: {crypto_provider:?}")
            })
            .ok(); // if something else is already default, ignore.

        let addr = {
            // Pick an open port
            let l = TcpListener::bind("127.0.0.1:0").await?;
            l.local_addr()?
                .to_socket_addrs()?
                .next()
                .expect("No socket available")
        };

        println!("Mock gRPC server listening on {addr}");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(
            Server::builder()
                .tls_config(tls)?
                .add_service(ForgeServer::new(self))
                .serve_with_shutdown(addr, async move {
                    shutdown_rx.await.ok();
                }),
        );

        Ok(MockApiServerHandle {
            addr,
            _shutdown_tx: shutdown_tx,
        })
    }
}
