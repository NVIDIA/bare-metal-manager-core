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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use bmc_mock::ipmi_sim::{IpmiSimConfig, IpmiSimHandle};
use bmc_mock::{
    BmcState, Callbacks, CombinedServer, HostnameQuerying, ListenerOrAddress, MachineInfo,
};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::config::MachineATronContext;
use crate::machine_state_machine::MachineStateError;
use crate::machine_utils::add_address_to_interface;
use crate::mock_ssh_server;
use crate::mock_ssh_server::{MockSshServerHandle, PromptBehavior};

/// BmcMockWrapper launches a single instance of bmc-mock, configured to mock a single BMC for
/// either a DPU or a Host. It will rewrite certain responses to customize them for the machines
/// machine-a-tron is mocking.
pub struct BmcMockWrapper {
    ssh_prompt_behavior: PromptBehavior,
    app_context: Arc<MachineATronContext>,
    bmc_mock_router: Router,
    bmc_mock_state: BmcState,
    hostname: Arc<dyn HostnameQuerying>,
    supports_ipmi_console: bool,
    stable_id: String,
}

impl BmcMockWrapper {
    pub fn new(
        machine_info: &MachineInfo,
        app_context: Arc<MachineATronContext>,
        callbacks: Arc<dyn Callbacks>,
        hostname: Arc<dyn HostnameQuerying>,
        host_id: Uuid,
    ) -> Self {
        let (bmc_mock_router, bmc_mock_state) =
            bmc_mock::machine_router(machine_info, callbacks, host_id.to_string(), true);

        BmcMockWrapper {
            ssh_prompt_behavior: match machine_info {
                MachineInfo::Host(_) => PromptBehavior::Dell,
                MachineInfo::Dpu(_) => PromptBehavior::Dpu,
            },
            app_context,
            bmc_mock_router,
            bmc_mock_state,
            hostname,
            supports_ipmi_console: machine_info.supports_ipmi_console(),
            stable_id: host_id.to_string(),
        }
    }

    /// Starts the per-machine Redfish server and any enabled SSH and IPMI simulators.
    /// When requested, the BMC address is first added as an alias on the configured interface.
    pub async fn start(
        &mut self,
        address: SocketAddr,
        add_ip_alias: bool,
    ) -> Result<BmcMockWrapperHandle, MachineStateError> {
        let root_ca_path = self.app_context.forge_client_config.root_ca_path.as_str();
        let certs_dir = self
            .app_context
            .bmc_mock_certs_dir
            .as_ref()
            .cloned()
            .or_else(|| {
                PathBuf::from(root_ca_path.to_owned())
                    .parent()
                    .map(Path::to_path_buf)
            })
            .ok_or_else(|| MachineStateError::MissingCertificates(root_ca_path.to_owned()))?;

        // Support dynamically assigning address: If configured for a dynamic address, pass the
        // listener itself to bmc-mock to prevent race conditions. Otherwise, pass the address.
        if add_ip_alias {
            add_address_to_interface(
                &address.ip().to_string(),
                &self.app_context.app_config.interface,
            )
            .await
            .inspect_err(|e| {
                tracing::warn!(
                    error = %e,
                    "failed to add BMC mock address to interface",
                )
            })
            .map_err(MachineStateError::ListenAddressConfigError)?;
        }

        let ssh_handle = if self.app_context.app_config.mock_bmc_ssh_server {
            // Port: Use the configured port, and if none is configured, use (1) a random port, if
            // we're launching a single BMC mock for all machines (needed for integration tests
            // where we can't rely on available ports), or (2) a fixed port if we're creating a new
            // IP address for every machine
            let port = self
                .app_context
                .app_config
                .mock_bmc_ssh_port
                .or(if add_ip_alias {
                    // We have to use a nonstandard port here even if we're using an ip alias, since most
                    // hosts listen to SSH on port 22 already on *all* interfaces, including any aliases we
                    // create for the test.
                    Some(2222)
                } else {
                    None
                });

            Some(
                mock_ssh_server::spawn(
                    address.ip(),
                    port,
                    self.hostname.clone(),
                    Some(mock_ssh_server::Credentials {
                        user: "root".to_string(),
                        password: "password".to_string(),
                    }),
                    self.ssh_prompt_behavior,
                )
                .await
                .map_err(|error| {
                    MachineStateError::MockSshServer(format!(
                        "error running mock SSH server on {}:{}: {error:?}",
                        address.ip(),
                        port.map(|p| p.to_string()).unwrap_or("<none>".to_string()),
                    ))
                })?,
            )
        } else {
            None
        };
        let ipmi_sim_handle = self.start_ipmi_sim(address.ip()).await?;

        tracing::info!(
            listen_address = ?address,
            "Starting BMC mock",
        );

        let tls_server_config = bmc_mock::tls::server_config(Some(certs_dir))?;
        let bmc_mock_router = self.bmc_mock_router.clone();
        Ok(BmcMockWrapperHandle {
            _bmc_mock: Some(CombinedServer::run(
                "bmc-mock",
                Arc::new(RwLock::new(HashMap::from([(
                    "".to_string(),
                    bmc_mock_router,
                )]))),
                Some(ListenerOrAddress::Address(address)),
                tls_server_config,
            )),
            ssh_handle,
            _ipmi_sim_handle: ipmi_sim_handle,
        })
    }

    /// Starts only the optional IPMI simulator when Redfish is served by a shared BMC mock.
    /// Returns `None` when IPMI simulation is disabled or the machine does not support IPMI SOL.
    pub async fn start_ipmi_only(
        &self,
        bind_ip: std::net::IpAddr,
    ) -> Result<Option<BmcMockWrapperHandle>, MachineStateError> {
        Ok(self
            .start_ipmi_sim(bind_ip)
            .await?
            .map(|ipmi_sim_handle| BmcMockWrapperHandle {
                _bmc_mock: None,
                ssh_handle: None,
                _ipmi_sim_handle: Some(ipmi_sim_handle),
            }))
    }

    async fn start_ipmi_sim(
        &self,
        bind_ip: std::net::IpAddr,
    ) -> Result<Option<IpmiSimHandle>, MachineStateError> {
        if !self.app_context.app_config.enable_ipmi_simulation || !self.supports_ipmi_console {
            return Ok(None);
        }

        let console_prompt = format!("root@{} # ", self.hostname.get_hostname());
        bmc_mock::ipmi_sim::start(
            &self.bmc_mock_state,
            IpmiSimConfig {
                bind_ip,
                stable_id: self.stable_id.clone(),
                console_prompt,
            },
        )
        .await
        .map(Some)
        .map_err(MachineStateError::IpmiSim)
    }

    pub fn router(&self) -> &Router {
        &self.bmc_mock_router
    }

    pub fn state(&self) -> &BmcState {
        &self.bmc_mock_state
    }
}

#[derive(Debug)]
pub struct BmcMockWrapperHandle {
    pub _bmc_mock: Option<CombinedServer>,
    pub ssh_handle: Option<MockSshServerHandle>,
    _ipmi_sim_handle: Option<IpmiSimHandle>,
}

/// BmcMockRegistry is shared state that MachineATron's mock hosts can use to register their BMC
/// mock routers, so that a single shared instance of BMC mock can delegate to them.
pub type BmcMockRegistry = Arc<RwLock<HashMap<String, Router>>>;
