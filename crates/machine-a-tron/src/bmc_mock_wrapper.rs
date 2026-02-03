/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use bmc_mock::{
    BmcMockError, BmcMockHandle, HostnameQuerying, ListenerOrAddress, MachineInfo, MockPowerState,
    POWER_CYCLE_DELAY, PowerControl,
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
#[derive(Debug)]
pub struct BmcMockWrapper {
    machine_info: MachineInfo,
    app_context: Arc<MachineATronContext>,
    bmc_mock_router: Router,
    hostname: Arc<dyn HostnameQuerying>,
}

impl BmcMockWrapper {
    pub fn new(
        machine_info: MachineInfo,
        app_context: Arc<MachineATronContext>,
        power_control: Arc<dyn PowerControl>,
        hostname: Arc<dyn HostnameQuerying>,
        host_id: Uuid,
    ) -> Self {
        let bmc_mock_router =
            bmc_mock::machine_router(machine_info.clone(), power_control, host_id.to_string());

        BmcMockWrapper {
            machine_info,
            app_context,
            bmc_mock_router,
            hostname,
        }
    }

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
            .inspect_err(|e| tracing::warn!("{}", e))
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
                    match self.machine_info {
                        MachineInfo::Host(_) => PromptBehavior::Dell,
                        MachineInfo::Dpu(_) => PromptBehavior::Dpu,
                    },
                )
                .await
                .map_err(|error| {
                    BmcMockError::MockSshServer(format!(
                        "error running mock SSH server on {}:{}: {error:?}",
                        address.ip(),
                        port.map(|p| p.to_string()).unwrap_or("<none>".to_string()),
                    ))
                })?,
            )
        } else {
            None
        };

        tracing::info!("Starting bmc mock on {:?}", address);

        let bmc_mock_router = self.bmc_mock_router.clone();
        Ok(BmcMockWrapperHandle {
            _bmc_mock: bmc_mock::run_combined_mock(
                Arc::new(RwLock::new(HashMap::from([(
                    "".to_string(),
                    bmc_mock_router,
                )]))),
                Some(certs_dir),
                Some(ListenerOrAddress::Address(address)),
            )?,
            ssh_handle,
        })
    }

    pub fn router(&self) -> &Router {
        &self.bmc_mock_router
    }
}

#[derive(Debug)]
pub struct BmcMockWrapperHandle {
    pub _bmc_mock: BmcMockHandle,
    pub ssh_handle: Option<MockSshServerHandle>,
}

/// BmcMockRegistry is shared state that MachineATron's mock hosts can use to register their BMC
/// mock routers, so that a single shared instance of BMC mock can delegate to them.
pub type BmcMockRegistry = Arc<RwLock<HashMap<String, Router>>>;

pub fn convert_power_state(val: MockPowerState) -> libredfish::PowerState {
    match val {
        MockPowerState::On => libredfish::PowerState::On,
        MockPowerState::Off => libredfish::PowerState::Off,
        MockPowerState::PowerCycling { since } => {
            if since.elapsed() < POWER_CYCLE_DELAY {
                libredfish::PowerState::Off
            } else {
                libredfish::PowerState::On
            }
        }
    }
}
