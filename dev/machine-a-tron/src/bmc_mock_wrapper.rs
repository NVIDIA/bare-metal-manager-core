use axum::Router;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use crate::config::MachineATronContext;
use crate::machine_state_machine::{AddressConfigError, MachineStateError};
use crate::machine_utils::add_address_to_interface;
use bmc_mock::{BmcMockError, ListenerOrAddress, MachineCommand, MachineInfo};

/// BmcMockWrapper launches a single instance of bmc-mock, configured to mock a single BMC for
/// either a DPU or a Host. It will rewrite certain responses to customize them for the machines
/// machine-a-tron is mocking.
#[derive(Debug)]
pub struct BmcMockWrapper {
    app_context: MachineATronContext,
    bmc_mock_router: Router,
    join_handle: Option<JoinHandle<Result<(), BmcMockError>>>,
    listen_mode: ListenMode,
    active_address: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub enum ListenMode {
    SpecifiedAddress {
        address: SocketAddr,
        add_ip_alias: bool,
    },
    LocalhostWithDynamicPort,
}

impl BmcMockWrapper {
    pub fn new(
        machine_info: MachineInfo,
        command_channel: mpsc::UnboundedSender<MachineCommand>,
        app_context: MachineATronContext,
        listen_mode: ListenMode,
    ) -> Self {
        let tar_router = match machine_info {
            MachineInfo::Dpu(_) => app_context.dpu_tar_router.clone(),
            MachineInfo::Host(_) => app_context.host_tar_router.clone(),
        };

        let bmc_mock_router = bmc_mock::wrap_router_with_mock_machine(
            tar_router,
            machine_info,
            Some(command_channel),
        );

        BmcMockWrapper {
            app_context,
            bmc_mock_router,
            join_handle: None,
            listen_mode,
            active_address: None,
        }
    }

    pub async fn start(&mut self) -> Result<SocketAddr, MachineStateError> {
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
        let listener_or_address = match self.listen_mode {
            ListenMode::LocalhostWithDynamicPort => {
                ListenerOrAddress::Listener(
                    TcpListener::bind("127.0.0.1:0").map_err(AddressConfigError::from)?,
                ) // let OS choose available port
            }
            ListenMode::SpecifiedAddress {
                address,
                add_ip_alias,
            } => {
                if add_ip_alias {
                    add_address_to_interface(
                        &address.ip().to_string(),
                        &self.app_context.app_config.interface,
                        &self.app_context.app_config.sudo_command,
                    )
                    .await
                    .inspect_err(|e| tracing::warn!("{}", e))
                    .map_err(MachineStateError::ListenAddressConfigError)?;
                }
                ListenerOrAddress::Address(address)
            }
        };

        let address = listener_or_address
            .address()
            .map_err(AddressConfigError::from)?;
        tracing::info!("Starting bmc mock on {:?}", address);

        let bmc_mock_router = self.bmc_mock_router.clone();
        self.join_handle = Some(tokio::spawn(async move {
            bmc_mock::run_combined_mock(
                HashMap::from([("".to_string(), bmc_mock_router)]),
                Some(certs_dir),
                Some(listener_or_address),
            )
            .await
            .inspect_err(|e| tracing::error!("{}", e))
        }));
        self.active_address = Some(address);

        Ok(address)
    }

    pub fn active_address(&self) -> Option<SocketAddr> {
        self.active_address
    }
}

/// BmcMockAddressRegistry is shared state that MachineATron's mock hosts can use to write the
/// actual address of the BMC-mocks they run, and that MachineATronBackedRedfishClientPool reads
/// from to know the "real" address of a mocked BMC.
pub type BmcMockAddressRegistry = Arc<RwLock<HashMap<Ipv4Addr, SocketAddr>>>;
