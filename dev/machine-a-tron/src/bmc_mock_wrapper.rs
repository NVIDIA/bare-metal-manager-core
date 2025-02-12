use axum::Router;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

use crate::config::MachineATronContext;
use crate::machine_state_machine::MachineStateError;
use crate::machine_utils::add_address_to_interface;
use bmc_mock::{BmcCommand, BmcMockHandle, ListenerOrAddress, MachineInfo};

/// BmcMockWrapper launches a single instance of bmc-mock, configured to mock a single BMC for
/// either a DPU or a Host. It will rewrite certain responses to customize them for the machines
/// machine-a-tron is mocking.
#[derive(Debug)]
pub struct BmcMockWrapper {
    app_context: Arc<MachineATronContext>,
    bmc_mock_router: Router,
}

impl BmcMockWrapper {
    pub fn new(
        machine_info: MachineInfo,
        command_channel: mpsc::UnboundedSender<BmcCommand>,
        app_context: Arc<MachineATronContext>,
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
        }
    }

    pub async fn start(
        &mut self,
        address: SocketAddr,
        add_ip_alias: bool,
    ) -> Result<BmcMockHandle, MachineStateError> {
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
                &self.app_context.app_config.sudo_command,
            )
            .await
            .inspect_err(|e| tracing::warn!("{}", e))
            .map_err(MachineStateError::ListenAddressConfigError)?;
        }

        tracing::info!("Starting bmc mock on {:?}", address);

        let bmc_mock_router = self.bmc_mock_router.clone();
        Ok(bmc_mock::run_combined_mock(
            Arc::new(RwLock::new(HashMap::from([(
                "".to_string(),
                bmc_mock_router,
            )]))),
            Some(certs_dir),
            Some(ListenerOrAddress::Address(address)),
        )
        .await?)
    }

    pub fn router(&self) -> &Router {
        &self.bmc_mock_router
    }
}

/// BmcMockRegistry is shared state that MachineATron's mock hosts can use to register their BMC
/// mock routers, so that a single shared instance of BMC mock can delegate to them.
pub type BmcMockRegistry = Arc<RwLock<HashMap<String, Router>>>;
