use axum::body::Body;
use axum::extract::State as AxumState;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tower::ServiceBuilder;

use crate::config::MachineATronContext;
use crate::machine_info::MachineInfo;
use crate::machine_state_machine::{AddressConfigError, MachineStateError};
use crate::machine_utils::add_address_to_interface;
use crate::redfish_rewriter;
use bmc_mock::{BmcMockError, ListenerOrAddress};

/// BmcMockWrapper launches a single instance of bmc-mock, configured to mock a single BMC for
/// either a DPU or a Host. It will rewrite certain responses to customize them for the machines
/// machine-a-tron is mocking.
#[derive(Debug)]
pub struct BmcMockWrapper {
    machine_info: MachineInfo,
    command_channel: mpsc::UnboundedSender<MachineCommand>,
    app_context: MachineATronContext,
    bmc_mock_router: Router,
    join_handle: Option<JoinHandle<Result<(), BmcMockError>>>,
    listen_mode: ListenMode,
    active_address: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub enum MachineCommand {
    Reboot(DateTime<Utc>),
}

#[derive(Debug, Clone)]
pub enum ListenMode {
    SpecifiedAddress {
        address: SocketAddr,
        add_ip_alias: bool,
    },
    LocalhostWithDynamicPort,
}

#[derive(Clone)]
struct BmcMockAxumState {
    machine_info: MachineInfo,
    command_channel: mpsc::UnboundedSender<MachineCommand>,
}

impl BmcMockWrapper {
    pub fn new(
        machine_info: MachineInfo,
        command_channel: mpsc::UnboundedSender<MachineCommand>,
        app_context: MachineATronContext,
        listen_mode: ListenMode,
    ) -> Self {
        let bmc_mock_router = match machine_info {
            MachineInfo::Dpu(_) => app_context.dpu_bmc_mock_router.clone(),
            MachineInfo::Host(_) => app_context.host_bmc_mock_router.clone(),
        };

        BmcMockWrapper {
            machine_info,
            command_channel,
            app_context,
            bmc_mock_router,
            join_handle: None,
            listen_mode,
            active_address: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), MachineStateError> {
        let router = self
            .bmc_mock_router
            .clone()
            .layer(
                ServiceBuilder::new().layer(axum::middleware::from_fn_with_state(
                    BmcMockAxumState {
                        machine_info: self.machine_info.clone(),
                        command_channel: self.command_channel.clone(),
                    },
                    Self::mock_request_or_call_next,
                )),
            );

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

        self.join_handle = Some(tokio::spawn(async move {
            bmc_mock::run_combined_mock(
                HashMap::from([("".to_string(), router)]),
                Some(certs_dir),
                Some(listener_or_address),
            )
            .await
            .inspect_err(|e| tracing::error!("{}", e))
        }));
        self.active_address = Some(address);

        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(j) = self.join_handle.take() {
            j.abort();
        }
    }

    async fn mock_request_or_call_next(
        AxumState(state): AxumState<BmcMockAxumState>,
        request: Request<Body>,
        next: Next,
    ) -> impl IntoResponse {
        let BmcMockAxumState {
            machine_info: mocked_machine,
            command_channel,
        } = state;
        tracing::debug!(
            "bmc-mock({}): {} {}",
            mocked_machine.bmc_mac_address(),
            request.method(),
            request.uri().path()
        );

        let path = request.uri().path().to_string();

        if let Some(mock_response) =
            redfish_rewriter::mock_response_if_needed(&mocked_machine, &request)
        {
            return mock_response;
        }

        let tar_response: Response<Body> = next.run(request).await;
        let status = tar_response.status();

        // for 404's/etc, don't do any processing
        if !status.is_success() {
            return tar_response;
        }

        let tar_response_data = axum::body::to_bytes(tar_response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Give the mocked machine the opportunity to rewrite the response, falling back on the
        // upstream response otherwise.
        let response_bytes = redfish_rewriter::rewritten_response_if_needed(
            &mocked_machine,
            &path,
            &tar_response_data,
            &command_channel,
        )
        .inspect_err(|e| tracing::error!("Error rewriting bmc-mock response: {}", e))
        .ok()
        .flatten()
        .unwrap_or(tar_response_data);

        Response::builder()
            .status(status)
            .body(Body::from(response_bytes))
            .unwrap()
    }

    pub fn active_address(&self) -> Option<SocketAddr> {
        self.active_address
    }
}
