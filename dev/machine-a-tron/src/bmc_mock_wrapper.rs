use axum::body::Body;
use axum::extract::State as AxumState;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use mac_address::MacAddress;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use tokio::task::JoinHandle;
use tower::ServiceBuilder;

use bmc_mock::{BmcMockError, ListenerOrAddress};

use crate::config::MachineATronContext;
use crate::host_machine::{AddressConfigError, MachineStateError};
use crate::machine_utils::add_address_to_interface;
use crate::redfish_rewriter;

/// BmcMockWrapper launches a single instance of bmc-mock, configured to mock a single BMC for
/// either a DPU or a Host. It will rewrite certain responses to customize them for the machines
/// machine-a-tron is mocking.
#[derive(Debug)]
pub struct BmcMockWrapper {
    mock_bmc_info: MockBmcInfo,
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

#[derive(Debug, Clone)]
pub enum MockBmcInfo {
    Host(HostBmcInfo),
    Dpu(DpuBmcInfo),
}

#[derive(Debug, Clone)]
pub struct HostBmcInfo {
    pub bmc_mac_address: MacAddress,
    pub serial: String,
    pub dpus: Vec<DpuBmcInfo>,
}

#[derive(Debug, Clone)]
pub struct DpuBmcInfo {
    pub bmc_mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub oob_mac_address: MacAddress,
    pub serial: String,
}

impl HostBmcInfo {
    pub fn primary_dpu(&self) -> Option<&DpuBmcInfo> {
        self.dpus.first()
    }

    pub fn system_mac_addresss(&self) -> Option<MacAddress> {
        self.primary_dpu().map(|d| d.host_mac_address)
    }
}

impl MockBmcInfo {
    pub fn serial(&self) -> String {
        match self {
            Self::Host(h) => h.serial.clone(),
            Self::Dpu(d) => d.serial.clone(),
        }
    }

    pub fn bmc_mac_address(&self) -> MacAddress {
        match self {
            Self::Host(h) => h.bmc_mac_address,
            Self::Dpu(d) => d.bmc_mac_address,
        }
    }
}

impl BmcMockWrapper {
    pub fn new(
        mock_bmc_info: MockBmcInfo,
        bmc_mock_router: Router,
        app_context: MachineATronContext,
        listen_mode: ListenMode,
    ) -> Self {
        BmcMockWrapper {
            mock_bmc_info,
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
                    self.mock_bmc_info.clone(),
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
        if let Some(j) = self.join_handle.as_ref() {
            j.abort();
            self.join_handle = None;
        }
    }

    async fn mock_request_or_call_next(
        AxumState(mocked_machine): AxumState<MockBmcInfo>,
        request: Request<Body>,
        next: Next,
    ) -> impl IntoResponse {
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
