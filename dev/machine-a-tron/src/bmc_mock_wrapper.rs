use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::body::{Body, Bytes};
use axum::extract::State as AxumState;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use http_body::Body as HttpBodyBody;
use mac_address::MacAddress;
use tokio::task::JoinHandle;
use tower::ServiceBuilder;

use bmc_mock::BmcMockError;

use crate::config::MachineATronContext;
use crate::host_machine::MachineStateError;
use crate::machine_utils::add_address_to_interface;
use crate::redfish_rewriter;

/// BmcMockWrapper launches a single instance of bmc-mock, configured to mock a single BMC for
/// either a DPU or a Host. It will rewrite certain responses to customize them for the machines
/// machine-a-tron is mocking.
#[derive(Debug)]
pub struct BmcMockWrapper {
    mock_bmc_info: MockBmcInfo,
    listen_address: SocketAddr,
    app_context: MachineATronContext,
    bmc_mock_router: Router,
    join_handle: Option<JoinHandle<Result<(), BmcMockError>>>,
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
        listen_address: SocketAddr,
        app_context: MachineATronContext,
    ) -> Self {
        BmcMockWrapper {
            mock_bmc_info,
            listen_address,
            app_context,
            bmc_mock_router,
            join_handle: None,
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

        tracing::info!("Starting bmc mock on {:?}", self.listen_address);
        let root_ca_path = self.app_context.forge_client_config.root_ca_path.as_str();
        let cert_path = PathBuf::from(root_ca_path.to_owned())
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .ok_or(MachineStateError::MissingCertificates(
                root_ca_path.to_owned(),
            ))?;

        let listen_address = self.listen_address;

        add_address_to_interface(
            &listen_address.ip().to_string(),
            &self.app_context.app_config.interface,
            &self.app_context.app_config.sudo_command,
        )
        .await
        .inspect_err(|e| tracing::warn!("{}", e))
        .map_err(MachineStateError::ListenAddressConfigError)?;

        self.join_handle = Some(tokio::spawn(async move {
            bmc_mock::run_combined_mock(
                HashMap::from([("".to_string(), router)]),
                Some(cert_path),
                Some(listen_address),
            )
            .await
            .inspect_err(|e| tracing::error!("{}", e))
        }));
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
        next: Next<Body>,
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

        let mut tar_response = next.run(request).await;

        let (status, body) = match tar_response.data().await {
            Some(Ok(bytes)) => (tar_response.status(), bytes),
            Some(Err(e)) => {
                let err = format!("error calling BMC mock: {e}");
                tracing::error!(err);
                (tar_response.status(), Bytes::from(err))
            }
            // Not clear why the data would be None, but map it to an empty body and relay the
            // status code
            None => {
                tracing::error!(
                    "No data in BMC mock response. status={}",
                    tar_response.status()
                );
                (tar_response.status(), Bytes::from(""))
            }
        };

        // for 404's/etc, don't do any processing
        if !status.is_success() {
            return Response::builder()
                .status(status)
                .body(Body::from(body))
                .unwrap();
        }

        // Give the mocked machine the opportunity to rewrite the response, falling back on the
        // upstream response otherwise.
        let response_bytes =
            redfish_rewriter::rewritten_response_if_needed(&mocked_machine, &path, &body)
                .inspect_err(|e| tracing::error!("Error rewriting bmc-mock response: {}", e))
                .ok()
                .flatten()
                .unwrap_or(body);

        Response::builder()
            .status(status)
            .body(Body::from(response_bytes))
            .unwrap()
    }
}
