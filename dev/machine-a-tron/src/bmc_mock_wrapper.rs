use axum::body::Body;
use axum::extract::State as AxumState;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::path::{Path, PathBuf};
use std::{collections::HashMap, net::SocketAddr};

use crate::config::MachineATronContext;
use crate::dpu_machine::DpuBmcInfo;
use bmc_mock::BmcMockError;
use tokio::task::JoinHandle;
use tower::ServiceBuilder;

use crate::host_machine::{HostBmcInfo, MachineStateError};

/// BmcMockWrapper launches a single instance of bmc-mock, configured to mock multiple BMCs
/// simultaneously (see docs in [`bmc_mock::run_combined_mock`] for details), while also
/// rewriting certain responses to customize them for the machines machine-a-tron is mocking.
///
/// bmc-mock is passed tar files for the base mock JSON data (see [`bmc_mock::tar_router`]), but for
/// respones that include things like the MAC address and serial number of a machine, the JSON is
/// rewritten by BmcMockWrapper to the appropriate values for the mocked machine.
pub struct BmcMockWrapper {
    hosts_by_mac_address: HashMap<String, HostBmcInfo>,
    dpus_by_mac_address: HashMap<String, DpuBmcInfo>,
    listen_address: SocketAddr,
    app_context: MachineATronContext,
    dpu_tar_router: Router,
    host_tar_router: Router,
    join_handle: Option<JoinHandle<Result<(), BmcMockError>>>,
}

impl BmcMockWrapper {
    pub fn new(
        hosts: Vec<HostBmcInfo>,
        listen_address: SocketAddr,
        app_context: MachineATronContext,
    ) -> eyre::Result<Self> {
        let hosts_by_mac_address = hosts
            .iter()
            .map(|h| (h.mac_address.to_string(), h.clone()))
            .collect();
        let dpus_by_mac_address = hosts
            .iter()
            .flat_map(|h| {
                h.dpus
                    .iter()
                    .map(|d| (d.mac_address.to_string(), d.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();

        let dpu_tar_router = bmc_mock::tar_router(
            Path::new(app_context.app_config.bmc_mock_dpu_tar.as_str()),
            None,
        )?;
        let host_tar_router = bmc_mock::tar_router(
            Path::new(app_context.app_config.bmc_mock_host_tar.as_str()),
            None,
        )?;

        Ok(BmcMockWrapper {
            hosts_by_mac_address,
            dpus_by_mac_address,
            listen_address,
            app_context,
            dpu_tar_router,
            host_tar_router,
            join_handle: None,
        })
    }

    pub fn start(&mut self) -> Result<(), MachineStateError> {
        tracing::info!("Starting bmc mock on {:?}", self.listen_address);
        let root_ca_path = self.app_context.forge_client_config.root_ca_path.as_str();
        let cert_path = PathBuf::from(root_ca_path.to_owned())
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .ok_or(MachineStateError::MissingCertificates(
                root_ca_path.to_owned(),
            ))?;

        let listen_address = self.listen_address;
        let routers = self.make_routers();

        self.join_handle = Some(tokio::spawn(async move {
            bmc_mock::run_combined_mock(routers, Some(cert_path), Some(listen_address))
                .await
                .inspect_err(|e| tracing::error!("{}", e))
        }));
        Ok(())
    }

    fn make_routers(&self) -> HashMap<String, Router> {
        let mut result = HashMap::new();
        for (mac_address, dpu) in &self.dpus_by_mac_address {
            let dpu = MockedMachine::Dpu(dpu.clone());
            let router_with_middleware =
                self.dpu_tar_router
                    .clone()
                    .layer(
                        ServiceBuilder::new().layer(axum::middleware::from_fn_with_state(
                            dpu,
                            Self::mock_request_or_call_next,
                        )),
                    );
            result.insert(mac_address.clone(), router_with_middleware);
        }
        for (mac_address, host) in &self.hosts_by_mac_address {
            let host = MockedMachine::Host(host.clone());
            let router_with_middleware =
                self.host_tar_router
                    .clone()
                    .layer(
                        ServiceBuilder::new().layer(axum::middleware::from_fn_with_state(
                            host,
                            Self::mock_request_or_call_next,
                        )),
                    );
            result.insert(mac_address.clone(), router_with_middleware);
        }
        result
    }

    pub fn stop(&mut self) {
        if let Some(j) = self.join_handle.as_ref() {
            j.abort()
        }
    }

    async fn mock_request_or_call_next(
        AxumState(mocked_machine): AxumState<MockedMachine>,
        request: Request<Body>,
        next: Next<Body>,
    ) -> Result<impl IntoResponse, Response<Body>> {
        // TODO: This is where we optionally edit the response to add the MAC address/serial/etc.
        tracing::info!("would mock response for {:?} here", mocked_machine);
        Ok(next.run(request).await)
    }
}

#[derive(Debug, Clone)]
enum MockedMachine {
    Host(HostBmcInfo),
    Dpu(DpuBmcInfo),
}
