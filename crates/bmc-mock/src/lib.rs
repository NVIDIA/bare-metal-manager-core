/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::future::Future;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::{Router, ServiceExt};
use axum_server::tls_rustls::RustlsConfig;
use hyper::body::Incoming;
use rustls::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls_pemfile::Item;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tower::{Layer, Service};
use tower_http::normalize_path::NormalizePathLayer;
use tracing::{debug, error, info};

mod bmc_state;
mod bug;
mod json;
mod machine_info;
mod middleware_router;
mod mock_machine_router;
mod redfish;
mod redfish_expander;
mod tar_router;

pub use machine_info::{DpuFirmwareVersions, DpuMachineInfo, HostMachineInfo, MachineInfo};
pub use mock_machine_router::{
    BmcCommand, SetSystemPowerError, SetSystemPowerResult, machine_router,
};
pub use redfish_expander::wrap_router_with_redfish_expander;
pub use tar_router::{EntryMap, TarGzOption, tar_router};

#[derive(thiserror::Error, Debug)]
pub enum BmcMockError {
    #[error("BMC Mock I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("BMC Mock Configuration error: {0}")]
    Config(String),
    #[error("Error running SSH server for BMC Mock: {0}")]
    MockSshServer(String),
}

#[derive(Debug)]
pub struct BmcMockHandle {
    join_handle: Option<JoinHandle<std::io::Result<()>>>,
    axum_handle: axum_server::Handle,
    pub address: SocketAddr,
}

impl Drop for BmcMockHandle {
    fn drop(&mut self) {
        if let Some(join_handle) = self.join_handle.take()
            && !join_handle.is_finished()
        {
            tracing::info!("Stopping BMC Mock at {}", self.address);
            self.axum_handle.shutdown();
            join_handle.abort()
        }
    }
}

impl BmcMockHandle {
    pub async fn stop(&mut self) -> std::io::Result<()> {
        if let Some(join_handle) = self.join_handle.take() {
            self.axum_handle.shutdown();
            join_handle.await.expect("join error")
        } else {
            Ok(())
        }
    }

    pub async fn wait(&mut self) -> std::io::Result<()> {
        if let Some(join_handle) = self.join_handle.take() {
            join_handle.await.expect("join error")
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "PascalCase")]
pub struct SetSystemPowerReq {
    pub reset_type: SystemPowerControl,
}

#[derive(Debug, Copy, Clone, Default)]
pub enum MockPowerState {
    #[default]
    On,
    Off,
    PowerCycling {
        since: Instant,
    },
}

pub trait PowerControl: std::fmt::Debug + Send + Sync {
    fn get_power_state(&self) -> MockPowerState;
    fn send_power_command(&self, reset_type: SystemPowerControl)
    -> Result<(), SetSystemPowerError>;
    fn set_power_state(&self, reset_type: SystemPowerControl) -> Result<(), SetSystemPowerError> {
        validate_power_request(reset_type, self.get_power_state())?;
        self.send_power_command(reset_type)
    }
}

pub trait HostnameQuerying: std::fmt::Debug + Send + Sync {
    fn get_hostname(&'_ self) -> Cow<'_, str>;
}

// Simulate a 5-second power cycle
pub const POWER_CYCLE_DELAY: Duration = Duration::from_secs(5);

// https://www.dmtf.org/sites/default/files/standards/documents/DSP2046_2023.3.html
// 6.5.5.1 ResetType
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Copy)]
pub enum SystemPowerControl {
    /// Power on a machine
    On,
    /// Graceful host shutdown
    GracefulShutdown,
    /// Forcefully powers a machine off
    ForceOff,
    /// Graceful restart. Asks the OS to restart via ACPI
    /// - Might restart DPUs if no OS is running
    /// - Will not apply pending BIOS/UEFI setting changes
    GracefulRestart,
    /// Force restart. This is equivalent to pressing the reset button on the front panel.
    /// - Will not restart DPUs
    /// - Will apply pending BIOS/UEFI setting changes
    ForceRestart,

    //
    // libredfish doesn't support these yet, and not all vendors provide them
    //

    // Cut then restore the power
    PowerCycle,

    // Forcefully power a machine on (?)
    ForceOn,

    // Like it says, pretend the button got pressed
    PushPowerButton,

    // Non-maskable interrupt then power off
    Nmi,

    // Write state to disk and power off
    Suspend,

    // VM / Hypervisor
    Pause,
    Resume,
}

pub fn validate_power_request(
    reset_type: SystemPowerControl,
    power_state: MockPowerState,
) -> Result<(), SetSystemPowerError> {
    type C = SystemPowerControl;
    match (reset_type, power_state) {
        (
            C::GracefulShutdown | C::ForceOff | C::GracefulRestart | C::ForceRestart,
            MockPowerState::Off,
        ) => Err(SetSystemPowerError::BadRequest(
            "bmc-mock: cannot power off machine, it is already off".to_string(),
        )),
        (C::On | C::ForceOn, MockPowerState::On) => Err(SetSystemPowerError::BadRequest(
            "bmc-mock: cannot power on machine, it is already on".to_string(),
        )),
        (_, MockPowerState::PowerCycling { since }) if since.elapsed() < POWER_CYCLE_DELAY => {
            Err(SetSystemPowerError::BadRequest(format!(
                "bmc-mock: cannot reset machine, it is in the middle of power cycling since {:?} ago",
                since.elapsed()
            )))
        }
        _ => Ok(()),
    }
}

/// Mock multiple BMCs while listening on a single IP/port.
///
/// Information on what machine to mock will be passed by carbide via the `x-really-to-mac` HTTP header,
/// which will be used to route the request to the appropriate entry in the `bmc_routers_by_mac_address`
/// table.
pub fn run_combined_mock<T: AsRef<OsStr>>(
    bmc_routers_by_ip_address: Arc<RwLock<HashMap<String, Router>>>,
    cert_path: Option<T>,
    listener_or_address: Option<ListenerOrAddress>,
) -> Result<BmcMockHandle, BmcMockError> {
    let cert_path = match cert_path.as_ref() {
        Some(cert_path) => Path::new(cert_path),
        None => {
            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            match manifest_dir.try_exists() {
                Ok(true) => manifest_dir,
                Ok(false) => Path::new("/opt/carbide"),
                Err(error) => {
                    return Err(BmcMockError::Config(format!(
                        "Could not determine if CARGO_MANIFEST_DIR exists: {error}"
                    )));
                }
            }
        }
    };

    let mut cert_file = cert_path.join("tls.crt");
    let mut key_file = cert_path.join("tls.key");
    if !cert_file.exists() {
        // let's try once more. This can be docker-compose case.
        let root_var =
            std::env::var("REPO_ROOT").expect("Could not find the crt file for bmc-mock.");
        let root_dir = Path::new(&root_var);
        let cert_path = root_dir.join("crates/bmc-mock");
        cert_file = cert_path.join("tls.crt");
        key_file = cert_path.join("tls.key");
    }
    info!("Loading {:?} and {:?}", cert_file, key_file);
    let tls_config = make_rustls_server_config(
        std::fs::read(cert_file)?.as_slice(),
        std::fs::read(key_file)?.as_slice(),
    )
    .map_err(|e| BmcMockError::Config(format!("Error building rustls config: {e}")))?;
    let config = RustlsConfig::from_config(Arc::new(tls_config));

    let axum_handle = axum_server::Handle::new();

    let (addr, server) = match listener_or_address {
        Some(ListenerOrAddress::Address(addr)) => (
            addr,
            axum_server::bind_rustls(addr, config).handle(axum_handle.clone()),
        ),
        Some(ListenerOrAddress::Listener(listener)) => (
            listener.local_addr().unwrap(),
            axum_server::from_tcp_rustls(listener, config).handle(axum_handle.clone()),
        ),
        None => {
            let addr = SocketAddr::from(([0, 0, 0, 0], 1266));
            (
                addr,
                axum_server::bind_rustls(addr, config).handle(axum_handle.clone()),
            )
        }
    };
    debug!("Listening on {}", addr);

    let bmc_service = BmcService {
        routers: bmc_routers_by_ip_address,
    };

    // Inject middleware to normalize request URIs by dropping the trailing slash
    let bmc_service = NormalizePathLayer::trim_trailing_slash().layer(bmc_service);

    let join_handle = tokio::task::Builder::new()
        .name("bmc mock")
        .spawn(async move {
            server
                .serve(bmc_service.into_make_service())
                .await
                .inspect_err(|e| {
                    tracing::error!("BMC mock could not listen on address {}: {}", addr, e)
                })?;
            Ok(())
        })
        .expect("tokio spawn error");
    Ok(BmcMockHandle {
        axum_handle,
        join_handle: Some(join_handle),
        address: addr,
    })
}

pub enum ListenerOrAddress {
    Listener(TcpListener),
    Address(SocketAddr),
}

impl ListenerOrAddress {
    pub fn address(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Listener(l) => l.local_addr(),
            Self::Address(a) => Ok(*a),
        }
    }
}

#[derive(Clone)]
struct BmcService {
    routers: Arc<RwLock<HashMap<String, Router>>>,
}

impl Service<axum::http::Request<Incoming>> for BmcService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        let forwarded_header = request
            .headers()
            .get("forwarded")
            .map(|v| v.to_str().unwrap())
            .unwrap_or("");

        // https://datatracker.ietf.org/doc/html/rfc7239#section-5.3
        let forwarded_host = forwarded_header
            .split(';')
            .find(|substr| substr.starts_with("host="))
            .map(|substr| substr.replace("host=", ""))
            .unwrap_or_default();

        let routers = self.routers.clone();
        Box::pin(async move {
            let Some(router) = routers.read().await.get(&forwarded_host).cloned() else {
                let err = format!("no BMC mock configured for host: {forwarded_host}");
                tracing::info!("{err}");
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(err.into())
                    .unwrap());
            };

            wrap_router_with_redfish_expander(router)
                .call(request)
                .await
        })
    }
}

pub fn default_host_mock() -> Router {
    let command_channel = spawn_qemu_reboot_handler();
    let power_control = Arc::new(ChannelPowerControl::new(command_channel));
    machine_router(
        MachineInfo::Host(HostMachineInfo::new(vec![DpuMachineInfo::default()])),
        power_control,
        String::default(),
    )
}

#[derive(Debug)]
struct ChannelPowerControl {
    command_channel: mpsc::UnboundedSender<BmcCommand>,
}

impl ChannelPowerControl {
    fn new(command_channel: mpsc::UnboundedSender<BmcCommand>) -> Self {
        Self { command_channel }
    }
}

impl PowerControl for ChannelPowerControl {
    fn get_power_state(&self) -> MockPowerState {
        MockPowerState::On
    }

    fn send_power_command(
        &self,
        reset_type: SystemPowerControl,
    ) -> Result<(), SetSystemPowerError> {
        self.command_channel
            .send(BmcCommand::SetSystemPower {
                request: SetSystemPowerReq { reset_type },
                reply: None,
            })
            .map_err(|err| SetSystemPowerError::CommandSendError(err.to_string()))
    }
}

fn spawn_qemu_reboot_handler() -> mpsc::UnboundedSender<BmcCommand> {
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Some(command) = command_rx.recv().await else {
                break;
            };
            match command {
                // Assume SetSystemPower is just a reboot
                BmcCommand::SetSystemPower { .. } => {}
            }
            let reboot_output = match Command::new("virsh")
                .arg("reboot")
                .arg("ManagedHost")
                .output()
            {
                Ok(o) => o,
                Err(err) if matches!(err.kind(), ErrorKind::NotFound) => {
                    info!("`virsh` not found. Cannot reboot QEMU host.");
                    continue;
                }
                Err(err) => {
                    error!("Error trying to run 'virsh reboot ManagedHost'. {}", err);
                    continue;
                }
            };

            match reboot_output.status.code() {
                Some(0) => {
                    debug!("Rebooted qemu managed host...");
                }
                Some(exit_code) => {
                    error!(
                        "Reboot command 'virsh reboot ManagedHost' failed with exit code {exit_code}."
                    );
                    info!("STDOUT: {}", String::from_utf8_lossy(&reboot_output.stdout));
                    info!("STDERR: {}", String::from_utf8_lossy(&reboot_output.stderr));
                }
                None => {
                    error!("Reboot command killed by signal");
                }
            }
        }
    });
    command_tx
}

/// Wrapper arond axum::Router::call which constructs a new request object. This works
/// around an issue where if you just call inner_router.call(request) when that request's
/// Path<> is parameterized (ie. /:system_id, etc) it fails if the inner router doesn't have
/// the same number of arguments in its path as we do.
///
/// The error looks like:
///
/// Wrong number of path arguments for `Path`. Expected 1 but got 3. Note that multiple parameters must be extracted with a tuple `Path<(_, _)>` or a struct `Path<YourParams>`
async fn call_router_with_new_request(
    router: &mut axum::Router,
    request: axum::http::request::Request<Body>,
) -> axum::response::Response {
    let (head, body) = request.into_parts();

    // Construct a new request matching the incoming one.
    let mut rb = Request::builder().uri(&head.uri).method(&head.method);
    for (key, value) in head.headers.iter() {
        rb = rb.header(key, value);
    }
    let inner_request = rb.body(body).unwrap();

    router.call(inner_request).await.expect("Infallible error")
}

// Note: Axum has a simple RustlsConfig::from_pem we could use, but it constructs a rustls
// ServerConfig without a default crypto provider. So we have to make our own rustls::ServerConfig
// and pass that to RustlsConfig::from.
fn make_rustls_server_config(tls_cert: &[u8], tls_key: &[u8]) -> eyre::Result<ServerConfig> {
    let certs =
        rustls_pemfile::certs(&mut tls_cert.to_vec().as_ref()).collect::<Result<Vec<_>, _>>()?;

    // Check the entire PEM file for the key in case it is not first section
    let key = rustls_pemfile::read_all(&mut tls_key.to_vec().as_ref())
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|i| match i {
            Item::Sec1Key(key) => Some(key.secret_sec1_der().to_vec()),
            Item::Pkcs1Key(key) => Some(key.secret_pkcs1_der().to_vec()),
            Item::Pkcs8Key(key) => Some(key.secret_pkcs8_der().to_vec()),
            _ => None,
        })
        .map(|data| PrivateKeyDer::try_from(data).map_err(|s| eyre::eyre!("{s}")))
        .next()
        .ok_or(eyre::eyre!("No keys in key file"))??;

    let mut server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
    // This is what axum is normally doing for you
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(server_config)
}
