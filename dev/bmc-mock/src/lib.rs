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

use std::collections::HashMap;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::future::Future;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::Router;
use axum::ServiceExt;
use axum_server::tls_rustls::RustlsConfig;
use hyper::body::Incoming;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;
use tower::{Layer, Service};
use tower_http::normalize_path::NormalizePathLayer;
use tracing::{debug, error, info};

mod machine_info;
mod mock_machine_router;
mod redfish_expander;
mod tar_router;

pub use machine_info::{DpuMachineInfo, HostMachineInfo, MachineInfo};
pub use mock_machine_router::{wrap_router_with_mock_machine, BmcCommand};
pub use redfish_expander::wrap_router_with_redfish_expander;
pub use tar_router::{tar_router, EntryMap, TarGzOption};

static DEFAULT_HOST_MOCK_TAR: &[u8] = include_bytes!("../dell_poweredge_r750.tar.gz");

#[macro_export]
macro_rules! rf {
    ($url:literal) => {
        &format!("/{}/{}", libredfish::REDFISH_ENDPOINT, $url)
    };
}

#[derive(thiserror::Error, Debug)]
pub enum BmcMockError {
    #[error("BMC Mock I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("BMC Mock Configuration error: {0}")]
    Config(String),
}

#[derive(Debug)]
pub struct BmcMockHandle {
    join_handle: Option<JoinHandle<std::io::Result<()>>>,
    axum_handle: axum_server::Handle,
    pub address: SocketAddr,
}

impl Drop for BmcMockHandle {
    fn drop(&mut self) {
        if let Some(join_handle) = self.join_handle.take() {
            if !join_handle.is_finished() {
                tracing::info!("Stopping BMC Mock at {}", self.address);
                self.axum_handle.shutdown();
                join_handle.abort()
            }
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

/// Mock multiple BMCs while listening on a single IP/port.
///
/// Information on what machine to mock will be passed by carbide via the `x-really-to-mac` HTTP header,
/// which will be used to route the request to the appropriate entry in the `bmc_routers_by_mac_address`
/// table.
pub async fn run_combined_mock<T: AsRef<OsStr>>(
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
                        "Could not determine if CARGO_MANIFEST_DIR exists: {}",
                        error
                    )));
                }
            }
        }
    };

    let cert_file = cert_path.join("tls.crt");
    let key_file = cert_path.join("tls.key");
    info!("Loading {:?} and {:?}", cert_file, key_file);
    let config = RustlsConfig::from_pem_file(cert_file.clone(), key_file)
        .await
        .inspect_err(|e| {
            tracing::error!(
                "Could not get cert from {}: {}",
                cert_file.to_string_lossy(),
                e
            )
        })
        .unwrap();

    let bmc_service = BmcService {
        routers: bmc_routers_by_ip_address,
    };

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
            // Hold the lock on the router until we finish calling the request
            let lock = routers.read().await;

            let Some(router) = lock.get(&forwarded_host).cloned() else {
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

pub fn default_host_tar_router(
    use_qemu: bool,
    tar_router_entries: Option<&mut HashMap<PathBuf, EntryMap>>,
) -> Router {
    let tar_router = tar_router(
        TarGzOption::Memory(DEFAULT_HOST_MOCK_TAR),
        tar_router_entries,
    )
    .unwrap();
    let maybe_command_channel = if use_qemu {
        Some(spawn_qemu_reboot_handler())
    } else {
        None
    };
    wrap_router_with_mock_machine(
        tar_router,
        MachineInfo::Host(HostMachineInfo::new(vec![DpuMachineInfo::new()])),
        maybe_command_channel,
    )
}

fn spawn_qemu_reboot_handler() -> mpsc::UnboundedSender<BmcCommand> {
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                command = command_rx.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    if !matches!(command, BmcCommand::Reboot(_)) {
                        continue;
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
                    error!("Reboot command 'virsh reboot ManagedHost' failed with exit code {exit_code}.");
                    info!("STDOUT: {}", String::from_utf8_lossy(&reboot_output.stdout));
                    info!("STDERR: {}", String::from_utf8_lossy(&reboot_output.stderr));
                }
                None => {
                    error!("Reboot command killed by signal");
                }
            }
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
