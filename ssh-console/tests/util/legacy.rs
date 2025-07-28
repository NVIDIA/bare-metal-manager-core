/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::util::fixtures::{
    API_CA_CERT, API_CLIENT_CERT, API_CLIENT_KEY, AUTHORIZED_KEYS_PATH, SSH_HOST_KEY,
};
use crate::util::{BaselineTestEnvironment, MockBmcHandle, log_stdout_and_stderr};
use api_test_helper::utils::REPO_ROOT;
use eyre::Context;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use lazy_static::lazy_static;
use ssh_console::ShutdownHandle;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime};
use std::{
    fs,
    io::{BufWriter, Write},
};
use temp_dir::TempDir;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinHandle;

lazy_static! {
    pub static ref LEGACY_SSH_CONSOLE_DIR: PathBuf =
        REPO_ROOT.join("ssh-console/legacy/ssh-console");
    pub static ref LEGACY_SSH_CONSOLE_METRICS_PATH: PathBuf = "/tmp/ssh_console/metrics".into();
}

pub struct LegacySshConsoleHandle {
    pub addr: SocketAddr,
    pub metrics_address: SocketAddr,
    _process: tokio::process::Child,
    _metrics_handle: LegacyMetricsHandle,
}

pub async fn run(
    env: &BaselineTestEnvironment,
    temp: &TempDir,
) -> eyre::Result<LegacySshConsoleHandle> {
    setup()
        .await
        .context("Error setting up legacy ssh-console")?;

    let addr = {
        // Pick an open port
        let l = TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?
            .to_socket_addrs()?
            .next()
            .expect("No socket available")
    };

    // Make sure the metrics path is created
    tokio::fs::create_dir_all(LEGACY_SSH_CONSOLE_METRICS_PATH.parent().unwrap()).await?;

    let bin = LEGACY_SSH_CONSOLE_DIR.join("ssh_console");

    tracing::info!("Launching legacy ssh-console at {}", bin.to_string_lossy());

    let known_hosts_path = temp.path().join("known_hosts");
    {
        let known_hosts_file = std::fs::File::create(&known_hosts_path)?;
        let mut writer = BufWriter::new(known_hosts_file);

        for mock_bmc_handle in &env.mock_bmc_handles {
            if let MockBmcHandle::Ssh(mock_ssh_server) = &mock_bmc_handle {
                writeln!(
                    writer,
                    "127.0.0.1:{} ssh-ed25519 {}",
                    mock_ssh_server.port, mock_ssh_server.host_pubkey
                )?;
            }
        }
    }

    assert_eq!(
        env.mock_bmc_handles.len(),
        1,
        "legacy tests only work against a single mock server"
    );
    let bmc_ssh_or_ipmi_port = env.mock_bmc_handles[0].port();

    let mut process = tokio::process::Command::new(&bin)
        .current_dir(LEGACY_SSH_CONSOLE_DIR.as_path())
        .arg("-v")
        .arg("-a")
        .arg(AUTHORIZED_KEYS_PATH.to_string_lossy().to_string())
        .arg("--insecure-ipmi-cipher")
        .arg("-p")
        .arg(addr.port().to_string())
        .arg("--bmc-ssh-port")
        .arg(bmc_ssh_or_ipmi_port.to_string())
        .arg("--ipmi-port")
        .arg(bmc_ssh_or_ipmi_port.to_string())
        .arg("-u")
        .arg(format!("localhost:{}", env.mock_api_server.addr.port()))
        .arg("-e")
        .arg(SSH_HOST_KEY.as_path())
        .arg("-k")
        .arg(known_hosts_path.as_os_str())
        .env("FORGE_ROOT_CA_PATH", API_CA_CERT.as_os_str())
        .env("CLIENT_CERT_PATH", API_CLIENT_CERT.as_os_str())
        .env("CLIENT_KEY_PATH", API_CLIENT_KEY.as_os_str())
        .env("SSH_PORT_OVERRIDE", "2222")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    log_stdout_and_stderr(&mut process, "legacy ssh-console");

    let metrics_handle = spawn_legacy_metrics().await?;

    Ok(LegacySshConsoleHandle {
        addr,
        metrics_address: metrics_handle.addr,
        _process: process,
        _metrics_handle: metrics_handle,
    })
}

pub async fn setup() -> eyre::Result<()> {
    if !LEGACY_SSH_CONSOLE_DIR.exists() {
        return Err(eyre::format_err!(
            "Legacy ssh-console source not found in {}. Either clone ssh-console from gitlab-master.nvidia.com/nvmetal/ssh-console, or symlink an existing clone to have working legacy tests.",
            LEGACY_SSH_CONSOLE_DIR.display()
        ));
    }
    if fs::exists(LEGACY_SSH_CONSOLE_DIR.join("ssh_console"))
        .context("Error checking if ssh_console binary exists")?
    {
        tracing::debug!("ssh_console binary already exists, not running setup");
        return Ok(());
    }

    let result = tokio::process::Command::new("make")
        .current_dir(LEGACY_SSH_CONSOLE_DIR.as_path())
        .spawn()
        .context("Error spawning `make` in legacy/ssh-console")?
        .wait()
        .await
        .context("Error running `make` in legacy/ssh-console")?;

    if !result.success() {
        return Err(eyre::eyre!(
            "`make` in legacy/ssh_console did not exit successfully"
        ));
    }
    Ok(())
}

// Legacy ssh-console uses a separate python script to serve metrics from a static file it writes to periodically. Emulate that here.
async fn spawn_legacy_metrics() -> eyre::Result<LegacyMetricsHandle> {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .context("error listening on legacy ssh-console metrics address")?;
    let addr = listener.local_addr()?;
    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    tracing::info!("legacy ssh-console metrics service shutting down");
                    break;
                }

                res = listener.accept() => match res {
                    Ok((stream, addr)) => {
                        tracing::info!("got metrics connection from {addr}");
                        tokio::task::spawn({
                            async move {
                                let io = TokioIo::new(stream);
                                auto::Builder::new(TokioExecutor::new())
                                    .serve_connection(
                                        io,
                                        hyper::service::service_fn(move |req| {
                                            async move {
                                                match (req.method(), req.uri().path()) {
                                                    (&Method::GET, "/metrics") => {
                                                        match tokio::fs::read_to_string(LEGACY_SSH_CONSOLE_METRICS_PATH.as_path()).await {
                                                            Ok(contents) => Response::builder()
                                                                .status(200)
                                                                .header(CONTENT_TYPE, "text/plain")
                                                                .header(CONTENT_LENGTH, contents.len())
                                                                .body(contents),
                                                            Err(e) => Response::builder()
                                                                .status(500)
                                                                .body(format!("Encoding error: {e}")),
                                                        }
                                                    }
                                                    (&Method::GET, "/") => Response::builder().status(200).body("/metrics".into()),
                                                    _ => Response::builder().status(404).body("Invalid URL".into()),
                                                }
                                            }
                                        }),
                                    )
                                    .await
                            }
                        });
                    }
                    Err(error) => {
                        tracing::error!(%error, "error accepting metrics connection");
                    }
                }
            }
        }
    });

    Ok(LegacyMetricsHandle {
        addr,
        shutdown_tx,
        join_handle,
    })
}

pub struct LegacyMetricsHandle {
    pub addr: SocketAddr,
    shutdown_tx: oneshot::Sender<()>,
    join_handle: tokio::task::JoinHandle<()>,
}

impl ShutdownHandle<()> for LegacyMetricsHandle {
    fn into_parts(self) -> (Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

/// legacy ssh-console writes metrics periodically every 60s, and this isn't configurable. So use
/// the mtime of the metrics file to judge when the metrics are "fresh" enough to actually assert on them.
///
/// It makes this test really slow, but legacy tests are opt-in with an env var so this shouldn't slow down CI.
pub async fn wait_for_metrics(duration: Duration) -> eyre::Result<String> {
    fn get_metrics_time() -> eyre::Result<SystemTime> {
        std::fs::metadata(LEGACY_SSH_CONSOLE_METRICS_PATH.as_path())
            .with_context(|| {
                format!(
                    "could not read metrics at {}",
                    LEGACY_SSH_CONSOLE_METRICS_PATH.as_path().display()
                )
            })?
            .modified()
            .context("could not read metrics mtime")
    }

    let metrics_first_mtime = get_metrics_time()?;

    tracing::info!(
        "Waiting {}s for legacy metrics to refresh",
        duration.as_secs()
    );
    let start = Instant::now();
    while get_metrics_time()?.le(&metrics_first_mtime) {
        if start.elapsed() > duration {
            return Err(eyre::format_err!(
                "Metrics were not refreshed within {}s",
                duration.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    tokio::fs::read_to_string(&LEGACY_SSH_CONSOLE_METRICS_PATH.as_path())
        .await
        .with_context(|| {
            format!(
                "Error reading metrics file at {}",
                LEGACY_SSH_CONSOLE_METRICS_PATH.display()
            )
        })
}
