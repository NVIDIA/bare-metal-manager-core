/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

mod cache;
mod command_line;
mod errors;
mod grpc_server;
mod modes;
mod packet_handler;
mod rpc;
mod util;
mod vendor_class;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use ::rpc::forge::{DhcpDiscovery, DhcpRecord};
use cache::CacheEntry;
use carbide_rpc_utils::dhcp::{DhcpConfig, DhcpTimestamps, DhcpTimestampsFilePath, HostConfig};
use chrono::Utc;
use command_line::{Args, ServerMode};
use errors::DhcpError;
use grpc_server::{ControlRequest, run_grpc_server};
use lru::LruCache;
use modes::DhcpMode;
use modes::controller::Controller;
use modes::dpu::{Dpu, get_host_config};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tonic::async_trait;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::util::get_socket;

pub struct Server {
    socket: Arc<UdpSocket>,
}

const MAX_PARALLEL_PACKET_HANDLING_ALLOWED: usize = 128;

/// Run one generation of the DHCP server (all interfaces) until `cancel_token` is cancelled.
///
/// Each interface gets its own tokio task.  Inside every task the packet-receive
/// loop uses `tokio::select!` to watch both the UDP socket and the cancellation
/// token, so shutdown is prompt once `cancel_token.cancel()` is called from main.
async fn run_dhcp_server(args: Args, cancel_token: CancellationToken) {
    let config__ = match init(args.clone()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to initialise DHCP server config: {}", e);
            return;
        }
    };

    let dhcp_timestamps = Arc::new(Mutex::new({
        let d = DhcpTimestamps::new(if let ServerMode::Dpu = args.mode {
            DhcpTimestampsFilePath::HbnTmp
        } else {
            DhcpTimestampsFilePath::NotSet
        });

        // It looks like we can only expect the file to be present
        // if something has successfully DHCP'ed, after write() has been
        // called at least once.  That means there's a possible window of time
        // where the file might be _expected_ to not exist, but read() will complain
        // and pollute the logs. We could have read() skip NotFound errors, but that
        // could be misleading in other scenarios.  Let's just "init" the file.
        if let Err(e) = d.write() {
            tracing::error!("Failed to init DHCP timestamps file: {}", e);
            return;
        }
        d
    }));

    // Rate limiter limits the packet processing from all interfaces.
    let rate_limiter_ = Arc::new(tokio::sync::Semaphore::new(
        MAX_PARALLEL_PACKET_HANDLING_ALLOWED,
    ));

    let mut join_handles = vec![];

    // Create a new socket for each interface.
    // In case of Controller, there will be only 1 interface.
    for interface in args.interfaces {
        let config_ = config__.clone();
        let args_mode = args.mode.clone();
        let dhcp_timestamps_ = dhcp_timestamps.clone();
        let rate_limiter = rate_limiter_.clone();
        let cancel = cancel_token.clone();

        let handle = tokio::spawn(async move {
            let handler: Arc<Box<dyn DhcpMode>> = Arc::new(get_mode(&args_mode));
            let listen_address = SocketAddr::new(std::net::IpAddr::from([0, 0, 0, 0]), 67);

            let socket = get_socket(listen_address, interface.clone()).await;
            tracing::info!(
                "Listening on {:?} on interface: {}, mode: {:?}",
                listen_address,
                interface,
                handler
            );

            let mut server = Server {
                socket: Arc::new(socket),
            };

            // Machine cache is used only in Controller mode and Controller listens only on one
            // interface, so it is ok to initialize cache here.
            let machine_cache_ = Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
            )));

            // Listen on each interface and process it.
            // The select! monitors both the UDP socket and the cancellation token so that
            // the loop exits promptly when a config reload is triggered from the gRPC server.
            loop {
                let mut buf = [0; 1500];
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!(
                            "DHCP server on interface {} received cancellation, shutting down",
                            interface
                        );
                        break;
                    }
                    result = server.socket.recv_from(&mut buf) => {
                        let (len, addr) = match result {
                            Ok((len, addr)) => (len, addr),
                            Err(err) => {
                                // We don't know after this read is failed, will we be able to read again
                                // from this socket? Mostly no. In this case, recreate the socket.
                                // We observed this fluctuation during admin to tenant network switch.
                                tracing::error!("Socket recv failed with error: {err}");
                                // Try to close the existing socket.
                                drop(server.socket);
                                tracing::info!("Recreating the socket on {listen_address}, {interface}");
                                server.socket =
                                    Arc::new(get_socket(listen_address, interface.clone()).await);
                                continue;
                            }
                        };

                        // We never close this semaphore, so if an error is returned it should be
                        // TryAcquireError::NoPermits; Not checking explicitly.
                        let Ok(permit) = rate_limiter.clone().try_acquire_owned() else {
                            // drop packet.
                            tracing::error!("Dropping packet because of rate limiting.");
                            continue;
                        };

                        // Not a valid packet.
                        if len < MINIMUM_DHCP_PKT_SIZE {
                            tracing::error!("Dropping packet because it is smaller than min length.");
                            continue;
                        }

                        let config = config_.clone();
                        let mut machine_cache = machine_cache_.clone();
                        let iface = interface.clone();
                        let handler_ = handler.clone();
                        let dhcp_timestamps = dhcp_timestamps_.clone();
                        let socket = server.socket.clone();

                        tokio::spawn(async move {
                            process(
                                addr,
                                socket,
                                &buf,
                                config.clone(),
                                &**handler_,
                                &iface,
                                &mut machine_cache,
                                dhcp_timestamps,
                            )
                            .await;
                            drop(permit);
                        });
                    }
                }
            }
        });

        join_handles.push(handle);
    }

    // Wait for all interface tasks to finish (they all exit on cancellation).
    futures::future::join_all(join_handles).await;
}

/// Initialises the tracing subscriber with per-crate log-level overrides.
fn setup_tracing() -> Result<(), Box<dyn Error>> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("tokio_util::codec=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap())
        .add_directive("hickory_resolver::error=info".parse().unwrap())
        .add_directive("hickory_proto::xfer=info".parse().unwrap())
        .add_directive("hickory_resolver::name_server=info".parse().unwrap())
        .add_directive("hickory_proto=info".parse().unwrap());

    tracing_subscriber::registry()
        .with(logfmt::layer().with_filter(env_filter))
        .try_init()?;
    Ok(())
}

/// Stages updated DHCP config YAML for an immediate reload.
///
/// Reads the current live config files and writes `_new` versions only when
/// the content actually differs, so the subsequent reload can detect whether
/// a restart is needed.
async fn handle_update_config(
    args: &Args,
    dhcp_yaml: String,
    host_yaml: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let new_dhcp = format!("{}_new", args.dhcp_config);
    let current_dhcp = tokio::fs::read_to_string(&args.dhcp_config)
        .await
        .unwrap_or_default();
    if current_dhcp != dhcp_yaml {
        tokio::fs::write(&new_dhcp, &dhcp_yaml)
            .await
            .map_err(|e| -> Box<dyn Error> { format!("write {new_dhcp}: {e}").into() })?;
        tracing::info!("dhcp_config changed – staged at {new_dhcp}");
    }

    if let (Some(yaml), Some(path)) = (host_yaml, &args.host_config) {
        let new_host = format!("{}_new", path);
        let current_host = tokio::fs::read_to_string(path).await.unwrap_or_default();
        if current_host != yaml {
            tokio::fs::write(&new_host, &yaml)
                .await
                .map_err(|e| -> Box<dyn Error> { format!("write {new_host}: {e}").into() })?;
            tracing::info!("host_config changed – staged at {new_host}");
        }
    }
    Ok(())
}

/// Promotes staged config files and (re)starts the DHCP server.
///
/// If no `_new` files exist and `force_start` is false the restart is skipped.
/// When `force_start` is true (e.g. after an explicit `StopServer`) the server
/// is started even if the config on disk has not changed.  Otherwise any running
/// server generation is cancelled, the `_new` files are renamed to their live
/// paths, and a fresh server generation is spawned.
async fn handle_reload(
    args: &Args,
    cancel_token: Option<CancellationToken>,
    dhcp_handle: Option<tokio::task::JoinHandle<()>>,
    force_start: bool,
) -> Result<
    (
        Option<CancellationToken>,
        Option<tokio::task::JoinHandle<()>>,
    ),
    Box<dyn Error>,
> {
    if args.interfaces.is_empty() {
        tracing::warn!("ReloadConfig: no interfaces configured yet, skipping start");
        return Ok((cancel_token, dhcp_handle));
    }

    let new_dhcp = format!("{}_new", args.dhcp_config);
    let has_new_dhcp = tokio::fs::try_exists(&new_dhcp).await.unwrap_or(false);
    let has_new_host = if let Some(host_path) = &args.host_config {
        tokio::fs::try_exists(format!("{}_new", host_path))
            .await
            .unwrap_or(false)
    } else {
        false
    };

    if !has_new_dhcp && !has_new_host && !force_start {
        tracing::debug!("ReloadConfig: no staged changes, skipping restart");
        return Ok((cancel_token, dhcp_handle));
    }

    // Stop any running server generation.
    if let (Some(ct), Some(h)) = (cancel_token, dhcp_handle) {
        tracing::info!("Stopping current DHCP server");
        ct.cancel();
        let _ = h.await;
        tracing::info!("DHCP server stopped");
    }

    // Atomically replace live config files.
    if has_new_dhcp {
        tokio::fs::rename(&new_dhcp, &args.dhcp_config)
            .await
            .map_err(|e| -> Box<dyn Error> {
                format!("rename {} -> {}: {e}", new_dhcp, args.dhcp_config).into()
            })?;
    }
    if let Some(host_path) = &args.host_config {
        let new_host = format!("{}_new", host_path);
        let exists = tokio::fs::try_exists(&new_host)
            .await
            .map_err(|e| -> Box<dyn Error> { format!("try_exists {new_host}: {e}").into() })?;
        if exists {
            tokio::fs::rename(&new_host, host_path)
                .await
                .map_err(|e| -> Box<dyn Error> {
                    format!("rename {new_host} -> {host_path}: {e}").into()
                })?;
        }
    }

    // Start new server generation.
    let ct = CancellationToken::new();
    let handle = tokio::spawn(run_dhcp_server(args.clone(), ct.clone()));
    tracing::info!("DHCP server (re)started with updated config");
    Ok((Some(ct), Some(handle)))
}

/// Runs the DHCP server under gRPC control.
///
/// Spawns the gRPC server as a background task, then enters the main control
/// loop.  The DHCP server is started immediately when the config file already
/// exists on disk; otherwise the first `ReloadConfig` call triggers the
/// initial start, avoiding a startup crash on a fresh node.
async fn run_with_grpc_control(
    mut args: Args,
    grpc_listen_addr: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    // Apply default for host_config path when running in gRPC mode.
    args.host_config
        .get_or_insert_with(|| "/var/support/forge-dhcp/conf/host.yaml".to_string());

    // Ensure the config directory exists so that the first gRPC UpdateConfig call
    // can write files immediately without the directory being absent.
    if let Some(dir) = std::path::Path::new(&args.dhcp_config).parent()
        && !tokio::fs::try_exists(dir).await.unwrap_or(false)
    {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| -> Box<dyn Error> {
                format!("create_dir_all {}: {e}", dir.display()).into()
            })?;
        tracing::info!("Created config directory {}", dir.display());
    }

    // Channel through which the gRPC handlers deliver control requests.
    // Capacity 4: allows a few queued UpdateConfig calls without blocking the gRPC caller.
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<ControlRequest>(4);

    tokio::spawn(async move {
        run_grpc_server(grpc_listen_addr, ctrl_tx).await;
    });

    // Both `cancel_token` and `dhcp_handle` are Option so the select! arm
    // that watches the handle pends forever while the server is not yet running.
    let mut cancel_token: Option<CancellationToken> = None;
    let mut dhcp_handle: Option<tokio::task::JoinHandle<()>> = None;

    if tokio::fs::try_exists(&args.dhcp_config)
        .await
        .unwrap_or(false)
        && !args.interfaces.is_empty()
    {
        tracing::info!("Config file and interfaces found at startup – starting DHCP server");
        let ct = CancellationToken::new();
        dhcp_handle = Some(tokio::spawn(run_dhcp_server(args.clone(), ct.clone())));
        cancel_token = Some(ct);
    } else {
        tracing::info!(
            "Config file or interfaces not ready at startup – \
             DHCP server will start after first ReloadConfig"
        );
    }

    loop {
        tokio::select! {
            // This arm pends forever while dhcp_handle is None, waiting for
            // gRPC messages until the first reload.
            result = async {
                match dhcp_handle.as_mut() {
                    Some(h) => h.await,
                    None => std::future::pending().await,
                }
            } => {
                tracing::error!("DHCP server exited unexpectedly: {:?}", result);
                return Ok(());
            }

            msg = ctrl_rx.recv() => {
                let Some(msg) = msg else {
                    tracing::error!("Control channel closed unexpectedly; terminating");
                    if let (Some(ct), Some(h)) = (cancel_token.take(), dhcp_handle.take()) {
                        ct.cancel();
                        let _ = h.await;
                    }
                    return Ok(());
                };

                match msg {
                    ControlRequest::UpdateAndReload { dhcp_yaml, host_yaml, interfaces } => {
                        args.interfaces = interfaces;
                        handle_update_config(&args, dhcp_yaml, host_yaml).await?;
                        // Force a start when the server is not currently running
                        // (stopped explicitly or never started) so that the server
                        // is (re)started even if the config on disk is unchanged.
                        let force = dhcp_handle.is_none();
                        let (ct, h) =
                            handle_reload(&args, cancel_token, dhcp_handle, force).await?;
                        cancel_token = ct;
                        dhcp_handle = h;
                    }
                    ControlRequest::Stop => {
                        if let (Some(ct), Some(h)) = (cancel_token.take(), dhcp_handle.take()) {
                            tracing::info!("StopServer: stopping DHCP server");
                            ct.cancel();
                            let _ = h.await;
                            tracing::info!("StopServer: DHCP server stopped; gRPC server remains up");
                        } else {
                            tracing::info!("StopServer: DHCP server was not running");
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    setup_tracing()?;

    let args = Args::load();

    // In gRPC mode the interfaces may be provided later via UpdateConfig, so
    // only validate the count when interfaces are already known at startup.
    if let ServerMode::Controller = args.mode
        && !args.interfaces.is_empty()
        && args.interfaces.len() != 1
    {
        return Err(
            DhcpError::MultipleInterfacesProvidedOneSupported(args.interfaces.len()).into(),
        );
    }

    if let Some(ref addr_str) = args.grpc_listen_addr {
        let grpc_listen_addr: SocketAddr = addr_str
            .parse()
            .map_err(|e| format!("Invalid --grpc-listen-addr '{}': {}", addr_str, e))?;
        run_with_grpc_control(args, grpc_listen_addr).await?;
    } else {
        // No gRPC server: run the DHCP server directly.  The CancellationToken
        // is wired up inside run_dhcp_server but is never triggered, so
        // behaviour is identical to the original server.
        run_dhcp_server(args, CancellationToken::new()).await;
    }

    Ok(())
}

fn get_mode(args_mode: &ServerMode) -> Box<dyn DhcpMode> {
    match args_mode {
        ServerMode::Dpu => Box::new(Dpu {}),
        ServerMode::Controller => Box::new(Controller {}),
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    dhcp_config: DhcpConfig,
    host_config: Option<HostConfig>, // Valid only for Dpu mode.
}

async fn init(args: Args) -> Result<Config, DhcpError> {
    let f = tokio::fs::read_to_string(args.dhcp_config).await?;
    let dhcp_config: DhcpConfig = serde_yaml::from_str(&f)?;

    let host_config;
    if let ServerMode::Dpu = args.mode {
        host_config = get_host_config(args.host_config).await?;
    } else {
        host_config = None;
    };

    Ok(Config {
        dhcp_config,
        host_config,
    })
}

#[derive(Debug)]
pub struct TestArm {}

#[async_trait]
impl DhcpMode for TestArm {
    async fn discover_dhcp(
        &self,
        _discovery_request: DhcpDiscovery,
        _config: &Config,
        _machine_cache: &mut Arc<Mutex<LruCache<String, CacheEntry>>>,
    ) -> Result<DhcpRecord, DhcpError> {
        Test::dhcp_record()
    }

    // Packets received from DPU to API must be relayed.
    fn should_be_relayed(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct Test {}

impl Test {
    pub fn dhcp_record() -> Result<DhcpRecord, DhcpError> {
        Ok(DhcpRecord {
            machine_id: Some(
                "fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0"
                    .parse()
                    .unwrap(),
            ),
            machine_interface_id: Some("0fd6e9a3-06fc-4a22-ad29-aca299677b00".parse().unwrap()),
            segment_id: Some("55a2d74e-f9e1-49d5-bf99-be05171a5d75".parse().unwrap()),
            subdomain_id: Some("56a2d74e-f9e1-49d5-bf99-be05171a5d75".parse().unwrap()),
            fqdn: "seventeen-connecticut.dev3.frg.nvidia.com".to_string(),
            mac_address: "b8:3f:d2:90:9a:12".to_string(),
            address: "10.217.132.204".to_string(),
            mtu: 6000,
            prefix: "10.217.132.192/26".to_string(),
            gateway: Some("10.217.132.193".to_string()),
            booturl: None,
            last_invalidation_time: None,
        })
    }
}

#[async_trait]
impl DhcpMode for Test {
    async fn discover_dhcp(
        &self,
        _discovery_request: DhcpDiscovery,
        _config: &Config,
        _machine_cache: &mut Arc<Mutex<LruCache<String, CacheEntry>>>,
    ) -> Result<DhcpRecord, DhcpError> {
        Test::dhcp_record()
    }

    fn should_be_relayed(&self) -> bool {
        false
    }
}

const MINIMUM_DHCP_PKT_SIZE: usize = 236;

#[tracing::instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
async fn process(
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
    buf: &[u8],
    config: Config,
    handler: &dyn DhcpMode,
    circuit_id: &str, // interface name
    machine_cache: &mut Arc<Mutex<LruCache<String, CacheEntry>>>,
    dhcp_timestamps: Arc<Mutex<DhcpTimestamps>>,
) {
    if !addr.is_ipv4() {
        tracing::error!("Dropping ivp6 packet.");
        return;
    }

    tracing::info!("Received packet [{}] from {}", buf[0], addr);

    let packet = match packet_handler::process_packet(
        buf,
        &config,
        circuit_id,
        handler,
        machine_cache,
    )
    .await
    {
        Ok(packet) => packet,
        Err(err) => {
            tracing::error!("Dropping packet because of error: {}", err);
            return;
        }
    };

    let dest_address = handler.get_destination_address(&packet);
    match packet.send(dest_address, socket).await {
        Ok(_) => {}
        Err(err) => {
            tracing::error!("Packet sending failed because of error: {}", err);
        }
    }

    // Tell forge-dpu-agent that an IP has been requested for this interface.
    if let Some(host_config) = config.host_config {
        let mut dhcp_timestamps = dhcp_timestamps.lock().await;
        dhcp_timestamps.add_timestamp(host_config.host_interface_id, Utc::now().to_rfc3339());
        if let Err(e) = dhcp_timestamps.write() {
            tracing::error!(
                "Failed writing to {}: {e}",
                DhcpTimestampsFilePath::HbnTmp.path_str()
            );
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::Arc;

    use carbide_rpc_utils::dhcp::{DhcpTimestamps, DhcpTimestampsFilePath};
    use chrono::{DateTime, Utc};
    use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
    use dhcproto::{Decodable, Decoder, Encodable};
    use lru::LruCache;
    use tempfile::TempDir;
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;

    use crate::command_line::{Args, ServerMode};
    use crate::errors::DhcpError;
    use crate::{DhcpMode, Test, TestArm, cache, handle_reload, init, packet_handler, process};

    fn make_reload_args(td: &TempDir, interfaces: Vec<String>) -> Args {
        Args {
            interfaces,
            dhcp_config: td.path().join("dhcp.yaml").display().to_string(),
            host_config: Some(td.path().join("host.yaml").display().to_string()),
            mode: ServerMode::Dpu,
            grpc_listen_addr: None,
        }
    }

    /// Reload with no staged `_new` files must not start the server.
    #[tokio::test]
    async fn reload_skips_when_nothing_staged() {
        let td = TempDir::new().unwrap();
        let args = make_reload_args(&td, vec!["eth0".to_string()]);

        let (cancel_token, dhcp_handle) = handle_reload(&args, None, None, false).await.unwrap();

        assert!(cancel_token.is_none(), "no server should have been started");
        assert!(dhcp_handle.is_none(), "no server should have been started");
    }

    /// Reload with an empty interface list must return early without starting the server.
    #[tokio::test]
    async fn reload_skips_when_interfaces_empty() {
        let td = TempDir::new().unwrap();
        let args = make_reload_args(&td, vec![]);

        // Stage a `_new` file so that the only reason to skip is empty interfaces.
        let new_dhcp = format!("{}_new", args.dhcp_config);
        tokio::fs::write(&new_dhcp, "staged").await.unwrap();

        let (cancel_token, dhcp_handle) = handle_reload(&args, None, None, false).await.unwrap();

        assert!(cancel_token.is_none(), "no server should have been started");
        assert!(dhcp_handle.is_none(), "no server should have been started");
    }

    /// force_start=true must start the server even when no `_new` files are staged.
    #[tokio::test]
    async fn reload_force_start_with_no_staged_files() {
        let td = TempDir::new().unwrap();
        let args = make_reload_args(&td, vec!["eth0".to_string()]);

        // Write a live config so run_dhcp_server can initialise (it will fail to
        // bind a real socket in CI, but the important thing is that a JoinHandle
        // is returned, proving the server was attempted).
        tokio::fs::write(&args.dhcp_config, "# placeholder")
            .await
            .unwrap();

        let (cancel_token, dhcp_handle) = handle_reload(&args, None, None, true).await.unwrap();

        assert!(
            cancel_token.is_some(),
            "server should have been started with force_start"
        );
        assert!(
            dhcp_handle.is_some(),
            "server should have been started with force_start"
        );

        // Clean up the spawned task.
        if let (Some(ct), Some(h)) = (cancel_token, dhcp_handle) {
            ct.cancel();
            let _ = h.await;
        }
    }

    /// force_start=false must still skip when no `_new` files are staged,
    /// even when a live config exists on disk.
    #[tokio::test]
    async fn reload_no_force_start_with_no_staged_files() {
        let td = TempDir::new().unwrap();
        let args = make_reload_args(&td, vec!["eth0".to_string()]);
        tokio::fs::write(&args.dhcp_config, "# placeholder")
            .await
            .unwrap();

        let (cancel_token, dhcp_handle) = handle_reload(&args, None, None, false).await.unwrap();

        assert!(
            cancel_token.is_none(),
            "server must not start without staged files"
        );
        assert!(
            dhcp_handle.is_none(),
            "server must not start without staged files"
        );
    }

    /// Sending Stop over the control channel must cancel the running server and
    /// leave dhcp_handle as None, while the subsequent UpdateAndReload (with the
    /// server down) must force-start it again.
    #[tokio::test]
    async fn stop_then_update_restarts_server() {
        let td = TempDir::new().unwrap();
        let mut args = make_reload_args(&td, vec!["eth0".to_string()]);

        // Provide a live config so handle_reload can start a server task.
        let dhcp_yaml = "# placeholder dhcp";
        tokio::fs::write(&args.dhcp_config, dhcp_yaml)
            .await
            .unwrap();

        // Simulate a running server.
        let ct = CancellationToken::new();
        let ct_clone = ct.clone();
        let mut dhcp_handle: Option<tokio::task::JoinHandle<()>> =
            Some(tokio::spawn(async move { ct_clone.cancelled().await }));
        let mut cancel_token: Option<CancellationToken> = Some(ct);

        // --- StopServer ---
        if let (Some(ct), Some(h)) = (cancel_token.take(), dhcp_handle.take()) {
            ct.cancel();
            let _ = h.await;
        }
        assert!(
            cancel_token.is_none(),
            "cancel_token must be None after stop"
        );
        assert!(dhcp_handle.is_none(), "dhcp_handle must be None after stop");

        // --- UpdateAndReload with server down (force=true) ---
        // Stage a _new` config so handle_update_config has something to write,
        // then call handle_reload with force=true (the path taken when dhcp_handle is None).
        let new_dhcp_yaml = "# updated dhcp";
        tokio::fs::write(format!("{}_new", args.dhcp_config), new_dhcp_yaml)
            .await
            .unwrap();
        args.interfaces = vec!["eth0".to_string()];

        let force = dhcp_handle.is_none(); // true — server is down
        let (ct, h) = handle_reload(&args, cancel_token, dhcp_handle, force)
            .await
            .unwrap();

        assert!(ct.is_some(), "server should have been restarted");
        assert!(h.is_some(), "server should have been restarted");

        if let (Some(ct), Some(h)) = (ct, h) {
            ct.cancel();
            let _ = h.await;
        }
    }

    /// Stop when no server is running must be a no-op (no panic, handle stays None).
    #[tokio::test]
    async fn stop_when_server_not_running_is_noop() {
        let mut cancel_token: Option<CancellationToken> = None;
        let mut dhcp_handle: Option<tokio::task::JoinHandle<()>> = None;

        // Mirrors the Stop arm in run_with_grpc_control.
        if let (Some(ct), Some(h)) = (cancel_token.take(), dhcp_handle.take()) {
            ct.cancel();
            let _ = h.await;
        }

        assert!(cancel_token.is_none());
        assert!(dhcp_handle.is_none());
    }

    fn get_test_args() -> Args {
        let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        Args {
            interfaces: vec!["eth0".to_string()],
            dhcp_config: base_path.join("conf/conf.yaml").display().to_string(),
            host_config: Some(
                base_path
                    .join("test/host_config.yaml")
                    .display()
                    .to_string(),
            ),
            mode: crate::command_line::ServerMode::Dpu,
            grpc_listen_addr: None,
        }
    }

    #[tokio::test]
    async fn test_init() {
        init(get_test_args()).await.unwrap();
    }

    #[tokio::test]
    async fn test_arm_non_relayed_packet() {
        let byte_stream = get_byte_stream(Ipv4Addr::new(0, 0, 0, 0), None, MessageType::Request);
        let handler: Box<dyn DhcpMode> = Box::new(TestArm {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));
        assert!(matches!(
            packet_handler::process_packet(
                &byte_stream,
                &config,
                "vlan200",
                &*handler,
                &mut machine_cache,
            )
            .await,
            Err(DhcpError::NonRelayedPacket(..))
        ));
    }

    #[tokio::test]
    async fn test_arm_relayed_packet() {
        let byte_stream = get_byte_stream(
            Ipv4Addr::new(0, 0, 0, 0),
            Some(Ipv4Addr::from_str("10.217.5.41").unwrap()),
            MessageType::Request,
        );
        let handler: Box<dyn DhcpMode> = Box::new(TestArm {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));
        assert!(
            packet_handler::process_packet(
                &byte_stream,
                &config,
                "vlan200",
                &*handler,
                &mut machine_cache,
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn test_complete_flow() {
        let byte_stream = get_byte_stream(
            Ipv4Addr::new(0, 0, 0, 0),
            Some(Ipv4Addr::from_str("10.217.5.41").unwrap()),
            MessageType::Request,
        );
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));
        let packet = packet_handler::process_packet(
            &byte_stream,
            &config,
            "vlan200",
            &*handler,
            &mut machine_cache,
        )
        .await
        .unwrap();

        assert_eq!(
            packet.dst_address(),
            SocketAddrV4::new(Ipv4Addr::from([0x0a, 0xd9, 0x05, 0x29]), 67)
        );
        let packet = Message::decode(&mut dhcproto::Decoder::new(packet.encoded_packet())).unwrap();

        assert_eq!(packet.yiaddr(), Ipv4Addr::from([10, 217, 132, 204]));
    }

    #[tokio::test]
    async fn test_complete_flow_with_valid_ciaddr() {
        let byte_stream = get_byte_stream(
            Ipv4Addr::new(10, 217, 132, 204),
            Some(Ipv4Addr::from_str("10.217.5.41").unwrap()),
            MessageType::Request,
        );
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));
        let packet = packet_handler::process_packet(
            &byte_stream,
            &config,
            "vlan200",
            &*handler,
            &mut machine_cache,
        )
        .await
        .unwrap();

        assert_eq!(
            packet.dst_address(),
            SocketAddrV4::new(Ipv4Addr::from([10, 217, 5, 41]), 67)
        );

        let packet = Message::decode(&mut dhcproto::Decoder::new(packet.encoded_packet())).unwrap();

        assert_eq!(packet.yiaddr(), Ipv4Addr::from([10, 217, 132, 204]));
    }

    #[tokio::test]
    async fn test_send_metadata_to_agent() {
        let byte_stream = get_byte_stream(Ipv4Addr::new(0, 0, 0, 0), None, MessageType::Discover);
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));

        // Remove any timestamps file left behind from a previous run.
        if std::fs::exists(DhcpTimestampsFilePath::Test.path_str()).unwrap() {
            std::fs::remove_file(DhcpTimestampsFilePath::Test.path_str()).unwrap();
        }

        // Try a read() to show that it will fail if the timestamps file
        // hasn't been initialized.
        let _ = DhcpTimestamps::new(DhcpTimestampsFilePath::Test)
            .read()
            .unwrap_err();

        let before_dhcp = Utc::now();
        let udp_socket_addr: SocketAddrV4 = "127.0.0.1:1236".parse().unwrap();
        let dhcp_timestamps = Arc::new(Mutex::new({
            let d = DhcpTimestamps::new(DhcpTimestampsFilePath::Test);
            // Init the file like we would do during live operation.
            d.write().unwrap();
            d
        }));

        // Try a read() to show that the "init" of the timestamps file was
        // successful.
        DhcpTimestamps::new(DhcpTimestampsFilePath::Test)
            .read()
            .unwrap();

        process(
            "1.2.3.4:0".parse().unwrap(),
            Arc::new(UdpSocket::bind(udp_socket_addr).await.unwrap()),
            &byte_stream,
            config.clone(),
            &*handler,
            "vlan100",
            &mut machine_cache,
            dhcp_timestamps.clone(),
        )
        .await;

        let dhcp_timestamps = dhcp_timestamps.lock().await;

        let timestamp = dhcp_timestamps
            .get_timestamp(&config.host_config.as_ref().unwrap().host_interface_id)
            .unwrap();

        let dhcp_time: DateTime<Utc> = timestamp.parse().unwrap();
        assert!(before_dhcp < dhcp_time);

        let mut dhcp_timestamps_new = DhcpTimestamps::new(DhcpTimestampsFilePath::Test);
        dhcp_timestamps_new.read().unwrap();
        let file_timestamp: DateTime<Utc> = dhcp_timestamps_new
            .get_timestamp(&config.host_config.unwrap().host_interface_id)
            .unwrap()
            .parse()
            .unwrap();

        assert!(before_dhcp < file_timestamp)
    }

    #[tokio::test]
    async fn validate_test_host_config() {
        let config = init(get_test_args()).await.unwrap();

        let host_config = config.host_config.unwrap();
        assert_eq!(host_config.host_ip_addresses.len(), 2);
        assert!(host_config.host_ip_addresses["vlan200"].booturl.is_none());
    }

    fn get_byte_stream(
        ciaddr: Ipv4Addr,
        giaddr: Option<Ipv4Addr>,
        message_type: MessageType,
    ) -> Vec<u8> {
        let mut msg = Message::new(
            ciaddr,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 0),
            &[00, 0x1b, 0x63, 0x84, 0x45, 0xe6],
        );

        if let Some(giaddr) = giaddr {
            msg.set_giaddr(giaddr);
        }

        msg.opts_mut().insert(DhcpOption::MessageType(message_type));

        let mut encoded_packet = Vec::new();
        let mut e = dhcproto::Encoder::new(&mut encoded_packet);
        msg.encode(&mut e).unwrap();
        encoded_packet
    }

    #[tokio::test]
    async fn validate_basic_ack() {
        let packet = get_byte_stream(Ipv4Addr::new(0, 0, 0, 0), None, MessageType::Request);

        let config = init(get_test_args()).await.unwrap();
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));

        let encoded_packet = packet_handler::process_packet(
            &packet,
            &config,
            "vlan200",
            &*handler,
            &mut machine_cache,
        )
        .await
        .unwrap();

        let packet = Message::decode(&mut Decoder::new(encoded_packet.encoded_packet())).unwrap();
        assert_eq!(
            packet.opts().get(OptionCode::MessageType).unwrap().clone(),
            DhcpOption::MessageType(MessageType::Ack)
        );
    }

    #[tokio::test]
    async fn validate_nak() {
        let packet = get_byte_stream(Ipv4Addr::new(10, 0, 0, 1), None, MessageType::Request);

        let config = init(get_test_args()).await.unwrap();
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));

        let encoded_packet = packet_handler::process_packet(
            &packet,
            &config,
            "vlan200",
            &*handler,
            &mut machine_cache,
        )
        .await
        .unwrap();

        let packet = Message::decode(&mut Decoder::new(encoded_packet.encoded_packet())).unwrap();
        assert_eq!(
            packet.opts().get(OptionCode::MessageType).unwrap().clone(),
            DhcpOption::MessageType(MessageType::Nak)
        );
    }
}
