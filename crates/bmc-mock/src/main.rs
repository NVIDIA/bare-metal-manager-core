/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
mod command_line;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use bmc_mock::{ListenerOrAddress, TarGzOption};
use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::prelude::*;

///
/// bmc-mock behaves like a Redfish BMC server
/// Run: 'cargo run'
/// Try it:
///  - start docker-compose things
///  - `cargo make bootstrap-forge-docker`
///  - `grpcurl -d '{"machine_id": {"value": "71363261-a95a-4964-9eb1-8dd98b870746"}}' -insecure
///  127.0.0.1:1079 forge.Forge/CleanupMachineCompleted`
///  where that UUID is a host machine in DB.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut routers_by_ip: HashMap<String, Router> = HashMap::default();

    let env_filter = EnvFilter::from_default_env()
        .add_directive(LevelFilter::DEBUG.into())
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(Layer::default().compact())
        .with(env_filter)
        .init();

    // collection of path to entries map to avoid duplicating entries when multiple machines
    // use the same archive
    let mut tar_router_entries = HashMap::default();

    let args = command_line::parse_args();
    if let Some(ip_routers) = args.ip_router {
        for ip_router in ip_routers {
            info!(
                "Using archive {} for {}",
                ip_router.targz.to_string_lossy(),
                ip_router.ip_address
            );
            let r = bmc_mock::tar_router(
                TarGzOption::Disk(&ip_router.targz),
                Some(&mut tar_router_entries),
            )
            .unwrap();
            routers_by_ip.insert(ip_router.ip_address, r);
        }
    }

    let listen_addr = args.port.map(|p| SocketAddr::from(([0, 0, 0, 0], p)));
    info!("Using cert_path: {:?}", args.cert_path);
    let router = if let Some(tar_path) = args.targz {
        info!("Using archive {} as default", tar_path.to_string_lossy());
        bmc_mock::tar_router(TarGzOption::Disk(&tar_path), Some(&mut tar_router_entries)).unwrap()
    } else {
        info!("Using default BMC mock");
        bmc_mock::default_host_mock()
    };

    routers_by_ip.insert("".to_owned(), router);

    let mut handle = bmc_mock::run_combined_mock(
        Arc::new(RwLock::new(routers_by_ip)),
        args.cert_path,
        listen_addr.map(ListenerOrAddress::Address),
    )?;
    handle.wait().await?;
    Ok(())
}
