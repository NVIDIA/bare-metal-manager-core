/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use carbide_redfish::nv_redfish::NvRedfishClientPool;
use carbide_site_explorer::BmcEndpointExplorer;
use carbide_site_explorer::config::SiteExplorerExploreMode;
use clap::Parser;
use forge_secrets::credentials::{Credentials, TestCredentialManager};
use mac_address::MacAddress;
use tracing_subscriber::fmt;

#[derive(Debug, Parser)]
#[command(
    name = "bmc-explorer-cli",
    about = "Explore BMC endpoints and generate reports."
)]
struct Cli {
    /// Username for BMC authentication
    #[arg(long)]
    username: String,

    /// Password for BMC authentication
    #[arg(long)]
    password: String,

    /// Exploration mode: one of `libredfish`, `nv-redfish`, or `compare-result`
    ///
    /// Defaults to `compare-result`.
    #[arg(long, default_value = "compare-result")]
    mode: String,

    /// Run benchmark instead of printing result; value is number of iterations
    #[arg(long)]
    benchmark: Option<u64>,

    /// IP address of the BMC (e.g. 192.168.0.10)
    ///
    /// First positional argument.
    bmc_ip: String,

    /// Port of the BMC (e.g. 443)
    #[arg(long, default_value_t = 443)]
    bmc_port: u16,

    /// Boot MAC Address (e.g. 02:03:04:05:06:07)
    #[arg(long)]
    boot_mac: Option<MacAddress>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing so logs go to stderr.
    fmt().with_writer(std::io::stderr).init();

    let args = Cli::parse();

    let fallback_credentials = Credentials::UsernamePassword {
        username: args.username,
        password: args.password,
    };

    let rf_pool = libredfish::RedfishClientPool::builder().build()?;
    let proxy_address = Arc::new(ArcSwap::new(None.into()));
    let credential_provider = Arc::new(TestCredentialManager::new(fallback_credentials.clone()));

    let redfish_client_pool = carbide_redfish::libredfish::new_pool(
        credential_provider.clone(),
        rf_pool,
        proxy_address.clone(),
    );
    let mode = match args.mode.as_str() {
        "libredfish" => SiteExplorerExploreMode::LibRedfish,
        "nv-redfish" => SiteExplorerExploreMode::NvRedfish,
        "compare-result" => SiteExplorerExploreMode::CompareResult,
        other => {
            eprintln!(
                "Invalid mode '{other}'. Valid values are: libredfish, nv-redfish, compare-result."
            );
            std::process::exit(1);
        }
    };
    let rotate_switch_nvos_credentials = Default::default();

    let explorer = BmcEndpointExplorer::new(
        redfish_client_pool,
        Arc::new(NvRedfishClientPool::new(proxy_address)),
        carbide_ipmi::test_support(),
        credential_provider.clone(),
        rotate_switch_nvos_credentials,
        mode,
    );

    let ip = args.bmc_ip.parse()?;
    let port = args.bmc_port;
    let bmc_ip_address = SocketAddr::new(ip, port);

    if let Some(iterations) = args.benchmark {
        let start = Instant::now();
        for _ in 0..iterations {
            explorer
                .generate_exploration_report(
                    bmc_ip_address,
                    fallback_credentials.clone(),
                    args.boot_mac,
                    None,
                )
                .await?;
        }
        let elapsed = start.elapsed();
        println!("Benchmark: ran {iterations} iterations in {:.3?}", elapsed);
    } else {
        println!(
            "{}",
            serde_json::to_string(
                &explorer
                    .generate_exploration_report(
                        bmc_ip_address,
                        fallback_credentials.clone(),
                        args.boot_mac,
                        None,
                    )
                    .await?,
            )
            .expect("serialization success")
        );
    }

    Ok(())
}
