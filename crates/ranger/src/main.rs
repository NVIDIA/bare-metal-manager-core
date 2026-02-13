/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::time::Duration;

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// Ranger Agent - Test executor for Carbide
///
/// TBD: Currently relies on Scout agent running alongside for TLS certificate
/// provisioning and secure communication with Carbide API. In the future,
/// Ranger will handle this directly.
#[derive(Parser, Debug)]
#[command(name = "ranger-agent")]
#[command(about = "Carbide Ranger Agent for rack-level validation testing")]
struct Args {
    /// Carbide API server URI
    #[arg(long, env = "RANGER_API_URI", default_value = "https://localhost:8443")]
    api: String,

    /// Machine interface ID
    #[arg(long, env = "RANGER_MACHINE_ID")]
    machine_interface_id: Option<String>,

    /// Print version and exit
    #[arg(short, long)]
    version: bool,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.version {
        println!("ranger-agent {}", carbide_version::version!());
        return Ok(());
    }

    // Initialize logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    info!("Ranger Agent starting...");
    info!("Version: {}", carbide_version::version!());
    info!("API endpoint: {}", args.api);

    if let Some(ref machine_id) = args.machine_interface_id {
        info!("Machine ID: {}", machine_id);
    }

    // TBD: Currently Scout handles TLS certificate provisioning. Once Ranger
    // has its own TLS support, this dependency can be removed.
    info!("Note: Scout agent provides TLS provisioning (TBD: will be replaced with ranger)");

    // Main loop - log heartbeat every 30 seconds
    let mut iteration: u64 = 0;
    loop {
        iteration += 1;
        info!(
            iteration = iteration,
            "Ranger agent heartbeat - awaiting instructions from Carbide"
        );

        // TODO: it must:
        // - Connect to Carbide test manager service via gRPC
        // - Register this node as available for receiving further instructions
        // - Receive download/execute commands
        // - Report results back to Carbide

        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}
