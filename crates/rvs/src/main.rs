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

//! Rack Validation Service (RVS)
//!
//! External validation orchestrator for NICC. Bridges NICC with test
//! frameworks (Benchpress, MPI-based, SLURM-based, etc.) to perform
//! partition-aware rack validation.
//!
//! NOTE: This is still a tracer / playground. The abstractions are
//! crystallizing but main.rs is not yet the final shape.

use std::path::PathBuf;

use forge_tls::client_config::ClientCert;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod client;
mod config;
mod error;
mod partitions;
mod rack;
mod scenario;
mod validation;

use client::NiccClient;
use config::Config;
use partitions::Partitions;

#[tokio::main]
async fn main() -> Result<(), error::RvsError> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(logfmt::layer())
        .with(env_filter)
        .init();

    tracing::info!("carbide-rvs: Rack Validation Service starting");

    // Load config: defaults -> optional TOML -> CARBIDE_RVS__* env vars
    let config_path = parse_config_path()?;
    let cfg = Config::load(config_path.as_deref())?;
    tracing::info!(config = ?cfg, "config loaded");

    // Try loading scenario -- soft fail, this is tracer code
    let scenario = match scenario::Scenario::load(std::path::Path::new(&cfg.scenario_config_path)) {
        Ok(s) => {
            tracing::info!(scenario = ?s, "scenario loaded");
            Some(s)
        }
        Err(e) => {
            tracing::warn!(error = %e, "scenario not loaded, continuing without it");
            None
        }
    };
    let os_uri = scenario.as_ref().map(|s| s.os.uri.as_str()).unwrap_or("");

    // Build NICC client from config
    let client_cert = ClientCert {
        cert_path: cfg.tls.identity_pemfile_path,
        key_path: cfg.tls.identity_keyfile_path,
    };
    let client_config = ForgeClientConfig::new(cfg.tls.root_cafile_path, Some(client_cert));
    let api_config = ApiConfig::new(&cfg.nicc.url, &client_config);
    let nicc = NiccClient::new(&api_config);

    // TODO[#416]: re-introduce a liveness/health probe (bound to
    // `cfg.metrics_endpoint`) once RVS runs as a long-lived service with
    // graceful shutdown and real health checks. For now, "alive" just means
    // the process is running -- the current stub probe would only echo 200
    // and buys nothing.

    let cancel_token = CancellationToken::new();
    let validation_cancel_token = cancel_token.clone();

    tokio::spawn(async move {
        loop {
            let Ok(mut sigint) = signal(SignalKind::interrupt()) else {
                break;
            };
            let Ok(mut sigterm) = signal(SignalKind::terminate()) else {
                break;
            };
            // Wait for SIGINT or SIGTERM
            let received_signal = tokio::select! {
                _ = sigint.recv() => "SIGINT",
                _ = sigterm.recv() => "SIGTERM",
            };

            if cancel_token.is_cancelled() {
                std::process::exit(130);
            } else {
                eprintln!(
                    "{received_signal} received, shutting down gracefully. Send {received_signal} again to exit."
                );
                cancel_token.cancel();
            }
        }
    });

    run_validation(
        &nicc,
        os_uri,
        cfg.poll_interval_secs,
        validation_cancel_token,
    )
    .await
}

/// Parse `--config <path>` from argv. Returns `None` if the flag is absent.
fn parse_config_path() -> Result<Option<PathBuf>, error::RvsError> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            let path = args.next().ok_or_else(|| {
                error::RvsError::InvalidArg("--config requires a path argument".to_string())
            })?;
            return Ok(Some(PathBuf::from(path)));
        }
    }
    Ok(None)
}

// Rack validation high-level flow
async fn run_validation(
    nicc: &NiccClient,
    os_uri: &str,
    poll_interval_secs: u64,
    cancel_token: CancellationToken,
) -> Result<(), error::RvsError> {
    let interval = std::time::Duration::from_secs(poll_interval_secs);
    loop {
        let racks = rack::fetch_racks(nicc).await?;
        for job in validation::plan(Partitions::try_from(racks)?, nicc, os_uri).await? {
            let report = validation::validate_partition(job).await?;
            validation::submit_report(report).await?;
        }
        tracing::info!(poll_interval_secs, "validation: cycle complete, sleeping");
        if cancel_token
            .run_until_cancelled(tokio::time::sleep(interval))
            .await
            .is_none()
        {
            break Ok(());
        }
    }
}
