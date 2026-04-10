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
use tokio::io::AsyncWriteExt;
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
        cert_path: cfg.tls.identity_pemfile_path.clone(),
        key_path: cfg.tls.identity_keyfile_path.clone(),
    };
    let client_config = ForgeClientConfig::new(cfg.tls.root_cafile_path.clone(), Some(client_cert));
    let api_config = ApiConfig::new(&cfg.nicc.url, &client_config);
    let nicc = NiccClient::new(&api_config);

    // Liveness probe server

    let listen_addr = cfg.metrics_endpoint.to_string();
    tracing::info!(addr = %listen_addr, "starting liveness HTTP server");

    let listener = tokio::net::TcpListener::bind(cfg.metrics_endpoint).await?;

    // Run validation and liveness concurrently; a hard error from validation
    // exits the process.
    tokio::select! {
        result = run_validation(&nicc, os_uri, cfg.poll_interval_secs) => result?,
        () = serve_liveness(listener) => {},
    }

    Ok(())
}

async fn serve_liveness(listener: tokio::net::TcpListener) {
    loop {
        match listener.accept().await {
            Ok((mut stream, _addr)) => {
                tokio::spawn(async move {
                    // TODO[#416]: proper responses instead of this
                    let mut buf = [0u8; 1024];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let body = "carbide-rvs: alive\n";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "liveness: accept failed, retrying");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
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
) -> Result<(), error::RvsError> {
    let interval = std::time::Duration::from_secs(poll_interval_secs);
    loop {
        let racks = rack::fetch_racks(nicc).await?;
        for job in validation::plan(Partitions::try_from(racks)?, nicc, os_uri).await? {
            let report = validation::validate_partition(job).await?;
            validation::submit_report(report).await?;
        }
        tracing::info!(poll_interval_secs, "validation: cycle complete, sleeping");
        tokio::time::sleep(interval).await;
    }
}
