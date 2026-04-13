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

//! Functional smoke test for the artifact caching pipeline.
//!
//! Exercises `process_artifacts` end-to-end using a local SOT JSON file and
//! one or more scenario TOMLs, without a live NICC gRPC connection.
//!
//! Usage:
//!   cargo run --bin test-artifact-cache -- \
//!     --sot      <path/to/sot.json>        \
//!     --scenario <path/to/scenario.toml>   \
//!     --cache-dir <path/to/cache>
//!
//! To capture logs for inspection, redirect output to a file:
//!   target/debug/test-artifact-cache \
//!     --sot      <path/to/sot.json>        \
//!     --scenario <path/to/scenario.toml>   \
//!     --cache-dir <path/to/cache>          \
//!     > /tmp/rvs-test.log 2>&1 &
//!   tail -f /tmp/rvs-test.log

use std::path::PathBuf;

use carbide_rvs::artifact;
use carbide_rvs::client::NiccClient;
use carbide_rvs::config::Config;
use carbide_rvs::ctx::RvsCtx;
use carbide_rvs::error::RvsError;
use carbide_rvs::rack::Racks;
use carbide_rvs::scenario::Scenario;
use clap::Parser;
use rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser)]
#[command(about = "Smoke-test the artifact cache pipeline without a live NICC connection")]
struct Cli {
    /// Path to SOT JSON file (replaces gRPC fetch).
    #[arg(long, value_name = "PATH")]
    sot: PathBuf,

    /// Path to scenario TOML (repeatable).
    #[arg(long, value_name = "PATH")]
    scenario: Vec<PathBuf>,

    /// Directory to cache downloaded artifacts into.
    #[arg(long, value_name = "PATH")]
    cache_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), RvsError> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(logfmt::layer())
        .with(env_filter)
        .init();

    let cli = Cli::parse();

    // Load scenarios from provided paths; hard-fail on any parse error.
    let scenarios: Vec<Scenario> = cli
        .scenario
        .iter()
        .map(|p| Scenario::load(p).map_err(RvsError::InvalidArg))
        .collect::<Result<_, _>>()?;

    if scenarios.is_empty() {
        return Err(RvsError::InvalidArg(
            "no scenarios provided; pass at least one --scenario <path>".to_string(),
        ));
    }

    // Build config with target cache dir; everything else default.
    let mut cfg = Config::default();
    cfg.artifact_cache.cache_dir = cli.cache_dir.to_string_lossy().into_owned();

    // NiccClient is required by RvsCtx but won't be called: fetch_sot
    // short-circuits to sot_override_path before touching gRPC.
    let client_config = ForgeClientConfig::new("/dev/null".to_string(), None);
    let api_config = ApiConfig::new(&cfg.nicc.url, &client_config);
    let nicc = NiccClient::new(&api_config);

    let sot_path = cli.sot.to_string_lossy().into_owned();
    let ctx = RvsCtx {
        nicc,
        scenarios,
        cfg,
        sot_override_path: Some(sot_path),
    };

    // Empty racks: fetch_sot ignores the racks argument while sot_override_path is set.
    let racks = Racks { inner: vec![] };

    tracing::info!("test-artifact-cache: starting artifact cache run");
    artifact::start_cache_server(&ctx).await?;
    artifact::process_artifacts(&racks, &ctx).await?;
    tracing::info!(
        port = ctx.cfg.artifact_cache.serve_port,
        cache_dir = %ctx.cfg.artifact_cache.cache_dir,
        "test-artifact-cache: downloads complete, cache server running — press Ctrl+C to stop"
    );
    tokio::signal::ctrl_c().await.map_err(RvsError::Io)?;

    Ok(())
}
