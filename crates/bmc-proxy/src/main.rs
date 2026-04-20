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
use std::io;
use std::sync::Arc;

mod acl;
mod bmc_proxy;
mod config;
mod metrics;
mod setup;

use bmc_proxy::{BmcProxyError, BmcProxyParams};
use clap::Parser;
use config::{Config, ConfigError};
use setup::{SetupError, setup_logging, setup_metrics};
use sqlx::postgres::PgSslMode;
use sqlx::{ConnectOptions, PgPool};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing_log::AsLog;

#[derive(Parser)]
#[clap(name = "carbide-bmc-proxy")]
pub struct Args {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    #[clap(short, long)]
    pub debug: bool,

    #[clap(long)]
    pub config_path: String,
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("Configuration error: {0}")]
    Config(Box<ConfigError>),
    #[error("Error setting up bmc-proxy: {0}")]
    Setup(#[from] SetupError),
    #[error("Error running bmc-proxy: {0}")]
    BmcProxy(#[from] BmcProxyError),
    #[error("Error connecting to database: {0}")]
    DatabaseConnection(sqlx::Error),
    #[error("Error running metrics endpoint: {0}")]
    Metrics(io::Error),
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Self {
        Self::Config(Box::new(e))
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    if args.version {
        println!("{}", carbide_version::version!());
        return Ok(());
    }

    let debug = args.debug;
    setup_logging(debug)?;

    let config = tokio::fs::read_to_string(&args.config_path)
        .await
        .map_err(|e| {
            ConfigError::Read(format!(
                "Error opening config file at {}: {}",
                args.config_path, e
            ))
        })
        .and_then(|s| Config::parse(&s))?;

    let mut join_set = JoinSet::new();
    let cancel_token = CancellationToken::new();

    // Run metrics endpoint
    let metrics_setup = setup_metrics()?;
    let meter = metrics_setup.meter.clone();
    metrics::start(
        config.metrics_endpoint,
        metrics_setup,
        cancel_token.clone(),
        &mut join_set,
    )
    .await
    .map_err(Error::Metrics)?;

    // Run the BMC proxy
    bmc_proxy::start(
        BmcProxyParams {
            pg_pool: connect_to_database(&config).await?,
            config: Arc::new(config),
            credential_config: Default::default(),
            meter,
        },
        cancel_token.clone(),
        &mut join_set,
    )
    .await?;

    // Cancel things when we get a ctrl+c
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        cancel_token.cancel();
    });

    // Wait until tasks are complete, propagating any panics
    join_set.join_all().await;

    Ok(())
}

async fn connect_to_database(config: &Config) -> Result<PgPool, Error> {
    // We need logs to be enabled at least at `INFO` level. Otherwise
    // our global logging filter would reject the logs before they get injected
    // into the `SqlxQueryTracing` layer.
    let mut database_connect_options = config
        .database_url
        .parse::<sqlx::postgres::PgConnectOptions>()
        .map_err(|e| ConfigError::DatabaseUrl(e.to_string()))?
        .log_statements(tracing::metadata::Level::INFO.as_log().to_level_filter());
    let tls_disabled = std::env::var("DISABLE_TLS_ENFORCEMENT").is_ok(); // the integration test doesn't like this
    if !tls_disabled {
        tracing::info!("using TLS for postgres connection.");
        database_connect_options = database_connect_options
            .ssl_mode(PgSslMode::Require)
            .ssl_root_cert(&config.tls.root_cafile_path);
    }
    sqlx::pool::PoolOptions::new()
        .max_connections(config.max_database_connections)
        .connect_with(database_connect_options)
        .await
        .map_err(Error::DatabaseConnection)
}
