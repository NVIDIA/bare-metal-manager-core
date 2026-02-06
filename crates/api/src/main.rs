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

use std::path::Path;
use std::str::FromStr;

use carbide::{Command, Options};
use clap::CommandFactory;
use forge_secrets::forge_vault::VaultConfig;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgSslMode};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let config = Options::load();
    if config.version {
        println!("{}", carbide_version::version!());
        return Ok(());
    }
    let debug = config.debug;

    let sub_cmd = match &config.sub_cmd {
        None => {
            return Ok(Options::command().print_long_help()?);
        }
        Some(s) => s,
    };
    match sub_cmd {
        Command::Migrate(m) => {
            tracing::info!("Running migrations");
            let mut pg_connection_options = PgConnectOptions::from_str(&m.datastore[..])?;
            let root_cafile_path = Path::new("/var/run/secrets/spiffe.io/ca.crt");
            if root_cafile_path.exists() {
                tracing::info!("using TLS for postgres connection.");
                pg_connection_options = pg_connection_options
                    .ssl_mode(PgSslMode::Require) //TODO: move this to VerifyFull once it actually works
                    .ssl_root_cert(root_cafile_path);
            }

            let pool = PgPool::connect_with(pg_connection_options).await?;
            db::migrations::migrate(&pool).await?;
        }
        Command::Run(config) => {
            // THIS SECTION HAS BEEN INTENTIONALLY KEPT SMALL.
            // Nothing should go before the call to carbide::run that isn't already here.
            // Everything that you think might belong here, belongs in carbide::run.
            let config_str = tokio::fs::read_to_string(&config.config_path).await?;
            let site_config_str = if let Some(site_path) = &config.site_config_path {
                Some(tokio::fs::read_to_string(&site_path).await?)
            } else {
                None
            };

            let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (ready_tx, _ready_rx) = tokio::sync::oneshot::channel();
            carbide::run(
                debug,
                config_str,
                site_config_str,
                VaultConfig::default(),
                false,
                stop_rx,
                ready_tx,
            )
            .await?;
        }
    }
    Ok(())
}
