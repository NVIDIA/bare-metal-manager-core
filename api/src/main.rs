/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use clap::CommandFactory;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::PgPool;
use std::path::Path;
use std::str::FromStr;
use tracing::subscriber::NoSubscriber;

use carbide::cfg::{Command, Options};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let config = Options::load();
    if config.version {
        println!("{}", forge_version::version!());
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
        Command::Migrate(ref m) => {
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
            carbide::db::migrations::migrate(&pool).await?;
        }
        Command::Run(ref config) => {
            // THIS SECTION HAS BEEN INTENTIONALLY KEPT SMALL.
            // Nothing should go before the call to carbide::run that isn't already here.
            // Everything that you think might belong here, belongs in carbide::run.
            let config_str = tokio::fs::read_to_string(&config.config_path).await?;
            let site_config_str = if let Some(site_path) = &config.site_config_path {
                Some(tokio::fs::read_to_string(&site_path).await?)
            } else {
                None
            };

            carbide::run(debug, config_str, site_config_str, None::<NoSubscriber>).await?;
        }
    }
    Ok(())
}
