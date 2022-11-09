/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::env;
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

use cfg::{Command, Options};
use forge_credentials::ForgeVaultClient;

mod api;
mod auth;
mod cfg;
mod dhcp_discover;

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

    let config = Options::load();

    let env_filter = EnvFilter::from_default_env()
        .add_directive(
            match config.debug {
                0 => LevelFilter::INFO,
                1 => {
                    // command line overrides config file
                    std::env::set_var("RUST_BACKTRACE", "1");
                    LevelFilter::DEBUG
                }
                _ => {
                    std::env::set_var("RUST_BACKTRACE", "1");
                    LevelFilter::TRACE
                }
            }
            .into(),
        )
        .add_directive("sqlx::query=warn".parse()?)
        .add_directive("h2::codec=warn".parse()?);

    tracing_subscriber::registry()
        .with(fmt::Layer::default().pretty())
        .with(env_filter)
        .try_init()?;

    match config.sub_cmd {
        Command::Migrate(ref m) => {
            log::debug!("Running migrations");
            let pool = PgPool::connect(&m.datastore[..]).await?;
            carbide::db::migrations::migrate(&pool).await?;
        }
        Command::Run(ref config) => {
            let vault_token = env::var("VAULT_TOKEN")?;
            let vault_addr = env::var("VAULT_ADDR")?;
            let vault_mount_location = env::var("VAULT_MOUNT_LOCATION")?;

            let vault_client_settings = VaultClientSettingsBuilder::default()
                .address(vault_addr)
                .token(vault_token)
                .timeout(Some(Duration::from_secs(60)))
                .verify(false) //TODO: remove me when we are starting to validate certs
                .build()?;
            let vault_client = VaultClient::new(vault_client_settings)?;
            let forge_vault_client = ForgeVaultClient::new(vault_client, vault_mount_location);
            let forge_vault_client = Arc::new(forge_vault_client);
            api::Api::run(config, forge_vault_client).await?
        }
    }
    Ok(())
}
