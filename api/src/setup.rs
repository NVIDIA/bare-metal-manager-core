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
use crate::cfg::CarbideConfig;
use eyre::WrapErr;
use figment::providers::{Env, Format, Toml};
use figment::Figment;
use forge_secrets::ForgeVaultClient;
use std::{env, sync::Arc, time::Duration};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

pub fn parse_carbide_config(
    config_str: String,
    site_config_str: Option<String>,
) -> eyre::Result<Arc<CarbideConfig>> {
    let mut figment = Figment::new().merge(Toml::string(config_str.as_str()));
    if let Some(site_config_str) = site_config_str {
        figment = figment.merge(Toml::string(site_config_str.as_str()));
    }

    let config: CarbideConfig = figment
        .merge(Env::prefixed("CARBIDE_API_"))
        .extract()
        .wrap_err("Failed to load configuration files")?;
    Ok(Arc::new(config))
}

pub fn create_vault_client() -> eyre::Result<Arc<ForgeVaultClient>> {
    let vault_token = env::var("VAULT_TOKEN")
        .wrap_err("VAULT_TOKEN")?
        .trim()
        .to_string();
    let vault_addr = env::var("VAULT_ADDR").wrap_err("VAULT_ADDR")?;
    let kv_mount_location =
        env::var("VAULT_KV_MOUNT_LOCATION").wrap_err("VAULT_KV_MOUNT_LOCATION")?;
    let pki_mount_location =
        env::var("VAULT_PKI_MOUNT_LOCATION").wrap_err("VAULT_PKI_MOUNT_LOCATION")?;
    let pki_role_name = env::var("VAULT_PKI_ROLE_NAME").wrap_err("VAULT_PKI_ROLE_NAME")?;

    let vault_client_settings = VaultClientSettingsBuilder::default()
        .address(vault_addr)
        .token(vault_token)
        .timeout(Some(Duration::from_secs(60)))
        .verify(false) //TODO: remove me when we are starting to validate certs
        .build()?;
    let vault_client = VaultClient::new(vault_client_settings)?;

    let forge_vault_client = ForgeVaultClient::new(
        vault_client,
        kv_mount_location,
        pki_mount_location,
        pki_role_name,
    );
    Ok(Arc::new(forge_vault_client))
}
