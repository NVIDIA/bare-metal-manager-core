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
use std::path::Path;
use std::{env, sync::Arc};

use eyre::WrapErr;
use figment::providers::{Env, Format, Toml};
use figment::Figment;

use forge_secrets::forge_vault::{ForgeVaultAuthenticationType, ForgeVaultClientConfig};
use forge_secrets::ForgeVaultClient;

use crate::cfg::CarbideConfig;

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

pub async fn create_vault_client(
    forge_root_ca_path: Option<String>,
) -> eyre::Result<Arc<ForgeVaultClient>> {
    let vault_address = env::var("VAULT_ADDR").wrap_err("VAULT_ADDR")?;
    let kv_mount_location =
        env::var("VAULT_KV_MOUNT_LOCATION").wrap_err("VAULT_KV_MOUNT_LOCATION")?;
    let pki_mount_location =
        env::var("VAULT_PKI_MOUNT_LOCATION").wrap_err("VAULT_PKI_MOUNT_LOCATION")?;
    let pki_role_name = env::var("VAULT_PKI_ROLE_NAME").wrap_err("VAULT_PKI_ROLE_NAME")?;

    let service_account_token_path =
        Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token");
    let auth_type = if service_account_token_path.exists() {
        ForgeVaultAuthenticationType::ServiceAccount(service_account_token_path.to_owned())
    } else {
        ForgeVaultAuthenticationType::Root(env::var("VAULT_TOKEN").wrap_err("VAULT_TOKEN")?)
    };

    let forge_vault_client = ForgeVaultClient::new(ForgeVaultClientConfig {
        auth_type,
        vault_address,
        kv_mount_location,
        pki_mount_location,
        pki_role_name,
        forge_root_ca_path,
    });
    Ok(Arc::new(forge_vault_client))
}
