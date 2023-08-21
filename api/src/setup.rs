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
use forge_secrets::credentials::CredentialProvider;

use crate::cfg::CarbideConfig;
use crate::ipmitool::{IPMITool, IPMIToolImpl, IPMIToolTestImpl};
use forge_secrets::forge_vault::{ForgeVaultAuthenticationType, ForgeVaultClientConfig};
use forge_secrets::ForgeVaultClient;

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

pub async fn create_vault_client() -> eyre::Result<Arc<ForgeVaultClient>> {
    let vault_address = env::var("VAULT_ADDR").wrap_err("VAULT_ADDR")?;
    let kv_mount_location =
        env::var("VAULT_KV_MOUNT_LOCATION").wrap_err("VAULT_KV_MOUNT_LOCATION")?;
    let pki_mount_location =
        env::var("VAULT_PKI_MOUNT_LOCATION").wrap_err("VAULT_PKI_MOUNT_LOCATION")?;
    let pki_role_name = env::var("VAULT_PKI_ROLE_NAME").wrap_err("VAULT_PKI_ROLE_NAME")?;

    let vault_root_ca_path = "/var/run/secrets/forge-roots/ca.crt".to_string();
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
        vault_root_ca_path,
    });
    Ok(Arc::new(forge_vault_client))
}

pub fn create_ipmi_tool<C: CredentialProvider + 'static>(
    credential_provider: Arc<C>,
    carbide_config: &CarbideConfig,
) -> Arc<dyn IPMITool> {
    if carbide_config
        .dpu_impi_tool_impl
        .as_ref()
        .is_some_and(|tool| tool == "test")
    {
        Arc::new(IPMIToolTestImpl {})
    } else {
        Arc::new(IPMIToolImpl::new(
            credential_provider,
            &carbide_config.dpu_ipmi_reboot_args,
            &carbide_config.dpu_ipmi_reboot_attempts,
        ))
    }
}
