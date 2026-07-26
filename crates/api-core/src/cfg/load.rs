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
use std::sync::Arc;

use eyre::WrapErr;
use figment::providers::{Env, Format, Toml};
use figment::value::{Dict, Map, Value};
use figment::{Figment, Metadata, Profile, Provider};

use super::file::{CarbideConfig, InitialObjectsConfig};

/// Parse the `InitialObjectsConfig` file referenced by
/// [`CarbideConfig::initial_objects_file`].
pub fn parse_initial_objects_config(path: &Path) -> eyre::Result<InitialObjectsConfig> {
    Figment::new()
        .merge(Toml::file(path))
        .extract()
        .wrap_err_with(|| format!("while parsing InitialObjectsConfig at {}", path.display()))
}

/// Return a list of all configuration files that were merged to create the
/// effective configuration, for logging purposes. This is used in error messages
/// when there is a problem with the configuration, to help the operator
/// understand which files to look at to fix the problem.
pub(crate) fn all_configuration_files(carbide_config: &CarbideConfig) -> Vec<&Path> {
    carbide_config
        .config_ctx
        .as_ref()
        .into_iter()
        .flat_map(|figment| figment.metadata())
        .filter_map(|metadata| metadata.source.as_ref()?.file_path())
        .collect()
}

/// Normalizes the legacy site-explorer DPU-policy key within one configuration
/// provider, before Figment applies provider precedence.
///
/// Keeping this at the provider boundary makes global < site < environment win
/// regardless of whether a source uses `dpu_policy` or legacy `dpu_mode`.
/// Within one source, the canonical key wins when both are present.
struct NormalizeLegacyDpuPolicy<P>(P);

impl<P: Provider> Provider for NormalizeLegacyDpuPolicy<P> {
    fn metadata(&self) -> Metadata {
        self.0.metadata()
    }

    fn data(&self) -> Result<Map<Profile, Dict>, figment::Error> {
        let mut data = self.0.data()?;
        for profile in data.values_mut() {
            let Some(Value::Dict(_, site_explorer)) = profile.get_mut("site_explorer") else {
                continue;
            };

            let legacy = site_explorer.remove("dpu_mode");
            let canonical_is_set = site_explorer
                .get("dpu_policy")
                .is_some_and(|value| !matches!(value, Value::Empty(..)));
            if !canonical_is_set && let Some(value) = legacy {
                site_explorer.insert("dpu_policy".to_string(), value);
            }
        }

        Ok(data)
    }

    fn profile(&self) -> Option<Profile> {
        self.0.profile()
    }
}

pub(crate) fn merged_carbide_config_figment(
    config_path: &Path,
    site_config_path: Option<&Path>,
) -> Figment {
    let mut figment = Figment::new().merge(NormalizeLegacyDpuPolicy(Toml::file(config_path)));
    if let Some(site_config_path) = site_config_path {
        figment = figment.merge(NormalizeLegacyDpuPolicy(Toml::file(site_config_path)));
    }

    figment.merge(NormalizeLegacyDpuPolicy(Env::prefixed("CARBIDE_API_")))
}

/// Load, normalize, and validate the Carbide API configuration.
pub fn parse_carbide_config(
    config_path: &Path,
    site_config_path: Option<&Path>,
) -> eyre::Result<Arc<CarbideConfig>> {
    let merged_config = merged_carbide_config_figment(config_path, site_config_path);
    let mut config: CarbideConfig = merged_config
        .extract()
        .wrap_err("failed to load configuration files")?;

    config.config_ctx = Some(merged_config);

    for (label, _) in config
        .host_models
        .iter()
        .filter(|(_, host)| host.vendor == bmc_vendor::BMCVendor::Unknown)
    {
        tracing::error!(label = %label, "Host firmware configuration has invalid vendor");
    }

    // If the carbide config does not say whether to allow dynamically changing the bmc_proxy or
    // not, the API handler for changing the bmc_proxy setting will reject changes to it for safety
    // reasons (it can be dangerous in production environments.) But if the config already sets
    // bmc_proxy, default to allow_changing_bmc_proxy=true, as we only should be setting bmc_proxy
    // in dev environments in the first place.
    if config.site_explorer.allow_changing_bmc_proxy.is_none()
        && (config.site_explorer.bmc_proxy.load().is_some()
            || config.site_explorer.override_target_port.is_some()
            || config.site_explorer.override_target_ip.is_some())
    {
        tracing::debug!(
            "Carbide config contains override for bmc_proxy, allowing dynamic bmc_proxy configuration"
        );
        config.site_explorer.allow_changing_bmc_proxy = Some(true);
    }

    if let Some(old_update_limit) = config.max_concurrent_machine_updates {
        if let Some(new_update_limit) = config
            .machine_updater
            .max_concurrent_machine_updates_absolute
        {
            // Both specified, use the smaller
            config
                .machine_updater
                .max_concurrent_machine_updates_absolute =
                Some(std::cmp::min(old_update_limit, new_update_limit));
        } else {
            config
                .machine_updater
                .max_concurrent_machine_updates_absolute = config.max_concurrent_machine_updates;
        }
    }

    // Validate that admin-UI tool entries have unique names.
    config.validate_web_ui_sidebar_tools()?;

    if let Some(config) = &config.dsx_exchange_event_bus {
        config.periodic_state_republish.validate()?;
    }

    // Publish the configured tool list so the admin-UI sidebar and per-machine
    // "Logs" deep link can read it back via `crate::configured_tools`. The list
    // is owned here (not in `carbide-api-web`) because it is derived from the
    // parsed config, before the web layer exists.
    crate::init_tools(config.web_ui_sidebar_tools.clone());

    // Publish the site name the same way, for the admin-UI sidebar header.
    crate::init_site_name(config.sitename.clone());

    // Publish the deployment-wide host naming policy so the DB layer can read it
    // wherever an interface is [re]named (same way we do it w/ `init_tools` above).
    db::host_naming::configure(config.host_naming_strategy);

    // Validate that the firmware profile config keys match their inner
    // part_number and psid values. Mismatches are logged as warnings.
    config.validate_supernic_firmware_profiles();

    if let Some(manager_config) = &config.component_manager {
        component_manager::rms::validate_rms_backend_rack_profiles(
            manager_config,
            &config.rack_profiles,
        )
        .map_err(|error| eyre::eyre!(error).wrap_err("invalid configuration"))?;
    }

    model::tenant::validate_trust_domain_allowlist_patterns(
        &config.machine_identity.trust_domain_allowlist,
    )
    .map_err(|error| eyre::eyre!(error).wrap_err("invalid configuration"))?;

    model::tenant::validate_token_endpoint_domain_allowlist_patterns(
        &config.machine_identity.token_endpoint_domain_allowlist,
    )
    .map_err(|error| eyre::eyre!(error).wrap_err("invalid configuration"))?;

    if config.machine_identity.enabled
        && config.machine_identity.current_encryption_key_id.is_none()
    {
        return Err(eyre::eyre!(
            "current_encryption_key_id must be set in [machine_identity] when machine identity is enabled"
        )
        .wrap_err("invalid configuration"));
    }

    tracing::trace!(config = ?config.redacted(), "Carbide config");
    Ok(Arc::new(config))
}
