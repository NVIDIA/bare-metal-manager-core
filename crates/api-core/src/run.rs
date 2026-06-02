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
use std::path::PathBuf;
use std::sync::Arc;

use carbide_utils::HostPortPair;
use eyre::WrapErr;
use forge_secrets::credentials::{CredentialManager, CredentialReader};
use forge_secrets::{
    CredentialConfig, MemoryCredentialStore, VaultConfig, create_credential_manager_from,
    create_vault_client,
};
use tokio::sync::oneshot::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::subscriber::NoSubscriber;

use crate::cfg::file::CarbideConfig;
use crate::listener::AdminUiRoutesBuilder;
use crate::logging::metrics_endpoint::{MetricsEndpointConfig, run_metrics_endpoint};
use crate::logging::setup::{
    Logging, create_metric_for_spancount_reader, create_metrics, setup_logging,
};
use crate::{CarbideError, dynamic_settings, setup};

/// Vault machine PKI URI SANs must match `[auth.trust]` when site auth config is present.
fn vault_config_for_site(vault: &VaultConfig, carbide_config: &CarbideConfig) -> VaultConfig {
    let mut config = vault.clone();
    if let Some(trust) = carbide_config
        .auth
        .as_ref()
        .and_then(|auth| auth.trust.as_ref())
    {
        config.spiffe_trust_domain = Some(trust.spiffe_trust_domain.clone());
        config.spiffe_machine_base_path = Some(trust.spiffe_machine_base_path.clone());
    }
    config
}

/// Run the carbide-api server until `cancel_token` is cancelled.
///
/// `admin_ui_routes_builder` is how the admin web UI's pages (everything under
/// `/admin`) get plugged in: pass `Some(Box::new(carbide_api_web::routes))` to
/// serve them, or `None` to skip the web UI entirely (e.g. in-process test
/// servers, which only hit the gRPC API). It's passed in rather than called
/// directly to avoid a dependency cycle — see [`AdminUiRoutesBuilder`] for why.
///
/// Note: even when `Some` is passed, the admin UI is only mounted if the
/// `enable_admin_ui` config flag is true (the default). When it's false,
/// `start_api` drops the builder and serves gRPC only — so `Some` here means
/// "offer the UI", not "force it on".
#[allow(clippy::too_many_arguments)]
pub async fn run(
    debug: u8,
    config_str: PathBuf,
    site_config_str: Option<PathBuf>,
    credential_config: CredentialConfig,
    skip_logging_setup: bool,
    admin_ui_routes_builder: Option<AdminUiRoutesBuilder>,
    cancel_token: CancellationToken,
    ready_channel: Sender<()>,
) -> eyre::Result<()> {
    let carbide_config = setup::parse_carbide_config(&config_str, site_config_str.as_deref())?;

    // If `CarbideConfig.initial_objects_file` is set, load it into an
    // `InitialObjectsConfig` so that `start_api` can reconcile its contents
    // against the database on first startup.
    let initial_objects = if let Some(path) = carbide_config.initial_objects_file.as_deref() {
        Some(setup::parse_initial_objects_config(path)?)
    } else {
        None
    };

    // Reject config that contains overlaps between deny_prefixes and site_fabric_prefixes.
    // deny_prefixes are IPv4-only; only check against IPv4 site fabric prefixes.
    for deny_prefix in carbide_config.deny_prefixes.iter() {
        for site_fabric_prefix in carbide_config.site_fabric_prefixes.iter() {
            if let ipnetwork::IpNetwork::V4(site_v4) = site_fabric_prefix
                && deny_prefix.overlaps(*site_v4)
            {
                return Err(eyre::eyre!(
                    "overlap found in deny_prefixes `{}` and site_fabric_prefixes `{}`",
                    deny_prefix,
                    site_fabric_prefix,
                ));
            }
        }
    }

    let log_history_max_bytes = carbide_config
        .log_history
        .max_megabytes
        .saturating_mul(1024 * 1024);
    let tconf = if skip_logging_setup {
        Logging::default()
    } else {
        setup_logging(
            debug,
            carbide_machine_controller::extra_logfmt_logging_fields(),
            None::<NoSubscriber>,
            log_history_max_bytes,
        )
        .wrap_err("setup_telemetry")?
    };

    // Redact credentials before printing the config
    let print_config = carbide_config.redacted();

    tracing::info!("Using configuration: {:#?}", print_config);
    tracing::info!(
        "Tokio worker thread count: {} (num_cpus::get()={}, TOKIO_WORKER_THREADS={})",
        tokio::runtime::Handle::current().metrics().num_workers(),
        num_cpus::get(),
        std::env::var("TOKIO_WORKER_THREADS").unwrap_or_else(|_| "UNSET".to_string())
    );

    let metrics = create_metrics()?;
    create_metric_for_spancount_reader(&metrics.meter, tconf.spancount_reader);

    // All background tasks that run "forever" (until canceled) are added to this JoinSet. When
    // initialization is complete, we use [`JoinSet::join_all`] to wait for them all to complete,
    // while propagating any panics to the current task.
    let mut join_set = JoinSet::new();

    // Spin up the webserver which servers `/metrics` requests
    if let Some(metrics_address) = carbide_config.metrics_endpoint {
        // If a replacement prefix for "carbide_" is configured, also emit metrics under that
        let additional_prefix = carbide_config
            .alt_metric_prefix
            .clone()
            .map(|alt_prefix| ("carbide_".to_string(), alt_prefix));
        join_set.build_task().name("metrics_endpoint").spawn({
            let cancel_token = cancel_token.clone();
            async move {
                if let Err(e) = run_metrics_endpoint(
                    &MetricsEndpointConfig {
                        address: metrics_address,
                        registry: metrics.registry,
                        additional_prefix,
                    },
                    cancel_token,
                )
                .await
                {
                    tracing::error!("Metrics endpoint failed with error: {}", e);
                }
            }
        })?;
    }

    let dynamic_settings = crate::dynamic_settings::DynamicSettings {
        log_filter: tconf.filter.clone(),
        site_explorer_enabled: carbide_config.site_explorer.enabled.clone(),
        create_machines: carbide_config.site_explorer.create_machines.clone(),
        bmc_proxy: carbide_config.site_explorer.bmc_proxy.clone(),
        tracing_enabled: tconf.tracing_enabled,
        log_stream: tconf.log_stream,
    };
    dynamic_settings.start_reset_task(
        &mut join_set,
        dynamic_settings::RESET_PERIOD,
        cancel_token.clone(),
    );

    tracing::info!(
        address = carbide_config.listen.to_string(),
        build_version = carbide_version::v!(build_version),
        build_date = carbide_version::v!(build_date),
        rust_version = carbide_version::v!(rust_version),
        "Start carbide-api",
    );

    let vault_config = vault_config_for_site(&credential_config.vault, &carbide_config);

    let certificate_provider = create_vault_client(&vault_config, metrics.meter.clone())?;

    // Pick a credential store based on CARBIDE_CREDENTIAL_STORE (default: "vault").
    // Set to "memory" to use an in-memory store with no persistence or shared state between
    // processes. This is only suitable for development and testing.
    let credential_store: Arc<dyn CredentialManager> = match std::env::var(
        "CARBIDE_CREDENTIAL_STORE",
    )
    .as_deref()
    .unwrap_or("vault")
    {
        "vault" => create_vault_client(&vault_config, metrics.meter.clone())?,
        "memory" => Arc::new(MemoryCredentialStore::default()),
        other => {
            return Err(eyre::eyre!(
                "Invalid CARBIDE_CREDENTIAL_STORE value {other:?}: expected \"vault\" or \"memory\""
            ));
        }
    };

    // Build credential reader chain. The idea is this chain
    // can be flexible, to allow us to introduce an ordered
    // list of readers, which we build on-demand based on
    // configuration.
    let mut readers: Vec<Box<dyn CredentialReader>> = Vec::new();

    // If EnvCredentials are enabled, then add that
    // to our chained credentials reader. It's expected
    // that this comes first if configured.
    if credential_config.env.enabled() {
        readers.push(Box::new(
            forge_secrets::local_credentials::EnvCredentials::new(credential_config.env.clone())?,
        ));
    }

    // Next, if FileCredentials are enabled, then
    // add those in as well. We expect these *after*
    // EnvCredentials.
    if credential_config.file.enabled() {
        readers.push(Box::new(
            forge_secrets::local_credentials::FileCredentialsWatcher::new(
                credential_config.file.clone(),
            )
            .await?,
        ));
    }

    // Last, we tack on the credential store to the end.
    readers.push(Box::new(credential_store.clone()));

    // And now we create our new composite credential manager
    // from the list of readers we just built, plus the credential store as writer.
    let credential_manager = create_credential_manager_from(credential_store, readers);

    let redfish_pool = {
        let rf_pool = libredfish::RedfishClientPool::builder()
            .danger_accept_invalid_certs()
            .build()
            .map_err(CarbideError::from)?;

        // Support deprecated configuration for site_explorer.override_target_ip and override_target_port. Configuration should migrate to site_explorer.bmc_proxy.
        match (
            &carbide_config.site_explorer.override_target_ip,
            carbide_config.site_explorer.override_target_port,
            carbide_config.site_explorer.bmc_proxy.load().as_ref(),
        ) {
            (Some(_), _, Some(_)) => {
                tracing::warn!(
                    "Ignoring deprecated config site_explorer.override_target_ip, since site_explorer.bmc_proxy is also set. Please delete override_target_ip from site_explorer config."
                );
            }
            (Some(ip), maybe_target_port, None) => {
                tracing::warn!(
                    "Deprecated site_explorer.override_target_ip in carbide config. Setting site_explorer.bmc_proxy instead. Please migrate configuration."
                );
                if let Some(port) = maybe_target_port {
                    carbide_config.site_explorer.bmc_proxy.store(Arc::new(Some(
                        HostPortPair::HostAndPort(ip.to_string(), port),
                    )));
                } else {
                    carbide_config
                        .site_explorer
                        .bmc_proxy
                        .store(Arc::new(Some(HostPortPair::HostOnly(ip.to_string()))));
                }
            }
            (None, Some(port), None) => {
                tracing::warn!(
                    "Deprecated site_explorer.override_target_port in carbide config. Setting site_explorer.bmc_proxy instead. Please migrate configuration."
                );
                carbide_config
                    .site_explorer
                    .bmc_proxy
                    .store(Arc::new(Some(HostPortPair::PortOnly(port))));
            }
            (None, Some(_), Some(_)) => {
                tracing::warn!(
                    "Ignoring deprecated config site_explorer.override_target_port, since site_explorer.bmc_proxy is also set. Please delete override_target_port from site_explorer config."
                );
            }
            (None, None, _) => {} // leave bmc_proxy untouched
        }

        carbide_redfish::libredfish::new_pool(
            credential_manager.clone(),
            rf_pool,
            carbide_config.site_explorer.bmc_proxy.clone(),
        )
    };

    let nv_redfish_pool =
        carbide_redfish::nv_redfish::new_pool(carbide_config.site_explorer.bmc_proxy.clone());

    setup::start_api(
        &mut join_set,
        carbide_config,
        initial_objects,
        metrics.meter,
        dynamic_settings,
        redfish_pool,
        nv_redfish_pool,
        credential_manager,
        certificate_provider,
        admin_ui_routes_builder,
        cancel_token,
        ready_channel,
    )
    .await?;

    // Block forever until all spawned tasks complete. Any panics in spawned tasks will be
    // propagated here.
    join_set.join_all().await;

    Ok(())
}
