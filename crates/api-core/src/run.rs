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
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use carbide_kms_provider::{
    DEFAULT_TRANSIT_MOUNT, IntegratedKmsProvider, KmsBackend, MultiKmsProvider, TransitKmsProvider,
};
use carbide_secrets::credentials::{CredentialManager, CredentialReader, CredentialWriter};
use carbide_secrets::{
    CredentialConfig, ForgeVaultClient, MemoryCredentialStore, VaultConfig,
    create_credential_manager_from, create_vault_client,
};
use carbide_utils::HostPortPair;
use eyre::WrapErr;
use sqlx::PgPool;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::subscriber::NoSubscriber;

use crate::cfg::file::{
    CarbideConfig, CredentialBackend, ImportSource, ProviderConfig, SecretsConfig,
};
use crate::listener::AdminUiRoutesBuilder;
use crate::logging::setup::{
    Logging, create_metric_for_spancount_reader, create_metrics, setup_logging,
};
use crate::secrets::{SecretRouting, SecretsContext};
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
/// "offer the UI", not "force it on". The flag also gates the log-stream
/// layer feeding the UI's live log viewer: with the UI off, no per-event
/// work is spent collecting lines nothing can read.
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
            carbide_config.enable_admin_ui,
            &carbide_config.tracing,
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
    // Counts are process-global, so this exposes the host's layer too when an
    // embedding binary (the integration harness) owns the subscriber.
    carbide_instrument::log_events::register(&metrics.meter);
    forge_http_connector::connector::register_global_metrics(&metrics.meter);

    // All background tasks that run "forever" (until canceled) are added to this JoinSet. When
    // initialization is complete, we use [`JoinSet::join_all`] to wait for them all to complete,
    // while propagating any panics to the current task.
    let mut join_set = JoinSet::new();

    // Spin up the webserver which servers `/metrics` requests
    if let Some(metrics_address) = carbide_config.metrics_endpoint {
        // If a replacement prefix for "carbide_" is configured, also emit metrics under that
        let additional_prefix =
            carbide_config
                .alt_metric_prefix
                .clone()
                .map(|alt| metrics_endpoint::PrefixMigration {
                    old: "carbide_".to_string(),
                    new: alt,
                });
        join_set.build_task().name("metrics_endpoint").spawn({
            let cancel_token = cancel_token.clone();
            async move {
                if let Err(e) = metrics_endpoint::run_metrics_endpoint_with_cancellation(
                    &metrics_endpoint::MetricsEndpointConfig {
                        address: metrics_address,
                        registry: metrics.registry,
                        health_controller: None,
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

    // One vault client serves every vault role below. PKI certificates stay
    // on vault no matter which credential backend is configured.
    let vault_client = create_vault_client(&vault_config, metrics.meter.clone())?;
    let certificate_provider = vault_client.clone();

    let db_pool = setup::create_and_connect_postgres_pool(&carbide_config).await?;

    // Build the local-override readers (env, file); each is consulted only when
    // its [credentials.*] section is enabled. The backends (postgres,
    // vault) and the writer are chosen below.
    let env_reader: Option<Box<dyn CredentialReader>> = if credential_config.env.enabled() {
        Some(Box::new(
            carbide_secrets::local_credentials::EnvCredentials::new(credential_config.env.clone())?,
        ))
    } else {
        None
    };
    let file_reader: Option<Box<dyn CredentialReader>> = if credential_config.file.enabled() {
        Some(Box::new(
            carbide_secrets::local_credentials::FileCredentialsWatcher::new(
                credential_config.file.clone(),
            )
            .await?,
        ))
    } else {
        None
    };
    // The local overrides that ended up enabled, in order -- always tried
    // ahead of the backends.
    let local_overrides: Vec<Box<dyn CredentialReader>> =
        [env_reader, file_reader].into_iter().flatten().collect();

    // With a [secrets] section, the credential chain and write target come from
    // `backends`/`writer` -- defaulting to env -> file -> vault writing to vault,
    // so the section alone changes nothing. The one-time vault import is
    // independent: it runs iff `import_from` is set. Without the section, the
    // store comes from CARBIDE_CREDENTIAL_STORE: vault (the default), or an
    // in-memory store for development and testing.
    let (credential_manager, secrets_context): (
        Arc<dyn CredentialManager>,
        Option<SecretsContext>,
    ) = if let Some(ref secrets_config) = carbide_config.secrets {
        // Reject a nonsensical backends list before anything with side effects
        // runs (KMS task setup, the one-time vault import): a config error
        // should fail the boot cleanly, not after a partial, hard-to-undo
        // import that has already written the completion marker.
        crate::secrets::validate_backends(&secrets_config.backends)?;

        let routing = SecretRouting::from_config(&secrets_config.routing)
            .map_err(eyre::Report::new)
            .wrap_err("secrets routing configuration")?;
        let kms = build_kms_backend(
            secrets_config,
            &vault_config,
            &routing,
            &mut join_set,
            &cancel_token,
        )?;

        let pg_mgr = Arc::new(crate::secrets::PostgresCredentialManager::new(
            db_pool.clone(),
            routing.clone(),
            kms.clone(),
        ));
        tracing::info!(
            active_provider = %secrets_config.kms.active,
            backends = ?secrets_config.backends,
            writer = ?secrets_config.writer,
            "Postgres secrets backend configured"
        );
        // New writes all go to `writer`, but reads take the first backend in
        // `backends` that holds the path -- first-match-wins, evaluated per path.
        // So unless `writer` is the highest-priority backend, a write can be
        // shadowed: if a higher-priority backend also holds that path, reads keep
        // returning its value and never reach the writer's. E.g. with
        // backends = [vault, postgres] and writer = postgres, a path that exists
        // in both reads vault's value until vault's copy of that path is
        // removed (a read-after-write gap). The same gap exists when `writer`
        // is not in `backends` at all. Both reduce to "writer isn't the top
        // backend." We allow it -- a deliberate shadow-write is a valid, if
        // advanced, setup -- but warn so an accidental one is visible.
        let writer_is_top_backend = secrets_config.backends.first() == Some(&secrets_config.writer);
        if !writer_is_top_backend {
            tracing::warn!(
                writer = ?secrets_config.writer,
                backends = ?secrets_config.backends,
                "secrets writer's backend is not the highest-priority backend: a write to a path a \
                 higher-priority backend also holds is shadowed on read until that copy is removed \
                 (read-after-write gap)"
            );
        }

        // A one-time bulk import from vault, only when the operator asks for
        // one. Independent of backends/writer.
        if secrets_config.import_from == Some(ImportSource::Vault) {
            import_vault_secrets_once(
                &db_pool,
                secrets_config,
                &routing,
                kms.as_ref(),
                &vault_client,
            )
            .await?;
        }

        // Read order: the always-first local overrides, then the configured
        // backends in the operator's chosen order (first match wins). The write
        // target is the single backend `writer` names. (`backends` was
        // validated at the top of this branch, before any side effects.)
        let backend_readers =
            secrets_config
                .backends
                .iter()
                .map(|backend| -> Box<dyn CredentialReader> {
                    match backend {
                        CredentialBackend::Postgres => Box::new(pg_mgr.clone()),
                        CredentialBackend::Vault => Box::new(vault_client.clone()),
                    }
                });
        let chain: Vec<Box<dyn CredentialReader>> =
            local_overrides.into_iter().chain(backend_readers).collect();
        let writer: Arc<dyn CredentialWriter> = match secrets_config.writer {
            CredentialBackend::Vault => vault_client.clone(),
            CredentialBackend::Postgres => pg_mgr.clone(),
        };
        (
            create_credential_manager_from(writer, chain),
            Some(SecretsContext { routing, kms }),
        )
    } else {
        let store: Arc<dyn CredentialManager> = match std::env::var("CARBIDE_CREDENTIAL_STORE")
            .as_deref()
            .unwrap_or("vault")
        {
            "vault" => vault_client.clone(),
            "memory" => Arc::new(MemoryCredentialStore::default()),
            other => {
                return Err(eyre::eyre!(
                    "Invalid CARBIDE_CREDENTIAL_STORE value {other:?}: expected \"vault\" or \"memory\""
                ));
            }
        };
        // env -> file -> the configured store; nothing from [secrets] applies.
        let chain: Vec<Box<dyn CredentialReader>> = local_overrides
            .into_iter()
            .chain(std::iter::once(
                Box::new(store.clone()) as Box<dyn CredentialReader>
            ))
            .collect();
        (create_credential_manager_from(store, chain), None)
    };

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
        db_pool,
        secrets_context,
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

/// Build the KMS stack from the `[secrets.kms]` config: construct every
/// named provider, check the routed KEKs against them, and combine them so
/// the active provider wraps DEKs for new writes while any provider can
/// unwrap rows recorded with its kek_ids.
fn build_kms_backend(
    secrets_config: &SecretsConfig,
    vault_config: &VaultConfig,
    routing: &SecretRouting,
    join_set: &mut JoinSet<()>,
    cancel_token: &CancellationToken,
) -> eyre::Result<Arc<dyn KmsBackend>> {
    // BTreeMap so the provider list below has a stable order -- with
    // duplicate kek_ids rejected, order never decides which provider
    // unwraps, but stable beats arbitrary if that invariant ever slips.
    let mut built: BTreeMap<String, Arc<dyn KmsBackend>> = BTreeMap::new();

    for (name, provider_config) in &secrets_config.kms.providers {
        let provider: Arc<dyn KmsBackend> = match provider_config {
            ProviderConfig::Integrated { keys } => Arc::new(
                IntegratedKmsProvider::from_config(keys)
                    .map_err(eyre::Report::new)
                    .wrap_err_with(|| format!("KMS provider {name:?} key configuration"))?,
            ),
            ProviderConfig::Transit {
                keys,
                transit_mount,
            } => {
                // The same address, CA trust, and timeout ForgeVaultClient
                // connects with -- a bare vaultrs client only trusts public
                // roots and fails TLS against a site-CA-signed vault.
                let vault_settings =
                    carbide_secrets::create_raw_vault_client_settings(vault_config).wrap_err(
                        "building the Transit KMS vault client (Transit requires a static \
                         VAULT_TOKEN; the Kubernetes service-account login flow is not \
                         supported for Transit yet)",
                    )?;
                let vault_client = Arc::new(
                    vaultrs::client::VaultClient::new(vault_settings)
                        .map_err(|e| eyre::eyre!("vault client: {e}"))?,
                );
                let transit_provider = TransitKmsProvider::new(
                    vault_client,
                    transit_mount
                        .as_deref()
                        .unwrap_or(DEFAULT_TRANSIT_MOUNT)
                        .to_string(),
                    keys.clone(),
                );
                join_set
                    .build_task()
                    .name("transit_kms_token_renewal")
                    .spawn(transit_provider.run_token_renewal(cancel_token.clone()))?;
                Arc::new(transit_provider)
            }
        };
        tracing::info!(name = %name, "initialized KMS provider");
        built.insert(name.clone(), provider);
    }

    let active = built
        .get(&secrets_config.kms.active)
        .ok_or_else(|| {
            eyre::eyre!(
                "active KMS provider {:?} not found; configured providers: {:?}",
                secrets_config.kms.active,
                built.keys().collect::<Vec<_>>()
            )
        })?
        .clone();

    // Check the config against itself now, while a mismatch is a config
    // mistake. Found at runtime instead, a missing key is a write failure
    // on whichever credential first routes to it, and a duplicated key
    // makes unwraps depend on provider order.
    //
    // Every routed KEK must exist in the active provider, because all new
    // DEK wraps go through it. And no KEK may exist in two providers --
    // checked across every configured KEK, not just the routed ones,
    // because rows wrapped by a rotated-out KEK still unwrap through
    // whichever provider has it.
    for (prefix, kek_id) in routing.routes() {
        if !active.can_decrypt_kek(kek_id) {
            return Err(eyre::eyre!(
                "routing assigns {kek_id:?} (prefix {prefix:?}), but the active KMS \
                 provider {:?} does not have that key",
                secrets_config.kms.active
            ));
        }
    }
    let mut kek_owners: BTreeMap<String, Vec<&String>> = BTreeMap::new();
    for (name, provider) in &built {
        // Dedup within a provider first: a transit key list can repeat a
        // name, and that is harmless, not "two providers".
        let mut kek_ids = provider.kek_ids();
        kek_ids.sort();
        kek_ids.dedup();
        for kek_id in kek_ids {
            kek_owners.entry(kek_id).or_default().push(name);
        }
    }
    for (kek_id, owners) in &kek_owners {
        if owners.len() > 1 {
            return Err(eyre::eyre!(
                "kek_id {kek_id:?} exists in more than one KMS provider \
                 ({owners:?}); unwraps would be ambiguous"
            ));
        }
    }

    let providers: Vec<Arc<dyn KmsBackend>> = built.into_values().collect();
    Ok(Arc::new(MultiKmsProvider::new(active, providers)))
}

/// Run the one-time vault import, skipping if the completion marker is
/// already written. The caller gates this on `import_from` (a fresh site
/// simply omits it), so by the time we are here an import is wanted.
///
/// The import either completes before this process serves traffic, or the
/// process does not start: enumeration is strict (any vault list or read
/// failure aborts the boot), and an empty enumeration aborts too, because
/// an empty vault on a site configured to import from it is far more
/// likely a vault problem than a truly empty vault. A genuinely fresh
/// site simply omits `import_from`. Keeping it strict gives a clean,
/// all-or-nothing bulk copy with no half-imported state to reason about.
///
/// This is orthogonal to the reader chain and writer: an import seeds
/// Postgres with vault's secrets, but the read order and write target stay
/// exactly as `backends` / `writer` set them -- importing changes neither.
///
/// Rolling upgrades still need care once writes move to Postgres: a replica
/// running an older config can write rotated credentials to its own writer,
/// where they are stranded. Site-explorer credential rotation is the writer
/// to worry about; keep it disabled until the whole fleet runs a consistent
/// config.
async fn import_vault_secrets_once(
    db_pool: &PgPool,
    secrets_config: &SecretsConfig,
    routing: &SecretRouting,
    kms: &dyn KmsBackend,
    vault_client: &ForgeVaultClient,
) -> eyre::Result<()> {
    if is_import_complete(db_pool).await? {
        tracing::info!("Vault import already completed");
        return Ok(());
    }

    // Several replicas can boot against the same empty database at once.
    // The marker path's advisory lock lets one of them import while the
    // rest wait here, re-check the marker, and move on. It is a session
    // lock on a dedicated connection rather than a transaction-scoped one:
    // the import awaits Vault enumeration and pool-backed writes, and
    // holding a transaction across those would trip `txn_held_across_await`
    // and, under concurrent startup, risk waiters starving the pool the
    // importer itself needs. Detaching the connection guarantees the lock
    // releases when it drops, including on an early error return.
    let mut lock_conn = db_pool
        .acquire()
        .await
        .wrap_err("acquire vault import lock connection")?
        .detach();
    db::secrets::lock_path_session(&mut lock_conn, crate::secrets::VAULT_IMPORT_MARKER_PATH)
        .await
        .map_err(eyre::Report::new)
        .wrap_err("acquire vault import lock")?;

    if is_import_complete(db_pool).await? {
        tracing::info!("Vault import completed by another replica");
        return Ok(());
    }

    // Strict enumeration: any list or read failure aborts the boot rather
    // than importing a subset and recording it as complete. The marker is
    // permanent, so a partial import here would be silent credential loss.
    let vault_secrets = vault_client
        .get_secrets_strict()
        .await
        .map_err(eyre::Report::from)
        .wrap_err("enumerate vault secrets for import")?;

    if vault_secrets.is_empty() {
        return Err(eyre::eyre!(
            "vault enumeration returned no secrets; refusing to record an import from an \
             empty vault. If this site really has no vault secrets, remove import_from \
             from the [secrets] config; otherwise fix vault and restart"
        ));
    }

    tracing::info!(
        count = vault_secrets.len(),
        approach = ?secrets_config.import_approach,
        "Importing secrets from vault"
    );

    let result = crate::secrets::import_secrets(
        db_pool,
        routing,
        kms,
        &vault_secrets,
        secrets_config.import_approach,
    )
    .await
    .map_err(eyre::Report::new)
    .wrap_err("vault secret import")?;

    tracing::info!(
        imported = result.imported,
        skipped = result.skipped,
        "Vault secret import completed"
    );

    crate::secrets::mark_vault_import_complete(db_pool, routing, kms)
        .await
        .map_err(eyre::Report::new)
        .wrap_err("mark vault import complete")?;
    tracing::info!("Vault import marked complete");

    // lock_conn drops here, closing the connection and releasing the
    // session advisory lock.
    Ok(())
}

async fn is_import_complete(db_pool: &PgPool) -> eyre::Result<bool> {
    crate::secrets::is_vault_import_complete(db_pool)
        .await
        .map_err(eyre::Report::new)
        .wrap_err("check vault import status")
}
