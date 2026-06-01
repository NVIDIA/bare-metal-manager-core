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
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use carbide_dpa_interface_controller::DpaInfo;
use carbide_dpa_interface_controller::context::DpaInterfaceStateHandlerServices;
use carbide_dpa_interface_controller::handler::DpaInterfaceStateHandler;
use carbide_dpa_interface_controller::io::DpaInterfaceStateControllerIO;
use carbide_firmware::FirmwareDownloader;
use carbide_ib_fabric::IbFabricMonitor;
use carbide_ib_fabric::ib::{self, IBFabricManager};
use carbide_ib_partition_controller::context::IBPartitionStateHandlerServices;
use carbide_ib_partition_controller::handler::IBPartitionStateHandler;
use carbide_ib_partition_controller::io::IBPartitionStateControllerIO;
use carbide_ipmi::IPMITool;
use carbide_network_segment_controller::context::NetworkSegmentStateHandlerServices;
use carbide_network_segment_controller::handler::NetworkSegmentStateHandler;
use carbide_network_segment_controller::io::NetworkSegmentStateControllerIO;
use carbide_nvlink_manager::NvlPartitionMonitor;
use carbide_power_shelf_controller::context::PowerShelfStateHandlerServices;
use carbide_power_shelf_controller::handler::PowerShelfStateHandler;
use carbide_power_shelf_controller::io::PowerShelfStateControllerIO;
use carbide_preingestion_manager::PreingestionManager;
use carbide_rack::bms_client::BmsDsxExchangeHandle;
use carbide_rack_controller::config::RackConfig;
use carbide_rack_controller::context::RackStateHandlerServices;
use carbide_rack_controller::handler::RackStateHandler;
use carbide_rack_controller::io::RackStateControllerIO;
use carbide_redfish::libredfish::RedfishClientPool;
use carbide_redfish::nv_redfish::NvRedfishClientPool;
use carbide_site_explorer::SiteExplorer;
use carbide_spdm_controller::context::SpdmStateHandlerServices;
use carbide_spdm_controller::handler::SpdmAttestationStateHandler;
use carbide_spdm_controller::io::SpdmStateControllerIO;
use carbide_switch_controller::context::SwitchStateHandlerServices;
use carbide_switch_controller::handler::SwitchStateHandler;
use carbide_switch_controller::io::SwitchStateControllerIO;
use carbide_utils::HostPortPair;
use db::machine::update_dpu_asns;
use db::resource_pool::DefineResourcePoolError;
use db::{Transaction, work_lock_manager};
use eyre::WrapErr;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::{CredentialManager, CredentialReader};
use futures_util::TryFutureExt;
use librms::RackManagerClientPool;
use model::attestation::spdm::VerifierImpl;
use model::expected_machine::ExpectedMachine;
use model::ib::DEFAULT_IB_FABRIC_NAME;
use model::machine::HostHealthConfig;
use model::network_segment::NetworkDefinition;
use model::resource_pool::{self, ResourcePoolDef};
use model::route_server::RouteServerSourceType;
use opentelemetry::metrics::Meter;
use sqlx::postgres::PgSslMode;
use sqlx::{ConnectOptions, PgPool};
use sqlx_query_tracing::SQLX_STATEMENTS_LOG_LEVEL;
use state_controller::controller::{Enqueuer, StateController};
use state_controller::state_change_emitter::StateChangeEmitterBuilder;
use tokio::sync::Semaphore;
use tokio::sync::oneshot::Sender;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing_log::AsLog as _;

use crate::api::Api;
use crate::api::metrics::ApiMetricsEmitter;
use crate::cfg::file::{CarbideConfig, InitialObjectsConfig, ListenMode};
use crate::dpa::handler::start_dpa_handler;
use crate::dynamic_settings::DynamicSettings;
use crate::errors::CarbideError;
use crate::handlers::machine_validation::apply_config_on_startup;
use crate::listener::ApiListenMode;
use crate::logging::log_limiter::LogLimiter;
use crate::logging::service_health_metrics::{
    ServiceHealthContext, start_export_service_health_metrics,
};
use crate::machine_update_manager::MachineUpdateManager;
use crate::measured_boot::metrics_collector::MeasuredBootMetricsCollector;
use crate::mqtt_state_change_hook::hook::MqttStateChangeHook;
use crate::scout_stream::ConnectionRegistry;
use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::machine::context::MachineStateHandlerServices;
use crate::state_controller::machine::handler::MachineStateHandlerBuilder;
use crate::state_controller::machine::io::MachineStateControllerIO;
use crate::{attestation, db_init, ethernet_virtualization, listener};

/// The resolved set of network declarations passed from `start_api` into
/// `initialize_and_start_controllers`.
pub(crate) type NetworkDefinitionSources<'a> = Cow<'a, HashMap<String, NetworkDefinition>>;

/// Parse an `InitialObjectsConfig` file (the file pointed at by
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
fn all_configuration_files(carbide_config: &CarbideConfig) -> Vec<&Path> {
    carbide_config
        .config_ctx
        .as_ref()
        .into_iter()
        .flat_map(|f| f.metadata())
        .filter_map(|m| m.source.as_ref()?.file_path())
        .collect::<Vec<&Path>>()
}

/// Given a figment and the name of a resource pool, return a human-readable
/// string describing where the resource pool definition came from
/// (for logging purposes). This is used to provide more helpful log messages
/// when there are conflicting resource pool definitions.
fn pool_source(figment: Option<&Figment>, name: &str) -> String {
    figment
        .and_then(|f| f.find_metadata(&format!("pools.{name}")))
        .and_then(|m| m.source.as_ref())
        .map(|source| source.to_string())
        .unwrap_or_else(|| "carbide-api config".to_string())
}

/// Given a figment and the name of a network definition, return the human-readable
/// string describing where the network definition came from.
fn network_source(figment: Option<&Figment>, name: &str) -> String {
    figment
        .and_then(|f| f.find_metadata(&format!("networks.{name}")))
        .and_then(|m| m.source.as_ref())
        .map(|source| source.to_string())
        .unwrap_or_else(|| "carbide-api config".to_string())
}

/// Determines the authoritative set of resource pool definitions to reconcile
/// against the database at startup, merging `InitialObjectsConfig.pools`
/// with the legacy `CarbideConfig.pools` source.
/// #[allow(clippy::result_large_err)] is used instead of Box
/// because this function is called once on startup of carbide-api and never again
#[allow(clippy::result_large_err)]
fn resolve_initial_pools(
    carbide_config: &CarbideConfig,
    initial_objects: Option<&InitialObjectsConfig>,
) -> Result<HashMap<String, ResourcePoolDef>, DefineResourcePoolError> {
    let from_initial_objects = initial_objects.and_then(|io| io.pools.as_ref());
    let from_carbide_config = carbide_config.pools.as_ref();

    match (from_initial_objects, from_carbide_config) {
        // No pools are defined anywhere
        (None, None) => Err(DefineResourcePoolError::InvalidArgument(format!(
            "No resource pools are defined in loaded configuration files: {:?}",
            all_configuration_files(carbide_config)
        ))),
        // Pools are defined in InitialObjectsConfig.pools
        (Some(io), None) => Ok(io.clone()),
        // Pools are defined in CarbideConfig.pools
        (None, Some(cc)) => {
            for name in cc.keys() {
                let source = pool_source(carbide_config.config_ctx.as_ref(), name);
                tracing::warn!(
                    pool = %name,
                    source = %source,
                    "Resource pool `{name} is defined in {source}. Defining Resource Pools \
                    in {source}` is deprecated move the definitions into `initial_objects_file`. ")
            }
            Ok(cc.clone())
        }
        // Pools are defined in both CarbideConfig.pools and InitialObjects.pools
        (Some(io), Some(cc)) => {
            let mut merged = io.clone();
            let mut conflicts: Vec<String> = vec![];
            let mut legacy_names: Vec<String> = vec![];

            for (name, legacy_pool_def) in cc {
                match merged.get(name) {
                    // `ResourcePoolDef`'s exist in both CarbideConfig.pools and InitialObjectsConfig.pools but are not the same `ResourcePoolDef`
                    // This is a conflict and must be resolved by the operator
                    Some(new_def) if new_def != legacy_pool_def => conflicts.push(name.clone()),
                    // `ResourcePoolDef`'s exist in both CarbideConfig.pools and InitialObjectsConfig.pools and have identical
                    // `ResourcePoolDef`.  `legacy_names` is the name of the pools defined in CarbideConfig.pools
                    Some(_) => legacy_names.push(name.clone()),
                    None => {
                        // `ResourcePoolDef` only exists in `CarbideConfig.pools`. We still return the ResourcePoolDef,
                        // but we also want to alert operator that defining pools in `CarbideConfig.pool` is deprecated.
                        legacy_names.push(name.clone());
                        merged.insert(name.clone(), legacy_pool_def.clone());
                    }
                }
            }

            if !conflicts.is_empty() {
                let conflict_details: Vec<String> = conflicts
                    .iter()
                    .map(|name| {
                        format!(
                            "`{name}` (in {})",
                            pool_source(carbide_config.config_ctx.as_ref(), name)
                        )
                    })
                    .collect();
                return Err(DefineResourcePoolError::InvalidArgument(format!(
                    "resource pools have conflicting definitions \
                     {conflict_details:?}. Reconcile each pool by \
                     removing it from one source.",
                )));
            }
            for name in &legacy_names {
                let source = pool_source(carbide_config.config_ctx.as_ref(), name);
                tracing::warn!(
                    pool = %name,
                    source = %source,
                    "Resource pool `{name}` is still defined in both {source}. \
                     Move it into initial_objects_file to silence this warning.",
                );
            }
            Ok(merged)
        }
    }
}

/// Determines the authoritative set of network definitions to reconcile
/// against the database at startup, merging `InitialObjectsConfig.networks`
/// with the legacy `CarbideConfig.networks` source.
fn resolve_initial_networks<'a>(
    carbide_config: &'a CarbideConfig,
    initial_objects: Option<&'a InitialObjectsConfig>,
) -> eyre::Result<NetworkDefinitionSources<'a>> {
    let from_initial_objects = initial_objects.and_then(|io| io.networks.as_ref());
    let from_carbide_config = carbide_config.networks.as_ref();

    match (from_initial_objects, from_carbide_config) {
        // No networks are defined anywhere — initial network creation is skipped.
        (None, None) => Ok(Cow::Owned(HashMap::new())),
        // Networks are defined in InitialObjectsConfig.networks
        (Some(io), None) => Ok(Cow::Borrowed(io)),
        // Networks are defined only in the legacy CarbideConfig.networks
        (None, Some(cc)) => {
            for name in cc.keys() {
                let source = network_source(carbide_config.config_ctx.as_ref(), name);
                tracing::warn!(
                    network = %name,
                    source = %source,
                    "Network `{name}` is defined in {source}. Defining networks in {source} \
                     is deprecated; move the definitions into `initial_objects_file`.",
                );
            }
            Ok(Cow::Borrowed(cc))
        }
        // Networks are defined in both sources.
        (Some(io), Some(cc)) => {
            // detect conflicts.
            let conflicts: Vec<&str> = cc
                .iter()
                .filter(|(name, legacy_def)| {
                    io.get(name.as_str())
                        .is_some_and(|new_def| new_def != *legacy_def)
                })
                .map(|(name, _)| name.as_str())
                .collect();

            if !conflicts.is_empty() {
                // Each conflicting name is declared in both sources.
                // Name them both so the operator knows which two files
                // to compare.
                let conflict_details: Vec<String> = conflicts
                    .iter()
                    .map(|name| {
                        format!(
                            "`{name}` (in initial_objects_file vs {})",
                            network_source(carbide_config.config_ctx.as_ref(), name),
                        )
                    })
                    .collect();
                return Err(eyre::eyre!(
                    "networks have conflicting definitions {conflict_details:?}. \
                     Reconcile each network by removing it from one source.",
                ));
            }

            // merge legacy-only entries into the result.
            let mut merged = Cow::Borrowed(io);
            for (name, legacy_def) in cc {
                if !io.contains_key(name) {
                    merged.to_mut().insert(name.clone(), legacy_def.clone());
                }
            }

            // Every name in `cc` is still in the deprecated source —
            // emit one warning per name regardless of whether it was a
            // legacy-only entry or an identical overlap.
            for name in cc.keys() {
                let source = network_source(carbide_config.config_ctx.as_ref(), name);
                tracing::warn!(
                    network = %name,
                    source = %source,
                    "Network `{name}` is still defined in {source}. \
                     Move it into initial_objects_file to silence this warning.",
                );
            }
            Ok(merged)
        }
    }
}

pub fn parse_carbide_config(
    config_str: &Path,
    site_config_str: Option<&Path>,
) -> eyre::Result<Arc<CarbideConfig>> {
    let mut figment = Figment::new().merge(Toml::file(config_str));
    if let Some(site_config_str) = site_config_str {
        figment = figment.merge(Toml::file(site_config_str));
    }

    let merged_config = figment.merge(Env::prefixed("CARBIDE_API_"));
    let mut config: CarbideConfig = merged_config
        .extract()
        .wrap_err("Failed to load configuration files")?;

    config.config_ctx = Some(merged_config);

    for (label, _) in config
        .host_models
        .iter()
        .filter(|(_, host)| host.vendor == bmc_vendor::BMCVendor::Unknown)
    {
        tracing::error!("Host firmware configuration has invalid vendor for {label}")
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
                .max_concurrent_machine_updates_absolute = config.max_concurrent_machine_updates
        }
    }

    // Validate that admin-UI tool entries have unique names.
    config.validate_web_ui_sidebar_tools()?;

    // Publish the configured tool list to the web layer so the
    // admin-UI sidebar and per-machine "Logs" deep link can read it.
    crate::web::init_tools(config.web_ui_sidebar_tools.clone());

    // Validate that the firmware profile config keys match their inner
    // part_number and psid values. Mismatches are logged as warnings.
    config.validate_supernic_firmware_profiles();

    model::tenant::validate_trust_domain_allowlist_patterns(
        &config.machine_identity.trust_domain_allowlist,
    )
    .map_err(|e| eyre::eyre!(e).wrap_err("Invalid configuration"))?;

    model::tenant::validate_token_endpoint_domain_allowlist_patterns(
        &config.machine_identity.token_endpoint_domain_allowlist,
    )
    .map_err(|e| eyre::eyre!(e).wrap_err("Invalid configuration"))?;

    if config.machine_identity.enabled
        && config.machine_identity.current_encryption_key_id.is_none()
    {
        return Err(eyre::eyre!(
            "current_encryption_key_id must be set in [machine_identity] when machine identity is enabled"
        )
        .wrap_err("Invalid configuration"));
    }

    tracing::trace!("Carbide config: {:#?}", config.redacted());
    Ok(Arc::new(config))
}

pub fn create_ipmi_tool(
    credential_reader: Arc<dyn CredentialReader>,
    carbide_config: &CarbideConfig,
    bmc_proxy: Arc<ArcSwap<Option<HostPortPair>>>,
) -> Arc<dyn IPMITool> {
    match carbide_config.dpu_ipmi_tool_impl.as_deref() {
        Some("test") => {
            tracing::info!("Disabling ipmitool");
            carbide_ipmi::test_support()
        }
        Some("bmc-mock") => {
            tracing::info!("Using HTTP IPMI transport via bmc_proxy");
            carbide_ipmi::bmc_mock(bmc_proxy, credential_reader)
        }
        _ => {
            tracing::info!("Using lanplus IPMI transport (/usr/bin/ipmitool)");
            carbide_ipmi::tool(credential_reader, carbide_config.dpu_ipmi_reboot_attempts)
        }
    }
}
/// Configure and create a postgres connection pool
///
/// This connects to the database to verify settings
async fn create_and_connect_postgres_pool(config: &CarbideConfig) -> eyre::Result<PgPool> {
    // We need logs to be enabled at least at `INFO` level. Otherwise
    // our global logging filter would reject the logs before they get injected
    // into the `SqlxQueryTracing` layer.
    let mut database_connect_options = config
        .database_url
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .log_statements(SQLX_STATEMENTS_LOG_LEVEL.as_log().to_level_filter());
    if let Some(ref tls_config) = config.tls {
        let tls_disabled = std::env::var("DISABLE_TLS_ENFORCEMENT").is_ok(); // the integration test doesn't like this
        if !tls_disabled {
            tracing::info!("using TLS for postgres connection.");
            database_connect_options = database_connect_options
                .ssl_mode(PgSslMode::Require) //TODO: move this to VerifyFull once it actually works
                .ssl_root_cert(&tls_config.root_cafile_path);
        }
    }
    Ok(sqlx::pool::PoolOptions::new()
        .max_connections(config.max_database_connections)
        .connect_with(database_connect_options)
        .await?)
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all)]
pub async fn start_api(
    join_set: &mut JoinSet<()>,
    carbide_config: Arc<CarbideConfig>,
    initial_objects: Option<InitialObjectsConfig>,
    meter: Meter,
    dynamic_settings: DynamicSettings,
    shared_redfish_pool: Arc<dyn RedfishClientPool>,
    shared_nv_redfish_pool: Arc<NvRedfishClientPool>,
    credential_manager: Arc<dyn CredentialManager>,
    certificate_provider: Arc<dyn CertificateProvider>,
    cancel_token: CancellationToken,
    ready_channel: Sender<()>,
) -> eyre::Result<()> {
    let ipmi_tool = create_ipmi_tool(
        credential_manager.clone(),
        &carbide_config,
        dynamic_settings.bmc_proxy.clone(),
    );

    let db_pool = create_and_connect_postgres_pool(&carbide_config).await?;

    let work_lock_manager_handle = work_lock_manager::start(
        join_set,
        db_pool.clone(),
        work_lock_manager::KeepaliveConfig::default(),
    )
    .await?;

    let rms_client = match carbide_config.rms.api_url.clone() {
        Some(url) if !url.is_empty() => {
            let rms_client_config = librms::client_config::RmsClientConfig::new(
                carbide_config.rms.root_ca_path.clone(),
                carbide_config.rms.client_cert.clone(),
                carbide_config.rms.client_key.clone(),
                carbide_config.rms.enforce_tls,
            );
            let rms_api_config = librms::client::RmsApiConfig::new(&url, &rms_client_config);
            let rms_client_pool = librms::RmsClientPool::new(&rms_api_config);
            let shared_rms_client = rms_client_pool.create_client().await;
            Some(shared_rms_client)
        }
        _ => None,
    };
    let ib_config = carbide_config.ib_config.clone().unwrap_or_default();
    let fabric_manager_type = match ib_config.enabled {
        true => ib::IBFabricManagerType::Rest,
        false => ib::IBFabricManagerType::Disable,
    };

    let ib_fabric_ids = match ib_config.enabled {
        false => HashSet::new(),
        true => carbide_config.ib_fabrics.keys().cloned().collect(),
    };

    // Note: Normally we want initialize_and_start_controllers to be responsible for populating
    // information into the database, but resource pools and route servers need to be defined first,
    // since the controllers rely on a fully-hydrated Api object, which relies on route_servers and
    // common_pools being populated. So if we're configured for listen_only, strictly read them from
    // the database (assuming another instance has populated them), otherwise, populate them now.
    //
    // Pool reconciliation specifically must happen before `create_common_pools` runs below, because
    // that call queries `resource_pool` and bails if any mandatory pool is missing or empty.
    //
    // Resolve initial networks up-front so any configuration conflicts surface
    // before we touch the database. The actual reconcile/creation runs inside
    // `initialize_and_start_controllers`.
    let resolved_networks = resolve_initial_networks(&carbide_config, initial_objects.as_ref())?;

    if carbide_config.listen_only {
        tracing::info!(
            "Not populating resource pools or route_servers in database, as listen_only=true"
        );
    } else {
        // Determine the authoritative list of resource_pools to seed into the database
        let resolved_pools = resolve_initial_pools(&carbide_config, initial_objects.as_ref())?;
        let mut txn = Transaction::begin(&db_pool).await?;
        db::resource_pool::reconcile_pool_defs(&mut txn, &resolved_pools).await?;

        // We'll always update whatever route servers are in the config
        // to the database, and then leverage the enable_route_servers
        // flag where needed to determine if we actually want to use
        // them (like in api/src/handlers/dpu.rs). This allows us
        // to decouple the configuration from the feature, and control
        // the feature separately (it can get confusing -- and potentially
        // buggy -- otherwise).
        //
        // These are of course set with RouteServerSourceType::ConfigFile.
        let route_servers: Vec<IpAddr> = carbide_config
            .route_servers
            .iter()
            .map(|rs| IpAddr::from_str(rs))
            .collect::<Result<Vec<IpAddr>, _>>()
            .map_err(CarbideError::AddressParseError)?;
        db::route_servers::replace(&mut txn, &route_servers, RouteServerSourceType::ConfigFile)
            .await?;

        txn.commit().await?;
    };
    let common_pools =
        db::resource_pool::create_common_pools(db_pool.clone(), ib_fabric_ids).await?;

    let ib_fabric_manager_impl = ib::create_ib_fabric_manager(
        credential_manager.clone(),
        ib::IBFabricManagerConfig {
            endpoints: if ib_config.enabled {
                carbide_config
                    .ib_fabrics
                    .iter()
                    .map(|(fabric_id, fabric_definition)| {
                        (fabric_id.clone(), fabric_definition.endpoints.clone())
                    })
                    .collect()
            } else {
                Default::default()
            },
            allow_insecure_fabric_configuration: ib_config.allow_insecure,
            manager_type: fabric_manager_type,
            max_partition_per_tenant: ib_config.max_partition_per_tenant,
            mtu: ib_config.mtu,
            rate_limit: ib_config.rate_limit,
            service_level: ib_config.service_level,
            fabric_manager_run_interval: ib_config.fabric_monitor_run_interval,
        },
    )?;

    let ib_fabric_manager: Arc<dyn IBFabricManager> = Arc::new(ib_fabric_manager_impl);

    let site_fabric_prefixes = ethernet_virtualization::SiteFabricPrefixList::from_ipnetwork_vec(
        carbide_config.site_fabric_prefixes.clone(),
    );

    let eth_data = ethernet_virtualization::EthVirtData {
        asn: carbide_config.asn,
        dhcp_servers: carbide_config.dhcp_servers.clone(),
        deny_prefixes: carbide_config.deny_prefixes.clone(),
        site_fabric_prefixes,
    };

    let listen_mode = match &carbide_config.listen_mode {
        ListenMode::Tls => {
            let tls_ref = carbide_config.tls.as_ref().expect("Missing tls config");

            let tls_config = Arc::new(listener::ApiTlsConfig {
                identity_pemfile_path: tls_ref.identity_pemfile_path.clone(),
                identity_keyfile_path: tls_ref.identity_keyfile_path.clone(),
                root_cafile_path: tls_ref.root_cafile_path.clone(),
                admin_root_cafile_path: tls_ref.admin_root_cafile_path.clone(),
            });

            ApiListenMode::Tls(tls_config)
        }
        ListenMode::PlaintextHttp1 => ApiListenMode::PlaintextHttp1,
        ListenMode::PlaintextHttp2 => ApiListenMode::PlaintextHttp2,
    };

    let bmc_explorer = carbide_site_explorer::new_bmc_explorer(
        shared_redfish_pool.clone(),
        shared_nv_redfish_pool,
        ipmi_tool.clone(),
        credential_manager.clone(),
        carbide_config
            .site_explorer
            .rotate_switch_nvos_credentials
            .clone(),
        carbide_config.site_explorer.explore_mode,
    );

    let nvlink_config = carbide_config.nvlink_config.clone().unwrap_or_default();

    let mut nmxc_builder = libnmxc::NmxcClientPool::builder();
    if let Some(tls) = nmxc_tls_config_from_nvlink(&nvlink_config) {
        nmxc_builder = nmxc_builder.tls(tls);
    }
    let nmxc_client_pool = nmxc_builder
        .build()
        .map_err(|e| eyre::eyre!("Failed to build NMX-C client pool: {e}"))?;
    let shared_nmxc_pool: Arc<dyn libnmxc::NmxcPool> = Arc::new(nmxc_client_pool);

    // Create DPF SDK and initialize CRs if enabled
    // If we end up having static DPUDeployments, we could move the static CRs outside of the API.
    let dpf_sdk: Option<Arc<dyn crate::state_controller::machine::dpf::DpfOperations>> =
        if carbide_config.dpf.enabled {
            tracing::info!("Initializing DPF SDK");
            let repo = carbide_dpf::KubeRepository::new()
                .await
                .map_err(|e| eyre::eyre!("Failed to create DPF repository: {e}"))?;

            let provider = crate::state_controller::machine::dpf::CarbideBmcPasswordProvider::new(
                credential_manager.clone(),
            );

            let mandatory_services = carbide_config.dpf.services.clone();
            let dpf_mandatory_services = vec![
                crate::dpf_services::dts_service(&mandatory_services.dts),
                crate::dpf_services::doca_hbn_service(&mandatory_services.doca_hbn),
                crate::dpf_services::dhcp_server_service(&mandatory_services.dhcp_server),
                crate::dpf_services::dpu_agent_service(&mandatory_services.dpu_agent),
                crate::dpf_services::fmds_service(&mandatory_services.fmds),
                crate::dpf_services::otelcol_service(&mandatory_services.otel),
            ];

            // This is just temparary code until we make v2 only option. (just 2 weeks)
            // Soon v2 flag will be removed and will become only mode for dpf handling.
            let init_config = carbide_dpf::InitDpfResourcesConfig {
                bfb_url: carbide_config.dpf.bfb_url.clone(),
                flavor_name: carbide_config.dpf.flavor_name.clone(),
                deployment_name: carbide_config.dpf.deployment_name.clone(),
                services: dpf_mandatory_services,
            };

            let sdk = carbide_dpf::DpfSdkBuilder::new(repo, carbide_dpf::NAMESPACE, provider)
                .with_labeler(
                    crate::state_controller::machine::dpf::CarbideDPFLabeler::new(
                        carbide_config.dpf.node_label_key.clone(),
                    ),
                )
                .with_bmc_password_refresh_interval(std::time::Duration::from_secs(60))
                .with_join_set(join_set)
                .initialize(&init_config)
                .await
                .map_err(|err| eyre::eyre!("Failed to initialize DPF SDK: {err}"))?;

            Some(Arc::new(
                crate::state_controller::machine::dpf::DpfSdkOps::new(
                    Arc::new(sdk),
                    db_pool.clone(),
                    join_set,
                )?,
            ))
        } else {
            None
        };

    let component_manager = if let Some(cd_config) = &carbide_config.component_manager {
        match component_manager::component_manager::build_component_manager(
            cd_config,
            rms_client.clone(),
            Some(db_pool.clone()),
            Some(shared_redfish_pool.clone()),
        )
        .await
        {
            Ok(cm) => {
                tracing::info!(
                    "Component manager configured (nv_switch={}, power_shelf={}, compute_tray={})",
                    cm.nv_switch.name(),
                    cm.power_shelf.name(),
                    cm.compute_tray.name()
                );
                Some(cm)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to build component managers, component manager RPCs will be unavailable: {e}"
                );
                None
            }
        }
    } else {
        tracing::info!(
            "No [component_manager] config found; component manager RPCs will be unavailable"
        );
        None
    };

    let api_service = Arc::new(Api {
        certificate_provider,
        common_pools,
        credential_manager,
        database_connection: db_pool.clone(),
        dpu_health_log_limiter: LogLimiter::default(),
        dynamic_settings,
        endpoint_explorer: bmc_explorer,
        eth_data,
        ib_fabric_manager,
        redfish_pool: shared_redfish_pool,
        runtime_config: carbide_config.clone(),
        scout_stream_registry: ConnectionRegistry::new(),
        rms_client: rms_client.clone(),
        nmxc_client_pool: shared_nmxc_pool.clone(),
        work_lock_manager_handle,
        dpf_sdk: dpf_sdk.clone(),
        machine_state_handler_enqueuer: Enqueuer::new(db_pool),
        metric_emitter: ApiMetricsEmitter::new(&meter),
        component_manager,
        bms_client: std::sync::OnceLock::new(),
    });

    if carbide_config.listen_only {
        tracing::info!("Not starting background services, as listen_only=true");
    } else {
        initialize_and_start_controllers(
            join_set,
            api_service.clone(),
            meter.clone(),
            ipmi_tool.clone(),
            resolved_networks,
            cancel_token.clone(),
        )
        .await?;
    };

    listener::start(
        join_set,
        api_service,
        listen_mode,
        carbide_config.listen,
        &carbide_config.auth,
        meter,
        cancel_token.clone(),
    )
    .await?;

    ready_channel
        .send(())
        .inspect_err(|_e| {
            // Note: the `_e` here is just sending us back (rejecting) the () that we sent to the ready
            // channel. This will only happen if the other end is closed.
            tracing::warn!(
                "Bug: api server ready_channel is closed, could not notify readiness status"
            )
        })
        .ok();

    Ok(())
}

/// Initialize and spawn all controllers and background tasks.
///
/// All background tasks will be spawned into `join_set`, which can be awaited with
/// [`JoinSet::join_all`] to wait for them to complete.
pub async fn initialize_and_start_controllers<'a>(
    join_set: &mut JoinSet<()>,
    api_service: Arc<Api>,
    meter: Meter,
    ipmi_tool: Arc<dyn IPMITool>,
    initial_networks: NetworkDefinitionSources<'a>,
    cancel_token: CancellationToken,
) -> eyre::Result<()> {
    let Api {
        runtime_config: carbide_config,
        endpoint_explorer: bmc_explorer,
        common_pools,
        database_connection: db_pool,
        ib_fabric_manager,
        redfish_pool: shared_redfish_pool,
        work_lock_manager_handle,
        rms_client,
        dpf_sdk,
        credential_manager,
        ..
    } = api_service.as_ref();
    // As soon as we get the database up, observe this version of forge so that we know when it was
    // first deployed
    {
        let mut txn = Transaction::begin(db_pool).await?;

        db::carbide_version::observe_as_latest_version(
            &mut txn,
            carbide_version::v!(build_version),
        )
        .await?;

        txn.commit().await?;
    }

    if let Some(domain_name) = &carbide_config.initial_domain_name
        && db_init::create_initial_domain(db_pool.clone(), domain_name).await?
    {
        tracing::info!("Created initial domain {domain_name}");
    }

    const EXPECTED_MACHINE_FILE_PATH: &str = "/etc/forge/carbide-api/site/expected_machines.json";
    if let Ok(file_str) = tokio::fs::read_to_string(EXPECTED_MACHINE_FILE_PATH).await {
        let expected_machines = serde_json::from_str::<Vec<ExpectedMachine>>(file_str.as_str()).inspect_err(|err| {
                tracing::error!("expected_machines.json file exists, but unable to parse expected_machines file, nothing was written to db, bailing: {err}.");
            })?;
        let mut txn = Transaction::begin(db_pool).await?;
        crate::handlers::expected_machine::create_missing_from(&mut txn, &expected_machines)
            .await
            .inspect_err(|err| {
                tracing::error!(
                    "Unable to update database from expected_machines list, bailing: {err}"
                );
            })?;
        txn.commit().await?;
        tracing::info!("Successfully wrote expected machines to db, continuing startup.");
    } else {
        tracing::info!("No expected machine file found, continuing startup.");
    }

    let ib_config = carbide_config.ib_config.clone().unwrap_or_default();

    if ib_config.enabled {
        // These are some sanity checks until full multi-fabric support is available
        // Right now there is only one fabric supported, and it needs to be called `default`
        if carbide_config.ib_fabrics.len() > 1 {
            return Err(eyre::eyre!(
                "Only a single IB fabric definition is allowed at the moment"
            ));
        }

        if !carbide_config.ib_fabrics.is_empty() {
            let fabric_id = carbide_config.ib_fabrics.iter().next().unwrap().0;
            if fabric_id != DEFAULT_IB_FABRIC_NAME {
                return Err(eyre::eyre!(
                    "ib_fabrics contains an entry \"{fabric_id}\", but only \"{DEFAULT_IB_FABRIC_NAME}\" is supported at the moment"
                ));
            }
        }

        // Populate IB specific resource pools
        let mut txn = Transaction::begin(db_pool).await?;

        for (fabric_id, x) in carbide_config.ib_fabrics.iter() {
            db::resource_pool::define(
                &mut txn,
                &model::resource_pool::common::ib_pkey_pool_name(fabric_id),
                &resource_pool::ResourcePoolDef {
                    pool_type: model::resource_pool::define::ResourcePoolType::Integer,
                    ranges: x.pkeys.clone(),
                    prefix: None,
                    delegate_prefix_len: None,
                },
            )
            .await?;
        }

        txn.commit().await?;
    }

    let health_pool = db_pool.clone();
    start_export_service_health_metrics(ServiceHealthContext {
        meter: meter.clone(),
        database_pool: health_pool,
        resource_pool_stats: common_pools.pool_stats.clone(),
    });

    if !initial_networks.is_empty() {
        db_init::create_initial_networks(&api_service, db_pool, &initial_networks).await?;
    }

    if let Some(fnn_config) = carbide_config.fnn.as_ref()
        && let Some(admin) = fnn_config.admin_vpc.as_ref()
        && admin.enabled
    {
        db_init::create_admin_vpc(db_pool, admin.vpc_vni).await?;
    }
    // Update SVI IP to segments which have VPC attached and type is FNN.
    db_init::update_network_segments_svi_ip(db_pool).await?;

    db_init::store_initial_dpu_agent_upgrade_policy(
        db_pool,
        carbide_config.initial_dpu_agent_upgrade_policy,
    )
    .await?;

    if let Err(e) = update_dpu_asns(db_pool, common_pools).await {
        tracing::warn!("Failed to update ASN for DPUs: {e}");
    }

    let downloader = FirmwareDownloader::new();
    let upload_limiter = Arc::new(Semaphore::new(carbide_config.firmware_global.max_uploads));

    let mut dpa_info: Option<Arc<DpaInfo>> = None;

    if carbide_config.is_dpa_enabled() {
        let mqtt_client =
            Some(start_dpa_handler(join_set, api_service.clone(), cancel_token.clone()).await?);
        let subnet_ip = carbide_config.get_dpa_subnet_ip()?;

        let subnet_mask = carbide_config.get_dpa_subnet_mask()?;

        let info: DpaInfo = DpaInfo {
            subnet_ip,
            subnet_mask,
            mqtt_client,
        };

        dpa_info = Some(Arc::new(info));
    }

    // Create state change emitter with DSX Exchange Event Bus hook if enabled
    let state_change_emitter = {
        let mut emitter_builder = StateChangeEmitterBuilder::default();

        if let Some(ref config) = carbide_config.dsx_exchange_event_bus
            && config.enabled
        {
            let options = {
                let defaults =
                    mqttea::client::ClientOptions::default().with_qos(mqttea::QoS::AtMostOnce);

                if let Some(provider) = crate::auth::mqtt_auth::build_credentials_provider(
                    &config.auth,
                    forge_secrets::credentials::CredentialKey::MqttAuth {
                        credential_type:
                            forge_secrets::credentials::MqttCredentialType::DsxExchangeEventBus,
                    },
                    api_service.credential_manager.clone(),
                )
                .await?
                {
                    defaults.with_credentials_provider(provider)
                } else {
                    defaults
                }
            };

            // Suffix the broker-level client identifier so multiple replicas
            // (or a new pod coming up while the old one is still terminating)
            // do not race for the same MQTT session and ping-pong each other
            // off the broker.
            let client_id = mqttea::unique_client_id("carbide-dsx-exchange-event-bus");
            let client = mqttea::MqtteaClient::new(
                &config.mqtt_endpoint,
                config.mqtt_broker_port,
                &client_id,
                Some(options),
            )
            .map_err(|e| eyre::eyre!("Failed to create DSX Exchange Event Bus MQTT client: {e}"))
            .await?;

            client.connect().await.map_err(|e| {
                eyre::eyre!("Failed to connect DSX Exchange Event Bus MQTT client: {e}")
            })?;

            tracing::info!(
                "DSX Exchange Event Bus enabled, publishing to {}:{}",
                config.mqtt_endpoint,
                config.mqtt_broker_port
            );

            let bms_client = BmsDsxExchangeHandle::new(
                client.clone(),
                db_pool,
                join_set,
                config.publish_timeout,
                config.queue_capacity,
                &meter,
                cancel_token.clone(),
            )
            .await?;

            api_service
                .bms_client
                .set(bms_client)
                .map_err(|_| eyre::eyre!("BMS DSX Exchange handle already initialized"))?;

            emitter_builder = emitter_builder.hook(Box::new(MqttStateChangeHook::new(
                client,
                join_set,
                config.publish_timeout,
                config.topic_prefix.clone(),
                config.queue_capacity,
                &meter,
                cancel_token.clone(),
            )));
        }

        emitter_builder.build()
    };

    let handler_services = Arc::new(CommonStateHandlerServices {
        db_pool: db_pool.clone(),
        db_reader: db_pool.clone().into(),
        redfish_client_pool: shared_redfish_pool.clone(),
        ib_fabric_manager: ib_fabric_manager.clone(),
        ib_pools: common_pools.infiniband.clone(),
        ipmi_tool: ipmi_tool.clone(),
        site_config: carbide_config.clone(),
        dpa_info,
        rms_client: rms_client.clone(),
        switch_system_image_rms_client: carbide_config
            .rms
            .api_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .map(|url| {
                let rms_client_config = librms::client_config::RmsClientConfig::new(
                    carbide_config.rms.root_ca_path.clone(),
                    carbide_config.rms.client_cert.clone(),
                    carbide_config.rms.client_key.clone(),
                    carbide_config.rms.enforce_tls,
                );
                let rms_api_config = librms::client::RmsApiConfig::new(url, &rms_client_config);
                Arc::new(librms::RackManagerApi::new(&rms_api_config))
                    as Arc<dyn carbide_rack::rms_client::SwitchSystemImageRmsClient>
            }),
        credential_manager: credential_manager.clone(),
    });

    // Use the hostname as cluster-wide state controller ID
    // The expectation here is that either the host only runs a single
    // carbide instance natively, or - if the multiple instances run as containers
    // - every container gets its own hostname (k8s pod name)
    let state_controller_id = hostname::get()
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string().into())
        .to_string_lossy()
        .to_string();

    // handles need to be stored in a variable
    // If they are assigned to _ then the destructor will be immediately called
    StateController::<MachineStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_machines", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(
            MachineStateHandlerServices {
                db_pool: handler_services.db_pool.clone(),
                db_reader: handler_services.db_reader.clone(),
                redfish_client_pool: handler_services.redfish_client_pool.clone(),
                ipmi_tool: handler_services.ipmi_tool.clone(),
                site_config: handler_services
                    .site_config
                    .machine_state_handler_site_config()
                    .into(),
            }
            .into(),
        )
        .iteration_config((&carbide_config.machine_state_controller.controller).into())
        .state_handler(Arc::new(
            MachineStateHandlerBuilder::builder()
                .dpu_up_threshold(carbide_config.machine_state_controller.dpu_up_threshold)
                .dpu_nic_firmware_reprovision_update_enabled(
                    carbide_config
                        .dpu_config
                        .dpu_nic_firmware_reprovision_update_enabled,
                )
                .dpu_enable_secure_boot(carbide_config.dpu_config.dpu_enable_secure_boot)
                .dpu_wait_time(carbide_config.machine_state_controller.dpu_wait_time)
                .power_down_wait(carbide_config.machine_state_controller.power_down_wait)
                .failure_retry_time(carbide_config.machine_state_controller.failure_retry_time)
                .scout_reporting_timeout(
                    carbide_config
                        .machine_state_controller
                        .scout_reporting_timeout,
                )
                .uefi_boot_wait(carbide_config.machine_state_controller.uefi_boot_wait)
                .hardware_models(carbide_config.get_firmware_config())
                .firmware_downloader(&downloader)
                .attestation_enabled(carbide_config.attestation_enabled)
                .upload_limiter(upload_limiter.clone())
                .machine_validation_config(carbide_config.machine_validation_config.clone())
                .common_pools(common_pools.clone())
                .bom_validation(carbide_config.bom_validation)
                .no_firmware_update_reset_retries(carbide_config.firmware_global.no_reset_retries)
                .instance_autoreboot_period(
                    carbide_config
                        .machine_updater
                        .instance_autoreboot_period
                        .clone(),
                )
                .credential_reader(api_service.credential_manager.clone())
                .power_options_config(carbide_config.power_manager_options.clone().into())
                .dpf_sdk(dpf_sdk.clone())
                .build(),
        ))
        .io(Arc::new(MachineStateControllerIO {
            host_health: HostHealthConfig {
                hardware_health_reports: carbide_config.host_health.hardware_health_reports,
                dpu_agent_version_staleness_threshold: carbide_config
                    .host_health
                    .dpu_agent_version_staleness_threshold,
                prevent_allocations_on_stale_dpu_agent_version: carbide_config
                    .host_health
                    .prevent_allocations_on_stale_dpu_agent_version,
                prevent_allocations_on_scout_heartbeat_timeout: carbide_config
                    .host_health
                    .prevent_allocations_on_scout_heartbeat_timeout,
                suppress_external_alerting_on_scout_heartbeat_timeout: carbide_config
                    .host_health
                    .suppress_external_alerting_on_scout_heartbeat_timeout,
            },
            sla_config: model::machine::slas::MachineSlaConfig::new(
                carbide_config.machine_state_controller.failure_retry_time,
            ),
        }))
        .state_change_emitter(state_change_emitter)
        .build_and_spawn(join_set, cancel_token.clone())
        .expect("Unable to build MachineStateController");

    let sc_pool_vlan_id = common_pools.ethernet.pool_vlan_id.clone();
    let sc_pool_vni = common_pools.ethernet.pool_vni.clone();

    let ns_builder = StateController::<NetworkSegmentStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_network_segments", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(
            NetworkSegmentStateHandlerServices {
                db_pool: handler_services.db_pool.clone(),
            }
            .into(),
        );
    ns_builder
        .iteration_config((&carbide_config.network_segment_state_controller.controller).into())
        .state_handler(Arc::new(NetworkSegmentStateHandler::new(
            carbide_config
                .network_segment_state_controller
                .network_segment_drain_time,
            sc_pool_vlan_id,
            sc_pool_vni,
        )))
        .build_and_spawn(join_set, cancel_token.clone())
        .expect("Unable to build NetworkSegmentController");

    if carbide_config.is_dpa_enabled() {
        tracing::info!("Starting DpaInterfaceStateController as dpa is enabled");
        StateController::<DpaInterfaceStateControllerIO>::builder()
            .database(db_pool.clone(), work_lock_manager_handle.clone())
            .meter("carbide_dpa_interfaces", meter.clone())
            .processor_id(state_controller_id.clone())
            .services(
                DpaInterfaceStateHandlerServices {
                    db_pool: handler_services.db_pool.clone(),
                    db_reader: handler_services.db_reader.clone(),
                    dpa_info: handler_services.dpa_info.clone(),
                    hb_interval: handler_services.site_config.get_hb_interval(),
                }
                .into(),
            )
            .iteration_config((&carbide_config.dpa_interface_state_controller.controller).into())
            .state_handler(Arc::new(DpaInterfaceStateHandler {}))
            .build_and_spawn(join_set, cancel_token.clone())
            .expect("Unable to build DpaInterfaceStateController");
    }

    if carbide_config.spdm.enabled {
        let Some(nras_config) = carbide_config.spdm.nras_config.clone() else {
            return Err(eyre::eyre!(
                "SPDM attestation is enabled but NRAS Config is missing!!"
            ));
        };

        let verifier = Arc::new(VerifierImpl::default());

        StateController::<SpdmStateControllerIO>::builder()
            .database(db_pool.clone(), work_lock_manager_handle.clone())
            .meter("carbide_spdm_attestation", meter.clone())
            .processor_id(state_controller_id.clone())
            .services(
                SpdmStateHandlerServices {
                    db_pool: handler_services.db_pool.clone(),
                    redfish_client_pool: handler_services.redfish_client_pool.clone(),
                }
                .into(),
            )
            .iteration_config((&carbide_config.spdm_state_controller.controller).into())
            .state_handler(Arc::new(SpdmAttestationStateHandler::new(
                verifier,
                nras_config,
            )))
            .build_and_spawn(join_set, cancel_token.clone())
            .expect("Unable to build SpdmStateController");
    }

    StateController::<IBPartitionStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_ib_partitions", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(
            IBPartitionStateHandlerServices {
                db_pool: handler_services.db_pool.clone(),
                ib_fabric_manager: handler_services.ib_fabric_manager.clone(),
                ib_pools: handler_services.ib_pools.clone(),
            }
            .into(),
        )
        .iteration_config((&carbide_config.ib_partition_state_controller.controller).into())
        .state_handler(Arc::new(IBPartitionStateHandler::default()))
        .build_and_spawn(join_set, cancel_token.clone())
        .expect("Unable to build IBPartitionStateController");

    StateController::<PowerShelfStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_power_shelves", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(
            PowerShelfStateHandlerServices {
                db_pool: handler_services.db_pool.clone(),
                rms_client: handler_services.rms_client.clone(),
                credential_manager: handler_services.credential_manager.clone(),
            }
            .into(),
        )
        .iteration_config((&carbide_config.power_shelf_state_controller.controller).into())
        .state_handler(Arc::new(PowerShelfStateHandler::default()))
        .build_and_spawn(join_set, cancel_token.clone())
        .expect("Unable to build PowerShelfStateController");

    StateController::<RackStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_racks", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(
            RackStateHandlerServices {
                db_pool: handler_services.db_pool.clone(),
                rms_client: handler_services.rms_client.clone(),
                site_config: RackConfig {
                    rms: handler_services.site_config.rms.clone(),
                    rack_validation_config: handler_services
                        .site_config
                        .rack_validation_config
                        .clone(),
                    rack_profiles: handler_services.site_config.rack_profiles.clone(),
                }
                .into(),
                switch_system_image_rms_client: handler_services
                    .switch_system_image_rms_client
                    .clone(),
                credential_manager: handler_services.credential_manager.clone(),
            }
            .into(),
        )
        .state_handler(Arc::new(RackStateHandler::default()))
        .build_and_spawn(join_set, cancel_token.clone())
        .expect("Unable to build RackStateController");

    StateController::<SwitchStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_switches", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(
            SwitchStateHandlerServices {
                db_pool: handler_services.db_pool.clone(),
                rms_client: handler_services.rms_client.clone(),
                credential_manager: handler_services.credential_manager.clone(),
            }
            .into(),
        )
        .iteration_config((&carbide_config.switch_state_controller.controller).into())
        .state_handler(Arc::new(SwitchStateHandler::default()))
        .build_and_spawn(join_set, cancel_token.clone())
        .expect("Unable to build SwitchStateController");

    IbFabricMonitor::new(
        db_pool.clone(),
        if ib_config.enabled {
            carbide_config.ib_fabrics.clone()
        } else {
            Default::default()
        },
        meter.clone(),
        ib_fabric_manager.clone(),
        carbide_config.host_health,
        work_lock_manager_handle.clone(),
    )
    .start(join_set, cancel_token.clone())?;

    NvlPartitionMonitor::new(
        db_pool.clone(),
        api_service.nmxc_client_pool.clone(),
        meter.clone(),
        carbide_config.nvlink_config.clone().unwrap_or_default(),
        carbide_config.host_health,
        work_lock_manager_handle.clone(),
    )
    .start(join_set, cancel_token.clone())?;

    SiteExplorer::new(
        db_pool.clone(),
        carbide_config.site_explorer.clone(),
        meter.clone(),
        bmc_explorer.clone(),
        Arc::new(carbide_config.get_firmware_config()),
        common_pools.clone(),
        work_lock_manager_handle.clone(),
        rms_client.clone(),
        credential_manager.clone(),
    )
    .start(join_set, cancel_token.clone())?;

    MachineUpdateManager::new(
        db_pool.clone(),
        carbide_config.clone(),
        meter.clone(),
        work_lock_manager_handle.clone(),
        dpf_sdk.clone(),
    )
    .start(join_set, cancel_token.clone())?;

    PreingestionManager::new(
        db_pool.clone(),
        carbide_config.preingestion_manager(),
        shared_redfish_pool.clone(),
        meter.clone(),
        Some(downloader.clone()),
        Some(upload_limiter),
        Some(api_service.credential_manager.clone()),
        work_lock_manager_handle.clone(),
    )
    .start(join_set, cancel_token.clone())?;

    MeasuredBootMetricsCollector::new(
        db_pool.clone(),
        carbide_config.measured_boot_collector.clone(),
        meter.clone(),
    )
    .start(join_set, cancel_token.clone())?;

    // we need to create ek_cert_status entries for all existing machines
    attestation::backfill_ek_cert_status_for_existing_machines(db_pool).await?;

    crate::machine_validation::MachineValidationManager::new(
        db_pool.clone(),
        carbide_config.machine_validation_config.clone(),
        meter.clone(),
    )
    .start(join_set, cancel_token.clone())?;

    apply_config_on_startup(
        &api_service,
        &carbide_config.machine_validation_config.clone(),
    )
    .await?;

    Ok(())
}

fn nmxc_tls_config_from_nvlink(
    cfg: &carbide_nvlink_manager::config::NvLinkConfig,
) -> Option<libnmxc::NmxcTlsConfig> {
    let ca = cfg.nmx_c_tls_ca_cert_path.as_ref().map(PathBuf::from);
    let client_cert = cfg.nmx_c_tls_client_cert_path.as_ref().map(PathBuf::from);
    let client_key = cfg.nmx_c_tls_client_key_path.as_ref().map(PathBuf::from);
    if ca.is_none()
        && client_cert.is_none()
        && client_key.is_none()
        && cfg.nmx_c_tls_authority.is_none()
    {
        return None;
    }
    Some(libnmxc::NmxcTlsConfig {
        ca_cert_path: ca,
        client_cert_path: client_cert,
        client_key_path: client_key,
        authority: cfg.nmx_c_tls_authority.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use figment::Figment;
    use figment::providers::{Format, Toml};
    use model::network_segment::{NetworkDefinition, NetworkDefinitionSegmentType};
    use model::resource_pool::ResourcePoolType;
    use model::resource_pool::define::ResourcePoolDef;

    use super::{resolve_initial_networks, resolve_initial_pools};
    use crate::cfg::file::{CarbideConfig, InitialObjectsConfig};

    fn carbide_with_networks(
        networks: Option<HashMap<String, NetworkDefinition>>,
    ) -> CarbideConfig {
        let mut cfg: CarbideConfig = Figment::new()
            .merge(Toml::string(
                r#"
               database_url = "postgres://test"
               listen = "[::]:1081"
               asn = 1
            "#,
            ))
            .extract()
            .expect("Unable to extract config");
        cfg.networks = networks;
        cfg
    }
    // Builds a `CarbideConfig` from the smallest valid TOML and overrides
    // the `pools` field. `resolve_initial_pools` only reads `.pools`, so
    // the rest of the config can be defaulted.
    fn carbide_with_pools(pools: Option<HashMap<String, ResourcePoolDef>>) -> CarbideConfig {
        let mut cfg: CarbideConfig = Figment::new()
            .merge(Toml::string(
                r#"
                    database_url = "postgres://test"
                    listen = "[::]:1081"
                    asn = 1
                "#,
            ))
            .extract()
            .expect("minimal CarbideConfig parses");
        cfg.pools = pools;
        cfg
    }

    fn network_definition(
        prefix: &str,
        segment_type: NetworkDefinitionSegmentType,
    ) -> NetworkDefinition {
        NetworkDefinition {
            segment_type,
            prefix: prefix.to_string(),
            gateway: "".to_string(),
            mtu: 0,
            reserve_first: 0,
            allocation_strategy: Default::default(),
        }
    }

    fn ipv4_pool(prefix: &str) -> ResourcePoolDef {
        ResourcePoolDef {
            ranges: Vec::new(),
            prefix: Some(prefix.to_string()),
            pool_type: ResourcePoolType::Ipv4,
            delegate_prefix_len: None,
        }
    }

    fn network_map(entries: &[(&str, NetworkDefinition)]) -> HashMap<String, NetworkDefinition> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }
    fn pool_map(entries: &[(&str, ResourcePoolDef)]) -> HashMap<String, ResourcePoolDef> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect()
    }

    fn initial_objects_networks(entries: &[(&str, NetworkDefinition)]) -> InitialObjectsConfig {
        InitialObjectsConfig {
            pools: None,
            networks: Some(network_map(entries)),
        }
    }

    fn initial_objects_pools(entries: &[(&str, ResourcePoolDef)]) -> InitialObjectsConfig {
        InitialObjectsConfig {
            pools: Some(pool_map(entries)),
            networks: None,
        }
    }

    // neither source declares pools — operator misconfiguration.
    #[test]
    fn no_pool_sources_errors() {
        let cfg = carbide_with_pools(None);
        let err =
            resolve_initial_pools(&cfg, None).expect_err("missing pools must surface as an error");
        assert!(
            err.to_string().to_lowercase().contains("no resource pools"),
            "error message should name the missing input: {err}"
        );
    }

    // only `InitialObjectsConfig.pools` declares pools
    #[test]
    fn initial_objects_only_succeeds() {
        let cfg = carbide_with_pools(None);
        let io = initial_objects_pools(&[("lo-ip", ipv4_pool("10.0.0.0/24"))]);

        let resolved =
            resolve_initial_pools(&cfg, Some(&io)).expect("InitialObjectsConfig-only must succeed");

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get("lo-ip"), Some(&ipv4_pool("10.0.0.0/24")));
    }

    // only legacy `CarbideConfig.pools` declares pools — the
    // Returns the legacy map; emits a deprecation warning
    #[test]
    fn legacy_only_returns_legacy_pools() {
        let cfg = carbide_with_pools(Some(pool_map(&[("lo-ip", ipv4_pool("10.0.0.0/24"))])));

        let resolved = resolve_initial_pools(&cfg, None).expect("legacy-only must succeed");

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get("lo-ip"), Some(&ipv4_pool("10.0.0.0/24")));
    }

    // both sources declare pools but with disjoint names
    // Resolver returns the union; emits a deprecation warning naming the still-legacy entries.
    #[test]
    fn disjoint_union_returns_all_pools() {
        let cfg = carbide_with_pools(Some(pool_map(&[("legacy-only", ipv4_pool("10.0.1.0/24"))])));
        let io = initial_objects_pools(&[("new-only", ipv4_pool("10.0.2.0/24"))]);

        let resolved = resolve_initial_pools(&cfg, Some(&io)).expect("disjoint union must succeed");

        assert_eq!(resolved.len(), 2);
        assert!(resolved.contains_key("legacy-only"));
        assert!(resolved.contains_key("new-only"));
    }

    // both sources declare the same pool with identical defs —
    // Resolver dedupes silently; the still-legacy entry is included in the deprecation warning.
    #[test]
    fn overlap_identical_succeeds() {
        let pool = ipv4_pool("10.0.0.0/24");
        let cfg = carbide_with_pools(Some(pool_map(&[("lo-ip", pool.clone())])));
        let io = initial_objects_pools(&[("lo-ip", pool.clone())]);

        let resolved = resolve_initial_pools(&cfg, Some(&io)).expect("identical defs must succeed");

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get("lo-ip"), Some(&pool));
    }

    // both sources declare the same pool with different defs —
    // Resolver must fail loudly so the bad state is fixed before reconcile runs.
    #[test]
    fn overlap_conflict_errors() {
        let cfg = carbide_with_pools(Some(pool_map(&[("lo-ip", ipv4_pool("10.0.0.0/24"))])));
        let io = initial_objects_pools(&[("lo-ip", ipv4_pool("10.0.0.0/16"))]);

        let err = resolve_initial_pools(&cfg, Some(&io)).expect_err("conflicting defs must error");

        assert!(
            err.to_string().contains("lo-ip"),
            "error message should name the conflicting pool: {err}"
        );
    }

    // every overlap is a conflict — the resolver collects all
    // bad names so the operator can fixe them
    #[test]
    fn collects_all_conflict_names() {
        let cfg = carbide_with_pools(Some(pool_map(&[
            ("alpha", ipv4_pool("10.0.0.0/24")),
            ("beta", ipv4_pool("10.0.1.0/24")),
        ])));
        let io = initial_objects_pools(&[
            ("alpha", ipv4_pool("10.0.0.0/16")),
            ("beta", ipv4_pool("10.0.1.0/16")),
        ]);

        let err = resolve_initial_pools(&cfg, Some(&io)).expect_err("any conflict must error");
        let msg = err.to_string();

        assert!(msg.contains("alpha"), "expected `alpha` in {msg}");
        assert!(msg.contains("beta"), "expected `beta` in {msg}");
    }

    // neither source declares networks — operator misconfiguration.
    #[test]
    fn no_network_sources_returns_empty() {
        let cfg = carbide_with_networks(None);
        let resolved =
            resolve_initial_networks(&cfg, None).expect("missing networks must not be an error");
        assert!(
            resolved.is_empty(),
            "no declared networks should produce an empty map"
        );
    }

    // only `InitialObjectsConfig.pools` declares pools
    #[test]
    fn initial_objects_networks_only_succeeds() {
        let cfg = carbide_with_networks(None);
        let io = initial_objects_networks(&[(
            "network1",
            network_definition("10.0.0.0/24", NetworkDefinitionSegmentType::Admin),
        )]);

        let resolved = resolve_initial_networks(&cfg, Some(&io))
            .expect("InitialObjectsConfig-only must succeed");

        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved.get("network1"),
            Some(&network_definition(
                "10.0.0.0/24",
                NetworkDefinitionSegmentType::Admin
            ))
        );
    }

    // only legacy `CarbideConfig.networks` declares networks
    #[test]
    fn legacy_only_returns_legacy_networks() {
        let cfg = carbide_with_networks(Some(network_map(&[(
            "network1",
            network_definition("10.0.0.0/24", NetworkDefinitionSegmentType::Admin),
        )])));

        let resolved = resolve_initial_networks(&cfg, None).expect("legacy-only must succeed");

        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved.get("network1"),
            Some(&network_definition(
                "10.0.0.0/24",
                NetworkDefinitionSegmentType::Admin
            ))
        );
    }

    // both sources declare networks but with different names
    // Resolver returns the union; emits a deprecation warning naming the still-legacy entries.
    #[test]
    fn disjoint_union_returns_all_networks() {
        let cfg = carbide_with_networks(Some(network_map(&[(
            "legacy-only",
            network_definition("10.0.1.0/24", NetworkDefinitionSegmentType::Admin),
        )])));
        let io = initial_objects_networks(&[(
            "new-only",
            network_definition("10.0.2.0/24", NetworkDefinitionSegmentType::Admin),
        )]);

        let resolved =
            resolve_initial_networks(&cfg, Some(&io)).expect("disjoint union must succeed");

        assert_eq!(resolved.len(), 2);
        assert!(resolved.contains_key("legacy-only"));
        assert!(resolved.contains_key("new-only"));
    }

    // both sources declare the same network with identical definitions —
    // Resolver dedupes silently; the still-legacy entry is included in the deprecation warning.
    #[test]
    fn overlap_networks_identical_succeeds() {
        let pool = network_definition("10.0.0.0/24", NetworkDefinitionSegmentType::Admin);
        let cfg = carbide_with_networks(Some(network_map(&[("network1", pool.clone())])));
        let io = initial_objects_networks(&[("network1", pool.clone())]);

        let resolved =
            resolve_initial_networks(&cfg, Some(&io)).expect("identical defs must succeed");

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved.get("network1"), Some(&pool));
    }

    // both sources declare the same network name but with different definitions —
    // Resolver must fail loudly so the bad state is fixed before reconcile runs.
    #[test]
    fn overlap_networks_conflict_errors() {
        let cfg = carbide_with_networks(Some(network_map(&[(
            "network1",
            network_definition("10.0.0.0/24", NetworkDefinitionSegmentType::Admin),
        )])));
        let io = initial_objects_networks(&[(
            "network1",
            network_definition("10.0.0.0/16", NetworkDefinitionSegmentType::Admin),
        )]);

        let err =
            resolve_initial_networks(&cfg, Some(&io)).expect_err("conflicting defs must error");

        assert!(
            err.to_string().contains("network1"),
            "error message should name the conflicting network: {err}"
        );
    }

    // every overlap is a conflict — the resolver collects all
    // bad names so the operator can fixe them
    #[test]
    fn collects_all_conflict_network_names() {
        let cfg = carbide_with_networks(Some(network_map(&[
            (
                "alpha",
                network_definition("10.0.0.0/24", NetworkDefinitionSegmentType::Admin),
            ),
            (
                "beta",
                network_definition("10.0.1.0/24", NetworkDefinitionSegmentType::Admin),
            ),
        ])));
        let io = initial_objects_networks(&[
            (
                "alpha",
                network_definition("10.0.0.0/16", NetworkDefinitionSegmentType::Admin),
            ),
            (
                "beta",
                network_definition("10.0.1.0/16", NetworkDefinitionSegmentType::Admin),
            ),
        ]);

        let err = resolve_initial_networks(&cfg, Some(&io)).expect_err("any conflict must error");
        let msg = err.to_string();

        assert!(msg.contains("alpha"), "expected `alpha` in {msg}");
        assert!(msg.contains("beta"), "expected `beta` in {msg}");
    }
}
