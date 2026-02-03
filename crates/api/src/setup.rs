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

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use db::machine::update_dpu_asns;
use db::resource_pool::DefineResourcePoolError;
use db::{Transaction, work_lock_manager};
use eyre::WrapErr;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use forge_secrets::ForgeVaultClient;
use forge_secrets::credentials::CredentialProvider;
use futures_util::TryFutureExt;
use model::attestation::spdm::VerifierImpl;
use model::expected_machine::ExpectedMachine;
use model::ib::DEFAULT_IB_FABRIC_NAME;
use model::machine::HostHealthConfig;
use model::resource_pool::{self};
use model::route_server::RouteServerSourceType;
use opentelemetry::metrics::Meter;
use sqlx::postgres::PgSslMode;
use sqlx::{ConnectOptions, PgPool};
use tokio::sync::oneshot::{Receiver, Sender};
use tokio::sync::{Semaphore, oneshot};
use tracing_log::AsLog as _;

use crate::api::Api;
use crate::cfg::file::{CarbideConfig, ListenMode};
use crate::dpa::DpaInfo;
use crate::dynamic_settings::DynamicSettings;
use crate::errors::CarbideError;
use crate::firmware_downloader::FirmwareDownloader;
use crate::handlers::machine_validation::apply_config_on_startup;
use crate::ib::{self, IBFabricManager};
use crate::ib_fabric_monitor::IbFabricMonitor;
use crate::ipmitool::{IPMITool, IPMIToolImpl, IPMIToolTestImpl};
use crate::listener::ApiListenMode;
use crate::logging::log_limiter::LogLimiter;
use crate::logging::service_health_metrics::{
    ServiceHealthContext, start_export_service_health_metrics,
};
use crate::logging::sqlx_query_tracing::SQLX_STATEMENTS_LOG_LEVEL;
use crate::machine_update_manager::MachineUpdateManager;
use crate::measured_boot::metrics_collector::MeasuredBootMetricsCollector;
use crate::mqtt_state_change_hook::hook::MqttStateChangeHook;
use crate::nvl_partition_monitor::NvlPartitionMonitor;
use crate::nvlink::{NmxmClientPool, NmxmClientPoolImpl};
use crate::preingestion_manager::PreingestionManager;
use crate::rack::rms_client::{RackManagerClientPool, RmsClientPool};
use crate::redfish::RedfishClientPool;
use crate::scout_stream::ConnectionRegistry;
use crate::site_explorer::{BmcEndpointExplorer, SiteExplorer};
use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::controller::{Enqueuer, StateController};
use crate::state_controller::dpa_interface::handler::DpaInterfaceStateHandler;
use crate::state_controller::dpa_interface::io::DpaInterfaceStateControllerIO;
use crate::state_controller::ib_partition::handler::IBPartitionStateHandler;
use crate::state_controller::ib_partition::io::IBPartitionStateControllerIO;
use crate::state_controller::machine::handler::MachineStateHandlerBuilder;
use crate::state_controller::machine::io::MachineStateControllerIO;
use crate::state_controller::network_segment::handler::NetworkSegmentStateHandler;
use crate::state_controller::network_segment::io::NetworkSegmentStateControllerIO;
use crate::state_controller::power_shelf::handler::PowerShelfStateHandler;
use crate::state_controller::power_shelf::io::PowerShelfStateControllerIO;
use crate::state_controller::rack::handler::RackStateHandler;
use crate::state_controller::rack::io::RackStateControllerIO;
use crate::state_controller::spdm::handler::SpdmAttestationStateHandler;
use crate::state_controller::spdm::io::SpdmStateControllerIO;
use crate::state_controller::state_change_emitter::StateChangeEmitterBuilder;
use crate::state_controller::switch::handler::SwitchStateHandler;
use crate::state_controller::switch::io::SwitchStateControllerIO;
use crate::{attestation, db_init, dpa, ethernet_virtualization, listener};

const API_URL_KEY: &str = "api_url";
const PXE_URL_KEY: &str = "pxe_url";
const API_URL: &str = "https://carbide-api.forge";
const PXE_URL: &str = "http://carbide-pxe.forge";
const BMC_FW_UPDATE_KEY: &str = "bmc_fw_update";
const SECONDS_SINCE_EPOCH_KEY: &str = "seconds_since_epoch";
const HBN_REPS_KEY: &str = "forge_hbn_reps";
const HBN_SFS_KEY: &str = "forge_hbn_sfs";
const VF_INTERCEPT_BRIDGE_NAME_KEY: &str = "forge_vf_intercept_bridge_name";
const HOST_INTERCEPT_BRIDGE_NAME_KEY: &str = "forge_host_intercept_bridge_name";
const HOST_INTERCEPT_HBN_PORT_KEY: &str = "forge_host_intercept_hbn_port";
const HOST_INTERCEPT_BRIDGE_PORT_KEY: &str = "forge_host_intercept_bridge_port";
const VF_INTERCEPT_HBN_PORT_KEY: &str = "forge_vf_intercept_hbn_port";
const VF_INTERCEPT_BRIDGE_PORT_KEY: &str = "forge_vf_intercept_bridge_port";
const VF_INTERCEPT_BRIDGE_SF_REPRESENTOR_KEY: &str = "forge_vf_intercept_bridge_sf_representor";
const VF_INTERCEPT_BRIDGE_SF_HBN_BRIDGE_REPRESENTOR_KEY: &str =
    "forge_vf_intercept_bridge_sf_hbn_bridge_representor";
const VF_INTERCEPT_BRIDGE_SF_KEY: &str = "forge_vf_intercept_bridge_sf";

pub fn parse_carbide_config(
    config_str: String,
    site_config_str: Option<String>,
) -> eyre::Result<Arc<CarbideConfig>> {
    let mut figment = Figment::new().merge(Toml::string(config_str.as_str()));
    if let Some(site_config_str) = site_config_str {
        figment = figment.merge(Toml::string(site_config_str.as_str()));
    }

    let mut config: CarbideConfig = figment
        .merge(Env::prefixed("CARBIDE_API_"))
        .extract()
        .wrap_err("Failed to load configuration files")?;

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

    tracing::trace!("Carbide config: {:#?}", config.redacted());
    Ok(Arc::new(config))
}

pub fn create_ipmi_tool(
    credential_provider: Arc<dyn CredentialProvider>,
    carbide_config: &CarbideConfig,
) -> Arc<dyn IPMITool> {
    if carbide_config
        .dpu_ipmi_tool_impl
        .as_ref()
        .is_some_and(|tool| tool == "test")
    {
        tracing::trace!("Disabling ipmitool");
        Arc::new(IPMIToolTestImpl {})
    } else {
        Arc::new(IPMIToolImpl::new(
            credential_provider,
            &carbide_config.dpu_ipmi_reboot_attempts,
        ))
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

#[tracing::instrument(skip_all)]
pub async fn start_api(
    carbide_config: Arc<CarbideConfig>,
    meter: Meter,
    dynamic_settings: DynamicSettings,
    shared_redfish_pool: Arc<dyn RedfishClientPool>,
    vault_client: Arc<ForgeVaultClient>,
    stop_channel: Receiver<()>,
    ready_channel: Sender<()>,
) -> eyre::Result<()> {
    let ipmi_tool = create_ipmi_tool(vault_client.clone(), &carbide_config);

    let db_pool = create_and_connect_postgres_pool(&carbide_config).await?;

    let work_lock_manager_handle = work_lock_manager::start(
        db_pool.clone(),
        work_lock_manager::KeepaliveConfig::default(),
    )
    .await?;

    let rms_client = match carbide_config.rms_api_url.clone() {
        Some(url) if !url.is_empty() => {
            let rms_client_pool = RmsClientPool::new(&url);
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
    if carbide_config.listen_only {
        tracing::info!(
            "Not populating resource pools or route_servers in database, as listen_only=true"
        );
    } else {
        let mut txn = Transaction::begin(&db_pool).await?;
        db::resource_pool::define_all_from(
            &mut txn,
            carbide_config.pools.as_ref().ok_or_else(|| {
                DefineResourcePoolError::InvalidArgument(String::from(
                    "resource pools are not defined in carbide config",
                ))
            })?,
        )
        .await?;

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
        vault_client.clone(),
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

    let site_fabric_prefixes = ethernet_virtualization::SiteFabricPrefixList::from_ipv4_slice(
        carbide_config.site_fabric_prefixes.as_slice(),
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

    let bmc_explorer = Arc::new(BmcEndpointExplorer::new(
        shared_redfish_pool.clone(),
        ipmi_tool.clone(),
        vault_client.clone(),
        carbide_config
            .site_explorer
            .rotate_switch_nvos_credentials
            .clone(),
    ));

    let nvlink_config = carbide_config.nvlink_config.clone().unwrap_or_default();

    let nmxm_client_pool =
        libnmxm::NmxmClientPool::builder(nvlink_config.allow_insecure).build()?;
    let nmxm_pool = NmxmClientPoolImpl::new(vault_client.clone(), nmxm_client_pool);

    let shared_nmxm_pool: Arc<dyn NmxmClientPool> = Arc::new(nmxm_pool);

    let api_service = Arc::new(Api {
        certificate_provider: vault_client.clone(),
        common_pools,
        credential_provider: vault_client,
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
        nmxm_pool: shared_nmxm_pool,
        work_lock_manager_handle,
        kube_client_provider: Arc::new(carbide_dpf::Production {}),
        machine_state_handler_enqueuer: Enqueuer::new(db_pool),
    });

    let (controllers_stop_tx, controllers_stop_rx) = oneshot::channel();
    let controllers_handle = if carbide_config.listen_only {
        tracing::info!("Not starting background services, as listen_only=true");
        tokio::spawn(controllers_stop_rx.map_err(|_| eyre::eyre!("joining noop task")))
    } else {
        tokio::spawn(initialize_and_start_controllers(
            api_service.clone(),
            meter.clone(),
            ipmi_tool.clone(),
            controllers_stop_rx,
        ))
    };

    listener::listen_and_serve(
        api_service,
        listen_mode,
        carbide_config.listen,
        &carbide_config.auth,
        meter,
        stop_channel,
        ready_channel,
    )
    .await?;

    controllers_stop_tx.send(()).ok();
    controllers_handle.await?
}

pub async fn initialize_and_start_controllers(
    api_service: Arc<Api>,
    meter: Meter,
    ipmi_tool: Arc<dyn IPMITool>,
    stop_rx: oneshot::Receiver<()>,
) -> eyre::Result<()> {
    let Api {
        runtime_config: carbide_config,
        endpoint_explorer: bmc_explorer,
        common_pools,
        database_connection: db_pool,
        ib_fabric_manager,
        redfish_pool: shared_redfish_pool,
        nmxm_pool: shared_nmxm_pool,
        work_lock_manager_handle,
        rms_client,
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

    let mut txn = Transaction::begin(db_pool).await?;
    db::resource_pool::define_all_from(
        &mut txn,
        carbide_config.pools.as_ref().ok_or_else(|| {
            DefineResourcePoolError::InvalidArgument(String::from(
                "resource pools are not defined in carbide config",
            ))
        })?,
    )
    .await?;
    txn.commit().await?;

    const EXPECTED_MACHINE_FILE_PATH: &str = "/etc/forge/carbide-api/site/expected_machines.json";
    if let Ok(file_str) = tokio::fs::read_to_string(EXPECTED_MACHINE_FILE_PATH).await {
        let expected_machines = serde_json::from_str::<Vec<ExpectedMachine>>(file_str.as_str()).inspect_err(|err| {
                tracing::error!("expected_machines.json file exists, but unable to parse expected_machines file, nothing was written to db, bailing: {err}.");
            })?;
        let mut txn = Transaction::begin(db_pool).await?;
        db::expected_machine::create_missing_from(&mut txn, &expected_machines)
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

    if let Some(networks) = carbide_config.networks.as_ref() {
        db_init::create_initial_networks(&api_service, db_pool, networks).await?;
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
        let mqtt_client = Some(dpa::start_dpa_handler(api_service.clone()).await?);
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
            let client = mqttea::MqtteaClient::new(
                &config.mqtt_endpoint,
                config.mqtt_broker_port,
                "carbide-dsx-exchange-event-bus",
                Some(mqttea::client::ClientOptions::default().with_qos(mqttea::QoS::AtMostOnce)),
            )
            .map_err(|e| eyre::eyre!("Failed to create DSX Exchange Event Bus MQTT client: {e}"))?;

            client.connect().await.map_err(|e| {
                eyre::eyre!("Failed to connect DSX Exchange Event Bus MQTT client: {e}")
            })?;

            tracing::info!(
                "DSX Exchange Event Bus enabled, publishing to {}:{}",
                config.mqtt_endpoint,
                config.mqtt_broker_port
            );
            emitter_builder = emitter_builder.hook(Box::new(MqttStateChangeHook::new(
                client,
                config.publish_timeout,
                config.queue_capacity,
                &meter,
            )));
        }

        emitter_builder.build()
    };

    let handler_services = Arc::new(CommonStateHandlerServices {
        db_pool: db_pool.clone(),
        redfish_client_pool: shared_redfish_pool.clone(),
        ib_fabric_manager: ib_fabric_manager.clone(),
        ib_pools: common_pools.infiniband.clone(),
        ipmi_tool: ipmi_tool.clone(),
        site_config: carbide_config.clone(),
        dpa_info,
        rms_client: rms_client.clone(),
    });

    // Use the hostname as cluster-wide state controller ID
    // The expectation here is that either the host only runs a single
    // carbide instance natively, or - if the multiple instances run as containers
    // - every container gets its own hostname (k8s pod name)
    let state_controller_id = hostname::get()
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string().into())
        .to_string_lossy()
        .to_string();

    // Create DPF CRDs if enabled
    if carbide_config.dpf.enabled {
        tracing::info!("Creating DPF CRDs");
        let key = forge_secrets::credentials::CredentialKey::BmcCredentials {
            credential_type: forge_secrets::credentials::BmcCredentialType::SiteWideRoot,
        };
        let credentials = api_service
            .credential_provider
            .get_credentials(&key)
            .await?;
        let Some(forge_secrets::credentials::Credentials::UsernamePassword {
            username: _,
            password,
        }) = credentials
        else {
            return Err(eyre::eyre!("Site wide BMC root credentials are not set"));
        };
        if let Err(err) =
            carbide_dpf::create_crds_and_secret(bfcfg_context(carbide_config), password).await
        {
            tracing::error!("Failed to create DPF CRDs: {err}");
            return Err(eyre::eyre!("Failed to create DPF CRDs: {err}"));
        }
    }

    // handles need to be stored in a variable
    // If they are assigned to _ then the destructor will be immediately called
    let _machine_state_controller_handle = StateController::<MachineStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_machines", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
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
                .credential_provider(api_service.credential_provider.clone())
                .power_options_config(carbide_config.power_manager_options.clone().into())
                .dpf_config(crate::state_controller::machine::handler::DpfConfig::from(
                    carbide_config.dpf.clone(),
                    Arc::new(carbide_dpf::Production {}) as Arc<dyn carbide_dpf::KubeImpl>,
                ))
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
            },
        }))
        .state_change_emitter(state_change_emitter)
        .build_and_spawn()
        .expect("Unable to build MachineStateController");

    let sc_pool_vlan_id = common_pools.ethernet.pool_vlan_id.clone();
    let sc_pool_vni = common_pools.ethernet.pool_vni.clone();

    let ns_builder = StateController::<NetworkSegmentStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_network_segments", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone());
    let _network_segment_controller_handle = ns_builder
        .iteration_config((&carbide_config.network_segment_state_controller.controller).into())
        .state_handler(Arc::new(NetworkSegmentStateHandler::new(
            carbide_config
                .network_segment_state_controller
                .network_segment_drain_time,
            sc_pool_vlan_id,
            sc_pool_vni,
        )))
        .build_and_spawn()
        .expect("Unable to build NetworkSegmentController");

    let dpa_pool_vni = common_pools.dpa.pool_dpa_vni.clone();

    let mut _dpa_interface_state_controller_handle: Option<
        crate::state_controller::controller::StateControllerHandle,
    > = None;

    if carbide_config.is_dpa_enabled() {
        tracing::info!("Starting DpaInterfaceStateController as dpa is enabled");
        _dpa_interface_state_controller_handle = Some(
            StateController::<DpaInterfaceStateControllerIO>::builder()
                .database(db_pool.clone(), work_lock_manager_handle.clone())
                .meter("carbide_dpa_interfaces", meter.clone())
                .processor_id(state_controller_id.clone())
                .services(handler_services.clone())
                .iteration_config(
                    (&carbide_config.dpa_interface_state_controller.controller).into(),
                )
                .state_handler(Arc::new(DpaInterfaceStateHandler::new(dpa_pool_vni)))
                .build_and_spawn()
                .expect("Unable to build DpaInterfaceStateController"),
        );
    }

    if carbide_config.spdm.enabled {
        let Some(nras_config) = carbide_config.spdm.nras_config.clone() else {
            return Err(eyre::eyre!(
                "SPDm attestation is enabled but NRAS Config is missing!!"
            ));
        };

        let verifier = Arc::new(VerifierImpl::default());

        let _spdm_state_controller_handle = StateController::<SpdmStateControllerIO>::builder()
            .database(db_pool.clone(), work_lock_manager_handle.clone())
            .meter("carbide_spdm_attestation", meter.clone())
            .processor_id(state_controller_id.clone())
            .services(handler_services.clone())
            .iteration_config((&carbide_config.spdm_state_controller.controller).into())
            .state_handler(Arc::new(SpdmAttestationStateHandler::new(
                verifier,
                nras_config,
            )))
            .build_and_spawn()
            .expect("Unable to build SpdmStateController");
    }

    let _ib_partition_controller_handle =
        StateController::<IBPartitionStateControllerIO>::builder()
            .database(db_pool.clone(), work_lock_manager_handle.clone())
            .meter("carbide_ib_partitions", meter.clone())
            .processor_id(state_controller_id.clone())
            .services(handler_services.clone())
            .iteration_config((&carbide_config.ib_partition_state_controller.controller).into())
            .state_handler(Arc::new(IBPartitionStateHandler::default()))
            .build_and_spawn()
            .expect("Unable to build IBPartitionStateController");

    let _power_shelf_controller_handle = StateController::<PowerShelfStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_power_shelves", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .iteration_config((&carbide_config.power_shelf_state_controller.controller).into())
        .state_handler(Arc::new(PowerShelfStateHandler::default()))
        .build_and_spawn()
        .expect("Unable to build PowerShelfStateController");

    let _rack_controller_handle = StateController::<RackStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_racks", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .state_handler(Arc::new(RackStateHandler::default()))
        .build_and_spawn()
        .expect("Unable to build RackStateController");

    let _switch_controller_handle = StateController::<SwitchStateControllerIO>::builder()
        .database(db_pool.clone(), work_lock_manager_handle.clone())
        .meter("carbide_switches", meter.clone())
        .processor_id(state_controller_id.clone())
        .services(handler_services.clone())
        .iteration_config((&carbide_config.switch_state_controller.controller).into())
        .state_handler(Arc::new(SwitchStateHandler::default()))
        .build_and_spawn()
        .expect("Unable to build SwitchStateController");

    let ib_fabric_monitor = IbFabricMonitor::new(
        db_pool.clone(),
        if ib_config.enabled {
            carbide_config.ib_fabrics.clone()
        } else {
            Default::default()
        },
        meter.clone(),
        ib_fabric_manager.clone(),
        carbide_config.clone(),
        work_lock_manager_handle.clone(),
    );
    let _ib_fabric_monitor_handle = ib_fabric_monitor.start()?;

    let nvlink_partition_monitor = NvlPartitionMonitor::new(
        db_pool.clone(),
        shared_nmxm_pool.clone(),
        meter.clone(),
        carbide_config.nvlink_config.clone().unwrap_or_default(),
        carbide_config.host_health,
        work_lock_manager_handle.clone(),
    );
    let _nv_link_partition_monitor_handle = nvlink_partition_monitor.start()?;

    let site_explorer = SiteExplorer::new(
        db_pool.clone(),
        carbide_config.site_explorer.clone(),
        meter.clone(),
        bmc_explorer.clone(),
        Arc::new(carbide_config.get_firmware_config()),
        common_pools.clone(),
        work_lock_manager_handle.clone(),
        rms_client.clone(),
    );
    let _site_explorer_stop_handle = site_explorer.start()?;

    let machine_update_manager = MachineUpdateManager::new(
        db_pool.clone(),
        carbide_config.clone(),
        meter.clone(),
        work_lock_manager_handle.clone(),
    );
    let _machine_update_manager_stop_handle = machine_update_manager.start()?;

    let preingestion_manager = PreingestionManager::new(
        db_pool.clone(),
        carbide_config.clone(),
        shared_redfish_pool.clone(),
        meter.clone(),
        Some(downloader.clone()),
        Some(upload_limiter),
        Some(api_service.credential_provider.clone()),
        work_lock_manager_handle.clone(),
    );
    let _preingestion_manager_stop_handle = preingestion_manager.start()?;

    let measured_boot_collector = MeasuredBootMetricsCollector::new(
        db_pool.clone(),
        carbide_config.measured_boot_collector.clone(),
        meter.clone(),
    );
    let _measured_boot_collector_handle = measured_boot_collector.start()?;

    // we need to create ek_cert_status entries for all existing machines
    attestation::backfill_ek_cert_status_for_existing_machines(db_pool).await?;

    let machine_validation_metric = crate::machine_validation::MachineValidationManager::new(
        db_pool.clone(),
        carbide_config.machine_validation_config.clone(),
        meter.clone(),
    );
    let _machine_validation_metric_handle = machine_validation_metric.start()?;

    apply_config_on_startup(
        &api_service,
        &carbide_config.machine_validation_config.clone(),
    )
    .await?;

    // We have to sleep until the calling thread stops us, or else all the handles get dropped and
    // the background tasks terminate.
    stop_rx
        .await
        .context("error reading from stop channel, calling thread likely panicked")
}

/// Constructs a context map for bf.cfg Tera template from CarbideConfig.
/// Used to populate deployment and runtime parameters for the DPF setup.
fn bfcfg_context(config: &CarbideConfig) -> HashMap<String, String> {
    let mut context = HashMap::new();
    context.insert(API_URL_KEY.to_string(), API_URL.to_string());
    context.insert(PXE_URL_KEY.to_string(), PXE_URL.to_string());
    context.insert(
        BMC_FW_UPDATE_KEY.to_string(),
        carbide_dpf::get_fw_update_data(),
    );
    let start = std::time::SystemTime::now();
    let seconds_since_epoch = start
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    context.insert(
        SECONDS_SINCE_EPOCH_KEY.to_string(),
        seconds_since_epoch.to_string(),
    );

    if let Some(vmaas) = config.vmaas_config.as_ref() {
        if let Some(hbn_reps) = vmaas.hbn_reps.as_ref() {
            context.insert(HBN_REPS_KEY.to_string(), hbn_reps.clone());
        }

        if let Some(hbn_sfs) = vmaas.hbn_sfs.as_ref() {
            context.insert(HBN_SFS_KEY.to_string(), hbn_sfs.clone());
        }

        if let Some(bridge) = vmaas.bridging.as_ref() {
            context.insert(
                VF_INTERCEPT_BRIDGE_NAME_KEY.to_string(),
                bridge.vf_intercept_bridge_name.clone(),
            );

            context.insert(
                HOST_INTERCEPT_BRIDGE_NAME_KEY.to_string(),
                bridge.host_intercept_bridge_name.clone(),
            );

            let host_intercept_bridge_port = bridge.host_intercept_bridge_port.clone();
            context.insert(
                HOST_INTERCEPT_HBN_PORT_KEY.to_string(),
                format!("patch-hbn-{host_intercept_bridge_port}"),
            );

            context.insert(
                HOST_INTERCEPT_BRIDGE_PORT_KEY.to_string(),
                host_intercept_bridge_port,
            );

            let vf_intercept_bridge_port = bridge.vf_intercept_bridge_port.clone();
            context.insert(
                VF_INTERCEPT_HBN_PORT_KEY.to_string(),
                format!("patch-hbn-{vf_intercept_bridge_port}"),
            );

            context.insert(
                VF_INTERCEPT_BRIDGE_PORT_KEY.to_string(),
                vf_intercept_bridge_port,
            );

            let vf_intercept_bridge_sf = bridge.vf_intercept_bridge_sf.clone();
            context.insert(
                VF_INTERCEPT_BRIDGE_SF_REPRESENTOR_KEY.to_string(),
                format!("{vf_intercept_bridge_sf}_r"),
            );

            context.insert(
                VF_INTERCEPT_BRIDGE_SF_HBN_BRIDGE_REPRESENTOR_KEY.to_string(),
                format!("{vf_intercept_bridge_sf}_if_r"),
            );

            context.insert(
                VF_INTERCEPT_BRIDGE_SF_KEY.to_string(),
                vf_intercept_bridge_sf,
            );
        }
    }

    context
}
