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

use eyre::WrapErr;
use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use forge_secrets::{ForgeVaultClient, credentials::CredentialProvider};
use futures_util::TryFutureExt;
use opentelemetry::metrics::Meter;
use sqlx::{ConnectOptions, PgPool, postgres::PgSslMode};
use std::net::IpAddr;
use std::{collections::HashSet, str::FromStr, sync::Arc};
use tokio::sync::{
    Semaphore, oneshot,
    oneshot::{Receiver, Sender},
};

use crate::storage::{NvmeshClientPool, NvmeshClientPoolImpl};
use crate::{db, db::machine::update_dpu_asns, resource_pool::DefineResourcePoolError};
use crate::{
    db::expected_machine::ExpectedMachine, handlers::machine_validation::apply_config_on_startup,
};
use crate::{ib::DEFAULT_IB_FABRIC_NAME, state_controller::machine::handler::PowerOptionConfig};

use crate::cfg::file::{HostHealthConfig, ListenMode};
use crate::db::route_servers::{RouteServer, RouteServerSourceType};
use crate::dynamic_settings::DynamicSettings;
use crate::errors::CarbideError;
use crate::listener::ApiListenMode;
use crate::logging::log_limiter::LogLimiter;
use crate::{
    api::Api,
    attestation,
    cfg::file::CarbideConfig,
    db::DatabaseError,
    db_init, ethernet_virtualization,
    firmware_downloader::FirmwareDownloader,
    ib::{self, IBFabricManager},
    ib_fabric_monitor::IbFabricMonitor,
    ipmitool::{IPMITool, IPMIToolImpl, IPMIToolTestImpl},
    listener,
    logging::service_health_metrics::{ServiceHealthContext, start_export_service_health_metrics},
    machine_update_manager::MachineUpdateManager,
    measured_boot::metrics_collector::MeasuredBootMetricsCollector,
    preingestion_manager::PreingestionManager,
    redfish::RedfishClientPool,
    resource_pool::{self, common::CommonPools},
    site_explorer::{BmcEndpointExplorer, SiteExplorer},
    state_controller::{
        controller::StateController,
        ib_partition::{handler::IBPartitionStateHandler, io::IBPartitionStateControllerIO},
        machine::{handler::MachineStateHandlerBuilder, io::MachineStateControllerIO},
        network_segment::{
            handler::NetworkSegmentStateHandler, io::NetworkSegmentStateControllerIO,
        },
    },
};

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
        .log_statements("INFO".parse()?);
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

    let nvmesh_client_pool = libnvmesh::NvmeshClientPool::builder().build()?;
    let nvmesh_pool = NvmeshClientPoolImpl::new(vault_client.clone(), nvmesh_client_pool);
    let shared_nvmesh_pool: Arc<dyn NvmeshClientPool> = Arc::new(nvmesh_pool);

    let db_pool = create_and_connect_postgres_pool(&carbide_config).await?;

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
        let mut txn = db_pool
            .begin()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "begin define resource pools", e))?;
        resource_pool::define_all_from(
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
        RouteServer::replace(&mut txn, &route_servers, RouteServerSourceType::ConfigFile).await?;

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "commit define resource pools", e))?;
    };
    let common_pools = CommonPools::create(db_pool.clone(), ib_fabric_ids).await?;

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
    ));

    let api_service = Arc::new(Api {
        certificate_provider: vault_client.clone(),
        common_pools,
        credential_provider: vault_client,
        database_connection: db_pool,
        dpu_health_log_limiter: LogLimiter::default(),
        dynamic_settings,
        endpoint_explorer: bmc_explorer,
        eth_data,
        ib_fabric_manager,
        nvmesh_pool: shared_nvmesh_pool,
        redfish_pool: shared_redfish_pool,
        runtime_config: carbide_config.clone(),
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
        nvmesh_pool: shared_nvmesh_pool,
        redfish_pool: shared_redfish_pool,
        ..
    } = api_service.as_ref();
    // As soon as we get the database up, observe this version of forge so that we know when it was
    // first deployed
    {
        let mut txn = db_pool
            .begin()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "begin observe forge_version", e))?;

        db::forge_version::observe_as_latest_version(&mut txn, forge_version::v!(build_version))
            .await?;

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "commit observe forge_version", e))?;
    }

    if let Some(domain_name) = &carbide_config.initial_domain_name {
        if db_init::create_initial_domain(db_pool.clone(), domain_name).await? {
            tracing::info!("Created initial domain {domain_name}");
        }
    }

    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin define resource pools", e))?;
    resource_pool::define_all_from(
        &mut txn,
        carbide_config.pools.as_ref().ok_or_else(|| {
            DefineResourcePoolError::InvalidArgument(String::from(
                "resource pools are not defined in carbide config",
            ))
        })?,
    )
    .await?;
    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit define resource pools", e))?;

    const EXPECTED_MACHINE_FILE_PATH: &str = "/etc/forge/carbide-api/site/expected_machines.json";
    if let Ok(file_str) = tokio::fs::read_to_string(EXPECTED_MACHINE_FILE_PATH).await {
        if let Ok(expected_machines) =
            serde_json::from_str::<Vec<ExpectedMachine>>(file_str.as_str())
        {
            let mut txn = db_pool.begin().await.map_err(|e| {
                DatabaseError::new(file!(), line!(), "begin define expected machines", e)
            })?;
            if let Err(err) =
                ExpectedMachine::create_missing_from(&mut txn, &expected_machines).await
            {
                tracing::error!(
                    "Unable to update database from expected_machines list, error: {err}"
                );
            } else {
                // everything worked, commit ok
                txn.commit().await.map_err(|e| {
                    DatabaseError::new(file!(), line!(), "commit define expected machines ", e)
                })?;

                tracing::info!("Successfully wrote expected machines to db, continuing startup.");
            }
        } else {
            tracing::error!("Unable to parse expected_machines file, nothing was written to db.");
        }
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
        let mut txn = db_pool
            .begin()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "begin define resource pools", e))?;

        for (fabric_id, x) in carbide_config.ib_fabrics.iter() {
            resource_pool::define::define(
                &mut txn,
                &resource_pool::common::ib_pkey_pool_name(fabric_id),
                &resource_pool::ResourcePoolDef {
                    pool_type: resource_pool::define::ResourcePoolType::Integer,
                    ranges: x.pkeys.clone(),
                    prefix: None,
                },
            )
            .await?;
        }

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "commit define resource pools", e))?;
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

    if let Some(fnn_config) = carbide_config.fnn.as_ref() {
        if let Some(admin) = fnn_config.admin_vpc.as_ref() {
            if admin.enabled {
                db_init::create_admin_vpc(db_pool, admin.vpc_vni).await?;
            }
        }
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

    // handles need to be stored in a variable
    // If they are assigned to _ then the destructor will be immediately called
    let _machine_state_controller_handle = StateController::<MachineStateControllerIO>::builder()
        .database(db_pool.clone())
        .meter("forge_machines", meter.clone())
        .redfish_client_pool(shared_redfish_pool.clone())
        .nvmesh_client_pool(shared_nvmesh_pool.clone())
        .ib_fabric_manager(ib_fabric_manager.clone())
        .forge_api(api_service.clone())
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
                .power_options_config(PowerOptionConfig {
                    // Should these parameters be configurable?
                    enabled: carbide_config.power_manager_options.enabled,
                    next_try_duration_on_success: carbide_config
                        .power_manager_options
                        .next_try_duration_on_success,
                    next_try_duration_on_failure: carbide_config
                        .power_manager_options
                        .next_try_duration_on_failure,
                    wait_duration_until_host_reboot: carbide_config
                        .power_manager_options
                        .wait_duration_until_host_reboot,
                })
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
        .ipmi_tool(ipmi_tool.clone())
        .site_config(carbide_config.clone())
        .build_and_spawn()
        .expect("Unable to build MachineStateController");

    let sc_pool_vlan_id = common_pools.ethernet.pool_vlan_id.clone();
    let sc_pool_vni = common_pools.ethernet.pool_vni.clone();

    let ns_builder = StateController::<NetworkSegmentStateControllerIO>::builder()
        .database(db_pool.clone())
        .meter("forge_network_segments", meter.clone())
        .redfish_client_pool(shared_redfish_pool.clone())
        .nvmesh_client_pool(shared_nvmesh_pool.clone())
        .ib_fabric_manager(ib_fabric_manager.clone())
        .forge_api(api_service.clone());
    let _network_segment_controller_handle = ns_builder
        .iteration_config((&carbide_config.network_segment_state_controller.controller).into())
        .state_handler(Arc::new(NetworkSegmentStateHandler::new(
            carbide_config
                .network_segment_state_controller
                .network_segment_drain_time,
            sc_pool_vlan_id,
            sc_pool_vni,
        )))
        .ipmi_tool(ipmi_tool.clone())
        .site_config(carbide_config.clone())
        .build_and_spawn()
        .expect("Unable to build NetworkSegmentController");

    let _ib_partition_controller_handle =
        StateController::<IBPartitionStateControllerIO>::builder()
            .database(db_pool.clone())
            .meter("forge_ib_partitions", meter.clone())
            .redfish_client_pool(shared_redfish_pool.clone())
            .nvmesh_client_pool(shared_nvmesh_pool.clone())
            .ib_fabric_manager(ib_fabric_manager.clone())
            .ib_pools(common_pools.infiniband.clone())
            .forge_api(api_service.clone())
            .iteration_config((&carbide_config.ib_partition_state_controller.controller).into())
            .state_handler(Arc::new(IBPartitionStateHandler::default()))
            .ipmi_tool(ipmi_tool.clone())
            .site_config(carbide_config.clone())
            .build_and_spawn()
            .expect("Unable to build IBPartitionStateController");

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
    );
    let _ib_fabric_monitor_handle = ib_fabric_monitor.start()?;

    let site_explorer = SiteExplorer::new(
        db_pool.clone(),
        carbide_config.site_explorer.clone(),
        meter.clone(),
        bmc_explorer.clone(),
        Arc::new(carbide_config.get_firmware_config()),
        common_pools.clone(),
    );
    let _site_explorer_stop_handle = site_explorer.start()?;

    let machine_update_manager =
        MachineUpdateManager::new(db_pool.clone(), carbide_config.clone(), meter.clone());
    let _machine_update_manager_stop_handle = machine_update_manager.start()?;

    let preingestion_manager = PreingestionManager::new(
        db_pool.clone(),
        carbide_config.clone(),
        shared_redfish_pool.clone(),
        meter.clone(),
        Some(downloader.clone()),
        Some(upload_limiter),
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
