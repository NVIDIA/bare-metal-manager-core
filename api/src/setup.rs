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

use std::{collections::HashSet, sync::Arc};

use eyre::WrapErr;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use forge_secrets::{credentials::CredentialProvider, ForgeVaultClient};
use sqlx::{postgres::PgSslMode, ConnectOptions, PgPool};

use crate::db::expected_machine::ExpectedMachine;
use crate::storage::{NvmeshClientPool, NvmeshClientPoolImpl};
use crate::{db::machine::update_dpu_asns, resource_pool::DefineResourcePoolError};
use crate::{ib::DEFAULT_IB_FABRIC_NAME, legacy};

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
    logging::service_health_metrics::{start_export_service_health_metrics, ServiceHealthContext},
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
use tokio::sync::{
    oneshot::{Receiver, Sender},
    Semaphore,
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
    meter: opentelemetry::metrics::Meter,
    dynamic_settings: crate::dynamic_settings::DynamicSettings,
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
    let fabric_manager_type = match ib_config.enabled {
        true => ib::IBFabricManagerType::Rest,
        false => ib::IBFabricManagerType::Disable,
    };

    let ib_fabric_ids = match ib_config.enabled {
        false => HashSet::new(),
        true => carbide_config.ib_fabrics.keys().cloned().collect(),
    };

    let common_pools = CommonPools::create(db_pool.clone(), ib_fabric_ids).await?;

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
                return Err(eyre::eyre!("ib_fabrics contains an entry \"{fabric_id}\", but only \"{DEFAULT_IB_FABRIC_NAME}\" is supported at the moment"));
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
            manager_type: fabric_manager_type,
            max_partition_per_tenant: ib_config.max_partition_per_tenant,
            mtu: ib_config.mtu,
            rate_limit: ib_config.rate_limit,
            service_level: ib_config.service_level,
            #[cfg(test)]
            ports: None,
        },
    )?;

    let ib_fabric_manager: Arc<dyn IBFabricManager> = Arc::new(ib_fabric_manager_impl);

    let route_servers = db_init::create_initial_route_servers(&db_pool, &carbide_config).await?;

    let site_fabric_prefixes = ethernet_virtualization::SiteFabricPrefixList::from_ipv4_slice(
        carbide_config.site_fabric_prefixes.as_slice(),
    );

    let deny_prefixes = match carbide_config.vpc_isolation_behavior {
        crate::cfg::file::VpcIsolationBehaviorType::MutualIsolation => [
            // FIXME: We're overloading the deny_prefixes list by adding the
            // site fabric prefixes, since both sets of prefixes get denied
            // on the DPU. It would be better to send these to the agent
            // separately.
            carbide_config.site_fabric_prefixes.as_slice(),
            carbide_config.deny_prefixes.as_slice(),
        ]
        .concat(),
        crate::cfg::file::VpcIsolationBehaviorType::Open => carbide_config.deny_prefixes.clone(),
    };

    let eth_data = ethernet_virtualization::EthVirtData {
        asn: carbide_config.asn,
        dhcp_servers: carbide_config.dhcp_servers.clone(),
        route_servers,
        route_servers_enabled: carbide_config.enable_route_servers,
        deny_prefixes,
        site_fabric_prefixes,
    };

    let health_pool = db_pool.clone();
    start_export_service_health_metrics(ServiceHealthContext {
        meter: meter.clone(),
        database_pool: health_pool,
        resource_pool_stats: Some(common_pools.pool_stats.clone()),
    });

    let tls_ref = carbide_config.tls.as_ref().expect("Missing tls config");

    let tls_config = listener::ApiTlsConfig {
        identity_pemfile_path: tls_ref.identity_pemfile_path.clone(),
        identity_keyfile_path: tls_ref.identity_keyfile_path.clone(),
        root_cafile_path: tls_ref.root_cafile_path.clone(),
        admin_root_cafile_path: tls_ref.admin_root_cafile_path.clone(),
        bypass_rbac: carbide_config.bypass_rbac,
    };

    let bmc_explorer = Arc::new(BmcEndpointExplorer::new(
        shared_redfish_pool.clone(),
        ipmi_tool.clone(),
        vault_client.clone(),
    ));

    let api_service = Arc::new(Api::new(
        carbide_config.clone(),
        vault_client.clone(),
        vault_client.clone(),
        db_pool.clone(),
        shared_redfish_pool.clone(),
        shared_nvmesh_pool.clone(),
        eth_data,
        common_pools.clone(),
        ib_fabric_manager.clone(),
        dynamic_settings,
        bmc_explorer.clone(),
    ));

    if let Some(networks) = carbide_config.networks.as_ref() {
        db_init::create_initial_networks(&api_service, &db_pool, networks).await?;
    }

    if let Some(fnn_config) = carbide_config.fnn.as_ref() {
        if let Some(admin) = fnn_config.admin_vpc.as_ref() {
            if admin.enabled {
                db_init::create_admin_vpc(&db_pool, admin.vpc_vni).await?;
            }
        }
    }

    // Update SVI IP to segments which have VPC attached and type is FNN.
    db_init::update_network_segments_svi_ip(&db_pool).await?;

    db_init::store_initial_dpu_agent_upgrade_policy(
        &db_pool,
        carbide_config.initial_dpu_agent_upgrade_policy,
    )
    .await?;

    if let Err(e) = update_dpu_asns(&db_pool, &common_pools).await {
        tracing::warn!("Failed to update ASN for DPUs: {e}");
    }

    let downloader = FirmwareDownloader::new();
    let upload_limiter = Arc::new(Semaphore::new(carbide_config.firmware_global.max_uploads));
    // This can take couple of seconds to migrate, by this time machine state controller will throw
    // error. Ignore it.
    // This can be removed once all environments are updated to new states.
    legacy::states::machine::start_migration(db_pool.clone()).await?;

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
                .dpu_wait_time(carbide_config.machine_state_controller.dpu_wait_time)
                .power_down_wait(carbide_config.machine_state_controller.power_down_wait)
                .failure_retry_time(carbide_config.machine_state_controller.failure_retry_time)
                .hardware_models(carbide_config.get_firmware_config())
                .firmware_downloader(&downloader)
                .attestation_enabled(carbide_config.attestation_enabled)
                .upload_limiter(upload_limiter.clone())
                .machine_validation_config(carbide_config.machine_validation_config)
                .common_pools(common_pools.clone())
                .build(),
        ))
        .io(Arc::new(MachineStateControllerIO {
            hardware_health: carbide_config.host_health.hardware_health_reports,
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
        carbide_config.ib_fabric_monitor.clone(),
        if ib_config.enabled {
            carbide_config.ib_fabrics.clone()
        } else {
            Default::default()
        },
        meter.clone(),
        ib_fabric_manager.clone(),
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
    attestation::backfill_ek_cert_status_for_existing_machines(&db_pool).await?;

    let listen_addr = carbide_config.listen;
    listener::listen_and_serve(
        api_service,
        tls_config,
        listen_addr,
        &carbide_config.auth,
        meter,
        stop_channel,
        ready_channel,
    )
    .await
}
