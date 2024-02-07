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

use chrono::Duration;
use eyre::WrapErr;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use forge_secrets::{
    certificates::CertificateProvider,
    credentials::CredentialProvider,
    forge_vault::{
        ForgeVaultAuthenticationType, ForgeVaultClientConfig, ForgeVaultMetrics, GaugeHolder,
        VaultTokenGaugeHolder,
    },
    ForgeVaultClient,
};
use opentelemetry::metrics::{Meter, Observer, Unit};
use sqlx::{postgres::PgSslMode, ConnectOptions, PgPool};
use std::{env, path::Path, sync::Arc};

use crate::{
    api::Api,
    auth,
    cfg::CarbideConfig,
    db_init, ethernet_virtualization,
    ib::{self, IBFabricManager},
    ipmitool::{IPMITool, IPMIToolImpl, IPMIToolTestImpl},
    listener,
    logging::service_health_metrics::{start_export_service_health_metrics, ServiceHealthContext},
    machine_update_manager::MachineUpdateManager,
    redfish::{RedfishClientPool, RedfishClientPoolImpl},
    resource_pool::{self, common::CommonPools},
    site_explorer::{RedfishEndpointExplorer, SiteExplorer},
    state_controller::{
        controller::{ReachabilityParams, StateController},
        ib_partition::{handler::IBPartitionStateHandler, io::IBPartitionStateControllerIO},
        machine::{handler::MachineStateHandler, io::MachineStateControllerIO},
        network_segment::{
            handler::NetworkSegmentStateHandler, io::NetworkSegmentStateControllerIO,
        },
    },
    CarbideError,
};

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

pub async fn create_vault_client(meter: Meter) -> eyre::Result<Arc<ForgeVaultClient>> {
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

    let vault_requests_total_counter = meter
        .u64_counter("carbide-api.vault.requests_attempted")
        .with_description("The amount of tls connections that were attempted")
        .init();
    let vault_requests_succeeded_counter = meter
        .u64_counter("carbide-api.vault.requests_succeeded")
        .with_description("The amount of tls connections that were successful")
        .init();
    let vault_requests_failed_counter = meter
        .u64_counter("carbide-api.vault.requests_failed")
        .with_description("The amount of tcp connections that were failures")
        .init();
    let vault_token_time_remaining_until_refresh_gauge = meter
        .u64_observable_gauge("carbide-api.vault.token_time_until_refresh")
        .with_description(
            "The amount of time, in seconds, until the vault token is required to be refreshed",
        )
        .with_unit(Unit::new("s"))
        .init();
    let vault_request_duration_histogram = meter
        .u64_histogram("carbide-api.vault.request_duration")
        .with_description("the duration of outbound vault requests, in milliseconds")
        .with_unit(Unit::new("ms"))
        .init();

    let vault_token_gauge_holder = Arc::new(VaultTokenGaugeHolder::new(
        vault_token_time_remaining_until_refresh_gauge,
    ));

    let forge_vault_metrics = ForgeVaultMetrics {
        vault_requests_total_counter,
        vault_requests_succeeded_counter,
        vault_requests_failed_counter,
        vault_token_gauge_holder: vault_token_gauge_holder.clone(),
        vault_request_duration_histogram,
    };

    meter
        .register_callback(
            &[vault_token_gauge_holder.emit_observable()],
            move |observer: &dyn Observer| vault_token_gauge_holder.observe_callback(observer),
        )
        .wrap_err("unable to register callback?")?;

    let vault_client_config = ForgeVaultClientConfig {
        auth_type,
        vault_address,
        kv_mount_location,
        pki_mount_location,
        pki_role_name,
        vault_root_ca_path,
    };

    let forge_vault_client = ForgeVaultClient::new(vault_client_config, forge_vault_metrics);
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
async fn create_and_connect_postgres_pool(
    config: &CarbideConfig,
    service_config: &ServiceConfig,
) -> eyre::Result<PgPool> {
    // We need logs to be enabled at least at `INFO` level. Otherwise
    // our global logging filter would reject the logs before they get injected
    // into the `SqlxQueryTracing` layer.
    let mut database_connect_options = config
        .database_url
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .log_statements("INFO".parse().unwrap());
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
        .max_connections(service_config.max_db_connections)
        .connect_with(database_connect_options)
        .await?)
}

#[tracing::instrument(skip_all)]
pub async fn start_api<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    carbide_config: Arc<CarbideConfig>,
    credential_provider: Arc<C1>,
    certificate_provider: Arc<C2>,
    meter: opentelemetry::metrics::Meter,
    ipmi_tool: Arc<dyn IPMITool>,
) -> eyre::Result<()> {
    let service_config = if carbide_config.rapid_iterations {
        tracing::info!("Running with rapid iterations for local development");
        ServiceConfig::for_local_development()
    } else {
        ServiceConfig::default()
    };

    let rf_pool = libredfish::RedfishClientPool::builder()
        .build()
        .map_err(CarbideError::from)?;
    let redfish_pool = RedfishClientPoolImpl::new(credential_provider.clone(), rf_pool);
    let shared_redfish_pool: Arc<dyn RedfishClientPool> = Arc::new(redfish_pool);

    let db_pool = create_and_connect_postgres_pool(&carbide_config, &service_config).await?;

    if let Some(domain_name) = &carbide_config.initial_domain_name {
        if db_init::create_initial_domain(db_pool.clone(), domain_name).await? {
            tracing::info!("Created initial domain {domain_name}");
        }
    }

    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin define resource pools", e))?;
    resource_pool::define_all_from(&mut txn, carbide_config.pools.as_ref().unwrap()).await?;
    txn.commit()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "commit define resource pools", e))?;

    let common_pools = CommonPools::create(db_pool.clone()).await?;

    let fabric_manager_type = match carbide_config.enable_ib_fabric.unwrap_or(false) {
        true => ib::IBFabricManagerType::Rest,
        false => ib::IBFabricManagerType::Disable,
    };

    let ib_fabric_manager_impl =
        ib::create_ib_fabric_manager(credential_provider.clone(), fabric_manager_type);

    let ib_fabric_manager: Arc<dyn IBFabricManager> = Arc::new(ib_fabric_manager_impl);

    let authorizer = auth::Authorizer::build_casbin(
        &carbide_config
            .auth
            .as_ref()
            .expect("Missing auth config")
            .casbin_policy_file,
        carbide_config
            .auth
            .as_ref()
            .expect("Missing auth config")
            .permissive_mode,
    )
    .await?;

    let route_servers = db_init::create_initial_route_servers(&db_pool, &carbide_config).await?;

    let eth_data = ethernet_virtualization::EthVirtData {
        asn: carbide_config.asn,
        dhcp_servers: carbide_config.dhcp_servers.clone(),
        route_servers,
        route_servers_enabled: carbide_config.enable_route_servers,
        // Include the site fabric prefixes in the deny prefixes list, since
        // we treat them the same way from here.
        deny_prefixes: [
            carbide_config.site_fabric_prefixes.as_slice(),
            carbide_config.deny_prefixes.as_slice(),
        ]
        .concat(),
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
    };

    let api_service = Arc::new(Api::new(
        carbide_config.clone(),
        credential_provider.clone(),
        certificate_provider.clone(),
        db_pool.clone(),
        shared_redfish_pool.clone(),
        eth_data,
        common_pools.clone(),
        ib_fabric_manager.clone(),
    ));

    if let Some(networks) = carbide_config.networks.as_ref() {
        db_init::create_initial_networks(&api_service, &db_pool, networks).await?;
    }

    db_init::store_initial_dpu_agent_upgrade_policy(
        &db_pool,
        carbide_config.initial_dpu_agent_upgrade_policy,
    )
    .await?;

    // handles need to be stored in a variable
    // If they are assigned to _ then the destructor will be immediately called
    let _machine_state_controller_handle = StateController::<MachineStateControllerIO>::builder()
        .database(db_pool.clone())
        .meter("forge_machines", meter.clone())
        .redfish_client_pool(shared_redfish_pool.clone())
        .ib_fabric_manager(ib_fabric_manager.clone())
        .forge_api(api_service.clone())
        .iteration_time(service_config.machine_state_controller_iteration_time)
        .state_handler(Arc::new(MachineStateHandler::new(
            service_config.dpu_up_threshold,
            carbide_config.dpu_nic_firmware_initial_update_enabled,
            carbide_config.dpu_nic_firmware_reprovision_update_enabled,
        )))
        .reachability_params(ReachabilityParams {
            dpu_wait_time: service_config.dpu_wait_time,
            host_wait_time: service_config.host_wait_time,
            power_down_wait: service_config.power_down_wait,
            failure_retry_time: service_config.failure_retry_time,
        })
        .ipmi_tool(ipmi_tool.clone())
        .build()
        .expect("Unable to build MachineStateController");

    let sc_pool_vlan_id = common_pools.ethernet.pool_vlan_id.clone();
    let sc_pool_vni = common_pools.ethernet.pool_vni.clone();

    let ns_builder = StateController::<NetworkSegmentStateControllerIO>::builder()
        .database(db_pool.clone())
        .meter("forge_network_segments", meter.clone())
        .redfish_client_pool(shared_redfish_pool.clone())
        .ib_fabric_manager(ib_fabric_manager.clone())
        .forge_api(api_service.clone());
    let _network_segment_controller_handle = ns_builder
        .iteration_time(service_config.network_segment_state_controller_iteration_time)
        .state_handler(Arc::new(NetworkSegmentStateHandler::new(
            service_config.network_segment_drain_time,
            sc_pool_vlan_id,
            sc_pool_vni,
        )))
        .reachability_params(ReachabilityParams {
            dpu_wait_time: service_config.dpu_wait_time,
            host_wait_time: service_config.host_wait_time,
            power_down_wait: service_config.power_down_wait,
            failure_retry_time: service_config.failure_retry_time,
        })
        .ipmi_tool(ipmi_tool.clone())
        .build()
        .expect("Unable to build NetworkSegmentController");

    let _ib_partition_controller_handle =
        StateController::<IBPartitionStateControllerIO>::builder()
            .database(db_pool.clone())
            .meter("forge_ib_partitions", meter.clone())
            .redfish_client_pool(shared_redfish_pool.clone())
            .ib_fabric_manager(ib_fabric_manager.clone())
            .pool_pkey(common_pools.infiniband.pool_pkey.clone())
            .reachability_params(ReachabilityParams {
                dpu_wait_time: service_config.dpu_wait_time,
                host_wait_time: service_config.host_wait_time,
                power_down_wait: service_config.power_down_wait,
                failure_retry_time: service_config.failure_retry_time,
            })
            .forge_api(api_service.clone())
            .iteration_time(service_config.network_segment_state_controller_iteration_time)
            .state_handler(Arc::new(IBPartitionStateHandler::new(
                service_config.network_segment_drain_time,
            )))
            .ipmi_tool(ipmi_tool.clone())
            .build()
            .expect("Unable to build IBPartitionStateController");

    let site_explorer = SiteExplorer::new(
        db_pool.clone(),
        carbide_config.site_explorer.as_ref(),
        meter.clone(),
        Arc::new(RedfishEndpointExplorer::new(shared_redfish_pool.clone())),
    );
    let _site_explorer_stop_handle = site_explorer.start()?;

    let machine_update_manager =
        MachineUpdateManager::new(db_pool.clone(), carbide_config.clone(), meter.clone());
    let _machine_update_manager_stop_handle = machine_update_manager.start()?;

    let listen_addr = carbide_config.listen;
    listener::listen_and_serve(api_service, tls_config, listen_addr, authorizer, meter).await
}

/// Configurations that are not yet exposed via the CLI
///
/// We might want to integrate those into a toml file instead of hardcoding,
/// but for now this will do it
struct ServiceConfig {
    /// The time for which network segments must have 0 allocated IPs, before they
    /// are actually released
    network_segment_drain_time: chrono::Duration,
    /// Iteration time for the machine state controller
    machine_state_controller_iteration_time: std::time::Duration,
    /// Iteration time for the network segment state controller
    network_segment_state_controller_iteration_time: std::time::Duration,
    /// Maximum database connections
    max_db_connections: u32,
    /// How long to wait for DPU to restart after BMC lockdown. Not a timeout, it's a forced wait.
    /// This will be replaced with querying lockdown state.
    dpu_wait_time: chrono::Duration,
    /// How long to wait for Host to restart if it does not respond after reboot.
    host_wait_time: chrono::Duration,
    /// How long to wait for after power down before power on the machine.
    power_down_wait: chrono::Duration,
    /// How long to wait for a health report from the DPU before we assume it's down
    dpu_up_threshold: chrono::Duration,
    /// How long to wait for after machine moved to failed state
    failure_retry_time: chrono::Duration,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            network_segment_drain_time: chrono::Duration::minutes(5),
            machine_state_controller_iteration_time: std::time::Duration::from_secs(30),
            network_segment_state_controller_iteration_time: std::time::Duration::from_secs(30),
            max_db_connections: 1000,
            dpu_wait_time: Duration::minutes(5),
            host_wait_time: Duration::minutes(30),
            power_down_wait: Duration::seconds(15),
            dpu_up_threshold: Duration::minutes(5),
            failure_retry_time: Duration::minutes(30),
        }
    }
}

impl ServiceConfig {
    /// Configuration for local development
    ///
    /// Components are running faster, so we can observe state changes without waiting too long.
    /// Machine state controller is kept normal for now, since it's output is noisy.
    pub fn for_local_development() -> Self {
        Self {
            network_segment_drain_time: chrono::Duration::seconds(60),
            machine_state_controller_iteration_time: std::time::Duration::from_secs(10),
            network_segment_state_controller_iteration_time: std::time::Duration::from_secs(2),
            max_db_connections: 1000,
            dpu_wait_time: Duration::seconds(1),
            host_wait_time: Duration::seconds(1),
            power_down_wait: Duration::seconds(1),
            // In local dev forge-dpu-agent probably isn't running, so no heartbeat
            dpu_up_threshold: Duration::weeks(52),
            failure_retry_time: Duration::seconds(1),
        }
    }
}
