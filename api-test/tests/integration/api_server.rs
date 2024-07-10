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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use carbide::cfg::{
    default_dpu_models, default_max_find_by_ids, AgentUpgradePolicyChoice, AuthConfig,
    CarbideConfig, FirmwareGlobal, IBFabricConfig, IbFabricMonitorConfig,
    IbPartitionStateControllerConfig, MachineStateControllerConfig,
    NetworkSegmentStateControllerConfig, SiteExplorerConfig, StateControllerConfig, TlsConfig,
};
use carbide::logging::setup::TelemetrySetup;
use carbide::logging::sqlx_query_tracing;
use carbide::model::network_segment::{NetworkDefinition, NetworkDefinitionSegmentType};
use carbide::redfish::RedfishClientPool;
use carbide::resource_pool::{Range, ResourcePoolDef, ResourcePoolType};
use tokio::sync::oneshot::Receiver;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{filter::EnvFilter, fmt::TestWriter, prelude::*, util::SubscriberInitExt};

const DOMAIN_NAME: &str = "forge.integrationtest";

pub async fn start(
    addr: SocketAddr,
    root_dir: String,
    db_url: String,
    vault_token: String,
    override_redfish_pool: Option<Arc<dyn RedfishClientPool>>,
    telemetry_setup: TelemetrySetup,
    stop_channel: Receiver<()>,
) -> eyre::Result<()> {
    let mut dpu_nic_firmware_update_versions = HashMap::new();
    dpu_nic_firmware_update_versions.insert("product_x".to_owned(), "v1".to_owned());

    let carbide_config = CarbideConfig {
        listen: addr,
        metrics_endpoint: Some("127.0.0.1:1080".parse().unwrap()),
        otlp_endpoint: None,
        database_url: db_url,
        max_database_connections: 1000,
        asn: 65535,
        dhcp_servers: vec![],
        route_servers: vec![],
        enable_route_servers: false,
        deny_prefixes: vec![],
        site_fabric_prefixes: vec![],
        ib_fabric_monitor: IbFabricMonitorConfig {
            enabled: true,
            run_interval: std::time::Duration::from_secs(10),
        },
        initial_domain_name: Some(DOMAIN_NAME.to_string()),
        initial_dpu_agent_upgrade_policy: Some(AgentUpgradePolicyChoice::Off),
        tls: Some(TlsConfig {
            identity_pemfile_path: format!("{root_dir}/dev/certs/server_identity.pem"),
            identity_keyfile_path: format!("{root_dir}/dev/certs/server_identity.key"),
            root_cafile_path: format!(
                "{root_dir}/dev/certs/forge_developer_local_only_root_cert_pem"
            ),
            admin_root_cafile_path: "nothing_will_read_from_this_during_integration_tests"
                .to_string(),
        }),
        auth: Some(AuthConfig {
            permissive_mode: true,
            casbin_policy_file: format!("{root_dir}/api/casbin-policy.csv").into(),
        }),
        pools: Some(HashMap::from([
            (
                "lo-ip".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Ipv4,
                    prefix: Some("10.180.62.1/26".to_string()),
                    ranges: vec![],
                },
            ),
            (
                "vlan-id".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Integer,
                    prefix: None,
                    ranges: vec![Range {
                        start: "100".to_string(),
                        end: "501".to_string(),
                    }],
                },
            ),
            (
                "vni".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Integer,
                    prefix: None,
                    ranges: vec![Range {
                        start: "1024500".to_string(),
                        end: "1024550".to_string(),
                    }],
                },
            ),
            (
                "vpc-vni".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Integer,
                    prefix: None,
                    ranges: vec![Range {
                        start: "2024500".to_string(),
                        end: "2024550".to_string(),
                    }],
                },
            ),
            (
                "pkey".to_string(),
                ResourcePoolDef {
                    pool_type: ResourcePoolType::Integer,
                    prefix: None,
                    ranges: vec![Range {
                        start: "1".to_string(),
                        end: "10".to_string(),
                    }],
                },
            ),
        ])),
        networks: Some(HashMap::from([
            (
                "admin".to_string(),
                NetworkDefinition {
                    segment_type: NetworkDefinitionSegmentType::Admin,
                    prefix: "172.20.0.0/24".to_string(),
                    gateway: "172.20.0.1".to_string(),
                    mtu: 9000,
                    reserve_first: 5,
                },
            ),
            (
                "DEV1-C09-IPMI-01".to_string(),
                NetworkDefinition {
                    segment_type: NetworkDefinitionSegmentType::Underlay,
                    prefix: "127.0.0.0/8".to_string(),
                    gateway: "127.0.0.10".to_string(),
                    mtu: 1490,
                    reserve_first: 0,
                },
            ),
        ])),
        dpu_ipmi_tool_impl: Some("test".to_owned()),
        dpu_ipmi_reboot_attempts: None,
        dpu_nic_firmware_update_version: Some(dpu_nic_firmware_update_versions),
        dpu_nic_firmware_initial_update_enabled: false,
        dpu_nic_firmware_reprovision_update_enabled: false,
        max_concurrent_machine_updates: Some(1),
        machine_update_run_interval: None,
        site_explorer: SiteExplorerConfig {
            enabled: true,
            run_interval: std::time::Duration::from_secs(5),
            concurrent_explorations: 5,
            explorations_per_run: 10,
            create_machines: carbide::dynamic_settings::create_machines(false),
            override_target_ip: None,
            override_target_port: None,
        },
        dpu_dhcp_server_enabled: true,
        nvue_enabled: true,
        attestation_enabled: false,
        ib_config: Some(IBFabricConfig {
            max_partition_per_tenant: IBFabricConfig::default_max_partition_per_tenant(),
            enabled: false,
        }),
        machine_state_controller: MachineStateControllerConfig {
            controller: StateControllerConfig {
                iteration_time: std::time::Duration::from_secs(1),
                ..StateControllerConfig::default()
            },
            dpu_wait_time: chrono::Duration::seconds(1),
            power_down_wait: chrono::Duration::seconds(1),
            failure_retry_time: chrono::Duration::seconds(1),
            dpu_up_threshold: chrono::Duration::weeks(52),
        },
        network_segment_state_controller: NetworkSegmentStateControllerConfig {
            network_segment_drain_time: chrono::Duration::seconds(60),
            controller: StateControllerConfig {
                iteration_time: std::time::Duration::from_secs(2),
                ..StateControllerConfig::default()
            },
        },
        ib_partition_state_controller: IbPartitionStateControllerConfig {
            controller: StateControllerConfig {
                // High iteration time because no IB is tested
                iteration_time: std::time::Duration::from_secs(20),
                ..StateControllerConfig::default()
            },
        },
        dpu_models: default_dpu_models(),
        host_models: HashMap::new(),
        firmware_global: FirmwareGlobal {
            autoupdate: false,
            host_enable_autoupdate: vec![],
            host_disable_autoupdate: vec![],
            max_uploads: 4,
            run_interval: Duration::seconds(30),
        },
        max_find_by_ids: default_max_find_by_ids(),
        min_dpu_functioning_links: None,
    };

    std::env::set_var("VAULT_ADDR", "http://127.0.0.1:8200");
    std::env::set_var("VAULT_KV_MOUNT_LOCATION", "secret");
    std::env::set_var("VAULT_PKI_MOUNT_LOCATION", "forgeca");
    std::env::set_var("VAULT_PKI_ROLE_NAME", "forge-cluster");
    std::env::set_var("VAULT_TOKEN", vault_token);

    let carbide_config_str = toml::to_string(&carbide_config).unwrap();
    carbide::run(
        0,
        carbide_config_str,
        None,
        Some(test_logging_subscriber()),
        override_redfish_pool,
        Some(telemetry_setup),
        stop_channel,
    )
    .await
}

pub fn test_logging_subscriber() -> impl SubscriberInitExt {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustify=off".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap())
        // Silence permissive mode related messages
        .add_directive("carbide::auth=error".parse().unwrap());

    // Note: `TestWriter` is required to use the standard behavior of Rust unit tests:
    // - Successful tests won't show output unless forced by the `--nocapture` CLI argument
    // - Failing tests will have their output printed
    Box::new(
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::Layer::default()
                    .compact()
                    .with_ansi(false)
                    .with_writer(TestWriter::new)
                    .with_filter(sqlx_query_tracing::block_sqlx_filter()),
            )
            .with(sqlx_query_tracing::create_sqlx_query_tracing_layer())
            .with(env_filter),
    )
}
