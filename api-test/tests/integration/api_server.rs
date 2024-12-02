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
use std::collections::HashMap;
use std::net::SocketAddr;

use carbide::cfg::{
    default_max_find_by_ids, AgentUpgradePolicyChoice, AuthConfig, CarbideConfig, FirmwareGlobal,
    HostHealthConfig, IBFabricConfig, IbFabricMonitorConfig, IbPartitionStateControllerConfig,
    MachineStateControllerConfig, MachineValidationConfig, MeasuredBootMetricsCollectorConfig,
    MultiDpuConfig, NetworkSegmentStateControllerConfig, SiteExplorerConfig, StateControllerConfig,
    TlsConfig,
};
use carbide::{IBMtu, IBRateLimit, IBServiceLevel};
use carbide::{NetworkDefinition, NetworkDefinitionSegmentType};
use carbide::{ResourcePoolDef, ResourcePoolRange, ResourcePoolType};
use tokio::sync::oneshot::{Receiver, Sender};
use utils::HostPortPair;

const DOMAIN_NAME: &str = "forge.integrationtest";

// Use a struct for the args to start() so that callers can see argument names
pub struct StartArgs {
    pub addr: SocketAddr,
    pub root_dir: String,
    pub db_url: String,
    pub vault_token: String,
    pub bmc_proxy: Option<HostPortPair>,
    pub site_explorer_create_machines: bool,
    pub stop_channel: Receiver<()>,
    pub ready_channel: Sender<()>,
}

pub async fn start(start_args: StartArgs) -> eyre::Result<()> {
    let StartArgs {
        addr,
        root_dir,
        db_url,
        vault_token,
        bmc_proxy,
        site_explorer_create_machines,
        stop_channel,
        ready_channel,
    } = start_args;

    let mut dpu_nic_firmware_update_versions = HashMap::new();
    dpu_nic_firmware_update_versions.insert("product_x".to_owned(), "v1".to_owned());

    let carbide_config = CarbideConfig {
        listen: addr,
        metrics_endpoint: Some("127.0.0.1:1080".parse().unwrap()),
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
                    ranges: vec![ResourcePoolRange {
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
                    ranges: vec![ResourcePoolRange {
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
                    ranges: vec![ResourcePoolRange {
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
                    ranges: vec![ResourcePoolRange {
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
            (
                "DEV1-C09-DPU-01".to_string(),
                NetworkDefinition {
                    segment_type: NetworkDefinitionSegmentType::Underlay,
                    prefix: "172.20.1.0/24".to_string(),
                    gateway: "172.20.1.1".to_string(),
                    mtu: 1490,
                    reserve_first: 5,
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
            concurrent_explorations: SiteExplorerConfig::default_concurrent_explorations(),
            explorations_per_run: SiteExplorerConfig::default_explorations_per_run(),
            create_machines: carbide::dynamic_settings::create_machines(
                site_explorer_create_machines,
            ),
            allow_zero_dpu_hosts: true,
            bmc_proxy: carbide::dynamic_settings::bmc_proxy(bmc_proxy),
            ..Default::default()
        },
        dpu_dhcp_server_enabled: true,
        nvue_enabled: true,
        attestation_enabled: false,
        ib_config: Some(IBFabricConfig {
            enabled: false,
            max_partition_per_tenant: IBFabricConfig::default_max_partition_per_tenant(),
            mtu: IBMtu::default(),
            service_level: IBServiceLevel::default(),
            rate_limit: IBRateLimit::default(),
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
        dpu_models: HashMap::new(),
        host_models: HashMap::new(),
        firmware_global: FirmwareGlobal::test_default(),
        max_find_by_ids: default_max_find_by_ids(),
        min_dpu_functioning_links: None,
        multi_dpu: MultiDpuConfig::default(),
        dpu_network_monitor_pinger_type: None,
        host_health: HostHealthConfig::default(),
        internet_l3_vni: Some(1337),
        measured_boot_collector: MeasuredBootMetricsCollectorConfig {
            enabled: true,
            run_interval: std::time::Duration::from_secs(10),
        },
        machine_validation_config: MachineValidationConfig { enabled: true },
        bypass_rbac: true,
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
        None,
        true,
        stop_channel,
        ready_channel,
    )
    .await
}
