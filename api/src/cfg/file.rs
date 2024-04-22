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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::{collections::HashMap, fmt::Display};

use chrono::Duration;
use ipnetwork::Ipv4Network;
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::state_controller::config::IterationConfig;
use crate::{model::network_segment::NetworkDefinition, resource_pool::ResourcePoolDef};
use duration_str::{deserialize_duration, deserialize_duration_chrono};

const MAX_IB_PARTITION_PER_TENANT: i32 = 3;

/// carbide-api configuration file content
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CarbideConfig {
    /// The socket address that is used for the gRPC API server
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// The socket address that is used for the HTTP server which serves
    /// prometheus metrics under /metrics
    pub metrics_endpoint: Option<SocketAddr>,

    /// The DNS name and port of the opentelemetry collector
    pub otlp_endpoint: Option<String>,

    /// A connection string for the utilized postgres database
    pub database_url: String,

    /// The maximum size of the database connection pool
    #[serde(default = "default_max_database_connections")]
    pub max_database_connections: u32,

    /// IB fabric related configuration
    pub ib_config: Option<IBFabricConfig>,

    /// ASN: Autonomous System Number
    /// Fixed per environment. Used by forge-dpu-agent to write frr.conf (routing).
    pub asn: u32,

    /// List of DHCP servers that should be announced
    #[serde(default)]
    pub dhcp_servers: Vec<String>,

    /// Comma-separated list of route server IP addresses. Optional, only for L2VPN (Eth Virt).
    #[serde(default)]
    pub route_servers: Vec<String>,

    #[serde(default)]
    pub enable_route_servers: bool,

    /// List of IPv4 prefixes (in CIDR notation) that tenant instances are not allowed to talk to.
    #[serde(default)]
    pub deny_prefixes: Vec<Ipv4Network>,

    /// List of IPv4 prefixes (in CIDR notation) that are assigned for tenant
    /// use within this site.
    #[serde(default)]
    pub site_fabric_prefixes: Vec<Ipv4Network>,

    /// TLS related configuration
    pub tls: Option<TlsConfig>,

    /// Authentication related configuration
    pub auth: Option<AuthConfig>,

    // Resource pools to allocate IPs, VNIs, etc.
    // Required.
    // Option so that we can de-serialize partial configs (and then merge them).
    pub pools: Option<HashMap<String, ResourcePoolDef>>,

    // Networks to create. Otherwise use grpcurl CreateNetworkSegment to create them later.
    pub networks: Option<HashMap<String, NetworkDefinition>>,

    // The type of ipmitool to user (prod or fake)
    pub dpu_impi_tool_impl: Option<String>,

    // The number of retries to perform if ipmi returns an error
    pub dpu_ipmi_reboot_attempts: Option<u32>,

    /// Domain to create if there are no domains.
    ///
    /// Most sites use a single domain for their lifetime. This is that domain.
    /// The alternative is to create it via `CreateDomain` grpc endpoint.
    pub initial_domain_name: Option<String>,

    /// The policy we use to decide whether a specific forge-dpu-agent should be upgraded
    /// Also settable via a `forge-admin-cli` command.
    pub initial_dpu_agent_upgrade_policy: Option<AgentUpgradePolicyChoice>,

    /// The version of DPU NIC firmware that is expected on the DPU.  If the actual DPU NIC firmware
    /// does not match, the DPU will be updated during reprovisioning.  It is the operators responsibility
    /// to make sure this value matches the version shipped with carbide.  If "None" updates
    /// during reprovisioning will be disabled
    pub dpu_nic_firmware_update_version: Option<HashMap<String, String>>,

    /// Enable dpu firmware updates on initial discovery
    #[serde(default)]
    pub dpu_nic_firmware_initial_update_enabled: bool,

    /// Enable dpu firmware updates on known machines
    #[serde(default)]
    pub dpu_nic_firmware_reprovision_update_enabled: bool,

    /// IbFabricMonitor related confipguration
    #[serde(default)]
    pub ib_fabric_monitor: IbFabricMonitorConfig,

    /// The maximum number of machines that have in-progress updates running.  This prevents
    /// too many machines from being put into maintenance at any given time.
    pub max_concurrent_machine_updates: Option<i32>,

    /// The interval at which the machine update manager checks for machine updates in seconds.
    pub machine_update_run_interval: Option<u64>,

    /// SiteExplorer related configuration
    pub site_explorer: Option<SiteExplorerConfig>,

    /// Enable DHCP server on DPU to serve host.
    #[serde(default)]
    pub dpu_dhcp_server_enabled: bool,

    /// DPU agent to use NVUE instead of writing files directly.
    /// Once we are comfortable with this and all DPUs are HBN 2+ it will become the only option.
    #[serde(default)]
    pub nvue_enabled: bool,

    /// MachineStateController related configuration parameter
    #[serde(default)]
    pub machine_state_controller: MachineStateControllerConfig,

    /// Config for DPU firmware update
    #[serde(default)]
    pub dpu_fw_update_config: DpuFwUpdateConfig,

    /// NetworkSegmentController related configuration parameter
    #[serde(default)]
    pub network_segment_state_controller: NetworkSegmentStateControllerConfig,

    /// IbPartitionStateController related configuration parameter
    #[serde(default)]
    pub ib_partition_state_controller: IbPartitionStateControllerConfig,

    /// DPU related configuration parameter
    #[serde(default = "default_dpus")]
    pub dpus: HashMap<DpuModel, DpuDesc>,
}

/// As of now, chrono::Duration does not support Serialization, so we have to handle it manually.
fn as_duration<S>(d: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}s", d.num_seconds()))
}

fn as_std_duration<S>(d: &std::time::Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}s", d.as_secs()))
}

/// MachineStateController related config.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MachineStateControllerConfig {
    /// Common state controller configs
    #[serde(default = "StateControllerConfig::default")]
    pub controller: StateControllerConfig,

    /// How long should we wait before a DPU goes down for sure.
    #[serde(
        default = "MachineStateControllerConfig::dpu_wait_time_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub dpu_wait_time: Duration,
    /// How long to wait for after power down before power on the machine.
    #[serde(
        default = "MachineStateControllerConfig::power_down_wait_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub power_down_wait: Duration,
    /// After how much time, state machine should retrigger reboot if machine does not call back.
    #[serde(
        default = "MachineStateControllerConfig::failure_retry_time_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub failure_retry_time: Duration,
    /// How long to wait for a health report from the DPU before we assume it's down
    #[serde(
        default = "MachineStateControllerConfig::dpu_up_threshold_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub dpu_up_threshold: Duration,
}

impl MachineStateControllerConfig {
    pub fn dpu_wait_time_default() -> Duration {
        Duration::minutes(5)
    }

    pub fn power_down_wait_default() -> Duration {
        Duration::minutes(2)
    }

    pub fn failure_retry_time_default() -> Duration {
        Duration::minutes(30)
    }

    pub fn dpu_up_threshold_default() -> Duration {
        Duration::minutes(5)
    }
}

impl Default for MachineStateControllerConfig {
    fn default() -> Self {
        Self {
            controller: StateControllerConfig::default(),
            dpu_wait_time: MachineStateControllerConfig::dpu_wait_time_default(),
            power_down_wait: MachineStateControllerConfig::power_down_wait_default(),
            failure_retry_time: MachineStateControllerConfig::failure_retry_time_default(),
            dpu_up_threshold: MachineStateControllerConfig::dpu_up_threshold_default(),
        }
    }
}

/// Firmware related config.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DpuFwUpdateConfig {
    /// The version of DPU BMC firmware that is expected on the DPU for BF3. If the actual DPU BMC firmware
    /// does not match, the DPU will be updated during discovering or reprovisioning. It is the operators responsibility
    /// to make sure this value matches the version shipped with carbide.
    #[serde(default)]
    pub dpu_bf3_bmc_firmware_update_version: HashMap<String, String>,

    /// The version of DPU BMC firmware that is expected on the DPU for BF2.
    #[serde(default)]
    pub dpu_bf2_bmc_firmware_update_version: HashMap<String, String>,

    /// Path where firmware files are located
    pub firmware_location: String,
}

impl Default for DpuFwUpdateConfig {
    fn default() -> Self {
        Self {
            dpu_bf3_bmc_firmware_update_version: HashMap::new(),
            dpu_bf2_bmc_firmware_update_version: HashMap::new(),
            firmware_location: "/forge-boot-artifacts/blobs/internal/firmware/nvidia/dpu/"
                .to_string(),
        }
    }
}

/// NetworkSegmentStateController related config.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct NetworkSegmentStateControllerConfig {
    /// Common state controller configs
    #[serde(default = "StateControllerConfig::default")]
    pub controller: StateControllerConfig,
    /// The time for which network segments must have 0 allocated IPs, before they
    /// are actually released.
    /// This should be set to a duration long enough that ensures no pending
    /// RPC calls might still use the network segment to avoid race conditions.
    #[serde(
        default = "NetworkSegmentStateControllerConfig::network_segment_drain_time_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub network_segment_drain_time: chrono::Duration,
}

impl NetworkSegmentStateControllerConfig {
    pub fn network_segment_drain_time_default() -> Duration {
        Duration::minutes(5)
    }
}

impl Default for NetworkSegmentStateControllerConfig {
    fn default() -> Self {
        Self {
            controller: StateControllerConfig::default(),
            network_segment_drain_time: Self::network_segment_drain_time_default(),
        }
    }
}

/// IbPartitionStateController related config
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct IbPartitionStateControllerConfig {
    /// Common state controller configs
    #[serde(default = "StateControllerConfig::default")]
    pub controller: StateControllerConfig,
}

/// Common StateController configurations
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StateControllerConfig {
    /// Configures the desired duration for one state controller iteration
    ///
    /// Lower iteration times will make the controller react faster to state changes.
    /// However they will also increase the load on the system
    #[serde(
        default = "StateControllerConfig::iteration_time_default",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub iteration_time: std::time::Duration,

    /// Configures the maximum time that the state handler will spend on evaluating
    /// and advancing the state of a single object. If more time elapses during
    /// state handling than this timeout allows for, state handling will fail with
    /// a `TimeoutError`.
    /// How long to wait for after power down before power on the machine.
    #[serde(
        default = "StateControllerConfig::max_object_handling_time_default",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub max_object_handling_time: std::time::Duration,

    /// Configures the maximum amount of concurrency for the object state controller
    ///
    /// The controller will attempt to advance the state of this amount of instances
    /// in parallel.
    #[serde(default = "StateControllerConfig::max_concurrency_default")]
    pub max_concurrency: usize,
}

impl StateControllerConfig {
    pub const fn max_object_handling_time_default() -> std::time::Duration {
        std::time::Duration::from_secs(3 * 60)
    }

    pub const fn iteration_time_default() -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }

    pub const fn max_concurrency_default() -> usize {
        10
    }
}

impl Default for StateControllerConfig {
    fn default() -> Self {
        Self {
            iteration_time: Self::iteration_time_default(),
            max_object_handling_time: Self::max_object_handling_time_default(),
            max_concurrency: Self::max_concurrency_default(),
        }
    }
}

impl From<&StateControllerConfig> for IterationConfig {
    fn from(config: &StateControllerConfig) -> Self {
        IterationConfig {
            iteration_time: config.iteration_time,
            max_object_handling_time: config.max_object_handling_time,
            max_concurrency: config.max_concurrency,
        }
    }
}

/// IBFabricManager related configuration
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct IBFabricConfig {
    #[serde(
        default = "IBFabricConfig::default_max_partition_per_tenant",
        deserialize_with = "IBFabricConfig::deserialize_max_partition"
    )]
    pub max_partition_per_tenant: i32,

    // If ib_fabrics is configured in 'site.toml', it's enabled by default.
    #[serde(default = "IBFabricConfig::enable_ib_fabric")]
    /// Enable IB fabric
    pub enabled: bool,
}

impl IBFabricConfig {
    pub fn enable_ib_fabric() -> bool {
        true
    }

    pub fn default_max_partition_per_tenant() -> i32 {
        MAX_IB_PARTITION_PER_TENANT
    }

    pub fn deserialize_max_partition<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let max_pkey = i32::deserialize(deserializer)?;

        match max_pkey {
            1..=31 => Ok(max_pkey),
            _ => Err(serde::de::Error::custom("invalid max partition per tenant")),
        }
    }
}

/// SiteExplorer related configuration
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct SiteExplorerConfig {
    #[serde(default)]
    /// Whether SiteExplorer is enabled
    pub enabled: bool,
    /// The interval at which site explorer runs.
    /// Defaults to 5 Minutes if not specified.
    #[serde(
        default = "SiteExplorerConfig::default_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub run_interval: std::time::Duration,
    /// The maximum amount of nodes that are explored concurrently.
    /// Default is 5.
    #[serde(default = "SiteExplorerConfig::default_concurrent_explorations")]
    pub concurrent_explorations: u64,
    /// How many nodes should be explored in a single run.
    /// Default is 10.
    /// This number divded by `concurrent_explorations` will determine how many
    /// exploration batches are needed inside a run.
    /// If the value is set too high the site exploration will take a lot of time
    /// and the exploration report will be updated less frequent. Therefore it
    /// is recommended to reduce `run_interval` instead of increasing
    /// `explorations_per_run`.
    #[serde(default = "SiteExplorerConfig::default_explorations_per_run")]
    pub explorations_per_run: u64,

    #[serde(default)]
    /// Whether SiteExplorer should create Managed Host state machine
    pub create_machines: bool,
}

impl SiteExplorerConfig {
    const fn default_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(5 * 60)
    }

    const fn default_concurrent_explorations() -> u64 {
        5
    }

    const fn default_explorations_per_run() -> u64 {
        10
    }
}

/// IbFabricMonitorConfig related configuration
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct IbFabricMonitorConfig {
    #[serde(default)]
    /// Whether IbFabricMonitor is enabled
    pub enabled: bool,
    /// The interval at which ib fabric monitor runs in seconds.
    /// Defaults to 1 Minute if not specified.
    #[serde(
        default = "IbFabricMonitorConfig::default_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub run_interval: std::time::Duration,
}

impl Default for IbFabricMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            run_interval: Self::default_run_interval(),
        }
    }
}

impl IbFabricMonitorConfig {
    const fn default_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
}

/// TLS related configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub root_cafile_path: String,

    #[serde(default)]
    pub identity_pemfile_path: String,

    #[serde(default)]
    pub identity_keyfile_path: String,

    #[serde(default)]
    pub admin_root_cafile_path: String,
}

/// Authentication related configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthConfig {
    /// Enable permissive mode in the authorization enforcer (for development).
    pub permissive_mode: bool,

    /// The Casbin policy file (in CSV format).
    pub casbin_policy_file: PathBuf,
}

// Should match api/src/model/machine/upgrade_policy.rs DpuAgentUpgradePolicy
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpgradePolicyChoice {
    Off,
    UpOnly,
    UpDown,
}

impl Display for AgentUpgradePolicyChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

fn default_listen() -> SocketAddr {
    "[::]:1079".parse().unwrap()
}

fn default_max_database_connections() -> u32 {
    1000
}

/// DPU related config.
fn default_dpus() -> HashMap<DpuModel, DpuDesc> {
    HashMap::from([
        (DpuModel::BlueField2, DpuDesc::new()),
        (DpuModel::BlueField3, DpuDesc::new()),
    ])
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DpuModel {
    BlueField2,
    BlueField3,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DpuComponent {
    Bmc,
    Uefi,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DpuDesc {
    #[serde(default)]
    pub min_component_version: HashMap<DpuComponent, String>,
}

impl DpuDesc {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

impl Default for DpuDesc {
    fn default() -> Self {
        Self {
            min_component_version: HashMap::from([
                (DpuComponent::Bmc, "23.07".to_string()),
                (DpuComponent::Uefi, "4.2".to_string()),
            ]),
        }
    }
}

impl From<CarbideConfig> for rpc::forge::RuntimeConfig {
    fn from(value: CarbideConfig) -> Self {
        Self {
            listen: value.listen.to_string(),
            metrics_endpoint: value
                .metrics_endpoint
                .map(|x| x.to_string())
                .unwrap_or("NA".to_string()),
            otlp_endpoint: value
                .otlp_endpoint
                .map(|x| x.to_string())
                .unwrap_or("NA".to_string()),
            database_url: value.database_url,
            max_database_connections: value.max_database_connections,
            enable_ip_fabric: value.ib_config.unwrap_or_default().enabled,
            asn: value.asn,
            dhcp_servers: value.dhcp_servers,
            route_servers: value.route_servers,
            enable_route_servers: value.enable_route_servers,
            deny_prefixes: value
                .deny_prefixes
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
            site_fabric_prefixes: value
                .site_fabric_prefixes
                .into_iter()
                .map(|x| x.to_string())
                .collect(),
            networks: value
                .networks
                .unwrap_or_default()
                .keys()
                .cloned()
                .collect_vec(),
            dpu_ipmi_tool_impl: value.dpu_impi_tool_impl.unwrap_or("Not Set".to_string()),
            dpu_ipmi_reboot_attempt: value.dpu_ipmi_reboot_attempts.unwrap_or_default(),
            initial_domain_name: value.initial_domain_name,
            initial_dpu_agent_upgrade_policy: value
                .initial_dpu_agent_upgrade_policy
                .unwrap_or(AgentUpgradePolicyChoice::Off)
                .to_string(),
            dpu_nic_firmware_update_version: value
                .dpu_nic_firmware_update_version
                .unwrap_or_default(),
            dpu_nic_firmware_initial_update_enabled: value.dpu_nic_firmware_initial_update_enabled,
            dpu_nic_firmware_reprovision_update_enabled: value
                .dpu_nic_firmware_reprovision_update_enabled,
            max_concurrent_machine_updates: value
                .max_concurrent_machine_updates
                .unwrap_or_default(),
            machine_update_runtime_interval: value.machine_update_run_interval.unwrap_or_default(),
            dpu_dhcp_server_enabled: value.dpu_dhcp_server_enabled,
            nvue_enabled: value.nvue_enabled,
        }
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Env, Format, Toml},
        Figment,
    };

    use super::*;
    use crate::resource_pool;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cfg/test_data");

    #[test]
    fn deserialize_serialize_machine_controller_config() {
        let input = MachineStateControllerConfig {
            controller: StateControllerConfig {
                iteration_time: std::time::Duration::from_secs(30),
                max_object_handling_time: std::time::Duration::from_secs(60),
                max_concurrency: 10,
            },
            dpu_wait_time: Duration::minutes(20),
            power_down_wait: Duration::seconds(10),
            failure_retry_time: Duration::minutes(90),
            dpu_up_threshold: Duration::weeks(1),
        };

        let config_str = serde_json::to_string(&input).unwrap();
        let config: MachineStateControllerConfig = serde_json::from_str(&config_str).unwrap();

        assert_eq!(config, input);
    }

    #[test]
    fn deserialize_serialize_machine_controller_config_default() {
        let input = MachineStateControllerConfig::default();
        let config_str = serde_json::to_string(&input).unwrap();
        let config: MachineStateControllerConfig = serde_json::from_str(&config_str).unwrap();
        assert_eq!(config, input);
    }

    #[test]
    fn deserialize_machine_controller_config() {
        let config = r#"{"dpu_wait_time": "20m","power_down_wait":"10s",
        "failure_retry_time":"1h30m", "dpu_up_threshold": "1w",
        "controller": {"iteration_time": "33s", "max_object_handling_time": "63s", "max_concurrency": 13}}"#;
        let config: MachineStateControllerConfig = serde_json::from_str(config).unwrap();

        assert_eq!(
            config,
            MachineStateControllerConfig {
                controller: {
                    StateControllerConfig {
                        iteration_time: std::time::Duration::from_secs(33),
                        max_object_handling_time: std::time::Duration::from_secs(63),
                        max_concurrency: 13,
                    }
                },
                dpu_wait_time: Duration::minutes(20),
                power_down_wait: Duration::seconds(10),
                failure_retry_time: Duration::minutes(90),
                dpu_up_threshold: Duration::weeks(1),
            }
        );
    }

    #[test]
    fn deserialize_machine_controller_config_with_default() {
        let config =
            r#"{"power_down_wait":"10s", "failure_retry_time":"1h30m", "dpu_up_threshold": "1w"}"#;
        let config: MachineStateControllerConfig = serde_json::from_str(config).unwrap();

        assert_eq!(
            config,
            MachineStateControllerConfig {
                controller: StateControllerConfig::default(),
                dpu_wait_time: Duration::minutes(5),
                power_down_wait: Duration::seconds(10),
                failure_retry_time: Duration::minutes(90),
                dpu_up_threshold: Duration::weeks(1),
            }
        );
    }

    #[test]
    fn deserialize_network_segment_state_controller_config() {
        let config = r#"{"network_segment_drain_time": "21m",
        "controller": {"iteration_time": "33s", "max_object_handling_time": "63s", "max_concurrency": 13}}"#;
        let config: NetworkSegmentStateControllerConfig = serde_json::from_str(config).unwrap();

        assert_eq!(
            config,
            NetworkSegmentStateControllerConfig {
                controller: {
                    StateControllerConfig {
                        iteration_time: std::time::Duration::from_secs(33),
                        max_object_handling_time: std::time::Duration::from_secs(63),
                        max_concurrency: 13,
                    }
                },
                network_segment_drain_time: Duration::minutes(21),
            }
        );
    }

    #[test]
    fn deserialize_network_segment_state_controller_config_with_default() {
        let config = r#"{}"#;
        let config: NetworkSegmentStateControllerConfig = serde_json::from_str(config).unwrap();

        assert_eq!(config, NetworkSegmentStateControllerConfig::default());
    }

    #[test]
    fn serialize_empty_state_controller_config() {
        let input = StateControllerConfig::default();
        let config_str = serde_json::to_string(&input).unwrap();
        assert_eq!(
            config_str,
            r#"{"iteration_time":"30s","max_object_handling_time":"180s","max_concurrency":10}"#
        );
        let config: StateControllerConfig = serde_json::from_str(&config_str).unwrap();
        assert_eq!(config, input);
    }

    #[test]
    fn serialize_configured_state_controller_config() {
        let input = StateControllerConfig {
            iteration_time: std::time::Duration::from_secs(11),
            max_object_handling_time: std::time::Duration::from_secs(22),
            max_concurrency: 33,
        };
        let config_str = serde_json::to_string(&input).unwrap();
        assert_eq!(
            config_str,
            r#"{"iteration_time":"11s","max_object_handling_time":"22s","max_concurrency":33}"#
        );
        let config: StateControllerConfig = serde_json::from_str(&config_str).unwrap();
        assert_eq!(config, input);
    }

    #[test]
    fn deserialize_serialize_dpu_config() {
        let value_input = DpuDesc {
            min_component_version: HashMap::from([
                (DpuComponent::Bmc, "x1.y1.z1".to_string()),
                (DpuComponent::Uefi, "x2.y2.z2".to_string()),
            ]),
        };

        let value_json = serde_json::to_string(&value_input).unwrap();
        let value_output: DpuDesc = serde_json::from_str(&value_json).unwrap();

        assert_eq!(value_output, value_input);

        let value_json = r#"{"min_component_version": {"bmc": "x1.y1.z1"}}"#;
        let value_output: DpuDesc = serde_json::from_str(value_json).unwrap();

        assert_eq!(
            value_output,
            DpuDesc {
                min_component_version: HashMap::from(
                    [(DpuComponent::Bmc, "x1.y1.z1".to_string()),]
                ),
            }
        );

        let value_input = DpuDesc::new();
        assert!(value_input
            .min_component_version
            .contains_key(&DpuComponent::Bmc));
        assert!(value_input
            .min_component_version
            .contains_key(&DpuComponent::Uefi));
        assert_eq!(2, value_input.min_component_version.keys().len());

        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Test.toml",
                r#"
                database_url="postgres://a:b@postgresql"
                listen="[::]:1081"
                asn=123
            "#,
            )?;
            let config: CarbideConfig = Figment::new()
                .merge(Toml::file("Test.toml"))
                .extract()
                .unwrap();

            assert_eq!(config.listen, "[::]:1081".parse().unwrap());
            assert_eq!(config.asn, 123);
            assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
            assert_eq!(config.dpus, default_dpus());
            Ok(())
        });

        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Test.toml",
                r#"
                database_url="postgres://a:b@postgresql"
                listen="[::]:1081"
                asn=123
                [dpus.bluefield2]
                min_component_version = {"bmc" = "23.10", "uefi" = "4.5"}
            "#,
            )?;
            let config: CarbideConfig = Figment::new()
                .merge(Toml::file("Test.toml"))
                .extract()
                .unwrap();

            assert_eq!(1, config.dpus.keys().len());
            assert!(config.dpus.contains_key(&DpuModel::BlueField2));
            assert_eq!(
                config.dpus.get(&DpuModel::BlueField2).unwrap().clone(),
                DpuDesc {
                    min_component_version: HashMap::from([
                        (DpuComponent::Bmc, "23.10".to_string()),
                        (DpuComponent::Uefi, "4.5".to_string()),
                    ]),
                }
            );
            Ok(())
        });

        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Test.toml",
                r#"
                database_url="postgres://a:b@postgresql"
                listen="[::]:1081"
                asn=123
                [dpus.bluefield2.min_component_version]
                bmc = "23.10"
                uefi = "4.5"
                [dpus.bluefield3.min_component_version]
                bmc = "23.07"
                uefi = "4.2"
            "#,
            )?;
            let config: CarbideConfig = Figment::new()
                .merge(Toml::file("Test.toml"))
                .extract()
                .unwrap();

            assert_eq!(2, config.dpus.keys().len());
            assert!(config.dpus.contains_key(&DpuModel::BlueField2));
            assert_eq!(
                config.dpus.get(&DpuModel::BlueField2).unwrap().clone(),
                DpuDesc {
                    min_component_version: HashMap::from([
                        (DpuComponent::Bmc, "23.10".to_string()),
                        (DpuComponent::Uefi, "4.5".to_string()),
                    ]),
                }
            );
            assert!(config.dpus.contains_key(&DpuModel::BlueField3));
            assert_eq!(
                config.dpus.get(&DpuModel::BlueField3).unwrap().clone(),
                DpuDesc {
                    min_component_version: HashMap::from([
                        (DpuComponent::Bmc, "23.07".to_string()),
                        (DpuComponent::Uefi, "4.2".to_string()),
                    ]),
                }
            );
            Ok(())
        });
    }

    #[test]
    fn deserialize_min_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/min_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, None);
        assert_eq!(config.asn, 123);
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert_eq!(
            config.max_database_connections,
            default_max_database_connections()
        );
        assert!(config.dhcp_servers.is_empty());
        assert!(config.route_servers.is_empty());
        assert!(config.tls.is_none());
        assert!(config.auth.is_none());
        assert!(config.pools.is_none());
        assert_eq!(config.ib_fabric_monitor, {
            IbFabricMonitorConfig {
                enabled: false,
                run_interval: IbFabricMonitorConfig::default_run_interval(),
            }
        });
        assert!(config.site_explorer.is_none());
        assert_eq!(
            config.machine_state_controller,
            MachineStateControllerConfig::default()
        );
        assert_eq!(
            config.network_segment_state_controller,
            NetworkSegmentStateControllerConfig::default()
        );
        assert_eq!(
            config.ib_partition_state_controller,
            IbPartitionStateControllerConfig::default()
        );
        assert_eq!(config.dpus, default_dpus());
    }

    #[test]
    fn deserialize_patched_min_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/min_config.toml", TEST_DATA_DIR)))
            .merge(Toml::file(format!("{}/site_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, None);
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert_eq!(config.max_database_connections, 1333);
        assert_eq!(config.asn, 777);
        assert_eq!(config.dhcp_servers, vec!["99.101.102.103".to_string()]);
        assert!(config.route_servers.is_empty());
        assert_eq!(
            config.tls.as_ref().unwrap().identity_pemfile_path,
            "/patched/path/to/cert"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().identity_keyfile_path,
            "/patched/path/to/key"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().root_cafile_path,
            "/patched/path/to/ca"
        );
        assert!(config.auth.as_ref().unwrap().permissive_mode);
        assert_eq!(
            config.auth.as_ref().unwrap().casbin_policy_file.as_os_str(),
            "/patched/path/to/policy"
        );
        let pools = config.pools.as_ref().unwrap();
        assert_eq!(
            pools.get("lo-ip").unwrap(),
            &ResourcePoolDef {
                ranges: Vec::new(),
                prefix: Some("10.180.63.0/26".to_string()),
                pool_type: resource_pool::ResourcePoolType::Ipv4
            }
        );
        assert!(pools.get("pkey").is_none());
        assert_eq!(
            config.ib_fabric_monitor,
            IbFabricMonitorConfig {
                enabled: true,
                run_interval: std::time::Duration::from_secs(102),
            }
        );
        assert_eq!(
            config.site_explorer.as_ref().unwrap(),
            &SiteExplorerConfig {
                enabled: true,
                run_interval: std::time::Duration::from_secs(300),
                concurrent_explorations: 10,
                explorations_per_run: 12,
                create_machines: true,
            }
        );
        assert_eq!(
            config.machine_state_controller,
            MachineStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(3 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(11),
                    max_concurrency: 22,
                },
                dpu_wait_time: Duration::minutes(7),
                power_down_wait: Duration::seconds(17),
                failure_retry_time: Duration::minutes(70),
                dpu_up_threshold: Duration::minutes(77),
            }
        );
        assert_eq!(
            config.network_segment_state_controller,
            NetworkSegmentStateControllerConfig {
                network_segment_drain_time: Duration::seconds(45),
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(18 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(188),
                    max_concurrency: 1888,
                },
            }
        );
        assert_eq!(
            config.ib_partition_state_controller,
            IbPartitionStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(17 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(177),
                    max_concurrency: 1777,
                },
            }
        );
    }

    #[test]
    fn deserialize_full_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/full_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, Some("[::]:1080".parse().unwrap()));
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert_eq!(config.max_database_connections, 1222);
        assert_eq!(config.asn, 123);
        assert_eq!(
            config.dhcp_servers,
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
        );
        assert_eq!(config.route_servers, vec!["9.10.11.12".to_string()]);
        assert_eq!(
            config.otlp_endpoint,
            Some("https://localhost:4317".to_string())
        );
        assert_eq!(
            config.tls.as_ref().unwrap().identity_pemfile_path,
            "/path/to/cert"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().identity_keyfile_path,
            "/path/to/key"
        );
        assert_eq!(config.tls.as_ref().unwrap().root_cafile_path, "/path/to/ca");
        assert!(!config.auth.as_ref().unwrap().permissive_mode);
        assert_eq!(
            config.auth.as_ref().unwrap().casbin_policy_file.as_os_str(),
            "/path/to/policy"
        );
        let pools = config.pools.as_ref().unwrap();
        assert_eq!(
            pools.get("lo-ip").unwrap(),
            &ResourcePoolDef {
                ranges: Vec::new(),
                prefix: Some("10.180.62.1/26".to_string()),
                pool_type: resource_pool::ResourcePoolType::Ipv4
            }
        );
        assert_eq!(
            pools.get("vlan-id").unwrap(),
            &ResourcePoolDef {
                ranges: vec![resource_pool::Range {
                    start: "100".to_string(),
                    end: "501".to_string()
                }],
                prefix: None,
                pool_type: resource_pool::ResourcePoolType::Integer
            }
        );
        assert_eq!(
            pools.get("pkey").unwrap(),
            &ResourcePoolDef {
                ranges: vec![resource_pool::Range {
                    start: "1".to_string(),
                    end: "10".to_string()
                }],
                prefix: None,
                pool_type: resource_pool::ResourcePoolType::Integer
            }
        );
        assert_eq!(
            config.ib_fabric_monitor,
            IbFabricMonitorConfig {
                enabled: false,
                run_interval: std::time::Duration::from_secs(101),
            }
        );
        assert_eq!(
            config.site_explorer.as_ref().unwrap(),
            &SiteExplorerConfig {
                enabled: false,
                run_interval: std::time::Duration::from_secs(100),
                concurrent_explorations: 5,
                explorations_per_run: 11,
                create_machines: true
            }
        );

        assert_eq!(
            config.machine_state_controller,
            MachineStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(9 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(99),
                    max_concurrency: 999,
                },
                dpu_wait_time: Duration::minutes(3),
                power_down_wait: Duration::seconds(13),
                failure_retry_time: Duration::minutes(31),
                dpu_up_threshold: Duration::minutes(33),
            }
        );
        assert_eq!(
            config.network_segment_state_controller,
            NetworkSegmentStateControllerConfig {
                network_segment_drain_time: Duration::seconds(44),
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(8 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(88),
                    max_concurrency: 888,
                },
            }
        );
        assert_eq!(
            config.ib_partition_state_controller,
            IbPartitionStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(7 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(77),
                    max_concurrency: 777,
                },
            }
        );
    }

    #[test]
    fn deserialize_patched_full_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/full_config.toml", TEST_DATA_DIR)))
            .merge(Toml::file(format!("{}/site_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, Some("[::]:1080".parse().unwrap()));
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert_eq!(config.max_database_connections, 1333);
        assert_eq!(
            config.otlp_endpoint,
            Some("https://localhost:4399".to_string())
        );
        assert_eq!(config.asn, 777);
        assert_eq!(config.dhcp_servers, vec!["99.101.102.103".to_string()]);
        assert_eq!(config.route_servers, vec!["9.10.11.12".to_string()]);
        assert_eq!(
            config.tls.as_ref().unwrap().identity_pemfile_path,
            "/patched/path/to/cert"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().identity_keyfile_path,
            "/patched/path/to/key"
        );
        assert_eq!(
            config.tls.as_ref().unwrap().root_cafile_path,
            "/patched/path/to/ca"
        );
        assert!(config.auth.as_ref().unwrap().permissive_mode);
        assert_eq!(
            config.auth.as_ref().unwrap().casbin_policy_file.as_os_str(),
            "/patched/path/to/policy"
        );
        let pools = config.pools.as_ref().unwrap();
        assert_eq!(
            pools.get("lo-ip").unwrap(),
            &ResourcePoolDef {
                ranges: Vec::new(),
                prefix: Some("10.180.63.0/26".to_string()),
                pool_type: resource_pool::ResourcePoolType::Ipv4
            }
        );
        assert_eq!(
            pools.get("vlan-id").unwrap(),
            &ResourcePoolDef {
                ranges: vec![resource_pool::Range {
                    start: "100".to_string(),
                    end: "501".to_string()
                }],
                prefix: None,
                pool_type: resource_pool::ResourcePoolType::Integer
            }
        );
        assert_eq!(
            pools.get("pkey").unwrap(),
            &ResourcePoolDef {
                ranges: vec![resource_pool::Range {
                    start: "1".to_string(),
                    end: "10".to_string()
                }],
                prefix: None,
                pool_type: resource_pool::ResourcePoolType::Integer
            }
        );
        assert_eq!(
            config.ib_fabric_monitor,
            IbFabricMonitorConfig {
                enabled: true,
                run_interval: std::time::Duration::from_secs(102),
            }
        );
        assert_eq!(
            config.site_explorer.as_ref().unwrap(),
            &SiteExplorerConfig {
                enabled: true,
                run_interval: std::time::Duration::from_secs(100),
                concurrent_explorations: 10,
                explorations_per_run: 12,
                create_machines: true,
            }
        );

        assert_eq!(
            config.machine_state_controller,
            MachineStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(3 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(11),
                    max_concurrency: 22,
                },
                dpu_wait_time: Duration::minutes(7),
                power_down_wait: Duration::seconds(17),
                failure_retry_time: Duration::minutes(70),
                dpu_up_threshold: Duration::minutes(77),
            }
        );
        assert_eq!(
            config.network_segment_state_controller,
            NetworkSegmentStateControllerConfig {
                network_segment_drain_time: Duration::seconds(45),
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(18 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(188),
                    max_concurrency: 1888,
                },
            }
        );
        assert_eq!(
            config.ib_partition_state_controller,
            IbPartitionStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(17 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(177),
                    max_concurrency: 1777,
                },
            }
        );
    }

    #[test]
    fn deserialize_env_patched_full_config() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("CARBIDE_API_DATABASE_URL", "postgres://othersql");
            jail.set_env("CARBIDE_API_ASN", 777);
            jail.set_env("CARBIDE_API_AUTH", "{permissive_mode=true}");
            jail.set_env(
                "CARBIDE_API_TLS",
                "{identity_pemfile_path=/patched/path/to/cert}",
            );

            let config: CarbideConfig = Figment::new()
                .merge(Toml::file(format!("{}/full_config.toml", TEST_DATA_DIR)))
                .merge(Env::prefixed("CARBIDE_API_"))
                .extract()
                .unwrap();
            assert_eq!(config.listen, "[::]:1081".parse().unwrap());
            assert_eq!(config.metrics_endpoint, Some("[::]:1080".parse().unwrap()));
            assert_eq!(
                config.otlp_endpoint,
                Some("https://localhost:4317".to_string())
            );
            assert_eq!(config.database_url, "postgres://othersql".to_string());
            assert_eq!(config.asn, 777);
            assert_eq!(
                config.dhcp_servers,
                vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
            );
            assert_eq!(config.route_servers, vec!["9.10.11.12".to_string()]);
            assert_eq!(
                config.tls.as_ref().unwrap().identity_pemfile_path,
                "/patched/path/to/cert"
            );
            assert_eq!(
                config.tls.as_ref().unwrap().identity_keyfile_path,
                "/path/to/key"
            );
            assert_eq!(config.tls.as_ref().unwrap().root_cafile_path, "/path/to/ca");
            assert!(config.auth.as_ref().unwrap().permissive_mode);
            assert_eq!(
                config.auth.as_ref().unwrap().casbin_policy_file.as_os_str(),
                "/path/to/policy"
            );

            Ok(())
        })
    }
}
