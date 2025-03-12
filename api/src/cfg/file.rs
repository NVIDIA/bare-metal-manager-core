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

use std::ffi::OsStr;
use std::ops::Deref;
use std::{
    cmp::Ordering, collections::HashMap, fmt, fmt::Display, fs, net::SocketAddr, path::PathBuf,
    sync::Arc, time::SystemTime,
};

use arc_swap::ArcSwap;
use bmc_vendor::BMCVendor;
use chrono::Duration;
use duration_str::{deserialize_duration, deserialize_duration_chrono};
use ipnetwork::Ipv4Network;
use itertools::Itertools;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utils::HostPortPair;

use crate::ib::types::{IBMtu, IBRateLimit, IBServiceLevel};
use crate::model::site_explorer::{EndpointExplorationReport, ExploredEndpoint};
use crate::state_controller::config::IterationConfig;
use crate::{
    model::network_segment::NetworkDefinition,
    resource_pool::{self, ResourcePoolDef},
};

const MAX_IB_PARTITION_PER_TENANT: i32 = 31;

/// carbide-api configuration file content
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CarbideConfig {
    /// The socket address that is used for the gRPC API server
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// The socket address that is used for the HTTP server which serves
    /// prometheus metrics under /metrics
    pub metrics_endpoint: Option<SocketAddr>,

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

    #[serde(default)]
    pub vpc_isolation_behavior: VpcIsolationBehaviorType,

    #[serde(default)]
    pub dpu_network_monitor_pinger_type: Option<String>,

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
    pub dpu_ipmi_tool_impl: Option<String>,

    // The number of retries to perform if ipmi returns an error
    pub dpu_ipmi_reboot_attempts: Option<u32>,

    /// Infiniband fabrics managed by the site
    /// Note: At the moment, only a single fabric is supported
    #[serde(default)]
    pub ib_fabrics: HashMap<String, IbFabricDefinition>,

    /// Domain to create if there are no domains.
    ///
    /// Most sites use a single domain for their lifetime. This is that domain.
    /// The alternative is to create it via `CreateDomain` grpc endpoint.
    pub initial_domain_name: Option<String>,

    /// The policy we use to decide whether a specific forge-dpu-agent should be upgraded
    /// Also settable via a `forge-admin-cli` command.
    pub initial_dpu_agent_upgrade_policy: Option<AgentUpgradePolicyChoice>,

    /// IbFabricMonitor related configuration
    #[serde(default)]
    pub ib_fabric_monitor: IbFabricMonitorConfig,

    /// The maximum number of machines that have in-progress updates running.  This prevents
    /// too many machines from being put into maintenance at any given time.
    pub max_concurrent_machine_updates: Option<i32>,

    /// The interval at which the machine update manager checks for machine updates in seconds.
    pub machine_update_run_interval: Option<u64>,

    /// SiteExplorer related configuration
    #[serde(default)]
    pub site_explorer: SiteExplorerConfig,

    /// Enable DHCP server on DPU to serve host.
    #[serde(default = "default_to_true")]
    pub dpu_dhcp_server_enabled: bool,

    /// DPU agent to use NVUE instead of writing files directly.
    /// Once we are comfortable with this and all DPUs are HBN 2+ it will become the only option.
    #[serde(default = "default_to_true")]
    pub nvue_enabled: bool,

    /// Controls whether or not machine attestion is required before a machine
    /// can go from Discovered -> Ready (and, when enabled, introduces the new
    /// `Measuring` state to the flow).
    ///
    /// This control exists so we can roll it out on a site-by-site basis,
    /// which includes making sure the latest Scout image for the site has
    /// been deployed with attestation support (and knows Action::MEASURE).
    #[serde(default)]
    pub attestation_enabled: bool,

    /// *** This mode is for testing purposes and is not widely supported right now ***
    /// Controls if machines allowed to be registered without TPM module,
    /// in this case for stable machine identifier api will use chasis serial.
    /// Set `true` by default
    #[serde(default = "default_to_true")]
    pub tpm_required: bool,

    /// MachineStateController related configuration parameter
    #[serde(default)]
    pub machine_state_controller: MachineStateControllerConfig,

    /// NetworkSegmentController related configuration parameter
    #[serde(default)]
    pub network_segment_state_controller: NetworkSegmentStateControllerConfig,

    /// IbPartitionStateController related configuration parameter
    #[serde(default)]
    pub ib_partition_state_controller: IbPartitionStateControllerConfig,

    #[serde(default)]
    pub host_models: HashMap<String, Firmware>,

    #[serde(default)]
    pub firmware_global: FirmwareGlobal,

    /// The maximum number of IDs allowed for find_(something)_by_ids APIs
    #[serde(default = "default_max_find_by_ids")]
    pub max_find_by_ids: u32,

    #[serde(default)]
    pub network_security_group: NetworkSecurityGroupConfig,

    /// The minimum number of functioning links on a dpu for it to be considered healthy
    /// if not present, all links must be functional.
    #[serde(default)]
    pub min_dpu_functioning_links: Option<u32>,

    #[serde(default)]
    pub multi_dpu: MultiDpuConfig,

    #[serde(default)]
    pub host_health: HostHealthConfig,

    // internet_l3_vni is a GNI-provided L3VNI to use for
    // FNN VPCs to have Internet connectivity. If it's
    // not set, VPCs in this site will not have the ability
    // to get out to the Internet.
    //
    // TODO(chet): This might be interesting to be able
    // to toggle on a per-VPC basis (e.g. if a customer
    // wants to create a VPC that is guaranteed not to
    // be able to access the Internet).
    #[serde(default)]
    pub internet_l3_vni: Option<u32>,

    /// MeasuredBootMetricsCollector related configuration
    #[serde(default)]
    pub measured_boot_collector: MeasuredBootMetricsCollectorConfig,

    /// Machine Validation config to api server
    #[serde(default)]
    pub machine_validation_config: MachineValidationConfig,

    #[serde(default)]
    pub bypass_rbac: bool,

    /// DPU specific configs including DPU orand DPU BMC firmware
    #[serde(default)]
    pub dpu_config: DpuConfig,

    #[serde(default)]
    pub fnn: Option<FnnConfig>,

    #[serde(default)]
    pub bom_validation: BomValidationConfig,

    #[serde(default)]
    pub bios_profiles: libredfish::BiosProfileVendor,

    #[serde(default)]
    pub selected_profile: libredfish::BiosProfileType,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct FnnConfig {
    #[serde(default)]
    pub admin_vpc: Option<AdminFnnConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AdminFnnConfig {
    // if FNN should be applicable on admin network as well.
    pub enabled: bool,

    #[serde(default)]
    // if enabled_on_admin_network is true, carbide will try to
    //   1. Create a VPC with the given vni.
    //   2. Attach this VPC to network_segment table with segment type `admin`.
    // if a vpc with exiting vni exists and network_segment table has this vpc attached to admin
    // segment, do nothing else throw a error and panic.
    pub vpc_vni: Option<u32>,
}

impl CarbideConfig {
    /// Returns a version of CarbideConfig where secrets are erased
    pub fn redacted(&self) -> Self {
        let mut config = self.clone();
        if let Some(host_index) = config.database_url.find('@') {
            let host = config.database_url.split_at(host_index).1;
            config.database_url = format!("postgres://redacted{}", host);
        }
        config
    }

    pub fn get_firmware_config(&self) -> FirmwareConfig {
        let mut base_map: HashMap<String, Firmware> = Default::default();
        for (_, host) in self.host_models.iter() {
            base_map.insert(
                vendor_model_to_key(host.vendor, host.model.to_owned()),
                host.clone(),
            );
        }
        for (_, dpu) in self.dpu_config.dpu_models.iter() {
            base_map.insert(
                vendor_model_to_key(dpu.vendor, DpuModel::from(dpu.model.to_owned()).to_string()),
                dpu.clone(),
            );
        }
        FirmwareConfig {
            base_map,
            firmware_directory: self.firmware_global.firmware_directory.clone(),
            #[cfg(test)]
            test_overrides: vec![],
        }
    }
}

fn vendor_model_to_key(vendor: bmc_vendor::BMCVendor, model: String) -> String {
    format!("{vendor}:{}", model.to_lowercase())
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

    /// Whether a fabric configuration that does not adhere to security requirements
    /// for tenant isolation and infrastructure protection is allowed
    #[serde(default)]
    pub allow_insecure: bool,

    #[serde(
        default = "IBMtu::default",
        deserialize_with = "IBFabricConfig::deserialize_mtu"
    )]
    pub mtu: IBMtu,

    #[serde(
        default = "IBRateLimit::default",
        deserialize_with = "IBFabricConfig::deserialize_rate_limit"
    )]
    pub rate_limit: IBRateLimit,

    #[serde(
        default = "IBServiceLevel::default",
        deserialize_with = "IBFabricConfig::deserialize_service_level"
    )]
    pub service_level: IBServiceLevel,
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

    pub fn deserialize_mtu<'de, D>(deserializer: D) -> Result<IBMtu, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mtu = i32::deserialize(deserializer)?;

        IBMtu::try_from(mtu).map_err(|e| serde::de::Error::custom(e.to_string()))
    }

    pub fn deserialize_rate_limit<'de, D>(deserializer: D) -> Result<IBRateLimit, D::Error>
    where
        D: Deserializer<'de>,
    {
        let rate_limit = i32::deserialize(deserializer)?;

        IBRateLimit::try_from(rate_limit).map_err(|e| serde::de::Error::custom(e.to_string()))
    }

    pub fn deserialize_service_level<'de, D>(deserializer: D) -> Result<IBServiceLevel, D::Error>
    where
        D: Deserializer<'de>,
    {
        let service_level = i32::deserialize(deserializer)?;

        IBServiceLevel::try_from(service_level).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// SiteExplorer related configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SiteExplorerConfig {
    #[serde(default = "default_to_true")]
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

    /// Whether SiteExplorer should create Managed Host state machine
    #[serde(
        default = "SiteExplorerConfig::default_create_machines",
        deserialize_with = "deserialize_create_machines",
        serialize_with = "serialize_create_machines"
    )]
    pub create_machines: Arc<ArcSwap<bool>>,

    #[serde(default = "SiteExplorerConfig::default_machines_created_per_run")]
    /// How many ManagedHosts should be created in a single run.
    /// Default is 1.
    pub machines_created_per_run: u64,

    /// DEPRECATED: Use `bmc_proxy` instead.
    /// The IP address to connect to instead of the BMC that made the dhcp request.
    /// This is a debug override and should not be used in production.
    pub override_target_ip: Option<String>,

    /// DEPRECATED: Use `bmc_proxy` instead.
    /// The port to connect to for redfish requests.
    /// This is a debug override and should not be used in production.
    pub override_target_port: Option<u16>,

    #[serde(default)]
    /// Whether to allow hosts with zero DPUs in site-explorer. This should typically be set to
    /// false in production environments where we expect all hosts to have DPUs. When false, if we
    /// encounter a host with no DPUs, site-explorer will throw an error for that host (because it
    /// should be assumed that there's a bug in detecting the DPUs.)
    pub allow_zero_dpu_hosts: bool,

    #[serde(
        default,
        deserialize_with = "deserialize_bmc_proxy",
        serialize_with = "serialize_bmc_proxy"
    )]
    /// The host:port to use as a proxy when making BMC calls to all hosts in carbide. This is used
    /// for integration testing, and for local development with machine-a-tron/bmc-mock. Should not
    /// be used in production.
    pub bmc_proxy: Arc<ArcSwap<Option<HostPortPair>>>,

    #[serde(default)]
    /// TODO: Drop this once api_test::test_integration is migrated to use site-explorer
    /// This is only used for api_test::test_integration not working with site-explorer. Do not use
    /// anywhere else.
    pub allow_proxy_to_unknown_host: bool,

    #[serde(default)]
    /// If set to `true`, the server will allow changes to the `bmc_proxy` setting at runtime. This
    /// will be default to true if the server is launched with bmc_proxy set:
    /// - If the value is not set, but the server is launched with bmc_proxy, override_target_ip, or
    ///   override_target_port set, it will be assumed true (ie. if bmc_proxy can be reconfigured if
    ///   it was initially configured)
    /// - If the value is not set, and the server is launched without bmc_proxy, override_target_ip,
    ///   or override_target_port set, it will be assumed false (ie. changes to bmc_proxy will not
    ///   be allowed if the config has not opted in)
    /// - If the value is set to true or false, it will be respected through the lifetime of the
    ///   process.
    pub allow_changing_bmc_proxy: Option<bool>,

    #[serde(
        default = "SiteExplorerConfig::default_reset_rate_limit",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    /// Represents the minimum amount of time in between consecutive force-restarts or bmc-resets
    /// initiated by SiteExplorer.
    /// Default is 1 hour.
    pub reset_rate_limit: Duration,
}

impl Default for SiteExplorerConfig {
    fn default() -> Self {
        SiteExplorerConfig {
            enabled: true,
            run_interval: Self::default_run_interval(),
            concurrent_explorations: Self::default_concurrent_explorations(),
            explorations_per_run: Self::default_explorations_per_run(),
            create_machines: crate::dynamic_settings::create_machines(true),
            machines_created_per_run: Self::default_machines_created_per_run(),
            override_target_ip: None,
            override_target_port: None,
            allow_zero_dpu_hosts: false,
            bmc_proxy: crate::dynamic_settings::bmc_proxy(None),
            allow_changing_bmc_proxy: None,
            reset_rate_limit: Self::default_reset_rate_limit(),
            allow_proxy_to_unknown_host: false,
        }
    }
}

impl PartialEq for SiteExplorerConfig {
    fn eq(&self, other: &SiteExplorerConfig) -> bool {
        self.enabled == other.enabled
            && self.run_interval == other.run_interval
            && self.concurrent_explorations == other.concurrent_explorations
            && self.explorations_per_run == other.explorations_per_run
            && *self.create_machines.load() == *other.create_machines.load()
            && self.override_target_ip == other.override_target_ip
            && self.override_target_port == other.override_target_port
    }
}

impl SiteExplorerConfig {
    pub const fn default_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(120)
    }

    pub fn default_create_machines() -> Arc<ArcSwap<bool>> {
        Arc::new(ArcSwap::new(Arc::new(true)))
    }

    pub const fn default_concurrent_explorations() -> u64 {
        30
    }

    pub const fn default_explorations_per_run() -> u64 {
        90
    }

    pub const fn default_machines_created_per_run() -> u64 {
        1
    }

    pub const fn default_reset_rate_limit() -> Duration {
        Duration::hours(1)
    }
}

pub fn deserialize_create_machines<'de, D>(deserializer: D) -> Result<Arc<ArcSwap<bool>>, D::Error>
where
    D: Deserializer<'de>,
{
    let b = bool::deserialize(deserializer)?;
    Ok(Arc::new(ArcSwap::new(Arc::new(b))))
}

pub fn serialize_create_machines<S>(cm: &Arc<ArcSwap<bool>>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bool(**cm.load())
}

pub fn deserialize_bmc_proxy<'de, D>(
    deserializer: D,
) -> Result<Arc<ArcSwap<Option<HostPortPair>>>, D::Error>
where
    D: Deserializer<'de>,
{
    let p = Option::deserialize(deserializer)?;
    Ok(Arc::new(ArcSwap::new(Arc::new(p))))
}

pub fn serialize_bmc_proxy<S>(
    val: &Arc<ArcSwap<Option<HostPortPair>>>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(val) = val.load().deref().deref() {
        s.serialize_str(val.to_string().as_str())
    } else {
        s.serialize_none()
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
    pub casbin_policy_file: Option<PathBuf>,

    /// Additional forge-admin-cli certs allowed.  This does not include actually allowing the cert to connect, just that certs that can be verified which match these criteria can do GRPC requests.
    pub cli_certs: Option<AllowedCertCriteria>,
}

#[derive(Eq, PartialEq, Hash, Clone, Debug, Deserialize, Serialize)]
pub enum CertComponent {
    IssuerO,
    IssuerOU,
    IssuerCN,
    SubjectO,
    SubjectOU,
    SubjectCN,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AllowedCertCriteria {
    /// These components of the cert must equal the given values to be approved
    pub required_equals: HashMap<CertComponent, String>,
    /// Use this cert component to specify the group it should be reported as
    pub group_from: Option<CertComponent>,
    /// Use this cert component to pick the username
    pub username_from: Option<CertComponent>,
    /// If not using username_from, specify the username used for all certs of this type
    pub username: Option<String>,
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

/// DpuConfig related internal configuration
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DpuConfig {
    /// Enable dpu firmware updates on initial discovery
    #[serde(default)]
    pub dpu_nic_firmware_initial_update_enabled: bool,

    /// Enable dpu firmware updates on known machines
    #[serde(default)]
    pub dpu_nic_firmware_reprovision_update_enabled: bool,

    /// The version of DPU NIC firmware that is expected on the DPU.  If the actual DPU NIC firmware
    /// does not match, the DPU will be updated during reprovisioning. This value is hardcoded in the API
    /// so the operator does not need to know what to do but can be overridden.
    #[serde(default)]
    pub dpu_nic_firmware_update_version: HashMap<String, String>,

    /// DPU related configuration parameter
    #[serde(default)]
    pub dpu_models: HashMap<String, Firmware>,
}

impl DpuConfig {
    pub fn find_bf3_entry(&self) -> Option<&FirmwareEntry> {
        self.dpu_models.get("bluefield3").and_then(|f| {
            f.components
                .get(&FirmwareComponentType::Bmc)
                .and_then(|fc| fc.known_firmware.first())
        })
    }
    pub fn find_bf2_entry(&self) -> Option<&FirmwareEntry> {
        self.dpu_models.get("bluefield2").and_then(|f| {
            f.components
                .get(&FirmwareComponentType::Bmc)
                .and_then(|fc| fc.known_firmware.first())
        })
    }
}

impl Default for DpuConfig {
    fn default() -> Self {
        Self {
            dpu_nic_firmware_initial_update_enabled: false,
            dpu_nic_firmware_reprovision_update_enabled: true,
            dpu_nic_firmware_update_version: HashMap::from([
                ("BlueField SoC".to_string(), "24.42.1000".to_string()),
                (
                    "BlueField-3 SmartNIC Main Card".to_string(),
                    "32.42.1000".to_string(),
                ),
            ]),
            dpu_models: HashMap::from([("bluefield2".to_string(), Firmware {
                vendor: BMCVendor::Nvidia,
                model: "Bluefield 2 SmartNIC Main Card".to_string(),
                ordering: vec![FirmwareComponentType::Bmc, FirmwareComponentType::Cec],
                components: HashMap::from([(FirmwareComponentType::Bmc, FirmwareComponent {
                    current_version_reported_as: Some(Regex::new("BMC_Firmware").unwrap()),
                    preingest_upgrade_when_below: Some("BF-23.10-5".to_string()),
                    known_firmware: vec![FirmwareEntry {
                        version: "BF-24.07-14".to_string(),
                        mandatory_upgrade_from_priority: None,
                        default: true,
                        filename: Some("/forge-boot-artifacts/blobs/internal/firmware/nvidia/dpu/bf2-bmc-ota-24.07-14-opn.tar".to_string()),
                        url: None,
                        checksum: None,
                        install_only_specified: false,
                        power_drains_needed: None,
                    }],
                }),
                    (FirmwareComponentType::Cec, FirmwareComponent {
                        current_version_reported_as: Some(Regex::new("Bluefield_FW_ERoT").unwrap()),
                        preingest_upgrade_when_below: Some("4-15".to_string()),
                        known_firmware: vec![FirmwareEntry {
                            version: "4-15".to_string(),
                            mandatory_upgrade_from_priority: None,
                            default: true,
                            filename: Some("/forge-boot-artifacts/blobs/internal/firmware/nvidia/dpu/cec_ota_BMGP-04.0f_prod.bin".to_string()),
                            url: None,
                            checksum: None,
                            install_only_specified: false,
                            power_drains_needed: None,
                        }],
                    })]),

            }), ("bluefield3".to_string(), Firmware {
                vendor: BMCVendor::Nvidia,
                model: "Bluefield 3 SmartNIC Main Card".to_string(),
                ordering: vec![FirmwareComponentType::Bmc, FirmwareComponentType::Cec],
                components: HashMap::from([(FirmwareComponentType::Bmc, FirmwareComponent {
                    current_version_reported_as: Some(Regex::new("BMC_Firmware").unwrap()),
                    preingest_upgrade_when_below: Some("BF-23.10-5".to_string()),
                    known_firmware: vec![FirmwareEntry {
                        version: "BF-24.07-14".to_string(),
                        mandatory_upgrade_from_priority: None,
                        default: true,
                        filename: Some("/forge-boot-artifacts/blobs/internal/firmware/nvidia/dpu/bf3-bmc-24.07-14_opn.fwpkg".to_string()),
                        url: None,
                        checksum: None,
                        install_only_specified: false,
                        power_drains_needed: None,
                    }],
                }),
                    (FirmwareComponentType::Cec, FirmwareComponent {
                        current_version_reported_as: Some(Regex::new("Bluefield_FW_ERoT").unwrap()),
                        preingest_upgrade_when_below: Some("00.02.0152.0000_n02".to_string()),
                        known_firmware: vec![FirmwareEntry {
                            version: "00.02.0182.0000_n02".to_string(),
                            mandatory_upgrade_from_priority: None,
                            default: true,
                            filename: Some("/forge-boot-artifacts/blobs/internal/firmware/nvidia/dpu/cec1736-ecfw-00.02.0182.0000-n02-rel-prod.fwpkg".to_string()),
                            url: None,
                            checksum: None,
                            install_only_specified: false,
                            power_drains_needed: None,
                        }],
                    })]),
            })]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct Firmware {
    pub vendor: bmc_vendor::BMCVendor,
    pub model: String,

    pub components: HashMap<FirmwareComponentType, FirmwareComponent>,

    #[serde(default)]
    pub ordering: Vec<FirmwareComponentType>,
}

impl Firmware {
    pub fn matching_version_id(
        &self,
        redfish_id: &str,
        firmware_type: FirmwareComponentType,
    ) -> bool {
        // This searches for the regex we've recorded for what this vendor + model + firmware_type gets reported as in the list of firmware versions
        self.components
            .get(&firmware_type)
            .unwrap_or(&FirmwareComponent::default()) // Will trigger the unwrap_or below
            .current_version_reported_as
            .as_ref()
            .unwrap_or(&Regex::new("^This should never match anything$").unwrap())
            .captures(redfish_id)
            .is_some()
    }
    pub fn ordering(&self) -> Vec<FirmwareComponentType> {
        let mut ordering = self.ordering.clone();
        if ordering.is_empty() {
            const ORDERING: [FirmwareComponentType; 2] =
                [FirmwareComponentType::Bmc, FirmwareComponentType::Uefi];
            ordering = ORDERING.to_vec();
        }
        ordering
    }

    /// find_version will locate a version number within an EndpointExplorationReport
    pub fn find_version(
        &self,
        report: &EndpointExplorationReport,
        firmware_type: FirmwareComponentType,
    ) -> Option<String> {
        for service in report.service.iter() {
            if let Some(matching_inventory) = service
                .inventories
                .iter()
                .find(|&x| self.matching_version_id(&x.id, firmware_type))
            {
                tracing::debug!(
                    "find_version {:?}: For {firmware_type:?} found {:?}",
                    report.machine_id,
                    matching_inventory.version
                );
                return matching_inventory.version.clone();
            };
        }
        None
    }
}

#[derive(
    Debug, Default, Deserialize, Serialize, Eq, PartialEq, Hash, Copy, Clone, Ord, PartialOrd,
)]
#[serde(rename_all = "lowercase")]
pub enum FirmwareComponentType {
    Bmc,
    Cec,
    Uefi,
    Nic,
    HGXBmc,
    CombinedBmcUefi,
    #[serde(other)]
    #[default]
    Unknown,
}

impl fmt::Display for FirmwareComponentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FirmwareComponentType::Bmc => write!(f, "BMC"),
            FirmwareComponentType::Uefi => write!(f, "UEFI"),
            FirmwareComponentType::CombinedBmcUefi => write!(f, "BMC+UEFI"),
            FirmwareComponentType::Nic => write!(f, "NIC"),
            FirmwareComponentType::Cec => write!(f, "CEC"),
            FirmwareComponentType::HGXBmc => write!(f, "HGX BMC"),
            FirmwareComponentType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<FirmwareComponentType> for libredfish::model::update_service::ComponentType {
    fn from(fct: FirmwareComponentType) -> libredfish::model::update_service::ComponentType {
        use libredfish::model::update_service::ComponentType;
        match fct {
            FirmwareComponentType::Bmc => ComponentType::BMC,
            FirmwareComponentType::Uefi => ComponentType::UEFI,
            FirmwareComponentType::Cec => ComponentType::Unknown,
            FirmwareComponentType::Nic => ComponentType::Unknown,
            FirmwareComponentType::HGXBmc => ComponentType::HGXBMC,
            FirmwareComponentType::CombinedBmcUefi => ComponentType::Unknown,
            FirmwareComponentType::Unknown => ComponentType::Unknown,
        }
    }
}

impl FirmwareComponentType {
    pub fn is_bmc(&self) -> bool {
        matches!(
            self,
            FirmwareComponentType::Bmc | FirmwareComponentType::CombinedBmcUefi
        )
    }
    pub fn is_uefi(&self) -> bool {
        matches!(
            self,
            FirmwareComponentType::Uefi | FirmwareComponentType::CombinedBmcUefi
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct FirmwareComponent {
    #[serde(with = "serde_regex")]
    pub current_version_reported_as: Option<Regex>,
    pub preingest_upgrade_when_below: Option<String>,
    #[serde(default)]
    pub known_firmware: Vec<FirmwareEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct FirmwareEntry {
    pub version: String,
    pub mandatory_upgrade_from_priority: Option<MandatoryUpgradeFromPriority>,
    #[serde(default)]
    pub default: bool,
    pub filename: Option<String>,
    pub url: Option<String>,
    pub checksum: Option<String>,
    #[serde(default)]
    // If set, we will pass the firmware type to libredfish which for some platforms will install only one part of a multi-firmware package.
    pub install_only_specified: bool,
    pub power_drains_needed: Option<u32>,
}

impl FirmwareEntry {
    pub fn get_filename(&self) -> PathBuf {
        // At present, we're just using the file key as a local file.  Eventually this gets retrieved from another container to reduce startup times.
        match &self.filename {
            None => PathBuf::from("/dev/null"),
            Some(file_key) => PathBuf::from(file_key),
        }
    }
    pub fn get_url(&self) -> String {
        match &self.url {
            None => "file://dev/null".to_string(),
            Some(url) => url.to_owned(),
        }
    }
    pub fn get_checksum(&self) -> String {
        match &self.checksum {
            None => "".to_string(),
            Some(checksum) => checksum.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MandatoryUpgradeFromPriority {
    None,
    Security,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkSecurityGroupConfig {
    /// The maximum number of unique rules allowed for
    /// a network security group after rules are expanded.
    /// (src port range * dst port range * src prefix list * dst prefix list)
    #[serde(default = "default_max_network_security_group_size")]
    pub max_network_security_group_size: u32,
}

impl Default for NetworkSecurityGroupConfig {
    fn default() -> Self {
        NetworkSecurityGroupConfig {
            max_network_security_group_size: default_max_network_security_group_size(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FirmwareGlobal {
    #[serde(default)]
    pub autoupdate: bool,
    #[serde(default)]
    pub host_enable_autoupdate: Vec<String>,
    #[serde(default)]
    pub host_disable_autoupdate: Vec<String>,
    #[serde(
        default = "FirmwareGlobal::run_interval_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub run_interval: Duration,
    #[serde(default = "FirmwareGlobal::max_uploads_default")]
    pub max_uploads: usize,
    #[serde(default = "FirmwareGlobal::concurrency_limit_default")]
    pub concurrency_limit: usize,
    #[serde(default = "FirmwareGlobal::firmware_directory_default")]
    pub firmware_directory: PathBuf,
    #[serde(
        default = "FirmwareGlobal::host_firmware_upgrade_retry_interval_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub host_firmware_upgrade_retry_interval: Duration,
}

impl FirmwareGlobal {
    #[cfg(test)]
    pub fn test_default() -> Self {
        FirmwareGlobal {
            autoupdate: true,
            host_enable_autoupdate: vec![],
            host_disable_autoupdate: vec![],
            max_uploads: 4,
            run_interval: Duration::seconds(5),
            concurrency_limit: FirmwareGlobal::concurrency_limit_default(),
            firmware_directory: PathBuf::default(),
            host_firmware_upgrade_retry_interval:
                FirmwareGlobal::host_firmware_upgrade_retry_interval_default(),
        }
    }
}

/// DPU related config.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DpuModel {
    BlueField2,
    BlueField3,
    Unknown,
}

impl<T> From<T> for DpuModel
where
    T: AsRef<str>,
{
    fn from(model: T) -> Self {
        match model.as_ref().to_lowercase().replace("-", " ") {
            value if value.contains("bluefield 2") => DpuModel::BlueField2,
            value if value.contains("bluefield 3") => DpuModel::BlueField3,
            _ => DpuModel::Unknown,
        }
    }
}

impl fmt::Display for DpuModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl FirmwareGlobal {
    pub fn run_interval_default() -> Duration {
        Duration::seconds(30)
    }
    pub fn max_uploads_default() -> usize {
        4
    }
    pub fn concurrency_limit_default() -> usize {
        16
    }
    pub fn firmware_directory_default() -> PathBuf {
        PathBuf::from("/opt/carbide/firmware")
    }
    pub fn host_firmware_upgrade_retry_interval_default() -> Duration {
        Duration::minutes(60)
    }
}

impl Default for FirmwareGlobal {
    fn default() -> FirmwareGlobal {
        FirmwareGlobal {
            autoupdate: false,
            host_enable_autoupdate: vec![],
            host_disable_autoupdate: vec![],
            run_interval: FirmwareGlobal::run_interval_default(),
            max_uploads: FirmwareGlobal::max_uploads_default(),
            concurrency_limit: FirmwareGlobal::concurrency_limit_default(),
            firmware_directory: FirmwareGlobal::firmware_directory_default(),
            host_firmware_upgrade_retry_interval:
                FirmwareGlobal::host_firmware_upgrade_retry_interval_default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct FirmwareConfig {
    base_map: HashMap<String, Firmware>,
    firmware_directory: PathBuf,
    #[cfg(test)]
    test_overrides: Vec<String>,
}

impl FirmwareConfig {
    pub fn find(&self, vendor: bmc_vendor::BMCVendor, model: String) -> Option<Firmware> {
        let dpu_model = DpuModel::from(model.clone());
        let key = if dpu_model != DpuModel::Unknown {
            vendor_model_to_key(vendor, dpu_model.to_string())
        } else {
            vendor_model_to_key(vendor, model)
        };
        let ret = self.map().get(&key).map(|x| x.to_owned());
        tracing::debug!("FirmwareConfig::find: key {key} found {ret:?}");
        ret
    }

    /// find_fw_info_for_host looks up the firmware config for the given endpoint
    pub fn find_fw_info_for_host(&self, endpoint: &ExploredEndpoint) -> Option<Firmware> {
        self.find_fw_info_for_host_report(&endpoint.report)
    }

    /// find_fw_info_for_host_report looks up the firmware config for the given endpoint report
    pub fn find_fw_info_for_host_report(
        &self,
        report: &EndpointExplorationReport,
    ) -> Option<Firmware> {
        let vendor = report.vendor?;
        let model = report
            .systems
            .iter()
            .find(|&x| x.model.is_some())?
            .model
            .to_owned()?;
        self.find(vendor, model)
    }

    pub fn map(&self) -> HashMap<String, Firmware> {
        let mut map = self.base_map.clone();
        if self.firmware_directory.to_string_lossy() != "" {
            self.merge_firmware_configs(&mut map, &self.firmware_directory);
        }

        #[cfg(test)]
        {
            // Fake configs to merge for unit tests
            for ovrd in &self.test_overrides {
                if let Err(err) = self.merge_from_string(&mut map, ovrd.clone()) {
                    tracing::error!("Bad override {ovrd}: {err}");
                }
            }
        }

        map
    }

    fn merge_firmware_configs(
        &self,
        map: &mut HashMap<String, Firmware>,
        firmware_directory: &PathBuf,
    ) {
        if !firmware_directory.is_dir() {
            tracing::error!("Missing firmware directory {:?}", firmware_directory);
            return;
        }

        for dir in subdirectories_sorted_by_modification_date(firmware_directory) {
            if dir
                .path()
                .file_name()
                .unwrap_or(OsStr::new("."))
                .to_string_lossy()
                .starts_with(".")
            {
                continue;
            }
            let metadata_path = dir.path().join("metadata.toml");
            let metadata = match fs::read_to_string(metadata_path.clone()) {
                Ok(str) => str,
                Err(e) => {
                    tracing::error!("Could not read {metadata_path:?}: {e}");
                    continue;
                }
            };
            if let Err(e) = self.merge_from_string(map, metadata) {
                tracing::error!("Failed to merge in metadata from {:?}: {e}", dir.path());
            }
        }
    }

    /// merge_from_string adds the given TOML based config to this Firmware.  Figment based merging won't work for this,
    /// as we want to append new FirmwareEntry instances instead of overwriting.  It is expected that this will be called
    /// on the metadata in order of oldest creation time to newest.
    fn merge_from_string(
        &self,
        map: &mut HashMap<String, Firmware>,
        config_str: String,
    ) -> eyre::Result<()> {
        let cfg: Firmware = toml::from_str(config_str.as_str())?;
        let key = vendor_model_to_key(cfg.vendor, cfg.model.clone());

        let Some(cur_model) = map.get_mut(&key) else {
            // We haven't seen this model before, so use this as given.
            map.insert(key, cfg);
            return Ok(());
        };

        if !cfg.ordering.is_empty() {
            // Newer ordering definitions take precedence.  For now we don't consider this at a specific version level.
            cur_model.ordering = cfg.ordering
        }

        for (new_type, new_component) in cfg.components {
            if let Some(cur_component) = cur_model.components.get_mut(&new_type) {
                // The simple fields from the newer version should be used if specified
                if new_component.current_version_reported_as.is_some() {
                    cur_component.current_version_reported_as =
                        new_component.current_version_reported_as;
                }
                if new_component.preingest_upgrade_when_below.is_some() {
                    cur_component.preingest_upgrade_when_below =
                        new_component.preingest_upgrade_when_below;
                }
                if new_component.known_firmware.iter().any(|x| x.default) {
                    // The newer one lists a default, remove default from the old.
                    cur_component.known_firmware = cur_component
                        .known_firmware
                        .iter()
                        .map(|x| {
                            let mut x = x.clone();
                            x.default = false;
                            x
                        })
                        .collect();
                }
                cur_component
                    .known_firmware
                    .extend(new_component.known_firmware.iter().cloned());
            } else {
                // Nothing for this component
                cur_model.components.insert(new_type, new_component);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn add_test_override(&mut self, ovrd: String) {
        self.test_overrides.push(ovrd);
    }
}

pub fn default_max_find_by_ids() -> u32 {
    100
}

pub fn default_max_network_security_group_size() -> u32 {
    200
}

pub fn default_to_true() -> bool {
    true
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct MultiDpuConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct HostHealthConfig {
    /// Whether or not to use hardware health reports in aggregate health reports
    /// and for restricting state transitions.
    #[serde(default)]
    pub hardware_health_reports: HardwareHealthReportsConfig,
    /// How old a DPU agent's version should be before considering stale
    #[serde(
        default = "HostHealthConfig::dpu_agent_version_staleness_threshold_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub dpu_agent_version_staleness_threshold: Duration,

    /// Whether to fail health checks if a DPU agent version is stale
    #[serde(default)]
    pub prevent_allocations_on_stale_dpu_agent_version: bool,
}

impl Default for HostHealthConfig {
    fn default() -> Self {
        HostHealthConfig {
            hardware_health_reports: HardwareHealthReportsConfig::default(),
            dpu_agent_version_staleness_threshold:
                Self::dpu_agent_version_staleness_threshold_default(),
            prevent_allocations_on_stale_dpu_agent_version: false,
        }
    }
}

impl HostHealthConfig {
    pub fn dpu_agent_version_staleness_threshold_default() -> Duration {
        Duration::days(1)
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, PartialEq)]
pub enum HardwareHealthReportsConfig {
    #[default]
    Disabled,
    /// Include successes and alerts but remove their classifications
    MonitorOnly,
    /// Include successes, alerts, and classifications.
    Enabled,
}

/// MeasuredBootMetricsCollectorConfig related configuration
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct MeasuredBootMetricsCollectorConfig {
    #[serde(default)]
    /// enabled controls whether the measured boot metrics
    /// monitor is enabled. When disabled, measured boot metrics
    /// won't be exported.
    pub enabled: bool,
    /// run_interval is the interval at which the monitor polls
    /// for the latest data, in seconds.
    /// Defaults to 60 if not specified.
    #[serde(
        default = "MeasuredBootMetricsCollectorConfig::default_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub run_interval: std::time::Duration,
}

impl Default for MeasuredBootMetricsCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            run_interval: Self::default_run_interval(),
        }
    }
}

impl MeasuredBootMetricsCollectorConfig {
    const fn default_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
}

/// Settings related to an IB fabric
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct IbFabricDefinition {
    /// UFM endpoint address
    /// These need to be fully qualified, e.g. https://1.2.3.4:443
    ///
    /// Note: Currently only a single endpoint is accepted.
    /// This limitation might be lifted in the future
    pub endpoints: Vec<String>,
    /// pkey ranges used for the fabric
    /// Note that editing the pkey ranges will never shrink the currently defined
    /// ranges. It can only be used to expand the range
    pub pkeys: Vec<resource_pool::define::Range>,
}

#[derive(Default, Clone, Copy, Debug, Deserialize, Serialize)]
pub enum MachineValidationTestSelectionMode {
    #[default]
    Default, // only update tests in DB that are specified in tests config
    EnableAll, // Enables all tests in DB, but allows config overrides specified in tests config
    DisableAll, // Disables all tests in DB, but allows config overrides specified in tests config
}

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct MachineValidationConfig {
    #[serde(default)]
    /// Whether MachineValidation is enabled
    pub enabled: bool,

    #[serde(default)]
    /// Controls whether to run all tests, no tests, or use per-test configuration
    pub test_selection_mode: MachineValidationTestSelectionMode,

    #[serde(
        default = "MachineValidationConfig::default_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub run_interval: std::time::Duration,

    #[serde(default)]
    /// Test specific config
    pub tests: Vec<MachineValidationTestConfig>,
}

/// Test specific config.
/// Example:
/// tests = [
///    { id = "forge_MmMemLatency", enable = true },
///    { id = "forge_FioSSD", enable = true }
/// ]
#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct MachineValidationTestConfig {
    pub id: String,
    pub enable: bool,
}

impl MachineValidationConfig {
    const fn default_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
}

/// The VPC isolation behavior enforced within a site.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VpcIsolationBehaviorType {
    #[default]
    /// VPCs will be isolated from each other.
    MutualIsolation,

    /// Open, no isolation.
    Open,
}

impl VpcIsolationBehaviorType {
    fn as_printable(&self) -> &'static str {
        use VpcIsolationBehaviorType::*;
        match self {
            MutualIsolation => "MutualIsolation",
            Open => "Open",
        }
    }
}

impl std::fmt::Display for VpcIsolationBehaviorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_printable())
    }
}

impl From<VpcIsolationBehaviorType> for rpc::forge::VpcIsolationBehaviorType {
    fn from(b: VpcIsolationBehaviorType) -> Self {
        match b {
            VpcIsolationBehaviorType::Open => {
                rpc::forge::VpcIsolationBehaviorType::VpcIsolationOpen
            }
            VpcIsolationBehaviorType::MutualIsolation => {
                rpc::forge::VpcIsolationBehaviorType::VpcIsolationMutual
            }
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
            vpc_isolation_behavior: value.vpc_isolation_behavior.to_string(),
            networks: value
                .networks
                .unwrap_or_default()
                .keys()
                .cloned()
                .collect_vec(),
            dpu_ipmi_tool_impl: value.dpu_ipmi_tool_impl.unwrap_or("Not Set".to_string()),
            dpu_ipmi_reboot_attempt: value.dpu_ipmi_reboot_attempts.unwrap_or_default(),
            initial_domain_name: value.initial_domain_name,
            initial_dpu_agent_upgrade_policy: value
                .initial_dpu_agent_upgrade_policy
                .unwrap_or(AgentUpgradePolicyChoice::Off)
                .to_string(),
            dpu_nic_firmware_update_version: DpuConfig::default().dpu_nic_firmware_update_version,
            dpu_nic_firmware_initial_update_enabled: DpuConfig::default()
                .dpu_nic_firmware_initial_update_enabled,
            dpu_nic_firmware_reprovision_update_enabled: DpuConfig::default()
                .dpu_nic_firmware_reprovision_update_enabled,
            max_concurrent_machine_updates: value
                .max_concurrent_machine_updates
                .unwrap_or_default(),
            machine_update_runtime_interval: value.machine_update_run_interval.unwrap_or_default(),
            dpu_dhcp_server_enabled: value.dpu_dhcp_server_enabled,
            nvue_enabled: value.nvue_enabled,
            attestation_enabled: value.attestation_enabled,
            auto_host_firmware_update: value.firmware_global.autoupdate,
            host_enable_autoupdate: value.firmware_global.host_enable_autoupdate,
            host_disable_autoupdate: value.firmware_global.host_disable_autoupdate,
            max_find_by_ids: value.max_find_by_ids,
            dpu_network_pinger_type: value.dpu_network_monitor_pinger_type,
            machine_validation_enabled: value.machine_validation_config.enabled,
            bom_validation_enabled: value.bom_validation.enabled,
            bom_validation_ignore_unassigned_machines: value
                .bom_validation
                .ignore_unassigned_machines,
        }
    }
}

fn subdirectories_sorted_by_modification_date(topdir: &PathBuf) -> Vec<fs::DirEntry> {
    let Ok(dirs) = topdir.read_dir() else {
        tracing::error!("Unreadable firmware directory {:?}", topdir);
        return vec![];
    };

    // We sort in ascending modification time so that we will use the newest made firmware metadata
    let mut dirs: Vec<fs::DirEntry> = dirs
        .filter_map(|x| match x {
            Ok(x) => Some(x),
            Err(_) => None,
        })
        .collect();
    dirs.sort_unstable_by(|x, y| {
        let x_time = match x.metadata() {
            Err(_) => SystemTime::now(),
            Ok(x) => match x.modified() {
                Err(_) => SystemTime::now(),
                Ok(x) => x,
            },
        };
        let y_time = match y.metadata() {
            Err(_) => SystemTime::now(),
            Ok(y) => match y.modified() {
                Err(_) => SystemTime::now(),
                Ok(y) => y,
            },
        };
        x_time.partial_cmp(&y_time).unwrap_or(Ordering::Equal)
    });
    dirs
}

/// MachineValidation related configuration
#[derive(Default, Clone, Copy, Debug, Deserialize, Serialize)]
pub struct BomValidationConfig {
    /// Whether BOM Validation is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Allow machines that do not have a sku to bypass sku validation
    #[serde(default)]
    pub ignore_unassigned_machines: bool,
}

#[cfg(test)]
mod tests {
    use figment::{
        Figment,
        providers::{Env, Format, Toml},
    };
    use libredfish::model::service_root::RedfishVendor;

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
    fn test_redact_config() {
        let mut config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{}/min_config.toml", TEST_DATA_DIR)))
            .extract()
            .unwrap();
        let redacted = config.redacted();
        assert_eq!(
            redacted.database_url,
            "postgres://redacted@postgresql".to_string()
        );
        config.database_url = "postgres://forge-system.carbide:very-very-long-password@forge-pg-cluster.postgres.svc.cluster.local:5432/forge_system_carbide".to_string();
        let redacted = config.redacted();
        assert_eq!(redacted.database_url, "postgres://redacted@forge-pg-cluster.postgres.svc.cluster.local:5432/forge_system_carbide".to_string());
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
        assert!(config.dpu_dhcp_server_enabled);
        assert_eq!(
            config.max_database_connections,
            default_max_database_connections()
        );
        assert!(config.dhcp_servers.is_empty());
        assert!(config.route_servers.is_empty());
        assert!(config.tls.is_none());
        assert!(config.auth.is_none());
        assert!(config.pools.is_none());
        assert!(config.ib_fabrics.is_empty());
        assert_eq!(config.ib_fabric_monitor, {
            IbFabricMonitorConfig {
                enabled: false,
                run_interval: IbFabricMonitorConfig::default_run_interval(),
            }
        });
        assert!(config.nvue_enabled);
        assert!(config.site_explorer.enabled);
        assert!(*config.site_explorer.create_machines.load_full());
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
        assert_eq!(config.max_find_by_ids, default_max_find_by_ids());
        assert_eq!(config.dpu_network_monitor_pinger_type, None);
        assert_eq!(config.measured_boot_collector, {
            MeasuredBootMetricsCollectorConfig {
                enabled: false,
                run_interval: MeasuredBootMetricsCollectorConfig::default_run_interval(),
            }
        });
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
        assert!(!config.dpu_dhcp_server_enabled);
        assert!(!config.nvue_enabled);
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
            config
                .auth
                .as_ref()
                .unwrap()
                .casbin_policy_file
                .as_ref()
                .unwrap()
                .as_os_str(),
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
            config.site_explorer,
            SiteExplorerConfig {
                enabled: false,
                run_interval: std::time::Duration::from_secs(120),
                concurrent_explorations: 10,
                explorations_per_run: 12,
                create_machines: crate::dynamic_settings::create_machines(false),
                machines_created_per_run: 1,
                override_target_ip: None,
                override_target_port: None,
                allow_zero_dpu_hosts: false,
                bmc_proxy: crate::dynamic_settings::bmc_proxy(None),
                allow_changing_bmc_proxy: None,
                reset_rate_limit: Duration::hours(1),
                allow_proxy_to_unknown_host: false,
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
        assert_eq!(config.max_find_by_ids, 50);
        assert_eq!(
            config.dpu_network_monitor_pinger_type,
            Some("OobNetBind".to_string())
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
        assert!(config.dpu_dhcp_server_enabled);
        assert!(config.nvue_enabled);
        assert_eq!(config.route_servers, vec!["9.10.11.12".to_string()]);
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
            config
                .auth
                .as_ref()
                .unwrap()
                .casbin_policy_file
                .clone()
                .unwrap()
                .as_os_str(),
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
            config.ib_fabrics,
            [(
                "default".to_string(),
                IbFabricDefinition {
                    endpoints: vec!["https://1.2.3.4".to_string()],
                    pkeys: vec![resource_pool::Range {
                        start: "1".to_string(),
                        end: "10".to_string()
                    }]
                }
            )]
            .into_iter()
            .collect()
        );

        assert_eq!(
            config.ib_fabric_monitor,
            IbFabricMonitorConfig {
                enabled: false,
                run_interval: std::time::Duration::from_secs(101),
            }
        );
        assert_eq!(
            config.site_explorer,
            SiteExplorerConfig {
                enabled: true,
                run_interval: std::time::Duration::from_secs(100),
                concurrent_explorations: 30,
                explorations_per_run: 11,
                create_machines: crate::dynamic_settings::create_machines(true),
                machines_created_per_run: 2,
                override_target_ip: Some("1.2.3.4".to_owned()),
                override_target_port: Some(10443),
                allow_zero_dpu_hosts: false,
                bmc_proxy: crate::dynamic_settings::bmc_proxy(None),
                allow_changing_bmc_proxy: None,
                reset_rate_limit: Duration::hours(2),
                allow_proxy_to_unknown_host: false,
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
        assert_eq!(config.dpu_config.dpu_models.len(), 2);
        for (_, entry) in config.dpu_config.dpu_models.iter() {
            assert_eq!(entry.vendor, bmc_vendor::BMCVendor::Nvidia);
        }
        assert_eq!(config.host_models.len(), 2);
        for (_, entry) in config.host_models.iter() {
            assert_eq!(entry.vendor, bmc_vendor::BMCVendor::Dell);
        }
        assert_eq!(config.firmware_global.max_uploads, 3);
        assert_eq!(config.firmware_global.run_interval, Duration::seconds(20));
        assert_eq!(config.max_find_by_ids, 75);
        assert_eq!(config.dpu_network_monitor_pinger_type, None);
        assert_eq!(
            config.measured_boot_collector,
            MeasuredBootMetricsCollectorConfig {
                enabled: false,
                run_interval: std::time::Duration::from_secs(555),
            }
        );
        assert_eq!(
            config.auth.clone().unwrap().cli_certs.unwrap().group_from,
            Some(CertComponent::SubjectOU)
        );
        assert_eq!(
            config
                .auth
                .clone()
                .unwrap()
                .cli_certs
                .unwrap()
                .username_from,
            Some(CertComponent::SubjectCN)
        );
        assert_eq!(
            config
                .auth
                .clone()
                .unwrap()
                .cli_certs
                .unwrap()
                .required_equals
                .len(),
            2
        );
        assert_eq!(
            config
                .auth
                .clone()
                .unwrap()
                .cli_certs
                .unwrap()
                .required_equals
                .get(&CertComponent::IssuerO),
            Some("NVIDIA Corporation".to_string()).as_ref()
        );
        assert_eq!(
            config
                .auth
                .clone()
                .unwrap()
                .cli_certs
                .unwrap()
                .required_equals
                .get(&CertComponent::IssuerCN),
            Some("NVIDIA Forge Root Certificate Authority 2022".to_string()).as_ref()
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
            config
                .auth
                .as_ref()
                .unwrap()
                .casbin_policy_file
                .clone()
                .unwrap()
                .as_os_str(),
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
            config.ib_fabrics,
            [(
                "default".to_string(),
                IbFabricDefinition {
                    endpoints: vec!["https://1.2.3.4".to_string()],
                    pkeys: vec![resource_pool::Range {
                        start: "1".to_string(),
                        end: "10".to_string()
                    }]
                }
            )]
            .into_iter()
            .collect()
        );
        assert_eq!(
            config.ib_fabric_monitor,
            IbFabricMonitorConfig {
                enabled: true,
                run_interval: std::time::Duration::from_secs(102),
            }
        );
        assert_eq!(
            config.site_explorer,
            SiteExplorerConfig {
                enabled: false,
                run_interval: std::time::Duration::from_secs(100),
                concurrent_explorations: 10,
                explorations_per_run: 12,
                create_machines: crate::dynamic_settings::create_machines(false),
                machines_created_per_run: 2,
                override_target_ip: Some("1.2.3.4".to_owned()),
                override_target_port: Some(10443),
                allow_zero_dpu_hosts: false,
                bmc_proxy: crate::dynamic_settings::bmc_proxy(None),
                allow_changing_bmc_proxy: None,
                reset_rate_limit: Duration::hours(2),
                allow_proxy_to_unknown_host: false,
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
        assert_eq!(
            config.dpu_network_monitor_pinger_type,
            Some("OobNetBind".to_string())
        );
        assert_eq!(
            config.selected_profile,
            libredfish::BiosProfileType::PowerEfficiency
        );
        assert_eq!(
            config
                .bios_profiles
                .get(&RedfishVendor::Lenovo)
                .unwrap()
                .get("ThinkSystem_SR655_V3")
                .unwrap()
                .get(&libredfish::BiosProfileType::Performance)
                .unwrap()
                .get("OperatingModes_ChooseOperatingMode")
                .unwrap()
                .as_str()
                .unwrap(),
            "MaximumPerformance"
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
            assert_eq!(config.database_url, "postgres://othersql".to_string());
            assert_eq!(config.asn, 777);
            assert_eq!(
                config.dhcp_servers,
                vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
            );
            assert_eq!(config.route_servers, vec!["9.10.11.12".to_string()]);
            assert_eq!(config.dpu_network_monitor_pinger_type, None);
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
                config
                    .auth
                    .as_ref()
                    .unwrap()
                    .casbin_policy_file
                    .clone()
                    .unwrap()
                    .as_os_str(),
                "/path/to/policy"
            );

            Ok(())
        })
    }

    #[test]
    fn merging_config() -> eyre::Result<()> {
        let cfg1 = r#"
    vendor = "Dell"
    model = "PowerEdge R750"
    ordering = ["uefi", "bmc"]


    [components.uefi]
    current_version_reported_as = "^Installed-.*__BIOS.Setup."
    preingest_upgrade_when_below = "1.13.2"

    [[components.uefi.known_firmware]]
    version = "1.13.2"
    url = "https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/BIOS_T3H20_WN64_1.13.2.EXE"
    default = true
"#;
        let cfg2 = r#"
model = "PowerEdge R750"
vendor = "Dell"

[components.uefi]
current_version_reported_as = "^Installed-.*__BIOS.Setup."
preingest_upgrade_when_below = "1.13.3"

[[components.uefi.known_firmware]]
version = "1.13.3"
url = "https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/BIOS_T3H20_WN64_1.13.2.EXE"
default = true

[components.bmc]
current_version_reported_as = "^Installed-.*__iDRAC."

[[components.bmc.known_firmware]]
version = "7.10.30.00"
url = "https://urm.nvidia.com/artifactory/sw-ngc-forge-cargo-local/misc/iDRAC-with-Lifecycle-Controller_Firmware_HV310_WN64_7.10.30.00_A00.EXE"
default = true
    "#;
        let mut config: FirmwareConfig = Default::default();
        config.add_test_override(cfg1.to_string());
        config.add_test_override(cfg2.to_string());

        println!("{config:#?}");
        let map = config.map();
        let server = map.get("dell:poweredge r750").unwrap();
        assert_eq!(
            server
                .components
                .get(&FirmwareComponentType::Uefi)
                .unwrap()
                .known_firmware
                .len(),
            2
        );
        assert_eq!(
            server
                .components
                .get(&FirmwareComponentType::Bmc)
                .unwrap()
                .known_firmware
                .len(),
            1
        );
        assert_eq!(
            *server
                .components
                .get(&FirmwareComponentType::Uefi)
                .unwrap()
                .preingest_upgrade_when_below
                .as_ref()
                .unwrap(),
            "1.13.3".to_string()
        );
        Ok(())
    }

    #[test]
    fn parse_ib_fabric() {
        let toml = r#"
rate_limit = 300
enabled = true
max_partition_per_tenant = 3
        "#;
        let ib_fabric_config: IBFabricConfig =
            Figment::new().merge(Toml::string(toml)).extract().unwrap();

        println!("{:?}", ib_fabric_config);

        assert_eq!(
            <IBMtu as std::convert::Into<i32>>::into(ib_fabric_config.mtu),
            4
        );
        assert_eq!(
            <IBRateLimit as std::convert::Into<i32>>::into(ib_fabric_config.rate_limit),
            300
        );
        assert_eq!(
            <IBServiceLevel as std::convert::Into<i32>>::into(ib_fabric_config.service_level),
            0
        );
        assert!(ib_fabric_config.enabled);
        assert_eq!(ib_fabric_config.max_partition_per_tenant, 3);
    }

    #[test]
    fn deserialize_serialize_ib_config() {
        let value_input = IBFabricConfig {
            enabled: true,
            allow_insecure: false,
            max_partition_per_tenant: 1,
            mtu: IBMtu(2),
            rate_limit: IBRateLimit(10),
            service_level: IBServiceLevel(2),
        };

        let value_json = serde_json::to_string(&value_input).unwrap();
        let value_output: IBFabricConfig = serde_json::from_str(&value_json).unwrap();

        assert_eq!(value_output, value_input);

        let value_json = r#"{"enabled": true, "max_partition_per_tenant": 2, "mtu": 4, "rate_limit": 20, "service_level": 10}"#;
        let value_output: IBFabricConfig = serde_json::from_str(value_json).unwrap();

        assert_eq!(
            value_output,
            IBFabricConfig {
                enabled: true,
                allow_insecure: false,
                max_partition_per_tenant: 2,
                mtu: IBMtu(4),
                rate_limit: IBRateLimit(20),
                service_level: IBServiceLevel(10),
            }
        );

        let value_input = IBFabricConfig::default();
        assert!(!value_input.enabled);

        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "Test.toml",
                r#"
                enabled=true
            "#,
            )?;
            let config: IBFabricConfig = Figment::new()
                .merge(Toml::file("Test.toml"))
                .extract()
                .unwrap();

            assert!(config.enabled);
            assert!(!config.allow_insecure);
            assert_eq!(config.max_partition_per_tenant, MAX_IB_PARTITION_PER_TENANT);
            assert_eq!(config.mtu, IBMtu::default());
            assert_eq!(config.rate_limit, IBRateLimit::default());
            assert_eq!(config.service_level, IBServiceLevel::default());
            Ok(())
        });
    }

    #[test]
    fn site_explorer_serde_defaults_match_core_defaults() -> eyre::Result<()> {
        // Make sure that if we let serde pick the defaults, it matches Default::default().
        let deserialized = serde_json::from_str::<SiteExplorerConfig>("{}")?;
        assert_eq!(deserialized, SiteExplorerConfig::default());
        Ok(())
    }
}
