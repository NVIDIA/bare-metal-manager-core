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

use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::SystemTime;
use std::{fmt, fs};

use arc_swap::ArcSwap;
use bmc_vendor::BMCVendor;
use chrono::Duration;
use duration_str::{deserialize_duration, deserialize_duration_chrono};
use ipnetwork::Ipv4Network;
use itertools::Itertools;
use mlxconfig_profile::MlxConfigProfile;
use mlxconfig_profile::serialization::{
    deserialize_option_profile_map, serialize_option_profile_map,
};
use model::DpuModel;
use model::firmware::{
    AgentUpgradePolicyChoice, Firmware, FirmwareComponent, FirmwareComponentType, FirmwareEntry,
};
use model::ib::{IBMtu, IBRateLimit, IBServiceLevel};
use model::machine::HostHealthConfig;
use model::network_security_group::NetworkSecurityGroupRule;
use model::network_segment::NetworkDefinition;
use model::resource_pool::define::ResourcePoolDef;
use model::site_explorer::{EndpointExplorationReport, ExploredEndpoint};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utils::HostPortPair;

use crate::state_controller::config::IterationConfig;

const MAX_IB_PARTITION_PER_TENANT: i32 = 31;

static BF2_NIC: &str = "24.47.1026";
static BF2_BMC: &str = "BF-25.10-9";
static BF2_CEC: &str = "4-15";
static BF2_UEFI: &str = "4.13.0-26-g337fea6bfd";
static BF3_NIC: &str = "32.47.1026";
static BF3_BMC: &str = "BF-25.10-9";
static BF3_CEC: &str = "00.02.0195.0000_n02";
static BF3_UEFI: &str = "4.13.0-26-g337fea6bfd";

/// carbide-api configuration file content
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CarbideConfig {
    /// The socket address that is used for the gRPC API server
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,

    /// Set to true to run this instance "passively", ie. don't start any background services and
    /// just listen for rpc/web connections. This is used in development mode when you want to run
    /// an additional carbide instance, against a cluster that is already running a "full" carbide
    /// instance.
    #[serde(default)]
    pub listen_only: bool,

    /// The socket address that is used for the HTTP server which serves
    /// prometheus metrics under /metrics
    pub metrics_endpoint: Option<SocketAddr>,

    /// An alternative prefix under which metrics will be emitted besides `carbide_`.
    /// Setting this flag will allow to dual emit metrics to migrate dashboards and alerts.
    /// Note that seting the flag will load to increased load on the observability system.
    pub alt_metric_prefix: Option<String>,

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

    /// List of aggregate IPv4 prefixes (in CIDR notation) that contain prefixes assigned
    /// to tenants so that they themselves can announce to the DPU.  E.g., BYOIP
    #[serde(default)]
    pub anycast_site_prefixes: Vec<Ipv4Network>,

    /// An ASN allocated for tenants to use
    /// when they peer with the DPU.
    /// If configured, the DPU will expect the host
    /// to peer with this ASN.  If left unset
    /// remote-as external will be used, allowing
    /// any ASN.
    pub common_tenant_host_asn: Option<u32>,

    #[serde(default)]
    pub vpc_isolation_behavior: VpcIsolationBehaviorType,

    #[serde(default)]
    pub dpu_network_monitor_pinger_type: Option<String>,

    /// TLS related configuration
    pub tls: Option<TlsConfig>,

    #[serde(default)]
    pub listen_mode: ListenMode,

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

    /// Deprecated, use machine_updater
    pub max_concurrent_machine_updates: Option<i32>,

    /// The interval at which the machine update manager checks for machine updates in seconds.
    pub machine_update_run_interval: Option<u64>,

    /// SiteExplorer related configuration
    #[serde(default)]
    pub site_explorer: SiteExplorerConfig,

    /// DPU agent to use NVUE instead of writing files directly.
    /// Once we are comfortable with this and all DPUs are HBN 2+ it will become the only option.
    #[serde(default = "default_to_true")]
    pub nvue_enabled: bool,

    /// The policy to decide whether two VPCs are allowed to peer with each other based on their
    /// network virtualization type during creation
    pub vpc_peering_policy: Option<VpcPeeringPolicy>,

    /// The policy to decide whether a VPC peering should be active
    pub vpc_peering_policy_on_existing: Option<VpcPeeringPolicy>,

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

    /// DpaInterfaceStateController related configuration parameter
    #[serde(default)]
    pub dpa_interface_state_controller: DpaInterfaceStateControllerConfig,

    /// RackStateController related configuration parameter
    #[serde(default)]
    pub rack_state_controller: RackStateControllerConfig,

    /// PowerShelfStateController related configuration parameter
    #[serde(default)]
    pub power_shelf_state_controller: PowerShelfStateControllerConfig,

    /// SwitchStateController related configuration parameter
    #[serde(default)]
    pub switch_state_controller: SwitchStateControllerConfig,

    /// SpdmStateController related configuration parameter
    #[serde(default)]
    pub spdm_state_controller: SpdmStateControllerConfig,

    #[serde(default)]
    pub host_models: HashMap<String, Firmware>,

    #[serde(default)]
    pub firmware_global: FirmwareGlobal,

    #[serde(default)]
    pub machine_updater: MachineUpdater,

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
    #[serde(default = "default_internet_l3_vni")]
    pub internet_l3_vni: u32,

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

    /// DpaConfig refers to East West Ethernet (aka
    /// Cluster Interconnect Network) configuration
    #[serde(default)]
    pub dpa_config: Option<DpaConfig>,

    /// DSX Exchange Event Bus configuration for publishing state change events via MQTT.
    #[serde(default)]
    pub dsx_exchange_event_bus: Option<DsxExchangeEventBusConfig>,

    /// FNN depends on various route-targets that
    /// are DC-specific.  This value is used to
    /// build those targets for import and,
    ///  eventually, export
    #[serde(default = "default_datacenter_asn")]
    pub datacenter_asn: u32,

    /// NvLink related configuration
    #[serde(default)]
    pub nvlink_config: Option<NvLinkConfig>,

    #[serde(default = "default_power_options")]
    pub power_manager_options: PowerManagerOptions,

    /// sitename is made visible to customers running
    /// tenant OS via an FMDS endpoint.
    pub sitename: Option<String>,

    /// Auto machine repair plugin configuration
    #[serde(default)]
    pub auto_machine_repair_plugin: AutoMachineRepairPluginConfig,

    /// configuration for using forge with a VM system
    pub vmaas_config: Option<VmaasConfig>,

    #[serde(
        default,
        rename = "mlx-config-profiles",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_option_profile_map",
        serialize_with = "serialize_option_profile_map"
    )]
    pub mlxconfig_profiles: Option<HashMap<String, MlxConfigProfile>>,

    /// The intent of this config option is to use the forge site controller as a standalone
    /// (disconnected / air-gapped) infrastructure manager for racks of GB200/GB300/VR144.
    /// Only set this if using Forge site controller with Rack Manager to manage GB200/300/VR144.
    /// It will change site controller behavior significantly in the following ways, etc.:
    /// 1. skip dpu management and use dpus in nic mode (optional, can set force_dpu_nic_mode=false)
    ///    a. no dpu bfb upgrade and host power cycle
    ///    b. no firmware upgrade and host power cycle
    ///    c. no hbn deployment (no ecmp, etc)
    ///    d. no dpu agent deployment
    ///    e. no restricted mode configuration
    ///    f. no tenant overlay network via L2 vxlan/evpn or L3 vni (fnn)
    /// 2. support any other nic interface on the compute nodes including the onboard 3p nic
    /// 3. require expected machines table rows to have other/all mac addresses for each machine
    /// 4. restrict dhcp service to only provide ip address to known mac addresses
    ///    a. for additional mac addresses, use HostInband network segment when dpu is in nic mode
    /// 5. disable compute host individual firmware upgrades
    ///    a. only rack level firmware upgrades are allowed
    /// 6. enable nvlink switch and power shelf discovery and ingestion
    ///    a. site explorer changes to explore switch and power shelf bmc
    ///    b. state machine for ingestion workflow
    ///    c. nvlink switch nvos deployment/upgrade via onie
    ///    d. nvlink switch default configuration and machine validation
    /// 7. enable rack state machine and calls to rack manager
    ///    a. depend on rack manager for firmware upgrades of the rack
    ///    b. depend on rack manager for all power sequencing of the rack and components
    ///    c. override/suspend component level state machine state transitions as needed
    /// 8. enable nvlink control plane integration with nmx-c
    ///    a. export nmx-c apis via site controller
    ///    b. hardware health daemon polling of switch telemetry and collection into site controller
    ///    prometheus instance
    /// 9. enable domain power service integration
    #[serde(default)]
    pub rack_management_enabled: bool,

    #[serde(default)]
    /// Treat any dpu found as a regular NIC and skip configuring it as a managed dpu.
    /// This is specifically for dev labs to allow using GB200/300 and VR compute
    /// trays with bluefield dpus as NICs.
    pub force_dpu_nic_mode: bool,

    // rms_api_url is the URL to the Rack Manager Service API.
    pub rms_api_url: Option<String>,

    /// Whether to use the host NIC instead of the DPUs on the compute trays.
    /// This is used to test the host NIC functionality.
    #[serde(
        default = "SiteExplorerConfig::default_use_onboard_nic",
        deserialize_with = "deserialize_arc_atomic_bool",
        serialize_with = "serialize_arc_atomic_bool"
    )]
    pub use_onboard_nic: Arc<AtomicBool>,

    // SPDM Config
    #[serde(default)]
    pub spdm: SpdmConfig,

    /// Due to limitations in Cumulus Linux route-leaking,
    /// some sites may require all VRFs to use the same VNI.
    /// Isolation is still possible via ACLs, and route-imports
    /// will still use the dynamically allocated VNI for deriving
    /// route-targets.
    /// This will limit the number of VRFs supported on the
    /// DPU to a single VRF.
    pub site_global_vpc_vni: Option<u32>,

    // DPF Config
    #[serde(default)]
    pub dpf: DpfConfig,

    /// The URL to use for overriding the PXE boot url on X86 machines.
    #[serde(default)]
    pub x86_pxe_boot_url_override: Option<String>,

    /// The URL to use for overriding the PXE boot url on ARM machines.
    #[serde(default)]
    pub arm_pxe_boot_url_override: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DpfConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SpdmConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub nras_config: Option<nras::Config>,
}

/// Parameters used by the Power config.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PowerManagerOptions {
    #[serde(default)]
    pub enabled: bool,
    #[serde(
        default = "default_next_duration_success",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub next_try_duration_on_success: chrono::TimeDelta,
    #[serde(
        default = "default_next_duration_failure",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub next_try_duration_on_failure: chrono::TimeDelta,
    #[serde(
        default = "default_wait_duration_next_reboot",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub wait_duration_until_host_reboot: chrono::TimeDelta,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct RouteTargetConfig {
    #[serde(default)]
    pub asn: u32,
    #[serde(default)]
    pub vni: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct FnnConfig {
    #[serde(default)]
    pub admin_vpc: Option<AdminFnnConfig>,

    /// We'll double-tag our internal tenant routes with this tag.
    /// Original consumer is GNI, who will import a common
    /// route-target for internal tenant routes, reducing
    /// the coordination needed between forge and GNI,
    /// but who knows what the future holds.
    #[serde(default)]
    pub common_internal_route_target: Option<RouteTargetConfig>,
    #[serde(default)]
    pub additional_route_target_imports: Vec<RouteTargetConfig>,

    #[serde(default)]
    pub routing_profiles: HashMap<String, FnnRoutingProfileConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Default)]
pub struct FnnRoutingProfileConfig {
    /// These are used for import policies to import routes
    /// that match these targets.
    #[serde(default)]
    pub route_target_imports: Vec<RouteTargetConfig>,

    /// These are used for tagging routes exported by the DPU
    #[serde(default)]
    pub route_targets_on_exports: Vec<RouteTargetConfig>,

    /// Is this an internal or external tenant/VPC profile
    #[serde(default)]
    pub internal: bool,
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

    /// The inline definition for the routing config to use for the admin network.
    #[serde(default)]
    pub routing_profile: FnnRoutingProfileConfig,
}

impl CarbideConfig {
    /// Returns a version of CarbideConfig where secrets are erased
    pub fn redacted(&self) -> Self {
        let mut config = self.clone();
        if let Some(host_index) = config.database_url.find('@') {
            let host = config.database_url.split_at(host_index).1;
            config.database_url = format!("postgres://redacted{host}");
        }
        config
    }
    pub fn get_firmware_config(&self) -> FirmwareConfig {
        let mut base_map: HashMap<String, Firmware> = Default::default();
        for (_, host) in self.host_models.iter() {
            base_map.insert(vendor_model_to_key(host.vendor, &host.model), host.clone());
        }
        for (_, dpu) in self.dpu_config.dpu_models.iter() {
            base_map.insert(
                vendor_model_to_key(
                    dpu.vendor,
                    &DpuModel::from(dpu.model.to_owned()).to_string(),
                ),
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

    // Given a device_type, return the profile that needs to be applied
    // to configure the DPA.
    pub fn get_dpa_profile(&self, _device_type: String) -> String {
        // XXX TODO XXX
        // Figure out profile that needs to be applied to the given device type
        // XXX TODO XXX
        "bf3-spx-enabled".to_string()
    }

    pub fn max_concurrent_machine_updates(&self) -> MaxConcurrentUpdates {
        MaxConcurrentUpdates {
            absolute: self.machine_updater.max_concurrent_machine_updates_absolute,
            percent: self.machine_updater.max_concurrent_machine_updates_percent,
        }
    }

    pub fn is_dpa_enabled(&self) -> bool {
        if self.dpa_config.is_none() {
            return false;
        }

        let conf = self.dpa_config.clone().unwrap();

        conf.enabled
    }

    pub fn get_dpa_subnet_ip(&self) -> Result<Ipv4Addr, eyre::Report> {
        if self.dpa_config.is_none() {
            tracing::error!("get_dpa_subnet_ip: DPA config missing");
            return Err(eyre::eyre!("get_dpa_subnet_ip: DPA config missing"));
        }

        let conf = self.dpa_config.clone().unwrap();
        Ok(conf.subnet_ip)
    }

    pub fn get_dpa_subnet_mask(&self) -> Result<i32, eyre::Report> {
        if self.dpa_config.is_none() {
            tracing::error!("get_dpa_subnet_mask: DPA config missing");
            return Err(eyre::eyre!("get_dpa_subnet_mask: DPA config missing"));
        }

        let conf = self.dpa_config.clone().unwrap();

        Ok(conf.subnet_mask)
    }

    pub fn mqtt_broker_host(&self) -> Option<String> {
        self.dpa_config
            .as_ref()
            .map(|conf| conf.mqtt_endpoint.clone())
    }

    pub fn mqtt_broker_port(&self) -> Option<u16> {
        self.dpa_config.as_ref().map(|conf| conf.mqtt_broker_port)
    }

    pub fn get_hb_interval(&self) -> Option<Duration> {
        self.dpa_config.as_ref().map(|conf| conf.hb_interval)
    }

    /// Returns true if the DSX Exchange Event Bus is enabled.
    pub fn is_dsx_exchange_event_bus_enabled(&self) -> bool {
        self.dsx_exchange_event_bus
            .as_ref()
            .map(|conf| conf.enabled)
            .unwrap_or(false)
    }

    /// Returns the DSX Exchange Event Bus MQTT broker endpoint if enabled.
    pub fn dsx_exchange_event_bus_mqtt_endpoint(&self) -> Option<&str> {
        self.dsx_exchange_event_bus
            .as_ref()
            .filter(|conf| conf.enabled)
            .map(|conf| conf.mqtt_endpoint.as_str())
    }

    /// Returns the DSX Exchange Event Bus MQTT broker port if enabled.
    pub fn dsx_exchange_event_bus_mqtt_broker_port(&self) -> Option<u16> {
        self.dsx_exchange_event_bus
            .as_ref()
            .filter(|conf| conf.enabled)
            .map(|conf| conf.mqtt_broker_port)
    }
}

pub struct MaxConcurrentUpdates {
    absolute: Option<i32>,
    percent: Option<i32>,
}

impl MaxConcurrentUpdates {
    pub fn max_concurrent_updates(&self, unhealthy: i32, out_of: i32) -> Option<i32> {
        if self.percent.is_none() {
            self.absolute
        } else {
            let percent = self.percent?;
            if out_of <= 0 || percent <= 0 {
                return Some(0);
            }
            let percent = percent as usize;
            // Round up, so if someone specified 10% with 9 hosts they'll get 1.
            let mut count = (percent * out_of as usize).div_ceil(100);
            count = count.saturating_sub(unhealthy as usize);
            if let Some(absolute) = self.absolute {
                count = count.min(absolute as usize);
            }
            Some(count as i32)
        }
    }
}

fn vendor_model_to_key(vendor: bmc_vendor::BMCVendor, model: &str) -> String {
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
    /// Duration after which a host is considered unhealthy if scout hasn't reported back
    #[serde(
        default = "MachineStateControllerConfig::scout_reporting_timeout_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub scout_reporting_timeout: Duration,
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

    fn scout_reporting_timeout_default() -> Duration {
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
            scout_reporting_timeout: MachineStateControllerConfig::scout_reporting_timeout_default(
            ),
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

/// DpaInterfaceStateController related config
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct DpaInterfaceStateControllerConfig {
    /// Common state controller configs
    #[serde(default = "StateControllerConfig::default")]
    pub controller: StateControllerConfig,
}

/// PowerShelfStateController related config
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct PowerShelfStateControllerConfig {
    /// Common state controller configs
    #[serde(default = "StateControllerConfig::default")]
    pub controller: StateControllerConfig,
}

/// RackStateController related config
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct RackStateControllerConfig {
    /// Common state controller configs
    #[serde(default = "StateControllerConfig::default")]
    pub controller: StateControllerConfig,
}

/// SwitchStateController related config
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SwitchStateControllerConfig {
    /// Common state controller configs
    #[serde(default = "StateControllerConfig::default")]
    pub controller: StateControllerConfig,
}

/// SpdmStateController related config
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SpdmStateControllerConfig {
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
    /// The controller will attempt to advance the state of this amount of objects
    /// in parallel.
    #[serde(default = "StateControllerConfig::max_concurrency_default")]
    pub max_concurrency: usize,

    /// Configures the maximum time the state processor will wait when checking
    /// for and dispatching new tasks.
    /// This value needs to be lower than `iteration_time` in order to assure that
    /// tasks are executed more often than generated.
    /// If the value is set to 0, the processor will dispatch object handling tasks
    /// immediately once they are enqueued. The downside of 0 (or low) interval is
    /// however that the state controller will poll the database for new tasks
    /// with the same low interval.
    #[serde(
        default = "StateControllerConfig::processor_dispatch_interval_default",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub processor_dispatch_interval: std::time::Duration,

    /// Configures how often the state handling processor will emit log messages
    #[serde(
        default = "StateControllerConfig::processor_log_interval_default",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub processor_log_interval: std::time::Duration,
}

impl StateControllerConfig {
    pub const fn max_object_handling_time_default() -> std::time::Duration {
        std::time::Duration::from_secs(3 * 60)
    }

    pub const fn iteration_time_default() -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }

    pub const fn processor_dispatch_interval_default() -> std::time::Duration {
        std::time::Duration::from_secs(2)
    }

    pub const fn processor_log_interval_default() -> std::time::Duration {
        std::time::Duration::from_secs(60)
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
            processor_dispatch_interval: Self::processor_dispatch_interval_default(),
            processor_log_interval: Self::processor_log_interval_default(),
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
            processor_dispatch_interval: config.processor_dispatch_interval,
            processor_log_interval: config.processor_log_interval,
        }
    }
}

/// IBFabricManager related configuration
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct IBFabricConfig {
    #[serde(
        default = "IBFabricConfig::default_max_partition_per_tenant",
        deserialize_with = "IBFabricConfig::deserialize_max_partition"
    )]
    pub max_partition_per_tenant: i32,

    #[serde(default)]
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

    /// The interval at which ib fabric monitor runs in seconds.
    /// Defaults to 1 Minute if not specified.
    #[serde(
        default = "IBFabricConfig::default_fabric_monitor_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub fabric_monitor_run_interval: std::time::Duration,
}

impl Default for IBFabricConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_partition_per_tenant: Self::default_max_partition_per_tenant(),
            allow_insecure: false,
            mtu: IBMtu::default(),
            rate_limit: IBRateLimit::default(),
            service_level: IBServiceLevel::default(),
            fabric_monitor_run_interval: Self::default_fabric_monitor_run_interval(),
        }
    }
}

impl IBFabricConfig {
    pub const fn default_max_partition_per_tenant() -> i32 {
        MAX_IB_PARTITION_PER_TENANT
    }

    pub const fn default_fabric_monitor_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(60)
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

/// NvLink related configuration
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct NvLinkConfig {
    #[serde(default)]
    /// Enable NvLink Partitioning
    pub enabled: bool,

    /// Defaults to 1 Minute if not specified.
    #[serde(
        default = "NvLinkConfig::default_monitor_run_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub monitor_run_interval: std::time::Duration,

    /// Timeout for pending NMX-M operations. Defaults to 10 seconds if not specified.
    #[serde(
        default = "NvLinkConfig::default_nmx_m_operation_timeout",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub nmx_m_operation_timeout: std::time::Duration,

    /// NMX-M endpoint (name or IP address) used to create client connections,
    /// include port number as well if required eg. https://127.0.0.1:4010
    #[serde(default = "default_nmx_m_endpoint")]
    pub nmx_m_endpoint: String,
    /// Set to true if NMX-M doesn't adhere to security requirements. Defaults to false
    pub allow_insecure: bool,
}

fn default_nmx_m_endpoint() -> String {
    "localhost".to_string()
}

impl Default for NvLinkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            monitor_run_interval: Self::default_monitor_run_interval(),
            nmx_m_operation_timeout: Self::default_nmx_m_operation_timeout(),
            nmx_m_endpoint: "localhost".to_string(),
            allow_insecure: false,
        }
    }
}

impl NvLinkConfig {
    pub const fn default_monitor_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
    pub const fn default_nmx_m_operation_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(10)
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
    /// This number divided by `concurrent_explorations` will determine how many
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
        deserialize_with = "deserialize_arc_atomic_bool",
        serialize_with = "serialize_arc_atomic_bool"
    )]
    pub create_machines: Arc<AtomicBool>,

    #[serde(default = "SiteExplorerConfig::default_machines_created_per_run")]
    /// How many ManagedHosts should be created in a single run.
    /// Default is 1.
    pub machines_created_per_run: u64,

    /// Whether SiteExplorer should rotate/update Switch NVOS admin credentials
    #[serde(
        default = "SiteExplorerConfig::default_rotate_switch_nvos_credentials",
        deserialize_with = "deserialize_arc_atomic_bool",
        serialize_with = "serialize_arc_atomic_bool"
    )]
    pub rotate_switch_nvos_credentials: Arc<AtomicBool>,

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

    #[serde(
        default = "SiteExplorerConfig::default_admin_segment_type_non_dpu",
        deserialize_with = "deserialize_arc_atomic_bool",
        serialize_with = "serialize_arc_atomic_bool"
    )]
    pub admin_segment_type_non_dpu: Arc<AtomicBool>,

    /// Whether site-controller should allocate a secondary
    /// VTEP IP or leave that to discovery.
    /// Current secondary VTEP use-case is additional
    /// VTEP IPs for GENEVE VTEPS (GTEPS) used by traffic-intercept users.
    ///  Only sites expected to support
    /// additional VTEPS would turn this on.
    #[serde(default)]
    pub allocate_secondary_vtep_ip: bool,

    /// Whether SiteExplorer should create Power Shelf state machine
    #[serde(
        default = "SiteExplorerConfig::default_create_power_shelves",
        deserialize_with = "deserialize_arc_atomic_bool",
        serialize_with = "serialize_arc_atomic_bool"
    )]
    pub create_power_shelves: Arc<AtomicBool>,

    /// Whether SiteExplorer should create Power Shelf state machine from static IP
    #[serde(
        default = "SiteExplorerConfig::default_explore_power_shelves_from_static_ip",
        deserialize_with = "deserialize_arc_atomic_bool",
        serialize_with = "serialize_arc_atomic_bool"
    )]
    pub explore_power_shelves_from_static_ip: Arc<AtomicBool>,

    #[serde(default = "SiteExplorerConfig::default_power_shelves_created_per_run")]
    /// How many Power Shelves should be created in a single run.
    /// Default is 1.
    pub power_shelves_created_per_run: u64,

    /// Whether SiteExplorer should create Switch state machine
    #[serde(
        default = "SiteExplorerConfig::default_create_switches",
        deserialize_with = "deserialize_arc_atomic_bool",
        serialize_with = "serialize_arc_atomic_bool"
    )]
    pub create_switches: Arc<AtomicBool>,

    #[serde(default = "SiteExplorerConfig::default_switches_created_per_run")]
    /// How many Switches should be created in a single run.
    /// Default is 9.
    pub switches_created_per_run: u64,

    #[serde(
        default = "SiteExplorerConfig::default_use_onboard_nic",
        deserialize_with = "deserialize_arc_atomic_bool",
        serialize_with = "serialize_arc_atomic_bool"
    )]
    pub use_onboard_nic: Arc<AtomicBool>,
}

impl Default for SiteExplorerConfig {
    fn default() -> Self {
        SiteExplorerConfig {
            enabled: true,
            run_interval: Self::default_run_interval(),
            concurrent_explorations: Self::default_concurrent_explorations(),
            explorations_per_run: Self::default_explorations_per_run(),
            create_machines: Arc::new(true.into()),
            machines_created_per_run: Self::default_machines_created_per_run(),
            override_target_ip: None,
            override_target_port: None,
            allow_zero_dpu_hosts: false,
            bmc_proxy: crate::dynamic_settings::bmc_proxy(None),
            allow_changing_bmc_proxy: None,
            reset_rate_limit: Self::default_reset_rate_limit(),
            admin_segment_type_non_dpu: Self::default_admin_segment_type_non_dpu(),
            allocate_secondary_vtep_ip: false,
            create_power_shelves: Arc::new(true.into()),
            explore_power_shelves_from_static_ip: Arc::new(true.into()),
            power_shelves_created_per_run: Self::default_power_shelves_created_per_run(),
            create_switches: Arc::new(true.into()),
            switches_created_per_run: Self::default_switches_created_per_run(),
            rotate_switch_nvos_credentials: Self::default_rotate_switch_nvos_credentials(),
            use_onboard_nic: Arc::new(false.into()),
        }
    }
}

impl PartialEq for SiteExplorerConfig {
    fn eq(&self, other: &SiteExplorerConfig) -> bool {
        self.enabled == other.enabled
            && self.run_interval == other.run_interval
            && self.concurrent_explorations == other.concurrent_explorations
            && self.explorations_per_run == other.explorations_per_run
            && self.create_machines.load(AtomicOrdering::Relaxed)
                == other.create_machines.load(AtomicOrdering::Relaxed)
            && self.override_target_ip == other.override_target_ip
            && self.override_target_port == other.override_target_port
    }
}

impl SiteExplorerConfig {
    pub const fn default_run_interval() -> std::time::Duration {
        std::time::Duration::from_secs(120)
    }

    pub fn default_create_machines() -> Arc<AtomicBool> {
        Arc::new(true.into())
    }

    pub const fn default_concurrent_explorations() -> u64 {
        30
    }

    pub const fn default_explorations_per_run() -> u64 {
        90
    }

    pub const fn default_machines_created_per_run() -> u64 {
        4
    }

    pub fn default_rotate_switch_nvos_credentials() -> Arc<AtomicBool> {
        Arc::new(false.into())
    }

    pub const fn default_reset_rate_limit() -> Duration {
        Duration::hours(1)
    }

    pub fn default_admin_segment_type_non_dpu() -> Arc<AtomicBool> {
        Arc::new(false.into())
    }

    pub fn default_create_power_shelves() -> Arc<AtomicBool> {
        Arc::new(false.into())
    }

    pub fn default_explore_power_shelves_from_static_ip() -> Arc<AtomicBool> {
        Arc::new(false.into())
    }

    pub const fn default_power_shelves_created_per_run() -> u64 {
        1
    }

    pub fn default_create_switches() -> Arc<AtomicBool> {
        Arc::new(false.into())
    }

    pub const fn default_switches_created_per_run() -> u64 {
        9
    }

    pub fn default_use_onboard_nic() -> Arc<AtomicBool> {
        Arc::new(false.into())
    }
}

impl DpaConfig {
    pub const fn default_hb_interval() -> chrono::Duration {
        Duration::minutes(2)
    }

    pub const fn default_subnet_ip() -> Ipv4Addr {
        Ipv4Addr::UNSPECIFIED
    }
}

impl Default for DpaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mqtt_endpoint: default_mqtt_endpoint(),
            mqtt_broker_port: default_mqtt_broker_port(),
            subnet_ip: Self::default_subnet_ip(),
            subnet_mask: 0,
            hb_interval: Self::default_hb_interval(),
        }
    }
}

pub fn deserialize_arc_atomic_bool<'de, D>(deserializer: D) -> Result<Arc<AtomicBool>, D::Error>
where
    D: Deserializer<'de>,
{
    let b = bool::deserialize(deserializer)?;
    Ok(Arc::new(b.into()))
}

pub fn serialize_arc_atomic_bool<S>(cm: &Arc<AtomicBool>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bool(cm.load(AtomicOrdering::Relaxed))
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenMode {
    PlaintextHttp1,
    PlaintextHttp2,
    #[serde(other)]
    #[default]
    Tls,
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

    /// Configuration for the root of trust for client cert auth
    pub trust: Option<TrustConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrustConfig {
    /// The SPIFFE trust domain which client certs must adhere to
    pub spiffe_trust_domain: String,
    /// Allowed base paths for valid client cert spiffe:// URIs for services
    pub spiffe_service_base_paths: Vec<String>,
    /// Allowed base path for client cert spiffe:// URIs for machines
    pub spiffe_machine_base_path: String,
    /// Additional issuer CN's to trust other than the SPIFFE issuer, useful for external user certs.
    pub additional_issuer_cns: Vec<String>,
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

fn default_listen() -> SocketAddr {
    "[::]:1079".parse().unwrap()
}

fn default_max_database_connections() -> u32 {
    1000
}

/// DpuConfig related internal configuration
#[derive(Clone, Debug, Serialize)]
pub struct DpuConfig {
    /// Enable dpu firmware updates on initial discovery
    #[serde(default)]
    pub dpu_nic_firmware_initial_update_enabled: bool,

    /// Enable dpu firmware updates on known machines
    #[serde(default)]
    pub dpu_nic_firmware_reprovision_update_enabled: bool,

    /// DPU related configuration parameter
    #[serde(default)]
    pub dpu_models: HashMap<String, Firmware>,

    #[serde(default)]
    pub dpu_nic_firmware_update_versions: Vec<String>,

    /// Whether to enable secure boot flow for DPU provisioning (via redfish)
    /// Default is false.
    #[serde(default)]
    pub dpu_enable_secure_boot: bool,
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

impl<'de> Deserialize<'de> for DpuConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Create a temporary struct for partial deserialization
        #[derive(Deserialize)]
        struct PartialDpuConfig {
            #[serde(default)]
            dpu_nic_firmware_initial_update_enabled: Option<bool>,
            #[serde(default)]
            dpu_nic_firmware_reprovision_update_enabled: Option<bool>,
            #[serde(default)]
            dpu_models: Option<HashMap<String, Firmware>>,
            #[serde(default)]
            dpu_nic_firmware_update_versions: Option<Vec<String>>,
            #[serde(default)]
            dpu_enable_secure_boot: Option<bool>,
        }

        let partial = PartialDpuConfig::deserialize(deserializer)?;
        let default = DpuConfig::default();

        Ok(DpuConfig {
            dpu_nic_firmware_initial_update_enabled: partial
                .dpu_nic_firmware_initial_update_enabled
                .unwrap_or(default.dpu_nic_firmware_initial_update_enabled),
            dpu_nic_firmware_reprovision_update_enabled: partial
                .dpu_nic_firmware_reprovision_update_enabled
                .unwrap_or(default.dpu_nic_firmware_reprovision_update_enabled),
            dpu_models: partial.dpu_models.unwrap_or(default.dpu_models),
            dpu_nic_firmware_update_versions: partial
                .dpu_nic_firmware_update_versions
                .unwrap_or(default.dpu_nic_firmware_update_versions),
            dpu_enable_secure_boot: partial
                .dpu_enable_secure_boot
                .unwrap_or(default.dpu_enable_secure_boot),
        })
    }
}

impl Default for DpuConfig {
    // Preingestion is only enabled for BF3 BMC Firmware upgrades. This is to support ingesting DPUs that come
    // with older BMC firmware versions than BF-23.10-5. BF-23.10-5 is the minimum BMC firmware that Site Explorer
    // can support auto-ingestion for.
    fn default() -> Self {
        Self {
            dpu_nic_firmware_initial_update_enabled: false,
            dpu_nic_firmware_reprovision_update_enabled: true,
            dpu_models: HashMap::from([
                (
                    "bluefield2".to_string(),
                    Firmware {
                        vendor: BMCVendor::Nvidia,
                        model: "Bluefield 2 SmartNIC Main Card".to_string(),
                        ordering: vec![FirmwareComponentType::Bmc, FirmwareComponentType::Cec],
                        explicit_start_needed: false,
                        components: HashMap::from([
                            (
                                FirmwareComponentType::Bmc,
                                FirmwareComponent {
                                    current_version_reported_as: Some(
                                        Regex::new("BMC_Firmware").unwrap(),
                                    ),
                                    preingest_upgrade_when_below: None,
                                    known_firmware: vec![FirmwareEntry::standard(BF2_BMC)],
                                },
                            ),
                            (
                                FirmwareComponentType::Cec,
                                FirmwareComponent {
                                    current_version_reported_as: Some(
                                        Regex::new("Bluefield_FW_ERoT").unwrap(),
                                    ),
                                    preingest_upgrade_when_below: None,
                                    known_firmware: vec![FirmwareEntry::standard(BF2_CEC)],
                                },
                            ),
                            (
                                FirmwareComponentType::Nic,
                                FirmwareComponent {
                                    current_version_reported_as: Some(
                                        Regex::new("DPU_NIC").unwrap(),
                                    ),
                                    preingest_upgrade_when_below: None,
                                    known_firmware: vec![FirmwareEntry::standard(BF2_NIC)],
                                },
                            ),
                            (
                                FirmwareComponentType::Uefi,
                                FirmwareComponent {
                                    current_version_reported_as: Some(
                                        Regex::new("DPU_UEFI").unwrap(),
                                    ),
                                    preingest_upgrade_when_below: None,
                                    known_firmware: vec![FirmwareEntry::standard(BF2_UEFI)],
                                },
                            ),
                        ]),
                    },
                ),
                (
                    "bluefield3".to_string(),
                    Firmware {
                        vendor: BMCVendor::Nvidia,
                        model: "Bluefield 3 SmartNIC Main Card".to_string(),
                        ordering: vec![FirmwareComponentType::Bmc, FirmwareComponentType::Cec],
                        explicit_start_needed: false,
                        components: HashMap::from([
                            (
                                FirmwareComponentType::Bmc,
                                FirmwareComponent {
                                    current_version_reported_as: Some(
                                        Regex::new("BMC_Firmware").unwrap(),
                                    ),
                                    preingest_upgrade_when_below: None,
                                    known_firmware: vec![
                                        // BF-24.10-33 (DOCA 2.9) is the expected BMC FW that we expect on BF3s after ingesting them
                                        FirmwareEntry::standard(BF3_BMC),
                                    ],
                                },
                            ),
                            (
                                FirmwareComponentType::Cec,
                                FirmwareComponent {
                                    current_version_reported_as: Some(
                                        Regex::new("Bluefield_FW_ERoT").unwrap(),
                                    ),

                                    preingest_upgrade_when_below: None,
                                    known_firmware: vec![FirmwareEntry::standard(BF3_CEC)],
                                },
                            ),
                            (
                                FirmwareComponentType::Nic,
                                FirmwareComponent {
                                    current_version_reported_as: Some(
                                        Regex::new("DPU_NIC").unwrap(),
                                    ),
                                    preingest_upgrade_when_below: None,
                                    known_firmware: vec![FirmwareEntry::standard(BF3_NIC)],
                                },
                            ),
                            (
                                FirmwareComponentType::Uefi,
                                FirmwareComponent {
                                    current_version_reported_as: Some(
                                        Regex::new("DPU_UEFI").unwrap(),
                                    ),
                                    preingest_upgrade_when_below: None,
                                    known_firmware: vec![FirmwareEntry::standard(BF3_UEFI)],
                                },
                            ),
                        ]),
                    },
                ),
            ]),
            dpu_nic_firmware_update_versions: vec![BF2_NIC.to_string(), BF3_NIC.to_string()],
            dpu_enable_secure_boot: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkSecurityGroupConfig {
    /// The maximum number of unique rules allowed for
    /// a network security group after rules are expanded.
    /// (src port range * dst port range * src prefix list * dst prefix list)
    #[serde(default = "default_max_network_security_group_size")]
    pub max_network_security_group_size: u32,
    /// Whether to allow stateful security groups.
    /// This will initially only be passed through to the
    /// DPU as a way to toggle default stateful options
    /// in nvue config.
    #[serde(default = "default_to_true")]
    pub stateful_acls_enabled: bool,

    /// A set of NSG rules that will be inserted before any user-defined rules.
    #[serde(default)]
    pub policy_overrides: Vec<NetworkSecurityGroupRule>,
}

impl Default for NetworkSecurityGroupConfig {
    fn default() -> Self {
        NetworkSecurityGroupConfig {
            max_network_security_group_size: default_max_network_security_group_size(),
            stateful_acls_enabled: default_to_true(),
            policy_overrides: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
    #[serde(default = "FirmwareGlobal::instance_updates_manual_tagging_default")]
    pub instance_updates_manual_tagging: bool,
    #[serde(default)]
    pub no_reset_retries: bool,
    #[serde(
        default = "FirmwareGlobal::hgx_bmc_gpu_reboot_delay_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub hgx_bmc_gpu_reboot_delay: Duration,
    #[serde(default)]
    pub requires_manual_upgrade: bool,
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
            host_firmware_upgrade_retry_interval: Self::get_retry_interval(),
            instance_updates_manual_tagging: false,
            no_reset_retries: false,
            hgx_bmc_gpu_reboot_delay: FirmwareGlobal::hgx_bmc_gpu_reboot_delay_default(),
            requires_manual_upgrade: false,
        }
    }

    #[cfg(test)]
    pub fn get_retry_interval() -> Duration {
        Duration::seconds(1)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct MachineUpdater {
    #[serde(default)]
    pub instance_autoreboot_period: Option<TimePeriod>,
    /// The maximum number of machines that have in-progress updates running.  This prevents
    /// too many machines from being put into maintenance at any given time.
    pub max_concurrent_machine_updates_absolute: Option<i32>,
    /// The maximum percentage of machines that have in-progress updates running.  This prevents
    /// too many machines from being put into maintenance at any given time.  If both values are given, the lesser will be used.
    pub max_concurrent_machine_updates_percent: Option<i32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct TimePeriod {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

impl FirmwareGlobal {
    pub fn instance_updates_manual_tagging_default() -> bool {
        true
    }
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
    pub fn hgx_bmc_gpu_reboot_delay_default() -> Duration {
        Duration::seconds(30)
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
            instance_updates_manual_tagging: false,
            no_reset_retries: false,
            hgx_bmc_gpu_reboot_delay: FirmwareGlobal::hgx_bmc_gpu_reboot_delay_default(),
            requires_manual_upgrade: false,
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
    pub fn find(&self, vendor: bmc_vendor::BMCVendor, model: &str) -> Option<Firmware> {
        let dpu_model = DpuModel::from(model);
        let key = if dpu_model != DpuModel::Unknown {
            vendor_model_to_key(vendor, &dpu_model.to_string())
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
        report.vendor.and_then(|vendor| {
            // Use report.model if it is already filled or use model()
            // function to extract model from the report.
            report
                .model
                .as_ref()
                .and_then(|model| self.find(vendor, model))
                .or_else(|| report.model().and_then(|model| self.find(vendor, &model)))
        })
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

    pub fn config_update_time(&self) -> Option<std::time::SystemTime> {
        if self.firmware_directory.to_string_lossy() == "" {
            return None;
        }

        let metadata = std::fs::metadata(self.firmware_directory.clone()).ok()?;

        metadata.modified().ok()
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
        let key = vendor_model_to_key(cfg.vendor, &cfg.model);

        let Some(cur_model) = map.get_mut(&key) else {
            // We haven't seen this model before, so use this as given.
            map.insert(key, cfg);
            return Ok(());
        };

        if !cfg.ordering.is_empty() {
            // Newer ordering definitions take precedence.  For now we don't consider this at a specific version level.
            cur_model.ordering = cfg.ordering
        }

        // if explicit_start_needed is true, it should take precedence. We shouldn't be doing automatic upgrades.
        if cfg.explicit_start_needed {
            cur_model.explicit_start_needed = true;
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

pub fn default_internet_l3_vni() -> u32 {
    // This is a number agreed upon between GNI and Forge
    // that they will use to tag the default route.
    // It will be combined with datacenter_asn to form
    // a route-target of <DC_ASN>:<INTERNET_VNI>.
    100001
}

pub fn default_datacenter_asn() -> u32 {
    // This is a number previously provided by GNI.
    // It represents a "global" (i.e., non-DC-specific)
    // identifier.  It's used in pre-FNN sites and in FNN
    // on DPU routes, but we'll transition away from that.
    11414
}

pub fn default_next_duration_success() -> Duration {
    Duration::minutes(5)
}

pub fn default_next_duration_failure() -> Duration {
    Duration::minutes(2)
}

pub fn default_wait_duration_next_reboot() -> Duration {
    Duration::minutes(15)
}

pub fn default_power_options() -> PowerManagerOptions {
    PowerManagerOptions {
        enabled: false,
        next_try_duration_on_success: default_next_duration_success(),
        next_try_duration_on_failure: default_next_duration_failure(),
        wait_duration_until_host_reboot: default_wait_duration_next_reboot(),
    }
}

pub fn default_to_true() -> bool {
    true
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
    pub pkeys: Vec<model::resource_pool::define::Range>,
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
            sitename: value.sitename,
            initial_dpu_agent_upgrade_policy: value
                .initial_dpu_agent_upgrade_policy
                .unwrap_or(AgentUpgradePolicyChoice::Off)
                .to_string(),
            dpu_nic_firmware_update_version: HashMap::default(),
            dpu_nic_firmware_initial_update_enabled: DpuConfig::default()
                .dpu_nic_firmware_initial_update_enabled,
            dpu_nic_firmware_reprovision_update_enabled: DpuConfig::default()
                .dpu_nic_firmware_reprovision_update_enabled,
            max_concurrent_machine_updates: value
                .machine_updater
                .max_concurrent_machine_updates_absolute
                .unwrap_or_default(),
            machine_update_runtime_interval: value.machine_update_run_interval.unwrap_or_default(),
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
            bom_validation_allow_allocation_on_validation_failure: value
                .bom_validation
                .allow_allocation_on_validation_failure,
            dpu_nic_firmware_update_versions: value.dpu_config.dpu_nic_firmware_update_versions,
            dpa_enabled: value.dpa_config.clone().unwrap_or_default().enabled,
            mqtt_endpoint: value.dpa_config.clone().unwrap_or_default().mqtt_endpoint,
            mqtt_broker_port: value
                .dpa_config
                .clone()
                .unwrap_or_default()
                .mqtt_broker_port as i32,
            mqtt_hb_interval: value
                .dpa_config
                .clone()
                .unwrap_or_default()
                .hb_interval
                .to_string(),
            bom_validation_auto_generate_missing_sku: value
                .bom_validation
                .auto_generate_missing_sku,
            bom_validation_auto_generate_missing_sku_interval: value
                .bom_validation
                .auto_generate_missing_sku_interval
                .as_secs(),
            dpu_secure_boot_enabled: value.dpu_config.dpu_enable_secure_boot,
            dpa_subnet_ip: value
                .dpa_config
                .clone()
                .unwrap_or_default()
                .subnet_ip
                .to_string(),
            dpa_subnet_mask: value.dpa_config.unwrap_or_default().subnet_mask,
        }
    }
}

fn subdirectories_sorted_by_modification_date(topdir: &PathBuf) -> Vec<fs::DirEntry> {
    let Ok(dirs) = topdir.read_dir() else {
        tracing::error!("Unreadable firmware directory {:?}", topdir);
        return vec![];
    };

    // We sort in ascending modification time so that we will use the newest made firmware metadata
    let mut dirs: Vec<fs::DirEntry> = dirs.filter_map(|x| x.ok()).collect();
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

fn default_mqtt_endpoint() -> String {
    "mqtt.forge".to_string()
}

fn default_mqtt_broker_port() -> u16 {
    1884
}

/// DPA (aka Cluster Ineteconnect Network) related configuration
/// In addition to enabling DPA and specifying
/// the mqtt endpoint, you need to specify the vni range to
/// be used by DPA as pools.dpa-vni
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct DpaConfig {
    /// Global enable/disable of Cluster Interconnect Network
    #[serde(default)]
    pub enabled: bool,

    /// MQTT broker host (name or IP address) used to create client connections
    #[serde(default = "default_mqtt_endpoint")]
    pub mqtt_endpoint: String,

    /// MQTT broker port to use to estabilsh client connections
    #[serde(default = "default_mqtt_broker_port")]
    pub mqtt_broker_port: u16,

    #[serde(default = "DpaConfig::default_subnet_ip")]
    pub subnet_ip: Ipv4Addr,

    #[serde(default)]
    pub subnet_mask: i32,

    /// hb_interval is the interval at which we issue heartbeat
    /// requests to the DPA.
    /// Defaults to 120 if not specified.
    #[serde(
        default = "DpaConfig::default_hb_interval",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub hb_interval: chrono::TimeDelta,
}

/// DSX Exchange Event Bus configuration for publishing state change events via MQTT 3.1.1.
///
/// When configured, Carbide will publish `ManagedHostState` transitions to the
/// topic `carbide/v1/machine/{machineId}/state` as defined in `carbide.yaml`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct DsxExchangeEventBusConfig {
    /// Enable/disable the DSX Exchange Event Bus.
    #[serde(default)]
    pub enabled: bool,

    /// MQTT broker host (name or IP address) used to create client connections.
    #[serde(default = "default_mqtt_endpoint")]
    pub mqtt_endpoint: String,

    /// MQTT broker port to use to establish client connections.
    #[serde(default = "default_mqtt_broker_port")]
    pub mqtt_broker_port: u16,

    /// Timeout for MQTT publish operations. Defaults to 1 second.
    #[serde(
        default = "DsxExchangeEventBusConfig::default_publish_timeout",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub publish_timeout: std::time::Duration,

    /// Queue capacity for buffering state change events while publishing.
    /// Events are dropped if the queue is full. Defaults to 1024.
    #[serde(default = "DsxExchangeEventBusConfig::default_queue_capacity")]
    pub queue_capacity: usize,
}

impl DsxExchangeEventBusConfig {
    pub const fn default_publish_timeout() -> std::time::Duration {
        std::time::Duration::from_secs(1)
    }

    pub const fn default_queue_capacity() -> usize {
        1024
    }
}

/// MachineValidation related configuration
#[derive(Default, Clone, Copy, Debug, Deserialize, Serialize)]
pub struct BomValidationConfig {
    /// Whether BOM Validation is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Allow machines that do not have a SKU assigned to bypass SKU validation
    /// When true, machines in WaitingForSkuAssignment state can proceed without a SKU
    #[serde(default)]
    pub ignore_unassigned_machines: bool,

    /// Allow machines to stay in Ready state and remain allocatable even when SKU validation fails
    /// When false (default): Standard mode - validation failures block allocation (machine enters failed state)
    /// When true: Allow allocation mode - validation still occurs and health reports are recorded, but machines do not transition
    /// into failed states (SkuVerificationFailed, SkuMissing, WaitingForSkuAssignment) and can proceed to Ready/MachineValidation
    #[serde(default)]
    pub allow_allocation_on_validation_failure: bool,

    /// The interval since the last time the state machine attempted
    /// to find an existing SKU that matches the machine.
    #[serde(
        default = "BomValidationConfig::default_bom_validation_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub find_match_interval: std::time::Duration,

    /// When a SKU is assigned to a machine, but doesn't exist
    /// attempt to create a SKU for the machine.  This only
    /// applies to SKUs assigned via expected machines.
    #[serde(default)]
    pub auto_generate_missing_sku: bool,
    /// The inteveral between attempting to generate a SKU from amachine
    #[serde(
        default = "BomValidationConfig::default_bom_validation_interval",
        deserialize_with = "deserialize_duration",
        serialize_with = "as_std_duration"
    )]
    pub auto_generate_missing_sku_interval: std::time::Duration,
}

impl BomValidationConfig {
    const fn default_bom_validation_interval() -> std::time::Duration {
        std::time::Duration::from_secs(300)
    }
}

/// Auto machine repair plugin related configuration
#[derive(Default, Clone, Copy, Debug, Deserialize, Serialize)]
pub struct AutoMachineRepairPluginConfig {
    /// Whether automatic machine repair mode is enabled
    #[serde(default)]
    pub enabled: bool,
}

/// Defines the policy for VPC peering based on network virtualization type.
#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VpcPeeringPolicy {
    /// Only VPCs with the same network virtualization type can peer.
    Exclusive,

    /// VPCs with any network virtualization type can peer with each other.
    Mixed,

    /// VPC peering is not allowed.
    None,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct VmaasConfig {
    /// Allow VFs on instance creation.  defaults to true, but will be disabled when
    /// using SDN to manage the instance network configuration for VMs
    #[serde(default = "default_to_true")]
    pub allow_instance_vf: bool,

    /// Configure the DPUs to create the reps specified.
    /// when not provided, the DPU creates the reps for the 2 physical devices and 14 virtual devices
    pub hbn_reps: Option<String>,

    /// Configure the DPUs to create the SF representors specified.
    pub hbn_sfs: Option<String>,

    /// Options to configure advanced routing and bridging.
    pub bridging: Option<TrafficInterceptBridging>,

    /// Prefixes expected to be publicly routable and used
    /// by traffic-intercept users.
    pub public_prefixes: Vec<Ipv4Network>,

    /// Whether a secondary overlay is expected,
    /// which will require secondary VTEP IPs to be allocated
    /// to DPUs
    #[serde(default = "default_to_true")]
    pub secondary_overlay_support: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct TrafficInterceptBridging {
    /// Prefix to be used for internal routing between HBN and intercept bridges
    /// within the DPU.
    pub internal_bridge_routing_prefix: Ipv4Network,

    /// The name of the bridge (aka br-host) that sits between host PF and br-hbn
    /// It will be connected to br-hbn or the hbn pod via a patch_point or
    /// patch port of some kind.
    #[serde(default = "default_host_intercept_bridge_name")]
    pub host_intercept_bridge_name: String,

    /// The name of the bridge that sits between VFs and br-hbn.
    /// This bridge will be assigned an address from <internal_bridge_routing_prefix>
    /// so that we can route traffic to a /32 bound to it and used as a VTEP for
    /// an additional GENEVE VPN.
    #[serde(default = "default_vf_intercept_bridge_name")]
    pub vf_intercept_bridge_name: String,

    /// The <vf_intercept_bridge_name> side of the SF representor that connects the HBN pod to br-hbn.
    /// This will be the side owned by the <vf_intercept_bridge_name> bridge
    #[serde(default = "default_vf_intercept_bridge_port")]
    pub vf_intercept_bridge_port: String,

    /// The <host_intercept_bridge_name> side of the SF representor that connects the HBN pod to br-hbn.
    /// This will be the side owned by the <host_intercept_bridge_name> bridge.
    #[serde(default = "default_host_intercept_bridge_port")]
    pub host_intercept_bridge_port: String,

    /// The SF used for internal routing of VF traffic.
    pub vf_intercept_bridge_sf: String,
}

pub fn default_host_intercept_bridge_name() -> String {
    "br-host".to_string()
}

pub fn default_vf_intercept_bridge_name() -> String {
    "br-dpu".to_string()
}

pub fn default_vf_intercept_bridge_port() -> String {
    "patch-br-dpu-to-hbn".to_string()
}

pub fn default_host_intercept_bridge_port() -> String {
    "patch-br-host-to-hbn".to_string()
}

#[cfg(test)]
mod tests {
    use chrono::Datelike;
    use figment::Figment;
    use figment::providers::{Env, Format, Toml};
    use libredfish::model::service_root::RedfishVendor;
    use mlxconfig_variables::MlxValueType;
    use model::resource_pool;

    use super::*;

    const TEST_DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cfg/test_data");

    #[test]
    fn deserialize_serialize_machine_controller_config() {
        let input = MachineStateControllerConfig {
            controller: StateControllerConfig {
                iteration_time: std::time::Duration::from_secs(30),
                max_object_handling_time: std::time::Duration::from_secs(60),
                max_concurrency: 10,
                processor_dispatch_interval: std::time::Duration::from_secs(2),
                processor_log_interval: std::time::Duration::from_secs(60),
            },
            dpu_wait_time: Duration::minutes(20),
            power_down_wait: Duration::seconds(10),
            failure_retry_time: Duration::minutes(90),
            dpu_up_threshold: Duration::weeks(1),
            scout_reporting_timeout: Duration::minutes(5),
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
                        processor_dispatch_interval: std::time::Duration::from_secs(2),
                        processor_log_interval: std::time::Duration::from_secs(60),
                    }
                },
                dpu_wait_time: Duration::minutes(20),
                power_down_wait: Duration::seconds(10),
                failure_retry_time: Duration::minutes(90),
                dpu_up_threshold: Duration::weeks(1),
                scout_reporting_timeout: Duration::minutes(5),
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
                scout_reporting_timeout: Duration::minutes(5),
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
                        processor_dispatch_interval: std::time::Duration::from_secs(2),
                        processor_log_interval: std::time::Duration::from_secs(60),
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
            r#"{"iteration_time":"30s","max_object_handling_time":"180s","max_concurrency":10,"processor_dispatch_interval":"2s","processor_log_interval":"60s"}"#
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
            processor_dispatch_interval: std::time::Duration::from_secs(2),
            processor_log_interval: std::time::Duration::from_secs(60),
        };
        let config_str = serde_json::to_string(&input).unwrap();
        assert_eq!(
            config_str,
            r#"{"iteration_time":"11s","max_object_handling_time":"22s","max_concurrency":33,"processor_dispatch_interval":"2s","processor_log_interval":"60s"}"#
        );
        let config: StateControllerConfig = serde_json::from_str(&config_str).unwrap();
        assert_eq!(config, input);
    }

    #[test]
    fn test_redact_config() {
        let mut config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{TEST_DATA_DIR}/min_config.toml")))
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
            .merge(Toml::file(format!("{TEST_DATA_DIR}/min_config.toml")))
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
        assert!(config.ib_config.is_none());
        assert!(config.ib_fabrics.is_empty());
        assert!(config.nvue_enabled);
        assert!(config.vpc_peering_policy.is_none());
        assert!(config.site_explorer.enabled);
        assert!(
            config
                .site_explorer
                .create_machines
                .load(AtomicOrdering::Relaxed)
        );
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
        // And make sure lack of [mlx-config-profiles] doesn't blow up
        // for sites not configured with any.
        assert!(config.mlxconfig_profiles.is_none());
    }

    #[test]
    fn deserialize_patched_min_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{TEST_DATA_DIR}/min_config.toml")))
            .merge(Toml::file(format!("{TEST_DATA_DIR}/site_config.toml")))
            .extract()
            .unwrap();
        assert_eq!(config.listen, "[::]:1081".parse().unwrap());
        assert_eq!(config.metrics_endpoint, None);
        assert_eq!(config.database_url, "postgres://a:b@postgresql".to_string());
        assert_eq!(config.max_database_connections, 1333);
        assert_eq!(config.asn, 777);
        assert_eq!(config.dhcp_servers, vec!["99.101.102.103".to_string()]);
        assert!(config.route_servers.is_empty());
        assert!(!config.nvue_enabled);
        assert_eq!(config.vpc_peering_policy, Some(VpcPeeringPolicy::Exclusive));
        assert_eq!(config.vpc_peering_policy_on_existing, None);
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
            config.ib_config,
            Some(IBFabricConfig {
                enabled: true,
                fabric_monitor_run_interval: std::time::Duration::from_secs(102),
                ..serde_json::from_str("{}").unwrap()
            })
        );
        assert_eq!(
            config.site_explorer,
            SiteExplorerConfig {
                enabled: false,
                run_interval: std::time::Duration::from_secs(120),
                concurrent_explorations: 10,
                explorations_per_run: 12,
                create_machines: Arc::new(false.into()),
                machines_created_per_run: 1,
                override_target_ip: None,
                override_target_port: None,
                allow_zero_dpu_hosts: false,
                bmc_proxy: crate::dynamic_settings::bmc_proxy(None),
                allow_changing_bmc_proxy: None,
                reset_rate_limit: Duration::hours(1),
                admin_segment_type_non_dpu: Arc::new(false.into()),
                allocate_secondary_vtep_ip: false,
                create_power_shelves: Arc::new(true.into()),
                explore_power_shelves_from_static_ip: Arc::new(true.into()),
                power_shelves_created_per_run: 1,
                create_switches: Arc::new(true.into()),
                switches_created_per_run: 9,
                rotate_switch_nvos_credentials: Arc::new(false.into()),
                use_onboard_nic: Arc::new(false.into()),
            }
        );
        assert_eq!(
            config.machine_state_controller,
            MachineStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(3 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(11),
                    max_concurrency: 22,
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
                },
                dpu_wait_time: Duration::minutes(7),
                power_down_wait: Duration::seconds(17),
                failure_retry_time: Duration::minutes(70),
                dpu_up_threshold: Duration::minutes(77),
                scout_reporting_timeout: Duration::minutes(5),
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
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
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
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
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
            .merge(Toml::file(format!("{TEST_DATA_DIR}/full_config.toml")))
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
        assert!(config.nvue_enabled);
        assert_eq!(config.vpc_peering_policy, Some(VpcPeeringPolicy::Exclusive));
        assert_eq!(
            config.vpc_peering_policy_on_existing,
            Some(VpcPeeringPolicy::Mixed)
        );
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
            config.ib_config,
            Some(IBFabricConfig {
                enabled: false,
                fabric_monitor_run_interval: std::time::Duration::from_secs(101),
                ..serde_json::from_str("{}").unwrap()
            })
        );
        assert_eq!(
            config.site_explorer,
            SiteExplorerConfig {
                enabled: true,
                run_interval: std::time::Duration::from_secs(100),
                concurrent_explorations: 30,
                explorations_per_run: 11,
                create_machines: Arc::new(true.into()),
                machines_created_per_run: 2,
                override_target_ip: Some("1.2.3.4".to_owned()),
                override_target_port: Some(10443),
                allow_zero_dpu_hosts: false,
                bmc_proxy: crate::dynamic_settings::bmc_proxy(None),
                allow_changing_bmc_proxy: None,
                reset_rate_limit: Duration::hours(2),
                admin_segment_type_non_dpu: Arc::new(false.into()),
                allocate_secondary_vtep_ip: false,
                create_power_shelves: Arc::new(true.into()),
                explore_power_shelves_from_static_ip: Arc::new(true.into()),
                power_shelves_created_per_run: 1,
                create_switches: Arc::new(true.into()),
                switches_created_per_run: 9,
                rotate_switch_nvos_credentials: Arc::new(false.into()),
                use_onboard_nic: Arc::new(false.into()),
            }
        );

        assert_eq!(
            config.machine_state_controller,
            MachineStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(9 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(99),
                    max_concurrency: 999,
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
                },
                dpu_wait_time: Duration::minutes(3),
                power_down_wait: Duration::seconds(13),
                failure_retry_time: Duration::minutes(31),
                dpu_up_threshold: Duration::minutes(33),
                scout_reporting_timeout: Duration::minutes(20),
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
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
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
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
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
        assert_eq!(
            config
                .machine_updater
                .instance_autoreboot_period
                .clone()
                .unwrap()
                .start
                .day(),
            7
        );
        assert_eq!(
            config
                .machine_updater
                .instance_autoreboot_period
                .clone()
                .unwrap()
                .end
                .day(),
            8
        );
        // Do some more in-depth validation of the MlxConfigProfile section, ensuring
        // we're able to deserialize the SerializedProfile into an MlxConfigProfile
        // and validate entries were properly deserialized back to their types + values.
        //
        // First verify that both serialized profiles are detected.
        assert_eq!(config.mlxconfig_profiles.clone().unwrap().len(), 2);
        // And then pluck out one of them and validate everything deserialized
        // as expected. All of this is generally handled by existing unit tests
        // within the mlxconfig_profile tests already, but it doesn't hurt to
        // verify stuff here also.
        let mlxconfig_profile = config
            .mlxconfig_profiles
            .as_ref()
            .unwrap()
            .get("test-profile")
            .unwrap();
        assert_eq!(mlxconfig_profile.name, "test-profile");
        assert_eq!(mlxconfig_profile.registry.name, "mlx_generic");
        assert_eq!(mlxconfig_profile.config_values.len(), 2);
        assert_eq!(
            mlxconfig_profile.get_variable("SRIOV_EN").unwrap().value,
            MlxValueType::Boolean(true)
        );
        assert_eq!(
            mlxconfig_profile.get_variable("NUM_OF_VFS").unwrap().value,
            MlxValueType::Integer(4)
        );
        assert!(mlxconfig_profile.get_variable("NONEXISTENT_GOO").is_none());
    }

    #[test]
    fn deserialize_patched_full_config() {
        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{TEST_DATA_DIR}/full_config.toml")))
            .merge(Toml::file(format!("{TEST_DATA_DIR}/site_config.toml")))
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
            config.ib_config,
            Some(IBFabricConfig {
                enabled: true,
                fabric_monitor_run_interval: std::time::Duration::from_secs(102),
                ..serde_json::from_str("{}").unwrap()
            })
        );
        assert_eq!(
            config.site_explorer,
            SiteExplorerConfig {
                enabled: false,
                run_interval: std::time::Duration::from_secs(100),
                concurrent_explorations: 10,
                explorations_per_run: 12,
                create_machines: Arc::new(false.into()),
                machines_created_per_run: 2,
                override_target_ip: Some("1.2.3.4".to_owned()),
                override_target_port: Some(10443),
                allow_zero_dpu_hosts: false,
                bmc_proxy: crate::dynamic_settings::bmc_proxy(None),
                allow_changing_bmc_proxy: None,
                reset_rate_limit: Duration::hours(2),
                admin_segment_type_non_dpu: Arc::new(false.into()),
                allocate_secondary_vtep_ip: false,
                create_power_shelves: Arc::new(true.into()),
                explore_power_shelves_from_static_ip: Arc::new(true.into()),
                power_shelves_created_per_run: 1,
                create_switches: Arc::new(true.into()),
                switches_created_per_run: 9,
                rotate_switch_nvos_credentials: Arc::new(false.into()),
                use_onboard_nic: Arc::new(false.into()),
            }
        );

        assert_eq!(
            config.machine_state_controller,
            MachineStateControllerConfig {
                controller: StateControllerConfig {
                    iteration_time: std::time::Duration::from_secs(3 * 60),
                    max_object_handling_time: std::time::Duration::from_secs(11),
                    max_concurrency: 22,
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
                },
                dpu_wait_time: Duration::minutes(7),
                power_down_wait: Duration::seconds(17),
                failure_retry_time: Duration::minutes(70),
                dpu_up_threshold: Duration::minutes(77),
                scout_reporting_timeout: Duration::minutes(20),
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
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
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
                    processor_dispatch_interval: std::time::Duration::from_secs(2),
                    processor_log_interval: std::time::Duration::from_secs(60),
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
                .merge(Toml::file(format!("{TEST_DATA_DIR}/full_config.toml")))
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
filenames = ["/opt/carbide/iDRAC-with-Lifecycle-Controller_Firmware_HV310_WN64_7.10.30.00_A00.EXE", "/opt/carbide/iDRAC-with-Lifecycle-Controller_Firmware_HV310_WN64_7.10.30.00_A01.EXE"]
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
            server
                .components
                .get(&FirmwareComponentType::Bmc)
                .unwrap()
                .known_firmware
                .first()
                .unwrap()
                .filenames
                .len(),
            2
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

        println!("{ib_fabric_config:?}");

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
        // An empty config matches the default object
        let deserialized_empty: IBFabricConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(
            IBFabricConfig::default(),
            deserialized_empty,
            "Empty IBFabricConfig does not match default"
        );
        assert!(!deserialized_empty.enabled);

        let value_input = IBFabricConfig {
            enabled: true,
            allow_insecure: false,
            max_partition_per_tenant: 1,
            mtu: IBMtu(2),
            rate_limit: IBRateLimit(10),
            service_level: IBServiceLevel(2),
            fabric_monitor_run_interval: std::time::Duration::from_secs(33),
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
                fabric_monitor_run_interval: std::time::Duration::from_secs(60),
            }
        );

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
            assert_eq!(
                config.fabric_monitor_run_interval,
                IBFabricConfig::default_fabric_monitor_run_interval()
            );
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

    #[test]
    fn test_max_concurrent_updates() -> eyre::Result<()> {
        let test = MaxConcurrentUpdates {
            absolute: Some(10),
            percent: None,
        };
        assert_eq!(test.max_concurrent_updates(1000, 5), Some(10));
        let test = MaxConcurrentUpdates {
            absolute: None,
            percent: Some(10),
        };
        assert_eq!(test.max_concurrent_updates(0, 500), Some(50));
        assert_eq!(test.max_concurrent_updates(7, 500), Some(43));
        assert_eq!(test.max_concurrent_updates(50, 500), Some(0));
        assert_eq!(test.max_concurrent_updates(0, 9), Some(1));

        Ok(())
    }

    #[test]
    fn deserialize_dpa_config() {
        let toml = r#"
enabled=true
mqtt_endpoint = "mqtt.forge"
        "#;

        let dpa_config: DpaConfig = Figment::new().merge(Toml::string(toml)).extract().unwrap();

        assert_eq!(
            dpa_config,
            DpaConfig {
                enabled: true,
                mqtt_endpoint: "mqtt.forge".to_string(),
                mqtt_broker_port: 1884,
                hb_interval: Duration::minutes(2),
                subnet_ip: Ipv4Addr::UNSPECIFIED,
                subnet_mask: 0_i32,
            }
        );
    }

    #[test]
    fn deserialize_serialize_nvlink_config() {
        let value_json = r#"{"enabled": true, "allow_insecure": true, "monitor_run_interval": "33", "nmx_m_operation_timeout": "21", "nmx_m_endpoint": "localhost"}"#;

        let nvlink_config: NvLinkConfig = serde_json::from_str(value_json).unwrap();
        assert_eq!(
            nvlink_config,
            NvLinkConfig {
                enabled: true,
                monitor_run_interval: std::time::Duration::from_secs(33),
                nmx_m_operation_timeout: std::time::Duration::from_secs(21),
                nmx_m_endpoint: "localhost".to_string(),
                allow_insecure: true,
            }
        );
    }

    #[test]
    fn deserialize_dpu_config() {
        let toml = r#"
[dpu_config]
dpu_enable_secure_boot = true
"#;

        let config: CarbideConfig = Figment::new()
            .merge(Toml::file(format!("{TEST_DATA_DIR}/full_config.toml")))
            .merge(Toml::string(toml))
            .extract()
            .unwrap();

        assert!(config.dpu_config.dpu_enable_secure_boot);
        assert!(!config.dpu_config.dpu_models.is_empty());
    }

    #[test]
    fn test_power_manager_default() {
        let toml = r#"
enabled = true
next_try_duration_on_success = "3m"
"#;

        let power_config: PowerManagerOptions =
            Figment::new().merge(Toml::string(toml)).extract().unwrap();

        println!("{power_config:?}");
        assert!(power_config.enabled);
        assert_eq!(
            Duration::minutes(3),
            power_config.next_try_duration_on_success
        );
        assert_eq!(
            Duration::minutes(2),
            power_config.next_try_duration_on_failure
        );
        assert_eq!(
            Duration::minutes(15),
            power_config.wait_duration_until_host_reboot
        );
    }

    #[test]
    fn test_power_manager_default_1() {
        let toml = r#""#;

        let power_config: PowerManagerOptions =
            Figment::new().merge(Toml::string(toml)).extract().unwrap();

        assert!(!power_config.enabled);
        assert_eq!(
            Duration::minutes(5),
            power_config.next_try_duration_on_success
        );
        assert_eq!(
            Duration::minutes(2),
            power_config.next_try_duration_on_failure
        );
        assert_eq!(
            Duration::minutes(15),
            power_config.wait_duration_until_host_reboot
        );
    }
}
