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
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;

use carbide_network::virtualization::VpcVirtualizationType;
use carbide_uuid::machine::MachineId;
use clap::Parser;

use crate::network_monitor::NetworkPingerType;

#[derive(Parser)]
#[clap(name = "forge-dpu-agent")]
pub struct Options {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    /// The path to the forge agent configuration file development overrides.
    /// This file will hold data in the `AgentConfig` format.
    #[clap(long)]
    pub config_path: Option<PathBuf>,

    #[clap(subcommand)]
    pub cmd: Option<AgentCommand>,
}

#[derive(Parser, Debug)]
pub enum AgentCommand {
    #[clap(
        about = "Run is the normal command. Runs main loop forever, configures networking, etc."
    )]
    Run(Box<RunOptions>),

    #[clap(about = "Detect hardware and exit")]
    Hardware(HardwareOptions),

    #[clap(about = "One-off health check")]
    Health,

    #[clap(about = "One-off network monitor")]
    Network(NetworkOptions),

    #[clap(about = "Do a duppet run for duppet-managed files")]
    Duppet(DuppetOptions),

    #[clap(about = "Write a templated config file", subcommand)]
    Write(WriteTarget),
}

#[derive(Parser, Debug)]
pub enum WriteTarget {
    #[clap(about = "Write frr.conf")]
    Frr(FrrOptions),
    #[clap(about = "Write /etc/network/interfaces")]
    Interfaces(InterfacesOptions),
    #[clap(about = "Write /etc/supervisor/conf.d/default-isc-dhcp-relay.conf")]
    Dhcp(DhcpOptions),
    #[clap(about = "Write NVUE startup.yaml")]
    Nvue(Box<NvueOptions>),
}

#[derive(Parser, Debug)]
pub struct NvueOptions {
    #[clap(long, help = "Full path of NVUE's startup.yaml")]
    pub path: String,

    #[clap(long, help = "Forge Native Networking mode")]
    pub is_fnn: bool,

    #[clap(
        long,
        help = "A single VNI to use for all VPCs.  This is a special case to handle environments where upstream switches are unable to handle traffic for route import for multiple VNIs.  Route targets will still be derived from the dynamically allocated VNI of the VPC."
    )]
    pub site_global_vpc_vni: Option<u32>,

    #[clap(long)]
    pub loopback_ip: IpAddr,

    #[clap(long)]
    pub asn: u32,

    #[clap(long)]
    pub datacenter_asn: u32,

    #[clap(long)]
    pub common_internal_route_target: Option<String>,

    #[clap(
        long,
        help = "Full JSON representation of a RouteConfig (see nvue.rs) to be used as additional route targets to import in FNN. Repeats with multiple --additional_fnn_route_target_import."
    )]
    pub additional_fnn_route_target_import: Vec<String>,

    #[clap(long)]
    pub dpu_hostname: String,

    #[clap(long, use_value_delimiter = true, help = "Comma separated")]
    pub uplinks: Vec<String>,

    #[clap(long, use_value_delimiter = true, help = "Comma separated")]
    pub route_servers: Vec<String>,

    #[clap(long, use_value_delimiter = true, help = "Comma separated")]
    pub dhcp_servers: Vec<String>,

    #[clap(
        long,
        help = "Format is l3vni,vrf_loopback,services_svi, e.g. --l3_domain 4096,10.0.0.1,svi . Repeats."
    )]
    pub l3_domain: Vec<String>,

    #[clap(long, help = "Format is 'id,host_route', e.g. --vlan 1,xyz. Repeats.")]
    pub vlan: Vec<String>,

    #[clap(long, help = "Compute Tenant [VRF] name")]
    pub ct_vrf_name: String,

    #[clap(long, help = "The VPC-specific L3VNI.")]
    pub ct_l3vni: Option<u32>,

    #[clap(long)]
    pub ct_vrf_loopback: String,

    #[clap(
        long,
        help = "Full JSON representation of a PortConfig (see nvue.rs). Repeats with multiple --ct-port-config."
    )]
    pub ct_port_config: Vec<String>,

    #[clap(long, use_value_delimiter = true, help = "Comma separated")]
    pub ct_external_access: Vec<String>,

    #[clap(long, help = "What version of hbn in format: 1.5.0-doca2.2.0")]
    pub hbn_version: Option<String>,

    #[clap(
        long,
        help = "Site-wide GNI-supplied VNI to use for VPCs to access the Internet."
    )]
    pub ct_internet_l3_vni: Option<u32>,

    #[clap(
        long,
        help = "The VpcVirtualizationType to use for this config + template (etv, etv_nvue, fnn_classic, fnn_l3)"
    )]
    pub virtualization_type: VpcVirtualizationType,

    #[clap(
        long,
        help = "Whether stateful ACLs are allowed and the DPU should adjust config to handle them.",
        default_value_t = false
    )]
    pub stateful_acls_enabled: bool,

    #[clap(
        long,
        help = "IP to be used for a local VTEP when configuring an additional overlay network"
    )]
    pub secondary_overlay_vtep_ip: Option<String>,

    #[clap(
        long,
        help = "Prefix to be used for configuring a set of internal bridges to be used with advanced routing for traffic interception.  Prefix length is expected to be /29 or smaller (i.e., 8 or more IP addresses)."
    )]
    pub internal_bridge_routing_prefix: Option<String>,

    #[clap(
        long,
        help = "The name of a patch-port to be used with advanced routing for traffic interception that connects the HBN pod to an intermediate bridge between VFs and HBN."
    )]
    pub vf_intercept_bridge_port_name: Option<String>,

    #[clap(
        long,
        help = "The name of patch-port to be used with advanced routing for traffic interception that connects the HBN pod to an intermediate bridge between the host PF and HBN."
    )]
    pub host_intercept_bridge_port_name: Option<String>,

    #[clap(
        long,
        help = "The SF used for routing intercepted VF traffic to the HBN pod."
    )]
    pub vf_intercept_bridge_sf: Option<String>,

    #[clap(
        long,
        help = "Full JSON representation of a NetworkSecurityGroupRule (see nvue.rs) that will be evaluated before any tenant-defined rules. Repeats with multiple --network_security_policy_override_rule."
    )]
    pub network_security_policy_override_rule: Vec<String>,

    #[clap(
        long,
        help = "Full JSON representation of a NetworkSecurityGroup (see nvue.rs). Repeats with multiple --network_security_group"
    )]
    pub network_security_group: Vec<String>,

    #[clap(
        long,
        help = "Full JSON representation of a RoutingProfile (see nvue.rs)."
    )]
    pub ct_routing_profile: Option<String>,

    #[clap(
        long,
        help = "BGP password to use with session between the DPU and the TOR"
    )]
    pub bgp_leaf_session_password: Option<String>,
}

#[derive(Parser, Debug)]
pub struct FrrOptions {
    #[clap(long, help = "Full path of frr.conf")]
    pub path: String,
    #[clap(long)]
    pub asn: u32,
    #[clap(long)]
    pub loopback_ip: IpAddr,
    #[clap(long, help = "Format is 'id,host_route', e.g. --vlan 1,xyz. Repeats.")]
    pub vlan: Vec<String>,
    #[clap(long, default_value = "etv")]
    pub network_virtualization_type: VpcVirtualizationType,
    #[clap(long, default_value = "0")]
    pub vpc_vni: u32,
    #[clap(long, use_value_delimiter = true)]
    pub route_servers: Vec<String>,
    #[clap(
        long,
        help = "Use admin interface, which removes tenant BGP config (Feature: Bring Your Own IP) from frr.conf"
    )]
    pub admin: bool,
}

#[derive(Parser, Debug)]
pub struct InterfacesOptions {
    #[clap(long, help = "Full path of interfaces file")]
    pub path: String,
    #[clap(long)]
    pub loopback_ip: IpAddr,
    #[clap(long, help = "Blank for admin network, vxlan48 for tenant networks")]
    pub vni_device: String,
    #[clap(
        long,
        help = "Format is JSON see PortConfig in interfaces.rs. Repeats."
    )]
    pub network: Vec<String>,
    #[clap(long, default_value = "etv")]
    pub network_virtualization_type: VpcVirtualizationType,
}

#[derive(Parser, Debug)]
pub struct DhcpOptions {
    #[clap(long, help = "Full path of dhcp relay config file")]
    pub path: String,
    #[clap(long, help = "vlan numeric id. Repeats")]
    pub vlan: Vec<u32>,
    // Note that these will be staying IPv4 only for now. This
    // config block is pretty tailored towards DHCPv4, and may
    // get refactored a bit as part of adding DHCPv6 support.
    #[clap(long, help = "DHCP server IP address. Repeats")]
    pub dhcp: Vec<Ipv4Addr>,
    #[clap(long, help = "Remote ID to be filled in Option 82 - Agent Remote ID")]
    pub remote_id: String,
    #[clap(long, default_value = "etv")]
    pub network_virtualization_type: VpcVirtualizationType,
}

#[derive(Parser, Debug)]
pub struct RunOptions {
    #[clap(long, help = "Enable metadata service")]
    pub enable_metadata_service: bool,
    #[clap(
        long,
        help = "Use this machine id instead of building it from hardware enumeration. Development/testing only"
    )]
    pub override_machine_id: Option<MachineId>,
    #[clap(
        long,
        help = "Use this network_virtualization_type for both service network and all instances."
    )]
    pub override_network_virtualization_type: Option<VpcVirtualizationType>,
    #[clap(
        long,
        default_value = "false",
        help = "Do not perform upgrade checks. This is for development only. Do not use in production."
    )]
    pub skip_upgrade_check: bool,
    #[clap(
        long,
        help = "gRPC address of the DHCP server control service (e.g. http://localhost:50051). \
                When set, the agent sends config updates via gRPC instead of writing files directly."
    )]
    pub dhcp_grpc_server: Option<String>,
    #[clap(
        long,
        help = "gRPC address of the external FMDS service (e.g. http://localhost:50052). \
                When set, the agent sends config updates via gRPC instead of running embedded FMDS."
    )]
    pub fmds_grpc_server: Option<String>,
    #[clap(
        default_value = "container-exec",
        help = "Set the configuration mode for HBN. Specify \"container-exec\" or \"nvue-rest\".",
        env = "HBN_CONFIG_MODE"
    )]
    pub hbn_config_mode: HbnConfigMode,
    #[clap(
        long,
        default_value = "dpu-os",
        help = "Set the platform type. Specify \"dpu-os\" or \"containerized\".",
        env = "AGENT_PLATFORM_TYPE"
    )]
    pub agent_platform_type: AgentPlatformType,
    #[clap(
        help = "Load discovery info from the specified file, rather than trying to probe hardware ourselves. This should be a JSON-serialized DiscoveryInfo message.",
        env = "DISCOVERY_INFO_FILE"
    )]
    pub discovery_info_file: Option<PathBuf>,

    #[clap(
        long,
        help = "Prepend this string to interface names before sending them to the DHCP server",
        env = "DHCP_SERVER_INTERFACE_PREPEND"
    )]
    pub dhcp_server_interface_prepend: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub enum HbnConfigMode {
    // ContainerExec: The old default, where we use crictl to exec into the HBN container.
    ContainerExec,
    // NvueRest: We use the NVUE REST API to manage HBN configuration.
    NvueRest,
}

impl HbnConfigMode {
    pub fn is_container_exec(&self) -> bool {
        matches!(self, Self::ContainerExec)
    }
}

impl FromStr for HbnConfigMode {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use HbnConfigMode::*;
        match s {
            "container-exec" => Ok(ContainerExec),
            "nvue-rest" => Ok(NvueRest),
            unknown_mode => Err(eyre::eyre!("Unknown HBN config mode \"{unknown_mode}\"")),
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub enum AgentPlatformType {
    // DpuOs: The old default, where we're running inside the main DPU OS and
    // are free to poke any files and containers directly through whatever
    // method we feel like.
    DpuOs,
    // Containerized: Something suitable for DPF, where the agent is running
    // inside a container with no direct access to the OS resources or any of
    // the other containers.
    Containerized,
    // init - init-container. This mode is used to fetch hardware info as json and feed to
    // containerized mode.
    ContainerInitializer,
    // should "fake DPU" be modeled as a variant here?
}

impl AgentPlatformType {
    pub fn is_dpu_os(&self) -> bool {
        matches!(self, AgentPlatformType::DpuOs)
    }
}

impl FromStr for AgentPlatformType {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use AgentPlatformType::*;
        match s {
            "dpu-os" => Ok(DpuOs),
            "containerized" => Ok(Containerized),
            "init" => Ok(ContainerInitializer),
            unknown_type => Err(eyre::eyre!("Unknown platform type \"{unknown_type}\"")),
        }
    }
}

#[derive(Parser, Debug)]
pub struct HardwareOptions {
    #[clap(
        long,
        help = "Write the hardware output (a JSON-serialized rpc::DiscoveryInfo message) to the specified file"
    )]
    pub output_file: Option<PathBuf>,
    #[clap(
        long,
        default_value = "dpu-os",
        help = "Set the platform type. Specify \"dpu-os\", \"containerized\", or \"init\".",
        env = "AGENT_PLATFORM_TYPE"
    )]
    pub agent_platform_type: AgentPlatformType,
}

#[derive(Parser, Debug)]
pub struct NetworkOptions {
    #[clap(
        long,
        help = "Use this network_pinger_type for the interface used for pinging."
    )]
    pub network_pinger_type: Option<NetworkPingerType>,
}

#[derive(Parser, Debug)]
pub struct DuppetOptions {
    #[arg(
        long,
        help = "Do everything, including logging, but don't actually create/update files or permissions."
    )]
    pub dry_run: bool,

    #[arg(
        long,
        help = "Don't log anything, but still dump out a report summary at the end."
    )]
    pub quiet: bool,

    #[arg(
        long = "no-color",
        help = "Don't show pretty colors with log messages, if that's how you feel."
    )]
    pub no_color: bool,

    /// Output format for the final summary: plaintext, json, or yaml
    #[arg(long, default_value = "plaintext", value_parser = ["plaintext", "json", "yaml"], help="The format to use for the report summary at the end of the run.")]
    pub summary_format: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_type_parses_all_valid_values() {
        assert!(matches!(
            "dpu-os".parse::<AgentPlatformType>().unwrap(),
            AgentPlatformType::DpuOs
        ));
        assert!(matches!(
            "containerized".parse::<AgentPlatformType>().unwrap(),
            AgentPlatformType::Containerized
        ));
        assert!(matches!(
            "init".parse::<AgentPlatformType>().unwrap(),
            AgentPlatformType::ContainerInitializer
        ));
    }

    #[test]
    fn test_platform_type_rejects_unknown_value() {
        let err = "banana".parse::<AgentPlatformType>().unwrap_err();
        assert!(err.to_string().contains("banana"));
    }

    #[test]
    fn test_is_dpu_os_only_true_for_dpu_os() {
        assert!(AgentPlatformType::DpuOs.is_dpu_os());
        assert!(!AgentPlatformType::Containerized.is_dpu_os());
        assert!(!AgentPlatformType::ContainerInitializer.is_dpu_os());
    }
}
