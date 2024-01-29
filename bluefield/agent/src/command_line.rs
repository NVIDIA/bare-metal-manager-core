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
use std::{fmt, net::Ipv4Addr, path::PathBuf};

use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[clap(name = "forge-dpu-agent")]
pub struct Options {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    /// The path to the forge agent configuration file
    /// This file will hold data in the `AgentConfig` format
    #[clap(long, default_value = "/etc/forge/config.toml")]
    pub config_path: PathBuf,

    #[clap(subcommand)]
    pub cmd: Option<AgentCommand>,
}

#[derive(Parser, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AgentCommand {
    #[clap(
        about = "Run is the normal command. Runs main loop forever, configures networking, etc."
    )]
    Run(RunOptions),

    #[clap(about = "Detect hardware and exit")]
    Hardware,

    #[clap(about = "One-off health check")]
    Health,

    #[clap(
        about = "One-off fetch network configuration from API, write relevant files, and report back observation"
    )]
    Netconf(NetconfParams),

    #[clap(about = "Write a templated config file", subcommand)]
    Write(WriteTarget),
}

#[derive(Parser, Debug)]
pub struct NetconfParams {
    #[clap(long, short, help = "machine id of the DPU to configure")]
    pub dpu_machine_id: String,
    #[clap(
        long,
        default_value = "11:22:33:44:55:66",
        help = "Factory MAC address - pf interface"
    )]
    pub mac_address: String,
    #[clap(
        long,
        help = "Use this network_virtualization_type for both service network and all instances."
    )]
    pub override_network_virtualization_type: Option<NetworkVirtualizationType>,
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
    Nvue(NvueOptions),
}

#[derive(Parser, Debug)]
pub struct NvueOptions {
    #[clap(long, help = "Full path of NVUE's startup.yaml")]
    pub path: String,

    #[clap(long, help = "Forge Native Networking mode")]
    pub is_fnn: bool,

    #[clap(long)]
    pub loopback_ip: Ipv4Addr,

    #[clap(long)]
    pub asn: u32,

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

    #[clap(long, help = "Compute Tenant name")]
    pub ct_name: String,

    #[clap(long)]
    pub ct_l3vni: String,

    #[clap(long)]
    pub ct_vrf_loopback: String,

    #[clap(long, help = "Format is JSON see Network in nvue.rs. Repeats.")]
    pub ct_port_config: Vec<String>,

    #[clap(long, use_value_delimiter = true, help = "Comma separated")]
    pub ct_external_access: Vec<String>,
}

#[derive(Parser, Debug)]
pub struct FrrOptions {
    #[clap(long, help = "Full path of frr.conf")]
    pub path: String,
    #[clap(long)]
    pub asn: u32,
    #[clap(long)]
    pub loopback_ip: Ipv4Addr,
    #[clap(long, help = "Format is 'id,host_route', e.g. --vlan 1,xyz. Repeats.")]
    pub vlan: Vec<String>,
    #[clap(long, default_value = "etv")]
    pub network_virtualization_type: NetworkVirtualizationType,
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
    pub loopback_ip: Ipv4Addr,
    #[clap(long, help = "Blank for admin network, vxlan5555 for tenant networks")]
    pub vni_device: String,
    #[clap(
        long,
        help = "Format is JSON see PortConfig in interfaces.rs. Repeats."
    )]
    pub network: Vec<String>,
    #[clap(long, default_value = "etv")]
    pub network_virtualization_type: NetworkVirtualizationType,
}

#[derive(Parser, Debug)]
pub struct DhcpOptions {
    #[clap(long, help = "Full path of dhcp relay config file")]
    pub path: String,
    #[clap(long, help = "vlan numeric id. Repeats")]
    pub vlan: Vec<u32>,
    #[clap(long, help = "DHCP server IP address. Repeats")]
    pub dhcp: Vec<Ipv4Addr>,
    #[clap(long, help = "Remote ID to be filled in Option 82 - Agent Remote ID")]
    pub remote_id: String,
    #[clap(long, default_value = "etv")]
    pub network_virtualization_type: NetworkVirtualizationType,
}

#[derive(Parser, Debug)]
pub struct RunOptions {
    #[clap(long, help = "Enable metadata service")]
    pub enable_metadata_service: bool,
    #[clap(
        long,
        help = "Use this machine id instead of building it from hardware enumeration. Development/testing only"
    )]
    pub override_machine_id: Option<String>,
    #[clap(
        long,
        help = "Use this network_virtualization_type for both service network and all instances."
    )]
    pub override_network_virtualization_type: Option<NetworkVirtualizationType>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum NetworkVirtualizationType {
    Etv,
    EtvNvue, // clap default is kebab-case, so this is "etv-nvue"
}

impl fmt::Display for NetworkVirtualizationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // enums are a special case where their debug impl is their name
        fmt::Debug::fmt(self, f)
    }
}

impl From<rpc::forge::VpcVirtualizationType> for NetworkVirtualizationType {
    fn from(v: rpc::forge::VpcVirtualizationType) -> Self {
        match v {
            rpc::forge::VpcVirtualizationType::EthernetVirtualizer => Self::Etv,
            rpc::forge::VpcVirtualizationType::EthernetVirtualizerWithNvue => Self::EtvNvue,
        }
    }
}

impl From<NetworkVirtualizationType> for rpc::forge::VpcVirtualizationType {
    fn from(nvt: NetworkVirtualizationType) -> Self {
        match nvt {
            NetworkVirtualizationType::Etv => {
                rpc::forge::VpcVirtualizationType::EthernetVirtualizer
            }
            NetworkVirtualizationType::EtvNvue => {
                rpc::forge::VpcVirtualizationType::EthernetVirtualizerWithNvue
            }
        }
    }
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
