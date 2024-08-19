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

    #[clap(about = "One-off network monitor")]
    Network(NetworkOptions),

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

    #[clap(long, help = "What version of hbn in format: 1.5.0-doca2.2.0")]
    pub hbn_version: Option<String>,
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
    #[clap(long, help = "Blank for admin network, vxlan48 for tenant networks")]
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
    #[clap(
        long,
        default_value = "false",
        help = "Do not perform upgrade checks. This is for development only. Do not use in production."
    )]
    pub skip_upgrade_check: bool,
}

#[derive(Parser, Debug)]
pub struct NetworkOptions {
    #[clap(
        long,
        help = "Use this network_pinger_type for the interface used for pinging."
    )]
    pub network_pinger_type: Option<NetworkPingerType>,
}

// TODO(chet): VpcVirtualizationType (from the api crate) and
// NetworkVirtualizationType (from the bluefield crate)
// should be merged together. I think the reason for having
// two separate ones is so the bluefield crate doesn't pull
// in the api crate, so we could just have a common location
// for this to be. Of course, VpcVirtualizationType returns
// a CarbideError, that would mean the common/network crate
// would need to pull in the api crate (to get at CarbideError),
// so we'd need to change the type error it returns too.
#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum NetworkVirtualizationType {
    Etv,        // clap default is kebab-case, so this is "etv"
    EtvNvue,    // and this is "etv-nvue"
    FnnClassic, // and this is "fnn-classic"
    FnnL3,      // and this is "fnn-l3"
}

impl NetworkVirtualizationType {
    pub fn prefix_length(&self) -> u8 {
        match self {
            Self::Etv => 32,
            Self::EtvNvue => 32,
            Self::FnnClassic => 32,
            Self::FnnL3 => 30,
        }
    }
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
            rpc::forge::VpcVirtualizationType::FnnClassic => Self::FnnClassic,
            rpc::forge::VpcVirtualizationType::FnnL3 => Self::FnnL3,
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
            NetworkVirtualizationType::FnnClassic => rpc::forge::VpcVirtualizationType::FnnClassic,
            NetworkVirtualizationType::FnnL3 => rpc::forge::VpcVirtualizationType::FnnL3,
        }
    }
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
