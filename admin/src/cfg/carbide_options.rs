/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use clap::{ArgGroup, Parser, ValueEnum};

#[derive(Parser, Debug)]
#[clap(name = env!("CARGO_BIN_NAME"))]
#[clap(propagate_version = true)]
#[clap(author = "Slack channel #swngc-forge-dev")]
#[clap(version = "0.0.2")]
pub struct CarbideOptions {
    #[clap(short, long, env = "CARBIDE_API_URL")]
    #[clap(
        help = "Default to CARBIDE_API_URL environment variable or $HOME/.config/carbide_api_cli.json file."
    )]
    pub carbide_api: Option<String>,

    #[clap(short, long, value_enum, default_value = "ascii-table")]
    pub format: OutputFormat,

    #[clap(short, long)]
    pub output: Option<String>,

    #[clap(long, env = "FORGE_ROOT_CA_PATH")]
    #[clap(
        help = "Default to FORGE_ROOT_CA_PATH environment variable or $HOME/.config/carbide_api_cli.json file."
    )]
    pub forge_root_ca_path: Option<String>,

    #[clap(short, long, num_args(0..), default_value = "0")]
    pub debug: u8,

    #[clap(subcommand)]
    pub commands: CarbideCommand,
}

#[derive(Parser, Debug)]
pub enum CarbideCommand {
    #[clap(about = "Machine related handling", subcommand)]
    Machine(Machine),
    #[clap(about = "Instance related handling", subcommand)]
    Instance(Instance),
    #[clap(about = "Network Segment related handling", subcommand)]
    NetworkSegment(NetworkSegment),
    #[clap(about = "Domain related handling", subcommand)]
    Domain(Domain),
    #[clap(about = "Managed host related handling", subcommand)]
    ManagedHost(ManagedHost),
    #[clap(about = "Resource pool handling (VPC)", subcommand)]
    ResourcePool(ResourcePool),
}

#[derive(Parser, Debug)]
pub enum Machine {
    #[clap(about = "Display Machine information")]
    Show(ShowMachine),
    #[clap(about = "Print DPU admin SSH username:password")]
    DpuSshCredentials(MachineQuery),
    #[clap(about = "Print network status of all machines")]
    NetworkStatus,
    #[clap(about = "Reboot a machine")]
    Reboot(BMCConfig),
    #[clap(about = "Force delete a machine")]
    ForceDelete(ForceDeleteMachineQuery),
}

#[derive(Parser, Debug)]
pub enum ManagedHost {
    #[clap(about = "Display managed host information")]
    Show(ShowManagedHost),
}

#[derive(Parser, Debug)]
pub struct BMCConfig {
    #[clap(long, help = "Hostname or IP of machine BMC")]
    pub address: String,

    #[clap(long, help = "Port of machine BMC. [443]")]
    pub port: Option<u32>,

    #[clap(long, help = "Username for machine BMC")]
    pub username: Option<String>,

    #[clap(long, help = "Password for machine BMC")]
    pub password: Option<String>,

    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: Option<String>,
}

#[derive(Parser, Debug)]
pub struct MachineQuery {
    #[clap(
        short,
        long,
        require_equals(true),
        help = "ID, IPv4, MAC or hostnmame of the DPU machine to query"
    )]
    pub query: String,
}

#[derive(Parser, Debug, Clone)]
pub struct ForceDeleteMachineQuery {
    #[clap(
        long,
        require_equals(true),
        help = "UUID, IPv4, MAC or hostnmame of the host or DPU machine to delete"
    )]
    pub machine: String,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_machine")
        .required(true)
        .args(&["all", "machine"])))]
pub struct ShowMachine {
    #[clap(short, long, action)]
    pub all: bool,

    #[clap(short, long)]
    pub machine: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_managed_host")
        .required(true)
        .args(&["all", "machine"])))]
pub struct ShowManagedHost {
    #[clap(short, long, action)]
    pub all: bool,

    #[clap(short, long)]
    pub machine: Option<String>,
}

#[derive(Parser, Debug)]
pub enum Instance {
    #[clap(about = "Display Instance information")]
    Show(ShowInstance),
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_instance")
        .required(true)
        .args(&["all", "instance", "machine"])))]
pub struct ShowInstance {
    #[clap(short, long, action)]
    pub all: bool,

    #[clap(short, long)]
    pub instance: Option<String>,

    #[clap(short, long)]
    pub machine: Option<String>,

    #[clap(short, long, action)]
    pub extrainfo: bool,
}

#[derive(Parser, Debug)]
pub enum Domain {
    #[clap(about = "Display Domain information")]
    Show(ShowDomain),
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_domain")
        .required(true)
        .args(&["all", "domain"])))]
pub struct ShowDomain {
    #[clap(short, long, action)]
    pub all: bool,

    #[clap(short, long)]
    pub domain: Option<String>,
}

#[derive(Parser, Debug)]
pub enum NetworkSegment {
    #[clap(about = "Display Network Segment information")]
    Show(ShowNetwork),
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_network")
        .required(true)
        .args(&["all", "network"])))]
pub struct ShowNetwork {
    #[clap(short, long, action)]
    pub all: bool,

    #[clap(short, long)]
    pub network: Option<String>,
}

#[derive(PartialEq, Eq, ValueEnum, Clone, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum OutputFormat {
    Json,
    Csv,
    AsciiTable,
}

impl CarbideOptions {
    pub fn load() -> Self {
        Self::parse()
    }
}

#[derive(Parser, Debug)]
pub enum ResourcePool {
    #[clap(about = "Define a set of resource pools from a yaml file")]
    Define(ResourcePoolDefinition),
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("define")
        .required(true)
        .args(&["filename"])))]
pub struct ResourcePoolDefinition {
    #[clap(short, long, default_value = "dev/resource_pools.toml")]
    pub filename: String,
}
