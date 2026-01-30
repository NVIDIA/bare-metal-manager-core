/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::path::PathBuf;

use clap::{Parser, ValueEnum, ValueHint};
use rpc::admin_cli::OutputFormat;

use crate::cfg::measurement;
use crate::{
    bmc_machine, boot_override, credential, devenv, domain, dpa, dpu, dpu_remediation,
    expected_machines, expected_power_shelf, expected_switch, extension_service, firmware,
    generate_shell_complete, host, ib_partition, instance, instance_type, inventory, ip, jump,
    machine, machine_interfaces, machine_validation, managed_host, mlx, network_devices,
    network_security_group, network_segment, nvl_logical_partition, nvl_partition, os_image, ping,
    power_shelf, rack, redfish, resource_pool, rms, route_server, scout_stream, set, site_explorer,
    sku, ssh, switch, tenant, tenant_keyset, tpm_ca, trim_table, version, vpc, vpc_peering,
    vpc_prefix,
};

#[derive(Parser, Debug)]
#[clap(name = "forge-admin-cli")]
#[clap(author = "Slack channel #swngc-forge-dev")]
pub struct CliOptions {
    #[clap(
        long,
        default_value = "false",
        help = "Print version number of forge-admin-cli and exit. For API server version see 'version' command."
    )]
    pub version: bool,

    #[clap(
        long,
        value_hint = ValueHint::Username,
        value_name = "USERNAME",
        help = "Never should be used against a production site. Use this flag only if you understand the impacts of inconsistencies with cloud db."
    )]
    pub cloud_unsafe_op: Option<String>,

    #[clap(short, long, env = "CARBIDE_API_URL")]
    #[clap(
        help = "Default to CARBIDE_API_URL environment variable or $HOME/.config/carbide_api_cli.json file or https://carbide-api.forge-system.svc.cluster.local:1079."
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

    #[clap(long, env = "CLIENT_CERT_PATH")]
    #[clap(
        help = "Default to CLIENT_CERT_PATH environment variable or $HOME/.config/carbide_api_cli.json file."
    )]
    pub client_cert_path: Option<String>,

    #[clap(long, env = "CLIENT_KEY_PATH")]
    #[clap(
        help = "Default to CLIENT_KEY_PATH environment variable or $HOME/.config/carbide_api_cli.json file."
    )]
    pub client_key_path: Option<String>,

    #[clap(long, env = "RMS_API_URL")]
    #[clap(help = "RMS API URL. Default to RMS_API_URL environment variable.")]
    pub rms_api_url: Option<String>,

    #[clap(long, env = "RMS_ROOT_CA_PATH")]
    #[clap(help = "RMS Root CA path. Default to RMS_ROOT_CA_PATH environment variable.")]
    pub rms_root_ca_path: Option<String>,

    #[clap(long, env = "RMS_CLIENT_CERT_PATH")]
    #[clap(
        help = "RMS client certificate path. Default to RMS_CLIENT_CERT_PATH environment variable."
    )]
    pub rms_client_cert_path: Option<String>,

    #[clap(long, env = "RMS_CLIENT_KEY_PATH")]
    #[clap(help = "RMS client key path. Default to RMS_CLIENT_KEY_PATH environment variable.")]
    pub rms_client_key_path: Option<String>,

    #[clap(short, long, num_args(0..), default_value = "0")]
    pub debug: u8,

    // This is primarily used by measured boot, where basic output contains just
    // what you probably care about, and "extended" output also dumps out all of
    // the internal UUIDs that are used to associate instances. Helpful for filing
    // reports, doing site import/exports, etc.
    #[clap(long, global = true, help = "Extended result output.")]
    pub extended: bool,

    #[clap(subcommand)]
    pub commands: Option<CliCommand>,

    #[clap(short = 'p', long, default_value_t = 100)]
    #[clap(help = "For commands that internally retrieve data with paging, use this page size.")]
    pub internal_page_size: usize,

    #[clap(
        long,
        value_enum,
        global = true,
        help = "Sort output by specified field",
        default_value = "primary-id"
    )]
    pub sort_by: SortField,
}

#[derive(PartialEq, Eq, ValueEnum, Clone, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum SortField {
    #[clap(help = "Sort by the primary id")]
    PrimaryId,
    #[clap(help = "Sort by state")]
    State,
}

#[derive(Parser, Debug)]
pub enum CliCommand {
    #[clap(about = "Print API server version", visible_alias = "v")]
    Version(version::Opts),
    #[clap(about = "Machine related handling", subcommand, visible_alias = "m")]
    Machine(machine::Cmd),
    #[clap(about = "Instance related handling", subcommand, visible_alias = "i")]
    Instance(instance::Cmd),
    #[clap(
        about = "Network Segment related handling",
        subcommand,
        visible_alias = "ns"
    )]
    NetworkSegment(network_segment::Cmd),
    #[clap(about = "Domain related handling", subcommand, visible_alias = "d")]
    Domain(domain::Cmd),
    #[clap(
        about = "Managed host related handling",
        subcommand,
        visible_alias = "mh"
    )]
    ManagedHost(managed_host::Cmd),
    #[clap(
        subcommand,
        about = "Work with measured boot data.",
        visible_alias = "mb"
    )]
    Measurement(measurement::Cmd),
    #[clap(about = "Resource pool handling", subcommand, visible_alias = "rp")]
    ResourcePool(resource_pool::Cmd),
    #[clap(about = "Redfish BMC actions", visible_alias = "rf")]
    Redfish(redfish::RedfishAction),
    #[clap(about = "Network Devices handling", subcommand)]
    NetworkDevice(network_devices::Cmd),
    #[clap(about = "IP address handling", subcommand)]
    Ip(ip::Cmd),
    #[clap(about = "DPU specific handling", subcommand)]
    Dpu(dpu::Cmd),
    #[clap(about = "Host specific handling", subcommand)]
    Host(host::Cmd),
    #[clap(about = "Generate Ansible Inventory")]
    Inventory(inventory::Cmd),
    #[clap(about = "Machine boot override", subcommand)]
    BootOverride(boot_override::Cmd),
    #[clap(
        about = "BMC Machine related handling",
        subcommand,
        visible_alias = "bmc"
    )]
    BmcMachine(bmc_machine::Cmd),
    #[clap(about = "Credential related handling", subcommand, visible_alias = "c")]
    Credential(credential::Cmd),
    #[clap(about = "Route server handling", subcommand)]
    RouteServer(route_server::Cmd),
    #[clap(about = "Site explorer functions", subcommand)]
    SiteExplorer(site_explorer::Cmd),
    #[clap(
        about = "List of all Machine interfaces",
        subcommand,
        visible_alias = "mi"
    )]
    MachineInterfaces(machine_interfaces::Cmd),
    #[clap(
        about = "Generate shell autocomplete. Source the output of this command: `source <(forge-admin-cli generate-shell-complete bash)`"
    )]
    GenerateShellComplete(generate_shell_complete::Cmd),
    #[clap(
        about = "Query the Version gRPC endpoint repeatedly printing how long it took and any failures."
    )]
    Ping(ping::Opts),
    #[clap(about = "Set carbide-api dynamic features", subcommand)]
    Set(set::Cmd),
    #[clap(about = "Expected machine handling", subcommand, visible_alias = "em")]
    ExpectedMachine(expected_machines::Cmd),
    #[clap(
        about = "Expected power shelf handling",
        subcommand,
        visible_alias = "ep"
    )]
    ExpectedPowerShelf(expected_power_shelf::Cmd),
    #[clap(about = "Expected switch handling", subcommand, visible_alias = "ew")]
    ExpectedSwitch(expected_switch::Cmd),
    #[clap(about = "VPC related handling", subcommand)]
    Vpc(vpc::Cmd),
    #[clap(about = "VPC peering handling", subcommand)]
    VpcPeering(vpc_peering::Cmd),
    #[clap(about = "VPC prefix handling", subcommand)]
    VpcPrefix(vpc_prefix::Cmd),
    #[clap(
        about = "InfiniBand Partition related handling",
        subcommand,
        visible_alias = "ibp"
    )]
    IbPartition(ib_partition::Cmd),
    #[clap(
        about = "Tenant KeySet related handling",
        subcommand,
        visible_alias = "tks"
    )]
    TenantKeySet(tenant_keyset::Cmd),

    #[clap(
        about = "Broad search across multiple object types",
        visible_alias = "j"
    )]
    Jump(jump::Cmd),

    #[clap(about = "Machine Validation", subcommand, visible_alias = "mv")]
    MachineValidation(machine_validation::Cmd),

    #[clap(about = "OS catalog management", visible_alias = "os", subcommand)]
    OsImage(os_image::Cmd),

    #[clap(about = "Manage TPM CA certificates", subcommand)]
    TpmCa(tpm_ca::Cmd),

    #[clap(
        about = "Network security group management",
        visible_alias = "nsg",
        subcommand
    )]
    NetworkSecurityGroup(network_security_group::Cmd),

    #[clap(about = "Manage machine SKUs", subcommand)]
    Sku(sku::Cmd),

    #[clap(about = "Dev Env related handling", subcommand)]
    DevEnv(devenv::Cmd),

    #[clap(about = "Instance type management", visible_alias = "it", subcommand)]
    InstanceType(instance_type::Cmd),

    #[clap(about = "SSH Util functions", subcommand)]
    Ssh(ssh::Cmd),

    #[clap(about = "Power Shelf management", subcommand, visible_alias = "ps")]
    PowerShelf(power_shelf::Cmd),

    #[clap(about = "Switch management", subcommand, visible_alias = "sw")]
    Switch(switch::Cmd),

    #[clap(about = "Rack Management", subcommand)]
    Rack(rack::Cmd),

    #[clap(
        about = "Rack Firmware configuration management",
        subcommand,
        visible_alias = "rack-fw"
    )]
    RackFirmware(RackFirmwareActions),

    #[clap(about = "Rms Actions", subcommand)]
    Rms(rms::Cmd),

    #[clap(about = "Firmware related actions", subcommand)]
    Firmware(firmware::Cmd),

    #[clap(about = "DPA related handling", subcommand)]
    Dpa(dpa::Cmd),
    #[clap(about = "Trim DB tables", subcommand)]
    TrimTable(trim_table::Cmd),
    #[clap(about = "Dpu Remediation handling", subcommand)]
    DpuRemediation(dpu_remediation::Cmd),
    #[clap(
        about = "Extension service management",
        visible_alias = "es",
        subcommand
    )]
    ExtensionService(extension_service::Cmd),
    #[clap(about = "Mellanox Device Handling", subcommand)]
    Mlx(mlx::MlxAction),
    #[clap(about = "Scout Stream Connection Handling", subcommand)]
    ScoutStream(scout_stream::ScoutStreamAction),
    #[clap(
        about = "NvLink Partition related handling",
        subcommand,
        visible_alias = "nvp"
    )]
    NvlPartition(nvl_partition::Cmd),

    #[clap(
        about = "Logical partition related handling",
        subcommand,
        visible_alias = "lp"
    )]
    LogicalPartition(nvl_logical_partition::Cmd),

    #[clap(subcommand)]
    #[clap(verbatim_doc_comment)]
    /// DPF-related commands.
    /// Note: These commands update the DPF state of the machine, which determines DPF-based DPU re-provisioning.
    /// The state is saved in the machine's metadata and will be deleted if the machine is force-deleted.
    /// To make the state persistent, add the DPF state for a machine (host) to the expected machines table.
    Dpf(crate::dpf::args::Cmd),

    #[clap(about = "Tenant management", subcommand, visible_alias = "tm")]
    Tenant(tenant::Cmd),
}

impl CliOptions {
    pub fn load() -> Self {
        Self::parse()
    }
}

// Rack Firmware Management

#[derive(Parser, Debug)]
pub enum RackFirmwareActions {
    #[clap(about = "Create a new Rack firmware configuration from JSON file")]
    Create(RackFirmwareCreate),

    #[clap(about = "Get a Rack firmware configuration by ID")]
    Get(RackFirmwareGet),

    #[clap(about = "List all Rack firmware configurations")]
    List(RackFirmwareList),

    #[clap(about = "Delete a Rack firmware configuration")]
    Delete(RackFirmwareDelete),

    #[clap(about = "Apply firmware to all devices in a rack")]
    Apply(RackFirmwareApply),
}

#[derive(Parser, Debug)]
pub struct RackFirmwareCreate {
    #[clap(help = "Path to JSON configuration file")]
    pub json_file: PathBuf,
    #[clap(help = "Artifactory token for downloading firmware files")]
    pub artifactory_token: String,
}

#[derive(Parser, Debug)]
pub struct RackFirmwareGet {
    #[clap(help = "ID of the configuration to retrieve")]
    pub id: String,
}

#[derive(Parser, Debug)]
pub struct RackFirmwareList {
    #[clap(long, help = "Show only available configurations")]
    pub only_available: bool,
}

#[derive(Parser, Debug)]
pub struct RackFirmwareDelete {
    #[clap(help = "ID of the configuration to delete")]
    pub id: String,
}

#[derive(Parser, Debug)]
pub struct RackFirmwareApply {
    #[clap(help = "Rack ID to apply firmware to")]
    pub rack_id: String,

    #[clap(help = "Firmware configuration ID to apply")]
    pub firmware_id: String,

    #[clap(help = "Firmware type: dev or prod", value_parser = ["dev", "prod"])]
    pub firmware_type: String,
}
