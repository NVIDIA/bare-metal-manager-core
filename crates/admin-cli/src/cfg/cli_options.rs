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
use std::net::SocketAddr;

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use clap::builder::BoolishValueParser;
use clap::{Parser, ValueEnum, ValueHint};
use mac_address::MacAddress;
use rpc::admin_cli::OutputFormat;
use rpc::forge::RouteServerSourceType;

use crate::cfg::measurement;
use crate::cfg::storage::OsImageActions;
use crate::machine::MachineQuery;
use crate::{
    domain, dpa, dpu, dpu_remediation, expected_machines, expected_power_shelf, expected_switch,
    extension_service, firmware, ib_partition, instance, instance_type, machine,
    machine_interfaces, machine_validation, managed_host, mlx, network_devices,
    network_security_group, network_segment, nvl_logical_partition, nvl_partition, ping,
    power_shelf, rack, redfish, resource_pool, scout_stream, site_explorer, sku, switch, tenant,
    tenant_keyset, tpm_ca, version, vpc, vpc_peering, vpc_prefix,
};

const DEFAULT_IB_FABRIC_NAME: &str = "default";

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
    Ip(IpAction),
    #[clap(about = "DPU specific handling", subcommand)]
    Dpu(dpu::Cmd),
    #[clap(about = "Host specific handling", subcommand)]
    Host(HostAction),
    #[clap(about = "Generate Ansible Inventory")]
    Inventory(InventoryAction),
    #[clap(about = "Machine boot override", subcommand)]
    BootOverride(BootOverrideAction),
    #[clap(
        about = "BMC Machine related handling",
        subcommand,
        visible_alias = "bmc"
    )]
    BmcMachine(BmcAction),
    #[clap(about = "Credential related handling", subcommand, visible_alias = "c")]
    Credential(CredentialAction),
    #[clap(about = "Route server handling", subcommand)]
    RouteServer(RouteServer),
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
    GenerateShellComplete(ShellCompleteAction),
    #[clap(
        about = "Query the Version gRPC endpoint repeatedly printing how long it took and any failures."
    )]
    Ping(ping::Opts),
    #[clap(about = "Set carbide-api dynamic features", subcommand)]
    Set(SetAction),
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
    Jump(JumpOptions),

    #[clap(about = "Machine Validation", subcommand, visible_alias = "mv")]
    MachineValidation(machine_validation::Cmd),

    #[clap(about = "OS catalog management", visible_alias = "os", subcommand)]
    OsImage(OsImageActions),

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
    DevEnv(DevEnv),

    #[clap(about = "Instance type management", visible_alias = "it", subcommand)]
    InstanceType(instance_type::Cmd),

    #[clap(about = "SSH Util functions", subcommand)]
    Ssh(SshActions),

    #[clap(about = "Power Shelf management", subcommand, visible_alias = "ps")]
    PowerShelf(power_shelf::Cmd),

    #[clap(about = "Switch management", subcommand, visible_alias = "sw")]
    Switch(switch::Cmd),

    #[clap(about = "Rack Management", subcommand)]
    Rack(rack::Cmd),

    #[clap(about = "Rms Actions", subcommand)]
    Rms(RmsActions),

    #[clap(about = "Firmware related actions", subcommand)]
    Firmware(firmware::Cmd),

    #[clap(about = "DPA related handling", subcommand)]
    Dpa(dpa::Cmd),
    #[clap(about = "Trim DB tables", subcommand)]
    TrimTable(TrimTableTarget),
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

    #[clap(about = "Tenant management", subcommand, visible_alias = "tm")]
    Tenant(tenant::Cmd),
}

#[derive(Parser, Debug)]
pub enum SetAction {
    #[clap(about = "Set RUST_LOG")]
    LogFilter(LogFilterOptions),
    #[clap(about = "Set create_machines")]
    CreateMachines(CreateMachinesOptions),
    #[clap(about = "Set bmc_proxy")]
    BmcProxy(BmcProxyOptions),
    #[clap(
        about = "Configure whether trace/span information is sent to an OTLP endpoint like Tempo"
    )]
    TracingEnabled {
        #[arg(num_args = 1, value_parser = BoolishValueParser::new(), action = clap::ArgAction::Set, value_name = "true|false")]
        value: bool,
    },
}

#[derive(Parser, Debug)]
pub struct InventoryAction {
    #[clap(short, long, help = "Write to file")]
    pub filename: Option<String>,
}

#[derive(Parser, Debug)]
pub enum HostAction {
    #[clap(about = "Set Host UEFI password")]
    SetUefiPassword(MachineQuery),
    #[clap(about = "Clear Host UEFI password")]
    ClearUefiPassword(MachineQuery),
    #[clap(about = "Generates a string that can be a site-default host UEFI password in Vault")]
    /// - the generated string will meet the uefi password requirements of all vendors
    GenerateHostUefiPassword,
    #[clap(subcommand, about = "Host reprovisioning handling")]
    Reprovision(HostReprovision),
}

#[derive(Parser, Debug)]
pub enum HostReprovision {
    #[clap(about = "Set the host in reprovisioning mode.")]
    Set(HostReprovisionSet),
    #[clap(about = "Clear the reprovisioning mode.")]
    Clear(HostReprovisionClear),
    #[clap(about = "List all hosts pending reprovisioning.")]
    List,
}

#[derive(Parser, Debug)]
pub struct HostReprovisionSet {
    #[clap(short, long, help = "Machine ID for which reprovisioning is needed.")]
    pub id: MachineId,

    #[clap(short, long, action)]
    pub update_firmware: bool,

    #[clap(
        long,
        alias = "maintenance_reference",
        help = "If set, a HostUpdateInProgress health alert will be applied to the host"
    )]
    pub update_message: Option<String>,
}

#[derive(Parser, Debug)]
pub struct HostReprovisionClear {
    #[clap(
        short,
        long,
        help = "Machine ID for which reprovisioning should be cleared."
    )]
    pub id: MachineId,

    #[clap(short, long, action)]
    pub update_firmware: bool,
}

#[derive(Parser, Debug)]
pub enum BootOverrideAction {
    Get(BootOverride),
    Set(BootOverrideSet),
    Clear(BootOverride),
}

#[derive(Parser, Debug)]
pub struct BootOverride {
    pub interface_id: MachineInterfaceId,
}

#[derive(Parser, Debug)]
pub struct BootOverrideSet {
    pub interface_id: MachineInterfaceId,
    #[clap(short = 'p', long)]
    pub custom_pxe: Option<String>,
    #[clap(short = 'u', long)]
    pub custom_user_data: Option<String>,
}

#[derive(Parser, Debug)]
pub enum IpAction {
    Find(IpFind),
}

#[derive(Parser, Debug)]
pub struct IpFind {
    /// The IP address we are looking to identify
    pub ip: std::net::Ipv4Addr,
}

#[derive(Parser, Debug)]
pub struct BMCIdentify {
    #[clap(long, help = "Hostname or IP of machine BMC")]
    pub address: String,
}

#[derive(Parser, Debug)]
pub struct BmcResetArgs {
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
    #[clap(short, long, help = "Use ipmitool")]
    pub use_ipmitool: bool,
}

#[derive(Parser, Debug)]
pub struct AdminPowerControlArgs {
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
    #[clap(long, help = "Power control action")]
    pub action: AdminPowerControlAction,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum AdminPowerControlAction {
    On,
    GracefulShutdown,
    ForceOff,
    GracefulRestart,
    ForceRestart,
    ACPowercycle,
}

#[derive(Parser, Debug)]
pub struct InfiniteBootArgs {
    #[clap(long, help = "ID of the machine to enable/query infinite boot")]
    pub machine: String,
    #[clap(short, long, help = "Issue reboot to apply BIOS change")]
    pub reboot: bool,
}

#[derive(Parser, Debug)]
pub struct LockdownArgs {
    #[clap(long, help = "ID of the machine to enable/disable lockdown")]
    pub machine: MachineId,
    #[clap(short, long, help = "Issue reboot to apply lockdown change")]
    pub reboot: bool,
    #[clap(
        long,
        conflicts_with = "disable",
        required_unless_present = "disable",
        help = "Enable lockdown"
    )]
    pub enable: bool,
    #[clap(
        long,
        conflicts_with = "enable",
        required_unless_present = "enable",
        help = "Disable lockdown"
    )]
    pub disable: bool,
}

#[derive(Parser, Debug)]
pub struct LockdownStatusArgs {
    #[clap(long, help = "ID of the machine to check lockdown status")]
    pub machine: MachineId,
}

impl From<AdminPowerControlAction> for rpc::forge::admin_power_control_request::SystemPowerControl {
    fn from(c_type: AdminPowerControlAction) -> Self {
        match c_type {
            AdminPowerControlAction::On => {
                rpc::forge::admin_power_control_request::SystemPowerControl::On
            }
            AdminPowerControlAction::GracefulShutdown => {
                rpc::forge::admin_power_control_request::SystemPowerControl::GracefulShutdown
            }
            AdminPowerControlAction::ForceOff => {
                rpc::forge::admin_power_control_request::SystemPowerControl::ForceOff
            }
            AdminPowerControlAction::GracefulRestart => {
                rpc::forge::admin_power_control_request::SystemPowerControl::GracefulRestart
            }
            AdminPowerControlAction::ForceRestart => {
                rpc::forge::admin_power_control_request::SystemPowerControl::ForceRestart
            }
            AdminPowerControlAction::ACPowercycle => {
                rpc::forge::admin_power_control_request::SystemPowerControl::AcPowercycle
            }
        }
    }
}

impl CliOptions {
    pub fn load() -> Self {
        Self::parse()
    }
}

#[derive(Parser, Debug)]
pub enum BmcAction {
    #[clap(about = "Reset BMC")]
    BmcReset(BmcResetArgs),
    #[clap(about = "Redfish Power Control")]
    AdminPowerControl(AdminPowerControlArgs),
    CreateBmcUser(CreateBmcUserArgs),
    DeleteBmcUser(DeleteBmcUserArgs),
    #[clap(about = "Enable infinite boot")]
    EnableInfiniteBoot(InfiniteBootArgs),
    #[clap(about = "Check if infinite boot is enabled")]
    IsInfiniteBootEnabled(InfiniteBootArgs),
    #[clap(about = "Enable or disable lockdown")]
    Lockdown(LockdownArgs),
    #[clap(about = "Check lockdown status")]
    LockdownStatus(LockdownStatusArgs),
}

#[derive(Parser, Debug)]
pub enum CredentialAction {
    #[clap(about = "Add UFM credential")]
    AddUFM(AddUFMCredential),
    #[clap(about = "Delete UFM credential")]
    DeleteUFM(DeleteUFMCredential),
    #[clap(about = "Generate UFM credential")]
    GenerateUFMCert(GenerateUFMCertCredential),
    #[clap(about = "Add BMC credentials")]
    AddBMC(AddBMCredential),
    #[clap(about = "Delete BMC credentials")]
    DeleteBMC(DeleteBMCredential),
    #[clap(
        about = "Add site-wide DPU UEFI default credential (NOTE: this parameter can be set only once)"
    )]
    AddUefi(AddUefiCredential),
    #[clap(about = "Add manufacturer factory default BMC user/pass for a given vendor")]
    AddHostFactoryDefault(AddHostFactoryDefaultCredential),
    #[clap(about = "Add manufacturer factory default BMC user/pass for the DPUs")]
    AddDpuFactoryDefault(AddDpuFactoryDefaultCredential),
    #[clap(about = "Add NmxM credentials")]
    AddNmxM(AddNmxMCredential),
    #[clap(about = "Delete NmxM credentials")]
    DeleteNmxM(DeleteNmxMCredential),
}

#[derive(Parser, Debug)]
pub struct AddUFMCredential {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,

    #[clap(long, default_value(""), help = "The UFM token")]
    pub token: String,
}

#[derive(Parser, Debug)]
pub struct DeleteUFMCredential {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,
}

#[derive(Parser, Debug)]
pub struct GenerateUFMCertCredential {
    #[clap(long, default_value_t = DEFAULT_IB_FABRIC_NAME.to_string(), help = "Infiniband fabric.")]
    pub fabric: String,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum BmcCredentialType {
    // Site Wide BMC Root Account Credentials
    SiteWideRoot,
    // BMC Specific Root Credentials
    BmcRoot,
    // BMC Specific Forge-Admin Credentials
    BmcForgeAdmin,
}

impl From<BmcCredentialType> for rpc::forge::CredentialType {
    fn from(c_type: BmcCredentialType) -> Self {
        use rpc::forge::CredentialType::*;
        match c_type {
            BmcCredentialType::SiteWideRoot => SiteWideBmcRoot,
            BmcCredentialType::BmcRoot => RootBmcByMacAddress,
            BmcCredentialType::BmcForgeAdmin => BmcForgeAdminByMacAddress,
        }
    }
}

#[derive(Parser, Debug)]
pub struct AddBMCredential {
    #[clap(
        long,
        require_equals(true),
        required(true),
        help = "The BMC Credential kind"
    )]
    pub kind: BmcCredentialType,
    #[clap(long, required(true), help = "The password of BMC")]
    pub password: String,
    #[clap(long, help = "The username of BMC")]
    pub username: Option<String>,
    #[clap(long, help = "The MAC address of the BMC")]
    pub mac_address: Option<MacAddress>,
}

#[derive(Parser, Debug)]
pub struct DeleteBMCredential {
    #[clap(
        long,
        require_equals(true),
        required(true),
        help = "The BMC Credential kind"
    )]
    pub kind: BmcCredentialType,
    #[clap(long, help = "The MAC address of the BMC")]
    pub mac_address: Option<MacAddress>,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum UefiCredentialType {
    Dpu,
    Host,
}

impl From<UefiCredentialType> for rpc::forge::CredentialType {
    fn from(c_type: UefiCredentialType) -> Self {
        use rpc::forge::CredentialType::*;
        match c_type {
            UefiCredentialType::Dpu => DpuUefi,
            UefiCredentialType::Host => HostUefi,
        }
    }
}

#[derive(Parser, Debug)]
pub struct AddUefiCredential {
    #[clap(long, require_equals(true), required(true), help = "The UEFI kind")]
    pub kind: UefiCredentialType,

    #[clap(long, require_equals(true), help = "The UEFI password")]
    pub password: String,
}

#[derive(Parser, Debug)]
pub struct AddHostFactoryDefaultCredential {
    #[clap(long, required(true), help = "Default username: root, ADMIN, etc")]
    pub username: String,
    #[clap(long, required(true), help = "Manufacturer default password")]
    pub password: String,
    #[clap(long, required(true))]
    pub vendor: bmc_vendor::BMCVendor,
}

#[derive(Parser, Debug)]
pub struct AddDpuFactoryDefaultCredential {
    #[clap(long, required(true), help = "Default username: root, ADMIN, etc")]
    pub username: String,
    #[clap(long, required(true), help = "DPU manufacturer default password")]
    pub password: String,
}

#[derive(Parser, Debug)]
pub struct AddNmxMCredential {
    #[clap(long, required(true), help = "Username")]
    pub username: String,
    #[clap(long, required(true), help = "password")]
    pub password: String,
}

#[derive(Parser, Debug)]
pub struct DeleteNmxMCredential {
    #[clap(long, required(true), help = "NmxM url")]
    pub username: String,
}

#[derive(Parser, Debug)]
pub enum RouteServer {
    Get,
    Add(RouteServerAddresses),
    Remove(RouteServerAddresses),
    Replace(RouteServerAddresses),
}

// RouteServerAddresses is used for add/remove/replace
// operations for route server addresses, with support
// for overriding the source_type to not be admin_api,
// and make ephemeral changes against whatever was
// loaded up via the config file at start.
#[derive(Parser, Debug)]
pub struct RouteServerAddresses {
    #[arg(value_delimiter = ',', help = "Comma-separated list of IPv4 addresses")]
    pub ip: Vec<std::net::Ipv4Addr>,
    // The optional source_type to set. If unset, this
    // defaults to admin_api, which is what we'd expect.
    // Override with --source_type=config to make
    // ephemeral changes to config file-based entries,
    // which is really intended for break-glass types
    // of scenarios.
    #[arg(
        long,
        default_value = "admin_api",
        help = "The source_type to use for the target addresses. Defaults to admin_api."
    )]
    pub source_type: RouteServerSourceType,
}

#[derive(Parser, Debug)]
pub struct CreateBmcUserArgs {
    #[clap(long, short, help = "IP of the BMC where we want to create a new user")]
    pub ip_address: Option<String>,
    #[clap(long, help = "MAC of the BMC where we want to create a new user")]
    pub mac_address: Option<MacAddress>,
    #[clap(
        long,
        short,
        help = "ID of the machine where we want to create a new user"
    )]
    pub machine: Option<String>,

    #[clap(long, short, help = "Username of new BMC account")]
    pub username: String,
    #[clap(long, short, help = "Password of new BMC account")]
    pub password: String,
    #[clap(
        long,
        short,
        help = "Role of new BMC account ('administrator', 'operator', 'readonly', 'noaccess')"
    )]
    pub role_id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DeleteBmcUserArgs {
    #[clap(long, short, help = "IP of the BMC where we want to delete a user")]
    pub ip_address: Option<String>,
    #[clap(long, help = "MAC of the BMC where we want to delete a user")]
    pub mac_address: Option<MacAddress>,
    #[clap(long, short, help = "ID of the machine where we want to delete a user")]
    pub machine: Option<String>,

    #[clap(long, short, help = "Username of BMC account to delete")]
    pub username: String,
}

#[derive(Parser, Debug)]
pub struct ShellCompleteAction {
    #[clap(subcommand)]
    pub shell: Shell,
}

#[derive(Parser, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum Shell {
    Bash,
    Fish,
    Zsh,
}

#[derive(Parser, Debug)]
pub struct LogFilterOptions {
    #[clap(short, long, help = "Set server's RUST_LOG.")]
    pub filter: String,
    #[clap(
        long,
        default_value("1h"),
        help = "Revert to startup RUST_LOG after this much time, friendly format e.g. '1h', '3min', https://docs.rs/duration-str/latest/duration_str/"
    )]
    pub expiry: String,
}

#[derive(Parser, Debug)]
pub struct CreateMachinesOptions {
    #[clap(long, action = clap::ArgAction::Set, help = "Enable site-explorer create_machines?")]
    pub enabled: bool,
}

#[derive(Parser, Debug)]
pub struct BmcProxyOptions {
    #[clap(long, action = clap::ArgAction::Set, help = "Enable site-explorer bmc_proxy")]
    pub enabled: bool,
    #[clap(long, action = clap::ArgAction::Set, help = "host:port string use as a proxy for talking to BMC's")]
    pub proxy: Option<String>,
}

#[derive(Parser, Debug)]
pub struct JumpOptions {
    #[clap(required(true), help = "The machine ID, IP, UUID, etc, to find")]
    pub id: String,
}

#[derive(Parser, Debug)]
pub enum DevEnv {
    #[clap(about = "Config related handling", visible_alias = "c", subcommand)]
    Config(DevEnvConfig),
}

#[derive(Parser, Debug)]
pub enum DevEnvConfig {
    #[clap(about = "Apply devenv config", visible_alias = "a")]
    Apply(DevEnvApplyConfig),
}

#[derive(Parser, Debug)]
pub struct DevEnvApplyConfig {
    #[clap(
        help = "Path to devenv config file. Usually this is in forged repo at envs/local-dev/site/site-controller/files/generated/devenv_config.toml"
    )]
    pub path: String,

    #[clap(long, short, help = "Vpc prefix or network segment?")]
    pub mode: NetworkChoice,
}

#[derive(ValueEnum, Parser, Debug, Clone, PartialEq)]
pub enum NetworkChoice {
    NetworkSegment,
    VpcPrefix,
}

#[derive(Parser, Debug)]
pub enum SshActions {
    #[clap(about = "Show Rshim Status")]
    GetRshimStatus(SshArgs),
    #[clap(about = "Disable Rshim")]
    DisableRshim(SshArgs),
    #[clap(about = "EnableRshim")]
    EnableRshim(SshArgs),
    #[clap(about = "Copy BFB to the DPU BMC's RSHIM ")]
    CopyBfb(CopyBfbArgs),
    #[clap(about = "Show the DPU's BMC's OBMC log")]
    ShowObmcLog(SshArgs),
}

#[derive(Parser, Debug)]
pub enum TrimTableTarget {
    MeasuredBoot(KeepEntries),
}

#[derive(Parser, Debug, Clone)]
pub struct KeepEntries {
    #[clap(help = "Number of entries to keep")]
    #[arg(long)]
    pub keep_entries: u32,
}

#[derive(Parser, Debug, Clone)]
pub struct BmcCredentials {
    #[clap(help = "BMC IP Address")]
    pub bmc_ip_address: SocketAddr,
    #[clap(help = "BMC Username")]
    pub bmc_username: String,
    #[clap(help = "BMC Password")]
    pub bmc_password: String,
}

#[derive(Parser, Debug, Clone)]
pub struct SshArgs {
    #[clap(flatten)]
    pub credentials: BmcCredentials,
}

#[derive(Parser, Debug)]
pub struct CopyBfbArgs {
    #[clap(flatten)]
    pub ssh_args: SshArgs,
    #[clap(help = "BFB Path")]
    pub bfb_path: String,
}

#[derive(Parser, Debug)]
pub enum RmsActions {
    #[clap(about = "Get Full Rms Inventory")]
    Inventory,
    #[clap(about = "Remove a node from Rms")]
    RemoveNode(RemoveNode),
    #[clap(about = "Get Poweron Order")]
    PoweronOrder,
    #[clap(about = "Get Power State for a given node")]
    PowerState(PowerState),
    #[clap(about = "Get Firmware Inventory for a given node")]
    FirmwareInventory(FirmwareInventory),
    #[clap(about = "Get Available Firmware Images for a given node")]
    AvailableFwImages(AvailableFwImages),
    #[clap(about = "Get BKC Files")]
    BkcFiles,
    #[clap(about = "Check BKC Compliance")]
    CheckBkcCompliance,
}

#[derive(Parser, Debug)]
pub struct RemoveNode {
    #[clap(help = "Node ID to remove")]
    pub node_id: String,
}

#[derive(Parser, Debug)]
pub struct PowerState {
    #[clap(help = "Node ID to get power state for")]
    pub node_id: String,
}

#[derive(Parser, Debug)]
pub struct FirmwareInventory {
    #[clap(help = "Node ID to get firmware inventory for")]
    pub node_id: String,
}

#[derive(Parser, Debug)]
pub struct AvailableFwImages {
    #[clap(help = "Node ID to get available firmware images for")]
    pub node_id: String,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::expected_machines::Cmd::Patch;
    use crate::expected_machines::args::{ExpectedMachine, PatchExpectedMachine};

    #[test]
    fn forge_admin_cli_expected_machine_test() {
        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
            ])
            .is_ok()
        );

        // No dpu serial
        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
            ])
            .is_ok_and(|t1| { !t1.has_duplicate_dpu_serials() })
        );

        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
                "--fallback-dpu-serial-number",
                "dpu_serial",
            ])
            .is_ok()
        );

        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
                "--fallback-dpu-serial-number",
                "dpu_serial",
                "-d",
                "dpu_serial2",
            ])
            .is_ok()
        );

        // Duplicate dpu_serial
        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
                "-d",
                "dpu_serial1",
                "-d",
                "dpu_serial2",
                "-d",
                "dpu_serial3",
                "-d",
                "dpu_serial1"
            ])
            .is_ok_and(|t| { t.has_duplicate_dpu_serials() })
        );

        // option --fallback-dpu-serial-number used w/o value
        assert!(
            ExpectedMachine::try_parse_from([
                "ExpectedMachine",
                "--bmc-mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--bmc-username",
                "me",
                "--bmc-password",
                "my-pw",
                "--chassis-serial-number",
                "<CHASSIS_SERIAL_NUMBER>",
                "--fallback-dpu-serial-number"
            ])
            .is_err()
        );

        fn test_patch_expected_machine<F: Fn(PatchExpectedMachine) -> bool>(
            options: CliOptions,
            pred: F,
        ) -> bool {
            let mut patch_args = None;
            if let Some(CliCommand::ExpectedMachine(Patch(args))) = options.commands {
                patch_args = Some(args);
            }
            patch_args.is_some() && pred(patch_args.unwrap())
        }
        // Test patch command: 1 dpu serial
        assert!(test_patch_expected_machine(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER>",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));
        // Test patch command: 2 dpu serials
        assert!(test_patch_expected_machine(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER_1>",
                "-d",
                "<DPU_SERIAL_NUMBER_2>",
            ])
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
            ])
            .is_err()
        );

        // Fail if duplicate dpu serials are given
        // duplicate dpu serials -
        assert!(test_patch_expected_machine(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "dpu1",
                "-d",
                "dpu2",
                "-d",
                "dpu3",
                "-d",
                "dpu2",
                "-d",
                "dpu4",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_err() }
        ));

        // Test patch command: update credential
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "<BMC_USERNAME>",
                "--bmc-password",
                "<BMC_PASSWORD>",
            ])
            .is_ok()
        );
        // Test patch command: update all fields
        assert!(test_patch_expected_machine(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "ssss",
                "--bmc-password",
                "ssss",
                "--chassis-serial-number",
                "sss",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER>",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));
        // Test patch command: username only - should error (requires password)
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "ssss",
            ])
            .is_err()
        );
        // Test patch command: password only - should error (requires username)
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "patch",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-password",
                "ssss",
            ])
            .is_err()
        );

        // Test update command (full replacement from JSON file)
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--filename",
                "/path/to/machine.json",
            ])
            .is_ok()
        );

        // Test update command with short flag
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "-f",
                "/path/to/machine.json",
            ])
            .is_ok()
        );

        // Test update command without filename - should fail
        assert!(
            CliOptions::try_parse_from(["forge-admin-cli", "expected-machine", "update",]).is_err()
        );

        // Test update command with CLI args (not JSON) - should fail
        // update only accepts --filename, not individual fields
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--sku-id",
                "sku123",
            ])
            .is_err()
        );
    }

    #[test]
    fn forge_admin_cli_credential_test() {
        //  bmc-root credential w.o optional username
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "credential",
                "add-bmc",
                "--kind=bmc-root",
                "--mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--password",
                "my-pw",
            ])
            .is_ok()
        );

        //  bmc-root credential with optional username
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "credential",
                "add-bmc",
                "--kind=bmc-root",
                "--mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--password",
                "my-pw",
                "--username",
                "me"
            ])
            .is_ok()
        );
    }

    #[test]
    fn forge_admin_cli_tpm_ca_test() {
        assert!(CliOptions::try_parse_from(["forge-admin-cli", "tpm-ca", "show"]).is_ok());

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "tpm-ca",
                "add",
                "--filename",
                "/tmp/somefile.cer"
            ])
            .is_ok()
        );

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "tpm-ca",
                "add-bulk",
                "--dirname",
                "/tmp"
            ])
            .is_ok()
        );

        assert!(
            CliOptions::try_parse_from(["forge-admin-cli", "tpm-ca", "delete", "--ca-id", "4"])
                .is_ok()
        );
    }
}
