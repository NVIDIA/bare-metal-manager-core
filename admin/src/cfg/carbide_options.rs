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
use std::fmt;
use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::cfg::measurement;

#[derive(Parser, Debug)]
#[clap(name = "forge-admin-cli")]
#[clap(author = "Slack channel #swngc-forge-dev")]
pub struct CarbideOptions {
    #[clap(
        long,
        default_value = "false",
        help = "Print version number of forge-admin-cli and exit. For API server version see 'version' command."
    )]
    pub version: bool,

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
    pub commands: Option<CarbideCommand>,
}

#[derive(Parser, Debug)]
pub enum CarbideCommand {
    #[clap(about = "Print API server version", visible_alias = "v")]
    Version(Version),
    #[clap(about = "Machine related handling", subcommand, visible_alias = "m")]
    Machine(Machine),
    #[clap(about = "Instance related handling", subcommand, visible_alias = "i")]
    Instance(Instance),
    #[clap(
        about = "Network Segment related handling",
        subcommand,
        visible_alias = "ns"
    )]
    NetworkSegment(NetworkSegment),
    #[clap(about = "Domain related handling", subcommand, visible_alias = "d")]
    Domain(Domain),
    #[clap(
        about = "Managed host related handling",
        subcommand,
        visible_alias = "mh"
    )]
    ManagedHost(ManagedHost),
    #[clap(
        subcommand,
        about = "Work with measured boot data.",
        visible_alias = "mb"
    )]
    Measurement(measurement::Cmd),
    #[clap(about = "Resource pool handling", subcommand, visible_alias = "rp")]
    ResourcePool(ResourcePool),
    #[clap(about = "Redfish BMC actions", visible_alias = "rf")]
    Redfish(RedfishAction),
    #[clap(about = "Migrate data, see sub-command", subcommand)]
    Migrate(MigrateAction),
    #[clap(about = "Network Devices handling", subcommand)]
    NetworkDevice(NetworkDeviceAction),
    #[clap(about = "IP address handling", subcommand)]
    Ip(IpAction),
    #[clap(about = "DPU specific handling", subcommand)]
    Dpu(DpuAction),
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
    BmcMachine(BmcMachine),
    #[clap(about = "Credential related handling", subcommand, visible_alias = "c")]
    Credential(CredentialAction),
    #[clap(about = "Route server handling", subcommand)]
    RouteServer(RouteServer),
    #[clap(about = "Site explorer functions", subcommand)]
    SiteExplorer(SiteExplorer),
    #[clap(
        about = "List of all Machine interfaces",
        subcommand,
        visible_alias = "mi"
    )]
    MachineInterfaces(MachineInterfaces),
    #[clap(
        about = "Generate shell autocomplete. Source the output of this command: `source <(forge-admin-cli generate-shell-complete bash)`"
    )]
    GenerateShellComplete(ShellCompleteAction),
    #[clap(
        about = "Query the Version gRPC endpoint repeatedly printing how long it took and any failures."
    )]
    Ping(PingOptions),
    #[clap(about = "Set RUST_LOG")]
    SetLogFilter(LogFilterOptions),
}

#[derive(Parser, Debug)]
pub struct Version {
    #[clap(short, long, action, help = "Display Runtime Config also.")]
    pub show_runtime_config: bool,
}

#[derive(Parser, Debug)]
pub struct InventoryAction {
    #[clap(short, long, help = "Write to file")]
    pub filename: Option<String>,
}

#[derive(Parser, Debug)]
pub enum DpuAction {
    #[clap(subcommand, about = "DPU Reprovisioning handling")]
    Reprovision(DpuReprovision),
    #[clap(about = "DPU Reset handling")]
    Reset(DpuReset),
    #[clap(about = "Get or set forge-dpu-agent upgrade policy")]
    AgentUpgradePolicy(AgentUpgrade),
    #[clap(about = "View DPU firmware status")]
    Versions(DpuVersionOptions),
    #[clap(about = "View DPU Status")]
    Status,
}

#[derive(Parser, Debug)]
pub struct DpuReset {
    #[clap(help = "DPU Machine ID for which reset is needed.")]
    pub id: String,
}

#[derive(Parser, Debug)]
pub enum DpuReprovision {
    #[clap(about = "Set the DPU in reprovisioning mode.")]
    Set(DpuReprovisionData),
    #[clap(about = "Clear the reprovisioning mode.")]
    Clear(DpuReprovisionData),
    #[clap(about = "List all DPUs pending reprovisioning.")]
    List,
    #[clap(about = "Restart the DPU reprovision.")]
    Restart(DpuReprovisionData),
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionData {
    #[clap(
        short,
        long,
        help = "DPU Machine ID for which reprovisioning is needed."
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub update_firmware: bool,
}

#[derive(Parser, Debug)]
pub struct DpuVersionOptions {
    #[clap(short, long, help = "Only show DPUs that need upgrades")]
    pub updates_only: bool,
}

#[derive(Parser, Debug)]
pub enum HostAction {
    #[clap(about = "Set Host UEFI password")]
    SetUefiPassword(MachineQuery),
}

#[derive(Parser, Debug)]
pub struct AgentUpgrade {
    #[clap(long)]
    pub set: Option<AgentUpgradePolicyChoice>,
}

// Should match api/src/model/machine/upgrade_policy.rs AgentUpgradePolicy
#[derive(ValueEnum, Debug, Clone)]
pub enum AgentUpgradePolicyChoice {
    Off,
    UpOnly,
    UpDown,
}

impl fmt::Display for AgentUpgradePolicyChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // enums are a special case where their debug impl is their name ("Off")
        fmt::Debug::fmt(self, f)
    }
}

// From the RPC
impl From<i32> for AgentUpgradePolicyChoice {
    fn from(rpc_policy: i32) -> Self {
        use rpc::forge::AgentUpgradePolicy::*;
        match rpc_policy {
            n if n == Off as i32 => AgentUpgradePolicyChoice::Off,
            n if n == UpOnly as i32 => AgentUpgradePolicyChoice::UpOnly,
            n if n == UpDown as i32 => AgentUpgradePolicyChoice::UpDown,
            _ => {
                unreachable!();
            }
        }
    }
}

#[derive(Parser, Debug)]
pub enum BootOverrideAction {
    Get(BootOverride),
    Set(BootOverrideSet),
    Clear(BootOverride),
}

#[derive(Parser, Debug)]
pub struct BootOverride {
    pub interface_id: String,
}

#[derive(Parser, Debug)]
pub struct BootOverrideSet {
    pub interface_id: String,
    #[clap(short = 'p', long)]
    pub custom_pxe: Option<String>,
    #[clap(short = 'u', long)]
    pub custom_user_data: Option<String>,
}

#[derive(Parser, Debug)]
pub enum NetworkDeviceAction {
    Show(NetworkDeviceShow),
}

#[derive(Parser, Debug)]
pub struct NetworkDeviceShow {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "id",
        help = "Show all network devices (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "Show data for the given network device (e.g. `mac=<mac>`), leave empty for all (default)"
    )]
    pub id: String,
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
pub struct RedfishAction {
    #[clap(subcommand)]
    pub command: RedfishCommand,

    #[clap(
        long,
        global = true,
        help = "IP:port of machine BMC. Port is optional and defaults to 443"
    )]
    pub address: Option<String>,

    #[clap(long, global = true, help = "Username for machine BMC")]
    pub username: Option<String>,

    #[clap(long, global = true, help = "Password for machine BMC")]
    pub password: Option<String>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum RedfishCommand {
    /// List BIOS attributes
    BiosAttrs,
    /// Set hard drive first in boot order
    BootHdd,
    /// Set PXE first in boot order
    BootPxe,
    /// On next boot only, boot from hard drive
    BootOnceHdd,
    /// On next boot only, boot from PXE
    BootOncePxe,
    /// Delete all pending jobs
    ClearPending,
    /// Create new BMC user
    CreateBmcUser(BmcUser),
    /// Setup host for Forge use
    ForgeSetup,
    /// Is everything ForgeSetup does already done? What's missing?
    ForgeSetupStatus,
    /// Set our password policy
    SetForgePasswordPolicy,
    /// List one or all BIOS boot options
    GetBootOption(BootOptionSelector),
    /// Is this thing on?
    GetPowerState,
    /// Disable BMC/BIOS lockdown
    LockdownDisable,
    /// Enable BMC/BIOS lockdown
    LockdownEnable,
    /// Display status of BMC/BIOS lockdown
    LockdownStatus,
    /// Force turn machine off
    #[clap(alias = "off", verbatim_doc_comment)]
    ForceOff,
    /// Force restart. This is equivalent to pressing the reset button on the front panel.
    /// - Will not restart DPUs
    /// - Will apply pending BIOS/UEFI setting changes
    #[clap(alias = "reset", verbatim_doc_comment)]
    ForceRestart,
    /// Graceful restart. Asks the OS to restart via ACPI
    /// - Might restart DPUs if no OS is running
    /// - Will not apply pending BIOS/UEFI setting changes
    #[clap(alias = "restart", verbatim_doc_comment)]
    GracefulRestart,
    /// Graceful host shutdown
    #[clap(alias = "shutdown", verbatim_doc_comment)]
    GracefulShutdown,
    /// Power on a machine
    On,
    /// List PCIe devices
    PcieDevices,
    /// List pending operations
    Pending,
    /// Display power metrics (voltages, power supplies, etc)
    PowerMetrics,
    /// Enable serial console
    SerialEnable,
    /// Serial console status
    SerialStatus,
    /// Display thermal metrics (fans and temperatures)
    ThermalMetrics,
    /// Clear Trusted Platform Module (TPM)
    TpmReset,
    /// Reboot the BMC itself
    BmcReset,
    /// Get Secure boot status
    GetSecureBoot,
    /// Disable Secure Boot
    DisableSecureBoot,
    /// List Chassis
    GetChassisAll,
    /// Show BMC's Ethernet interface information
    GetBmcEthernetInterfaces,
    /// Show System Ethernet interface information
    GetSystemEthernetInterfaces,
    /// List of existing BMC accounts
    GetBmcAccounts,
    /// Rename an account
    ChangeBmcUsername(BmcUsername),
    /// Change password for a BMC user
    ChangeBmcPassword(BmcPassword),
    /// Change UEFI password
    ChangeUefiPassword(UefiPassword),
    #[clap(about = "DPU specific operations", subcommand)]
    Dpu(DpuOperations),
    /// Generates a string that can be a site-default host UEFI password in Vault
    /// - the generated string will meet the uefi password requirements of all vendors
    GenerateHostUefiPassword,
    GetManager,
    /// Update host firmware
    UpdateFirmwareMultipart(Multipart),
    // Get detailed info on a Redfish task
    GetTask(Task),
    // Get a list of Redfish tasks
    GetTasks,
}

#[derive(Parser, Debug, PartialEq, Clone)]
#[clap(group(ArgGroup::new("selector").required(true).args(&["all", "id"])))]
pub struct BootOptionSelector {
    #[clap(long)]
    pub all: bool,
    #[clap(long)]
    pub id: Option<String>,
}

#[derive(clap::Parser, Debug, PartialEq, Clone)]
pub enum DpuOperations {
    /// BMC's FW Commands
    #[clap(visible_alias = "fw", about = "BMC's FW Commands", subcommand)]
    Firmware(FwCommand),
    /// Show ports information
    Ports(ShowPort),
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub enum FwCommand {
    /// Print FW update status
    Status,
    /// Update BMC's FW to the given FW package
    Update(FwPackage),
    /// Show FW versions of different components
    Show(ShowFw),
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct FwPackage {
    #[clap(short, long, help = "FW package to install")]
    pub package: PathBuf,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct UefiPassword {
    #[clap(long, help = "Current UEFI password")]
    pub current_password: String,
    #[clap(long, help = "New UEFI password")]
    pub new_password: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct BmcUsername {
    #[clap(long, help = "Old username")]
    pub old_user: String,
    #[clap(long, help = "New username")]
    pub new_user: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct BmcPassword {
    #[clap(long, help = "New BMC password")]
    pub new_password: String,
    #[clap(long, help = "BMC user")]
    pub user: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Multipart {
    #[clap(long, help = "Local filename for the firmware to be installed")]
    pub filename: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Task {
    #[clap(long, help = "Task ID")]
    pub taskid: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct BmcUser {
    #[clap(long, help = "BMC password")]
    pub new_password: String,
    #[clap(long, help = "BMC user")]
    pub user: String,
    #[clap(
        long,
        help = "BMC role (administrator, operator, readonly, noaccess). Default to administrator"
    )]
    pub role_id: Option<String>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
#[clap(group(
        ArgGroup::new("show_fw")
        .required(true)
        .args(&["all", "bmc", "dpu_os", "uefi", "fw"])))]
pub struct ShowFw {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "fw",
        help = "Show all discovered firmware key/values"
    )]
    pub all: bool,

    #[clap(long, action, conflicts_with = "fw", help = "Show BMC FW Version")]
    pub bmc: bool,

    #[clap(
        long,
        action,
        conflicts_with = "fw",
        help = "Show DPU OS version (shortcut for `show DPU_OS`)"
    )]
    pub dpu_os: bool,

    #[clap(
        long,
        action,
        conflicts_with = "fw",
        help = "Show UEFI version (shortcut for `show DPU_UEFI`)"
    )]
    pub uefi: bool,

    #[clap(
        default_value(""),
        help = "The firmware type to query (e.g. DPU_OS, DPU_UEFI, DPU_NIC), leave empty for all (default)"
    )]
    pub fw: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct ShowPort {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "port",
        help = "Show all ports (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "The port to query (e.g. eth0, eth1), leave empty for all (default)"
    )]
    pub port: String,
}

#[derive(Parser, Debug)]
pub enum MigrateAction {
    #[clap(about = "Assign a VNI to every VPC. Prepare for Forge Native Networking.")]
    VpcVni,
}

#[derive(Parser, Debug)]
pub enum Machine {
    #[clap(about = "Display Machine information")]
    Show(ShowMachine),
    #[clap(about = "Print DPU admin SSH username:password")]
    DpuSshCredentials(MachineQuery),
    #[clap(subcommand, about = "Networking information")]
    Network(NetworkCommand),
    #[clap(about = "Reboot a machine")]
    Reboot(BMCConfigForReboot),
    #[clap(about = "Force delete a machine")]
    ForceDelete(ForceDeleteMachineQuery),
}

#[derive(Parser, Debug)]
pub enum NetworkCommand {
    #[clap(about = "Print network status of all machines")]
    Status,
    #[clap(about = "Machine network configuration, used by VPC.")]
    Config(NetworkConfigQuery),
}

#[derive(Parser, Debug)]
pub enum ManagedHost {
    #[clap(about = "Display managed host information")]
    Show(ShowManagedHost),
    #[clap(
        about = "Switch a machine in/out of maintenance mode",
        subcommand,
        visible_alias = "fix"
    )]
    Maintenance(MaintenanceAction),
}

#[derive(Parser, Debug)]
pub struct BMCConfigForReboot {
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
pub struct BMCIdentify {
    #[clap(long, help = "Hostname or IP of machine BMC")]
    pub address: String,
}

pub type BMCConfigForReset = BMCConfigForReboot;

#[derive(Parser, Debug)]
pub struct MachineQuery {
    #[clap(
        short,
        long,
        help = "ID, IPv4, MAC or hostnmame of the machine to query"
    )]
    pub query: String,
}

#[derive(Parser, Debug, Clone)]
pub struct ForceDeleteMachineQuery {
    #[clap(
        long,
        help = "UUID, IPv4, MAC or hostnmame of the host or DPU machine to delete"
    )]
    pub machine: String,

    #[clap(
        short = 'd',
        long,
        action,
        help = "Delete interfaces. Redeploy kea after deleting machine interfaces."
    )]
    pub delete_interfaces: bool,

    #[clap(
        short = 'b',
        long,
        action,
        help = "Delete BMC interfaces. Redeploy kea after deleting machine interfaces."
    )]
    pub delete_bmc_interfaces: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct NetworkConfigQuery {
    #[clap(long, required(true), help = "DPU machine id")]
    pub machine_id: String,
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct ShowMachine {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show all machines (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show only DPUs"
    )]
    pub dpus: bool,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show only hosts"
    )]
    pub hosts: bool,

    #[clap(
        default_value(""),
        help = "The machine to query, leave empty for all (default)"
    )]
    pub machine: String,
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct ShowManagedHost {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(
        short,
        long,
        action,
        help = "Show all managed hosts (DEPRECATED)",
        conflicts_with = "machine"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "Show managed host specific details (using host or dpu machine id), leave empty for all"
    )]
    pub machine: String,

    #[clap(
        short,
        long,
        action,
        help = "Show IP details in summary",
        conflicts_with = "machine"
    )]
    pub ips: bool,

    #[clap(
        short,
        long,
        action,
        help = "Show GPU and memory details in summary",
        conflicts_with = "machine"
    )]
    pub more: bool,

    #[clap(long, action, help = "Show only hosts in maintenance mode")]
    pub fix: bool,
}

/// Enable or disable maintenance mode on a managed host.
/// To list machines in maintenance mode use `forge-admin-cli mh show --all --fix`
#[derive(Parser, Debug)]
pub enum MaintenanceAction {
    /// Put this machine into maintenance mode. Prevents an instance being assigned to it.
    On(MaintenanceOn),
    /// Return this machine to normal operation.
    Off(MaintenanceOff),
}

#[derive(Parser, Debug)]
pub struct MaintenanceOn {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: String,

    #[clap(
        long,
        visible_alias = "ref",
        required(true),
        help = "URL of reference (ticket, issue, etc) for this machine's maintenance"
    )]
    pub reference: String,
}

#[derive(Parser, Debug)]
pub struct MaintenanceOff {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: String,
}

#[derive(Parser, Debug)]
pub enum Instance {
    #[clap(about = "Display instance information")]
    Show(ShowInstance),
    #[clap(about = "Reboot instance")]
    Reboot(RebootInstance),
    #[clap(about = "De-allocate instance")]
    Release(ReleaseInstance),
}

#[derive(Parser, Debug)]
pub struct ShowInstance {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "id",
        help = "Show all instances (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "The instance ID to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub extrainfo: bool,

    #[clap(long, help = "The key of label instance to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of label instance to query")]
    pub label_value: Option<String>,
}

#[derive(Parser, Debug)]
pub struct RebootInstance {
    #[clap(short, long)]
    pub instance: String,

    #[clap(short, long, action)]
    pub custom_pxe: bool,

    #[clap(short, long, action)]
    pub apply_updates_on_reboot: bool,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("release_instance")
        .required(true)
        .args(&["instance", "machine"])))]
pub struct ReleaseInstance {
    #[clap(short, long)]
    pub instance: Option<String>,

    #[clap(short, long)]
    pub machine: Option<String>,
}

#[derive(Parser, Debug)]
pub enum Domain {
    #[clap(about = "Display Domain information")]
    Show(ShowDomain),
}

#[derive(Parser, Debug)]
pub struct ShowDomain {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "domain",
        help = "Show all domains (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "The domain to query, leave empty for all (default)"
    )]
    pub domain: String,
}

#[derive(Parser, Debug)]
pub enum NetworkSegment {
    #[clap(about = "Display Network Segment information")]
    Show(ShowNetwork),
}

#[derive(Parser, Debug)]
pub struct ShowNetwork {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "network",
        help = "Show all network segments (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "The network segment to query, leave empty for all (default)"
    )]
    pub network: String,
}

#[derive(PartialEq, Eq, ValueEnum, Clone, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum OutputFormat {
    Json,
    Csv,
    AsciiTable,
    Yaml,
}

impl CarbideOptions {
    pub fn load() -> Self {
        Self::parse()
    }
}

#[derive(Parser, Debug)]
pub enum ResourcePool {
    #[clap(
        about = "Add capacity to one or more resource pools from a TOML file. See carbide-api admin_grow_resource_pool docs for example TOML."
    )]
    Grow(ResourcePoolDefinition),
    #[clap(about = "List all resource pools with stats")]
    List,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("grow")
        .required(true)
        .args(&["filename"])))]
pub struct ResourcePoolDefinition {
    #[clap(short, long)]
    pub filename: String,
}

#[derive(Parser, Debug)]
pub enum BmcMachine {
    #[clap(about = "Reset a BMC machine")]
    Reset(BMCConfigForReset),
    #[clap(about = "Identify a BMC vendor by the TLS certificate issuer")]
    Identify(BMCIdentify),
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum BMCCredentialType {
    Host,
    Dpu,
}

impl From<BMCCredentialType> for rpc::forge::CredentialType {
    fn from(c_type: BMCCredentialType) -> Self {
        use rpc::forge::CredentialType::*;
        match c_type {
            BMCCredentialType::Host => HostBmc,
            BMCCredentialType::Dpu => Dpubmc,
        }
    }
}

#[derive(Parser, Debug)]
pub enum CredentialAction {
    #[clap(about = "Add UFM credential")]
    AddUFM(AddUFMCredential),
    #[clap(about = "Delete UFM credential")]
    DeleteUFM(DeleteUFMCredential),
    #[clap(
        about = "Add site-wide Host/DPU BMC default credential (NOTE: this parameter can be set only once)"
    )]
    AddBMC(AddBMCredential),
    #[clap(
        about = "Add site-wide DPU UEFI default credential (NOTE: this parameter can be set only once)"
    )]
    AddUefi(AddUefiCredential),
    #[clap(about = "Add manufacturer factory default BMC user/pass for a given vendor")]
    AddHostFactoryDefault(AddHostFactoryDefaultCredential),
    #[clap(about = "Add manufacturer factory default BMC user/pass for the DPUs")]
    AddDpuFactoryDefault(AddDpuFactoryDefaultCredential),
}

#[derive(Parser, Debug)]
pub struct AddUFMCredential {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,

    #[clap(long, required(true), help = "The UFM token")]
    pub token: String,
}

#[derive(Parser, Debug)]
pub struct DeleteUFMCredential {
    #[clap(long, required(true), help = "The UFM url")]
    pub url: String,
}

#[derive(Parser, Debug)]
pub struct AddBMCredential {
    #[clap(long, required(true), help = "The kind of BMC credential")]
    pub kind: BMCCredentialType,

    #[clap(long, required(true), help = "The password of BMC")]
    pub password: String,
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
pub enum RouteServer {
    Get,
    Add(IpFind),
    Remove(IpFind),
}
#[derive(Parser, Debug)]
pub enum MachineInterfaces {
    #[clap(about = "List of all Machine interfaces")]
    Show(ShowMachineInterfaces),
    #[clap(about = "Delete Machine interface.")]
    Delete(DeleteMachineInterfaces),
}

#[derive(Parser, Debug)]
pub struct ShowMachineInterfaces {
    #[clap(
        short,
        long,
        action,
        conflicts_with = "interface_id",
        help = "Show all machine interfaces (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        default_value(""),
        help = "The interface ID to query, leave empty for all (default)"
    )]
    pub interface_id: String,

    #[clap(long, action)]
    pub more: bool,
}

#[derive(Parser, Debug)]
pub struct DeleteMachineInterfaces {
    #[clap(help = "The interface ID to delete. Redeploy kea after deleting machine interfaces.")]
    pub interface_id: String,
}

#[derive(Parser, Debug)]
pub enum SiteExplorer {
    #[clap(about = "Retrieves the latest site exploration report")]
    GetReport,
    #[clap(
        about = "Asks carbide-api to explore a single host and prints the report. Does not store it."
    )]
    Explore(ExploreOptions),
}

#[derive(Parser, Debug)]
pub struct ExploreOptions {
    #[clap(help = "BMC IP address or hostname with optional port")]
    pub address: String,
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
pub struct PingOptions {
    #[clap(
        short,
        long,
        default_value("1.0"),
        help = "Wait interval seconds between sending each request. Real number allowed with dot as a decimal separator."
    )]
    pub interval: f32,
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
