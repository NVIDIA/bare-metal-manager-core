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

    #[clap(subcommand)]
    pub commands: Option<CarbideCommand>,
}

#[derive(Parser, Debug)]
pub enum CarbideCommand {
    #[clap(about = "Print API server version", visible_alias = "v")]
    Version,
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
    #[clap(about = "Generate Ansible Inventory")]
    Inventory(InventoryAction),
    #[clap(about = "Cloud init override", subcommand)]
    BootOverride(BootOverrideAction),
    #[clap(
        about = "BMC Machine related handling",
        subcommand,
        visible_alias = "bmc"
    )]
    BmcMachine(BmcMachine),
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
    #[clap(about = "Get or set forge-dpu-agent upgrade policy")]
    AgentUpgradePolicy(AgentUpgrade),
}

#[derive(Parser, Debug)]
pub enum DpuReprovision {
    #[clap(about = "Set the DPU in reprovisioing mode.")]
    Set(DpuReprovisionData),
    #[clap(about = "Clear the reprovisioing mode.")]
    Clear(DpuReprovisionData),
    #[clap(about = "List all DPUs pending reprovisioning.")]
    List,
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
#[clap(group(
        ArgGroup::new("show_nd")
        .required(true)
        .args(&["all", "id"])))]
pub struct NetworkDeviceShow {
    #[clap(short, long, action, help = "Show all network devices")]
    pub all: bool,

    #[clap(short, long, help = "Show data for given network devices")]
    pub id: Option<String>,
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

#[derive(Parser, Debug)]
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
    /// Setup host for Forge use
    ForgeSetup,
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
    /// Enable serial console
    SerialEnable,
    /// Serial console status
    SerialStatus,
    /// Clear Trusted Platform Module (TPM)
    TpmReset,
    /// Reboot the BMC itself
    BmcReset,
    /// Disable Secure Boot
    DisableSecureBoot,
    /// List Chassis
    GetChassisAll,
    /// Show BMC's Ethernet interface information
    GetBmcEthernetInterface,
    /// Change password for a BMC user
    ChangeBmcPassword(BmcPassword),
    /// Change UEFI password
    ChangeUefiPassword(UefiPassword),
    #[clap(about = "DPU specific operations", subcommand)]
    Dpu(DpuOperations),
}

#[derive(clap::Parser, Debug)]
pub enum DpuOperations {
    /// Set host level to to restricted. Host will not be able to configure DPU
    SetHostLevelRestricted,
    /// Set host level to to privilged. Allow host to configure the DPU
    SetHostLevelPrivileged,
    /// BMC's FW Commands
    #[clap(visible_alias = "fw", about = "BMC's FW Commands", subcommand)]
    Firmware(FwCommand),
    /// Show ports information
    Ports(ShowPort),
}

#[derive(Parser, Debug)]
pub enum FwCommand {
    /// Print FW update status
    Status,
    /// Update BMC's FW to the given FW package
    Update(FwPackage),
    /// Show FW versions of different components
    Show(ShowFw),
}

#[derive(Parser, Debug)]
pub struct FwPackage {
    #[clap(short, long, help = "FW package to install")]
    pub package: PathBuf,
}

#[derive(Parser, Debug)]
pub struct UefiPassword {
    #[clap(long, require_equals(true), help = "Current UEFI password")]
    pub current_password: String,
    #[clap(long, require_equals(true), help = "New UEFI password")]
    pub new_password: String,
}

#[derive(Parser, Debug)]
pub struct BmcPassword {
    #[clap(long, require_equals(true), help = "New BMC password")]
    pub new_password: String,
    #[clap(long, require_equals(true), help = "BMC user")]
    pub user: String,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_fw")
        .required(true)
        .args(&["all", "bmc", "dpu_os", "uefi", "fw"])))]
pub struct ShowFw {
    #[clap(short, long, action, help = "Show information")]
    pub all: bool,

    #[clap(long, action, help = "Show BMC FW Version")]
    pub bmc: bool,

    #[clap(long, action, help = "Show DPU OS version")]
    pub dpu_os: bool,

    #[clap(long, action, help = "Show UEFI version")]
    pub uefi: bool,

    #[clap(short, long)]
    pub fw: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_port")
        .required(true)
        .args(&["all", "port"])))]
pub struct ShowPort {
    #[clap(short, long, action, help = "Show information")]
    pub all: bool,

    #[clap(short, long)]
    pub port: Option<String>,
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

pub type BMCConfigForReset = BMCConfigForReboot;

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

#[derive(Parser, Debug, Clone)]
pub struct NetworkConfigQuery {
    #[clap(long, require_equals(true), required(true), help = "DPU machine id")]
    pub machine_id: String,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_machine")
        .required(true)
        .args(&["all", "dpus", "hosts", "machine"])))]
pub struct ShowMachine {
    #[clap(short, long, action, help = "Show all machines")]
    pub all: bool,

    #[clap(long, action, help = "Show only DPUs")]
    pub dpus: bool,

    #[clap(long, action, help = "Show only hosts")]
    pub hosts: bool,

    #[clap(short, long)]
    pub machine: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_managed_host")
        .required(true)
        .args(&["all", "host"])))]
pub struct ShowManagedHost {
    #[clap(short, long, action)]
    pub all: bool,

    #[clap(long)]
    pub host: Option<String>,

    #[clap(short, long, action)]
    pub ips: bool,

    #[clap(long, action)]
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
    #[clap(long, require_equals(true), required(true), help = "Managed Host ID")]
    pub host: String,

    #[clap(
        long,
        visible_alias = "ref",
        require_equals(true),
        required(true),
        help = "URL of reference (ticket, issue, etc) for this machine's maintenance"
    )]
    pub reference: String,
}

#[derive(Parser, Debug)]
pub struct MaintenanceOff {
    #[clap(long, require_equals(true), required(true), help = "Managed Host ID")]
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
pub struct RebootInstance {
    #[clap(short, long)]
    pub instance: String,

    #[clap(short, long, action)]
    pub custom_pxe: bool,
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
}
