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
use forge_network::virtualization::VpcVirtualizationType;
use forge_uuid::machine::MachineId;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use utils::{admin_cli::OutputFormat, has_duplicates};

use crate::cfg::measurement;
use carbide::ib::DEFAULT_IB_FABRIC_NAME;

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

    #[clap(
        long,
        default_value = "false",
        help = "Never should be used against a production site. Use this flag only if you undrestand the impacts of inconsistencies with cloud db."
    )]
    pub cloud_unsafe_op: bool,

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

    #[clap(short = 'p', long, default_value_t = 100)]
    #[clap(help = "For commands that internally retrieve data with paging, use this page size.")]
    pub internal_page_size: usize,
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
    BmcMachine(BmcAction),
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
    #[clap(about = "Set carbide-api dynamic features", subcommand)]
    Set(SetAction),
    #[clap(about = "Expected machine handling", subcommand, visible_alias = "em")]
    ExpectedMachine(ExpectedMachineAction),
    #[clap(about = "VPC related handling", subcommand)]
    Vpc(VpcOptions),
    #[clap(
        about = "InfiniBand Partition related handling",
        subcommand,
        visible_alias = "ibp"
    )]
    IbPartition(IbPartitionOptions),
    #[clap(
        about = "Tenant KeySet related handling",
        subcommand,
        visible_alias = "tks"
    )]
    TenantKeySet(TenantKeySetOptions),

    #[clap(
        about = "Broad search across multiple object types",
        visible_alias = "j"
    )]
    Jump(JumpOptions),

    #[clap(about = "Machine Validation", subcommand, visible_alias = "mv")]
    MachineValidation(MachineValidationCommand),
}

#[derive(Parser, Debug)]
pub enum SetAction {
    #[clap(about = "Set RUST_LOG")]
    LogFilter(LogFilterOptions),
    #[clap(about = "Set create_machines")]
    CreateMachines(CreateMachinesOptions),
    #[clap(about = "Set bmc_proxy")]
    BmcProxy(BmcProxyOptions),
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
    #[clap(about = "Get or set forge-dpu-agent upgrade policy")]
    AgentUpgradePolicy(AgentUpgrade),
    #[clap(about = "View DPU firmware status")]
    Versions(DpuVersionOptions),
    #[clap(about = "View DPU Status")]
    Status,
}

#[derive(Parser, Debug)]
pub enum DpuReprovision {
    #[clap(about = "Set the DPU in reprovisioning mode.")]
    Set(DpuReprovisionSet),
    #[clap(about = "Clear the reprovisioning mode.")]
    Clear(DpuReprovisionClear),
    #[clap(about = "List all DPUs pending reprovisioning.")]
    List,
    #[clap(about = "Restart the DPU reprovision.")]
    Restart(DpuReprovisionRestart),
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionSet {
    #[clap(
        short,
        long,
        help = "DPU Machine ID for which reprovisioning is needed, or host machine id if all DPUs should be reprovisioned."
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub update_firmware: bool,

    #[clap(short, long)]
    pub maintenance_reference: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionClear {
    #[clap(
        short,
        long,
        help = "DPU Machine ID for which reprovisioning should be cleared, or host machine id if all DPUs should be cleared."
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub update_firmware: bool,
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionRestart {
    #[clap(
        short,
        long,
        help = "Host Machine ID for which reprovisioning should be restarted."
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

#[allow(clippy::enum_variant_names)]
#[derive(Parser, Debug)]
pub enum HostAction {
    #[clap(about = "Set Host UEFI password")]
    SetUefiPassword(MachineQuery),
    #[clap(about = "Clear Host UEFI password")]
    ClearUefiPassword(MachineQuery),
    #[clap(about = "Generates a string that can be a site-default host UEFI password in Vault")]
    /// - the generated string will meet the uefi password requirements of all vendors
    GenerateHostUefiPassword,
}

#[derive(Parser, Debug)]
pub enum ExpectedMachineAction {
    #[clap(about = "Show expected machine data")]
    Show(ShowExpectedMachineQuery),
    #[clap(about = "Add expected machine")]
    Add(ExpectedMachine),
    #[clap(about = "Delete expected machine")]
    Delete(DeleteExpectedMachine),
    #[clap(about = "Update expected machine")]
    Update(UpdateExpectedMachine),
    /// Replace all entries in the expected machines table with the entries from an inputted json file.
    ///
    /// Example json file:
    ///    {
    ///        "expected_machines":
    ///        [
    ///            {
    ///                "bmc_mac_address": "1a:1b:1c:1d:1e:1f",
    ///                "bmc_username": "user",
    ///                "bmc_password": "pass",
    ///                "chassis_serial_number": "sample_serial-1"
    ///            },
    ///            {
    ///                "bmc_mac_address": "2a:2b:2c:2d:2e:2f",
    ///                "bmc_username": "user",
    ///                "bmc_password": "pass",
    ///                "chassis_serial_number": "sample_serial-2",
    ///                "fallback_dpu_serial_numbers": ["MT020100000003"]
    ///            }
    ///        ]
    ///    }
    #[clap(verbatim_doc_comment)]
    ReplaceAll(ExpectedMachineReplaceAllRequest),
    #[clap(about = "Erase all expected machines")]
    Erase,
}

#[derive(Parser, Debug, Serialize, Deserialize)]
pub struct ExpectedMachine {
    #[clap(short = 'a', long, help = "BMC MAC Address of the expected machine")]
    pub bmc_mac_address: MacAddress,
    #[clap(short = 'u', long, help = "BMC username of the expected machine")]
    pub bmc_username: String,
    #[clap(short = 'p', long, help = "BMC password of the expected machine")]
    pub bmc_password: String,
    #[clap(
        short = 's',
        long,
        help = "Chassis serial number of the expected machine"
    )]
    pub chassis_serial_number: String,
    #[clap(
        short = 'd',
        long = "fallback-dpu-serial-number",
        value_name = "DPU_SERIAL_NUMBER",
        help = "Serial number of the DPU attached to the expected machine. This option should be used only as a last resort for ingesting those servers whose BMC/Redfish do not report serial number of network devices. This option can be repeated.",
        action = clap::ArgAction::Append
    )]
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,
}

impl ExpectedMachine {
    pub fn has_duplicate_dpu_serials(&self) -> bool {
        match self.fallback_dpu_serial_numbers.clone() {
            Some(fallback_dpu_serial_numbers) => has_duplicates(fallback_dpu_serial_numbers),
            None => false,
        }
    }
}
#[derive(Parser, Debug, Serialize, Deserialize)]
#[clap(group(ArgGroup::new("group").required(true).multiple(true).args(&[
"bmc_username",
"bmc_password",
"chassis_serial_number",
"fallback_dpu_serial_numbers",
])))]
pub struct UpdateExpectedMachine {
    #[clap(
        short = 'a',
        required = true,
        long,
        help = "BMC MAC Address of the expected machine"
    )]
    pub bmc_mac_address: MacAddress,
    #[clap(
        short = 'u',
        long,
        group = "group",
        requires("bmc_password"),
        help = "BMC username of the expected machine"
    )]
    pub bmc_username: Option<String>,
    #[clap(
        short = 'p',
        long,
        group = "group",
        requires("bmc_username"),
        help = "BMC password of the expected machine"
    )]
    pub bmc_password: Option<String>,
    #[clap(
        short = 's',
        long,
        group = "group",
        help = "Chassis serial number of the expected machine"
    )]
    pub chassis_serial_number: Option<String>,
    #[clap(
        short = 'd',
        long = "fallback-dpu-serial-number",
        value_name = "DPU_SERIAL_NUMBER",
        group = "group",
        help = "Serial number of the DPU attached to the expected machine. This option should be used only as a last resort for ingesting those servers whose BMC/Redfish do not report serial number of network devices. This option can be repeated.",
        action = clap::ArgAction::Append
    )]
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,
}

impl UpdateExpectedMachine {
    pub fn validate(&self) -> Result<(), String> {
        // TODO: It is possible to do these checks by clap itself, via arg groups
        if self.bmc_username.is_none()
            && self.bmc_password.is_none()
            && self.chassis_serial_number.is_none()
            && self.fallback_dpu_serial_numbers.is_none()
        {
            return Err("One of the following options must be specified: bmc-user-name and bmc-password or chassis-serial-number or fallback-dpu-serial-number".to_string());
        }
        if let Some(dpu_serials) = self.fallback_dpu_serial_numbers.clone() {
            if has_duplicates(&dpu_serials) {
                return Err("Duplicate dpu serial numbers found".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Parser, Debug)]
pub struct DeleteExpectedMachine {
    #[clap(help = "BMC MAC address of the expected machine to delete.")]
    pub bmc_mac_address: MacAddress,
}

#[derive(Parser, Debug)]
pub struct ShowExpectedMachineQuery {
    #[clap(
        default_value(None),
        help = "BMC MAC address of the expected machine to show. Leave unset for all."
    )]
    pub bmc_mac_address: Option<MacAddress>,
}

#[derive(Parser, Debug)]
pub struct ExpectedMachineReplaceAllRequest {
    #[clap(short, long)]
    pub filename: String,
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
    /// Set Boot order to UEFI Http First
    BootUefiHttp,
    /// On next boot only, boot from hard drive
    BootOnceHdd,
    /// On next boot only, boot from PXE
    BootOncePxe,
    /// Boot rom UEFI HTTP Once
    BootOnceUefiHttp,
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
    /// Reset BMC to factory defaults
    BmcResetToDefaults,
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
    GetManager,
    /// Update host firmware
    UpdateFirmwareMultipart(Multipart),
    // Get detailed info on a Redfish task
    GetTask(Task),
    // Get a list of Redfish tasks
    GetTasks,
    /// Clear UEFI password
    ClearUefiPassword(UefiPassword),
    // Is IPMI enabled over LAN
    IsIpmiOverLanEnabled,
    // Enable IPMI over LAN
    EnableIpmiOverLan,
    // Disable IPMI over LAN
    DisableIpmiOverLan,
    // Get Base Mac Address (DPU only)
    GetBaseMacAddress,
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
pub enum Machine {
    #[clap(about = "Display Machine information")]
    Show(ShowMachine),
    #[clap(about = "Print DPU admin SSH username:password")]
    DpuSshCredentials(MachineQuery),
    #[clap(subcommand, about = "Networking information")]
    Network(NetworkCommand),
    #[clap(
        about = "Health override related handling",
        subcommand,
        visible_alias = "ho"
    )]
    HealthOverride(OverrideCommand),
    #[clap(about = "Reboot a machine")]
    Reboot(BMCConfigForReboot),
    #[clap(about = "Force delete a machine")]
    ForceDelete(ForceDeleteMachineQuery),
    #[clap(about = "Set individual machine firmware autoupdate (host only)")]
    AutoUpdate(MachineAutoupdate),
}

#[derive(Parser, Debug)]
pub enum NetworkCommand {
    #[clap(about = "Print network status of all machines")]
    Status,
    #[clap(about = "Machine network configuration, used by VPC.")]
    Config(NetworkConfigQuery),
}

#[derive(Parser, Debug)]
pub enum OverrideCommand {
    #[clap(about = "List the health reports overrides")]
    Show { machine_id: String },
    #[clap(about = "Insert a health report override")]
    Add {
        machine_id: String,
        #[clap(help = "New health report as json")]
        health_report: String,
        #[clap(long, help = "Override all other health reports")]
        r#override: bool,
    },
    #[clap(about = "Remove a health report override")]
    Remove {
        machine_id: String,
        report_source: String,
    },
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
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
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
        }
    }
}

#[derive(Parser, Debug, Clone)]
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

    #[clap(
        short = 'c',
        long,
        action,
        help = "Delete BMC credentials. Only applicable if site explorer has configured credentials for the BMCs associated with this managed host."
    )]
    pub delete_bmc_credentials: bool,
}

#[derive(Parser, Debug, Clone)]
#[clap(group(ArgGroup::new("autoupdate_action").required(true).args(&["enable", "disable", "clear"])))]
pub struct MachineAutoupdate {
    #[clap(long, help = "Machine ID of the host to change")]
    pub machine: MachineId,
    #[clap(
        short = 'e',
        long,
        action,
        help = "Enable auto updates even if globally disabled or individually disabled by config files"
    )]
    pub enable: bool,
    #[clap(
        short = 'd',
        long,
        action,
        help = "Disable auto updates even if globally enabled or individually enabled by config files"
    )]
    pub disable: bool,
    #[clap(
        short = 'c',
        long,
        action,
        help = "Perform auto updates according to config files"
    )]
    pub clear: bool,
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
    pub help: Option<bool>,

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
    #[clap(about = "Allocate instance")]
    Allocate(AllocateInstance),
}

/// ShowInstance is used for `cli instance show` configuration,
/// with the ability to filter by a combination of labels, tenant
/// org ID, and VPC ID.
//
// TODO: Possibly add the ability to filter by a list of tenant
// org IDs and/or VPC IDs.
#[derive(Parser, Debug)]
pub struct ShowInstance {
    #[clap(
        default_value(""),
        help = "The instance ID to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, action)]
    pub extrainfo: bool,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The VPC ID to query.")]
    pub vpc_id: Option<String>,

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
        .args(&["instance", "machine", "label_key"])))]
pub struct ReleaseInstance {
    #[clap(short, long)]
    pub instance: Option<String>,

    #[clap(short, long)]
    pub machine: Option<String>,

    #[clap(long, help = "The key of label instance to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of label instance to query")]
    pub label_value: Option<String>,
}

#[derive(Parser, Debug)]
pub struct AllocateInstance {
    #[clap(short, long)]
    pub number: Option<u16>,

    #[clap(short, long, required = true)]
    pub subnet: String,

    #[clap(short, long, required = true)]
    pub prefix_name: String,

    #[clap(long, help = "The key of label instance to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of label instance to query")]
    pub label_value: Option<String>,
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
        default_value(""),
        help = "The network segment to query, leave empty for all (default)"
    )]
    pub network: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The VPC name to query")]
    pub name: Option<String>,
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
pub enum BmcAction {
    #[clap(about = "Reset BMC")]
    BmcReset(BmcResetArgs),
    #[clap(about = "Redfish Power Control")]
    AdminPowerControl(AdminPowerControlArgs),
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
    #[clap(about = "Retrieves the latest site exploration report", subcommand)]
    GetReport(GetReportMode),
    #[clap(
        about = "Asks carbide-api to explore a single host and prints the report. Does not store it."
    )]
    Explore(ExploreOptions),
    #[clap(
        about = "Asks carbide-api to explore a single host in the next exploration cycle. The results will be stored."
    )]
    ReExplore(ReExploreOptions),
    #[clap(
        about = "Clear the last known error for the BMC in the latest site exploration report."
    )]
    ClearError(ExploreOptions),
    IsBmcInManagedHost(ExploreOptions),
    HaveCredentials(ExploreOptions),
}

#[derive(Parser, Debug)]
pub enum BmcEndpointExplorer {
    #[clap(about = "Reset the BMC for an endpoint.")]
    ResetBMC(ExploreOptions),
    RedfishForceRestartBmc(ExploreOptions),
}

#[derive(Parser, Debug, PartialEq)]
pub enum GetReportMode {
    #[clap(about = "Get everything in Json")]
    All,
    #[clap(about = "Get discovered host details.")]
    ManagedHost(ManagedHostInfo),
    #[clap(about = "Get Endpoint details.")]
    Endpoint(EndpointInfo),
}

#[derive(Parser, Debug, PartialEq)]
#[clap(group(ArgGroup::new("selector").required(false).args(&["erroronly", "successonly"])))]
pub struct EndpointInfo {
    #[clap(help = "BMC IP address of Endpoint.")]
    pub address: Option<String>,

    #[clap(
        short,
        long,
        help = "Filter based on vendor. Valid only for table view."
    )]
    pub vendor: Option<String>,

    #[clap(
        long,
        action,
        help = "By default shows all endpoints. If wants to see unpairedonly, choose this option."
    )]
    pub unpairedonly: bool,

    #[clap(long, action, help = "Show only endpoints which have error.")]
    pub erroronly: bool,

    #[clap(long, action, help = "Show only endpoints which have no error.")]
    pub successonly: bool,
}

#[derive(Parser, Debug, PartialEq)]
pub struct ManagedHostInfo {
    #[clap(help = "BMC IP address of host or DPU")]
    pub address: Option<String>,

    #[clap(
        short,
        long,
        help = "Filter based on vendor. Valid only for table view."
    )]
    pub vendor: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ExploreOptions {
    #[clap(help = "BMC IP address or hostname with optional port")]
    pub address: String,
    #[clap(long, help = "The MAC address the BMC sent DHCP from")]
    pub mac: Option<MacAddress>,
}

#[derive(Parser, Debug)]
pub struct ReExploreOptions {
    #[clap(help = "BMC IP address")]
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
pub enum VpcOptions {
    #[clap(about = "Display VPC information")]
    Show(ShowVpc),
    SetVirtualizer(SetVpcVirt),
}

#[derive(Parser, Debug)]
pub struct ShowVpc {
    #[clap(
        default_value(""),
        help = "The VPC ID to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The VPC name to query")]
    pub name: Option<String>,

    #[clap(long, help = "The key of VPC label to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of VPC label to query")]
    pub label_value: Option<String>,
}

#[derive(Parser, Debug)]
pub struct SetVpcVirt {
    #[clap(help = "The VPC ID for the VPC to update")]
    pub id: String,
    #[clap(help = "The virtualizer to use for this VPC")]
    pub virtualizer: VpcVirtualizationType,
}

#[derive(Parser, Debug)]
pub enum IbPartitionOptions {
    #[clap(about = "Display InfiniBand Partition information")]
    Show(ShowIbPartition),
}

#[derive(Parser, Debug)]
pub struct ShowIbPartition {
    #[clap(
        default_value(""),
        help = "The InfiniBand Partition ID to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The InfiniBand Partition name to query")]
    pub name: Option<String>,
}

#[derive(Parser, Debug)]
pub enum TenantKeySetOptions {
    #[clap(about = "Display Tenant KeySet information")]
    Show(ShowTenantKeySet),
}

#[derive(Parser, Debug)]
pub struct ShowTenantKeySet {
    #[clap(
        default_value(""),
        help = "The Tenant KeySet ID in the format of <tenant_org_id>/<keyset_id> to query, leave empty for all (default)"
    )]
    pub id: String,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,
}

#[derive(Parser, Debug)]
pub struct JumpOptions {
    #[clap(required(true), help = "The machine ID, IP, UUID, etc, to find")]
    pub id: String,
}
#[derive(Parser, Debug)]

pub enum MachineValidationCommand {
    #[clap(about = "External config", subcommand, visible_alias = "mve")]
    ExternalConfig(MachineValidationExternalConfigCommand),
    #[clap(about = "Validation Results", subcommand, visible_alias = "mvr")]
    Validation(MachineValidationResultsCommand),
    #[clap(about = "Ondemand Validation", subcommand, visible_alias = "mvo")]
    OnDemand(MachineValidationOnDemandCommand),
}
#[derive(Parser, Debug)]
pub enum MachineValidationExternalConfigCommand {
    #[clap(about = "Show External config")]
    Show(MachineValidationExternalConfigShowOptions),

    #[clap(about = "Update External config")]
    AddUpdate(MachineValidationExternalConfigAddOptions),
}

#[derive(Parser, Debug)]
pub struct MachineValidationExternalConfigShowOptions {
    #[clap(short, long, help = "Machine validation external config name")]
    pub name: String,
}

#[derive(Parser, Debug)]
pub struct MachineValidationExternalConfigAddOptions {
    #[clap(short, long, help = "Name of the file to update")]
    pub file_name: String,
    #[clap(short, long, help = "Name of the config")]
    pub name: String,
    #[clap(short, long, help = "description of the file to update")]
    pub description: String,
}
#[derive(Parser, Debug)]
pub enum MachineValidationResultsCommand {
    #[clap(about = "Display all machine validation runs", subcommand)]
    Runs(ShowMachineValidationRuns),
    #[clap(
        about = "Display machine validation in results of indivisual runs",
        subcommand
    )]
    Results(ShowMachineValidationResults),
}

#[derive(Parser, Debug)]
pub enum ShowMachineValidationRuns {
    #[clap(about = "Show expected machine data")]
    Show(ShowMachineValidationRunsOptions),
}

#[derive(Parser, Debug)]
pub enum ShowMachineValidationResults {
    #[clap(about = "Show expected machine data")]
    Show(ShowMachineValidationResultsOptions),
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct ShowMachineValidationRunsOptions {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(
        short,
        long,
        default_value(""),
        help = "Show machine validation runs of a machine"
    )]
    pub machine: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct ShowMachineValidationResultsOptions {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(short, long, help = "Show machine validation result of a machine")]
    pub machine: String,

    #[clap(long, default_value = "false", help = "Results history")]
    pub history: bool,
}

#[derive(Parser, Debug)]
pub enum MachineValidationOnDemandCommand {
    #[clap(about = "Start on demand machine validation")]
    Start(MachineValidationOnDemandOptions),
}

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct MachineValidationOnDemandOptions {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    help: Option<bool>,

    #[clap(short, long, help = "Machine id for start validation")]
    pub machine: String,

    #[clap(long, help = "Results history")]
    pub tags: Option<Vec<String>>,
}
