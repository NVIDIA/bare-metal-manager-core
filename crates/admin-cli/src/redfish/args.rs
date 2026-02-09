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

use std::path::PathBuf;

use clap::{ArgGroup, Parser};
use libredfish::model::update_service::ComponentType;

#[derive(Parser, Debug, Clone)]
pub struct RedfishAction {
    #[clap(subcommand)]
    pub command: Cmd,

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
pub enum Cmd {
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
    /// Create new BMC user
    DeleteBmcUser(DeleteBmcUser),
    /// Setup host for use
    MachineSetup(MachineSetupArgs),
    /// Is everything MachineSetup does already done? What's missing?
    MachineSetupStatus(MachineSetupStatusArgs),
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
    /// AC power cycle
    ACPowerCycle,
    /// Power on a machine
    On,
    /// List PCIe devices
    PcieDevices,
    /// List Direct Attached drives
    LocalStorage,
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
    // List Chassis Subsystem
    GetChassis(Chassis),
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
    // Clear Nvram (Viking only)
    ClearNvram,
    // Redfish browser
    Browse(UriInfo),
    // Set BIOS options
    SetBios(SetBios),
    GetNicMode,
    IsInfiniteBootEnabled,
    EnableInfiniteBoot,
    SetNicMode,
    SetDpuMode,
    ChassisResetCard1Powercycle,
    SetBootOrderDpuFirst(SetBootOrderDpuFirstArgs),
    GetHostRshim,
    EnableHostRshim,
    DisableHostRshim,
    GetBossController,
    DecomissionController(DecomissionControllerArgs),
    CreateVolume(CreateVolumeArgs),
    IsBootOrderSetup(SetBootOrderDpuFirstArgs),
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct UriInfo {
    #[clap(long, help = "Redfish URI")]
    pub uri: String,
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
    #[clap(
        long,
        help = "Firmware type, ignored by some platforms and optional on others"
    )]
    pub component_type: Option<ComponentType>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Task {
    #[clap(long, help = "Task ID")]
    pub taskid: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct Chassis {
    #[clap(long, help = "Chassis ID")]
    pub chassis_id: String,
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
pub struct DeleteBmcUser {
    #[clap(long, help = "BMC user")]
    pub user: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct MachineSetupArgs {
    #[clap(long, help = "boot_interface_mac")]
    pub boot_interface_mac: Option<String>,
    #[clap(long, help = "BIOS profile config in JSON format")]
    pub bios_profiles: Option<String>,
    #[clap(long, help = "BIOS profile to use")]
    pub selected_profile: Option<libredfish::BiosProfileType>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct MachineSetupStatusArgs {
    #[clap(long, help = "boot_interface_mac")]
    pub boot_interface_mac: Option<String>,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct SetBootOrderDpuFirstArgs {
    #[clap(long, help = "boot_interface_mac")]
    pub boot_interface_mac: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct DecomissionControllerArgs {
    #[clap(long, help = "controller_id")]
    pub controller_id: String,
}

#[derive(Parser, Debug, PartialEq, Clone)]
pub struct CreateVolumeArgs {
    #[clap(long, help = "controller_id")]
    pub controller_id: String,
    #[clap(long, help = "volume_name")]
    pub volume_name: String,
    #[clap(long, help = "raid_type")]
    pub raid_type: String,
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

#[derive(Parser, Debug, Clone, PartialEq)]
pub struct SetBios {
    #[clap(
        long,
        help = "BIOS attributes to set in JSON, ex: {\"OperatingModes_ChooseOperatingMode\": \"MaximumPerformance\"}"
    )]
    pub attributes: String,
}
