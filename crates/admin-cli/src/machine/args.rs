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

use carbide_uuid::machine::MachineId;
use clap::{ArgGroup, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
pub enum Cmd {
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
    #[clap(subcommand, about = "Edit Metadata associated with a Machine")]
    Metadata(MachineMetadataCommand),
    #[clap(subcommand, about = "Update/show machine hardware info")]
    HardwareInfo(MachineHardwareInfoCommand),
    #[clap(
        about = "Show physical location info for machines in rack-based systems",
        long_about = "Show physical location info for machines in rack-based systems.\n\n\
            Returns rack topology information including:\n\
            - Physical slot number: The slot position in the rack\n\
            - Compute tray index: The compute tray containing this machine\n\
            - Topology ID: Identifier for the rack topology configuration\n\
            - Revision ID: Hardware revision identifier\n\
            - Switch ID: Associated network switch\n\
            - Power shelf ID: Associated power shelf"
    )]
    Positions(Positions),
    #[clap(subcommand, about = "Update/show NVLink info for an MNNVL machine")]
    NvlinkInfo(NvlinkInfoCommand),
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
        short = 't',
        long,
        action,
        // DPUs don't get associated with instance types.
        // Wouldn't hurt to allow the query, but might as well
        // be helpful here.
        conflicts_with = "dpus",
        help = "Show only machines for this instance type"
    )]
    pub instance_type_id: Option<String>,

    #[clap(
        default_value(None),
        help = "The machine to query, leave empty for all (default)"
    )]
    pub machine: Option<MachineId>,

    #[clap(
        short = 'c',
        long,
        default_value("5"),
        help = "History count. Valid if `machine` argument is passed."
    )]
    pub history_count: u32,
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

#[derive(Parser, Debug)]
pub enum NetworkCommand {
    #[clap(about = "Print network status of all machines")]
    Status,
    #[clap(about = "Machine network configuration, used by VPC.")]
    Config(NetworkConfigQuery),
}

#[derive(Parser, Debug, Clone)]
pub struct NetworkConfigQuery {
    #[clap(long, required(true), help = "DPU machine id")]
    pub machine_id: MachineId,
}

#[derive(Parser, Debug)]
pub enum OverrideCommand {
    #[clap(about = "List the health reports overrides")]
    Show { machine_id: MachineId },
    #[clap(about = "Insert a health report override")]
    Add(HealthAddOptions),
    #[clap(about = "Print a empty health override template, which user can modify and use")]
    PrintEmptyTemplate,
    #[clap(about = "Remove a health report override")]
    Remove {
        machine_id: MachineId,
        report_source: String,
    },
}

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("override_health").required(true).args(&["health_report", "template"])))]
pub struct HealthAddOptions {
    pub machine_id: MachineId,
    #[clap(long, help = "New health report as json")]
    pub health_report: Option<String>,
    #[clap(
        long,
        help = "Predefined Template name. Use host-update for DPU Reprovision"
    )]
    pub template: Option<HealthOverrideTemplates>,
    #[clap(long, help = "Message to be filled in template.")]
    pub message: Option<String>,
    #[clap(long, help = "Replace all other health reports with this override")]
    pub replace: bool,
    #[clap(long, help = "Print the template that is going to be send to carbide")]
    pub print_only: bool,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum HealthOverrideTemplates {
    HostUpdate,
    InternalMaintenance,
    OutForRepair,
    Degraded,
    Validation,
    SuppressExternalAlerting,
    MarkHealthy,
    StopRebootForAutomaticRecoveryFromStateMachine,
    TenantReportedIssue,
    RequestRepair,
}

#[derive(Parser, Debug)]
pub struct BMCConfigForReboot {
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
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

    #[clap(
        long,
        action,
        help = "Delete machine with allocated instance. This flag acknowledges destroying the user instance as well."
    )]
    pub allow_delete_with_instance: bool,
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
pub enum MachineMetadataCommand {
    #[clap(about = "Set the Name or Description of the Machine")]
    Set(MachineMetadataCommandSet),
    #[clap(about = "Show the Metadata of the Machine")]
    Show(MachineMetadataCommandShow),
    #[clap(about = "Adds a label to the Metadata of a Machine")]
    AddLabel(MachineMetadataCommandAddLabel),
    #[clap(about = "Removes labels from the Metadata of a Machine")]
    RemoveLabels(MachineMetadataCommandRemoveLabels),
    #[clap(about = "Copy Machine Metadata from Expected-Machine to Machine")]
    FromExpectedMachine(MachineMetadataCommandFromExpectedMachine),
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandShow {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandSet {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
    #[clap(long, help = "The updated name of the Machine")]
    pub name: Option<String>,
    #[clap(long, help = "The updated description of the Machine")]
    pub description: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandAddLabel {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
    #[clap(long, help = "The key to add")]
    pub key: String,
    #[clap(long, help = "The optional value to add")]
    pub value: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandRemoveLabels {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
    #[clap(long, help = "The keys to remove")]
    pub keys: Vec<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct MachineMetadataCommandFromExpectedMachine {
    #[clap(help = "The machine which should get updated metadata")]
    pub machine: MachineId,
    /// Whether to fully replace the Metadata that is currently stored on the Machine.
    /// - If not set, existing Metadata on the Machine will not be touched by executing
    ///   the command:
    ///   - The existing Name will not be changed if the Name is not equivalent
    ///     to the Machine ID or Empty.
    ///   - The existing Description will not be changed if it is not empty.
    ///   - Existing Labels and their values will not be changed. Only labels which
    ///     do not exist on the Machine will be added.
    /// - If set, the Machines Metadata will be set to the same values as
    ///   they would if the Machine would get freshly ingested.
    ///   Metadata that is currently set on the Machine will be overridden.
    #[clap(long, verbatim_doc_comment)]
    pub replace_all: bool,
}

#[derive(Parser, Debug)]
pub enum MachineHardwareInfoCommand {
    #[clap(about = "Show the hardware info of the machine")]
    Show(ShowMachineHardwareInfo),
    #[clap(subcommand, about = "Update the hardware info of the machine")]
    Update(MachineHardwareInfo),
}

#[derive(Parser, Debug)]
pub struct ShowMachineHardwareInfo {
    #[clap(long, help = "Show the hardware info of this Machine ID")]
    pub machine: MachineId,
}

#[derive(Parser, Debug)]
pub enum MachineHardwareInfo {
    //Cpu(MachineTopologyCommandCpu),
    #[clap(about = "Update the GPUs of this machine")]
    Gpus(MachineHardwareInfoGpus),
    //Memory(MachineTopologyCommandMemory),
    //Storage(MachineTopologyCommandStorage),
    //Network(MachineTopologyCommandNetwork),
    //Infiniband(MachineTopologyCommandInfiniband),
    //Dpu(MachineTopologyCommandDpu),
}

#[derive(Parser, Debug)]
pub struct MachineHardwareInfoGpus {
    #[clap(long, help = "Machine ID of the server containing the GPUs")]
    pub machine: MachineId,
    #[clap(
        long,
        help = "JSON file containing GPU info. It should contain an array of JSON objects like this:
        {
            \"name\": \"string\",
            \"serial\": \"string\",
            \"driver_version\": \"string\",
            \"vbios_version\": \"string\",
            \"inforom_version\": \"string\",
            \"total_memory\": \"string\",
            \"frequency\": \"string\",
            \"pci_bus_id\": \"string\"
        }
        Pass an empty array if you want to remove GPUs."
    )]
    pub gpu_json_file: std::path::PathBuf,
}

#[derive(Parser, Debug)]
pub struct Positions {
    #[clap(
        short = 'm',
        long,
        num_args = 0..,
        value_delimiter = ' ',
        help = "The machine(s) to query, leave empty for all (default)"
    )]
    pub machine: Vec<MachineId>,
}

#[derive(Subcommand, Debug)]
pub enum NvlinkInfoCommand {
    #[clap(about = "Show existing NVLink info")]
    Show(NvlinkInfoArgs),
    #[clap(about = "Build NVLink info from Redfish + NMX-M and populate DB")]
    Populate(NvlinkInfoPopulateArgs),
}

#[derive(Parser, Debug)]
pub struct NvlinkInfoArgs {
    #[clap(help = "Machine ID to query")]
    pub machine_id: MachineId,
}

#[derive(Parser, Debug)]
pub struct NvlinkInfoPopulateArgs {
    #[clap(help = "Machine ID to populate")]
    pub machine_id: MachineId,

    #[clap(long, action, help = "Update the database with the nvlink_info")]
    pub update_db: bool,
}
