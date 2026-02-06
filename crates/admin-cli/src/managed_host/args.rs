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

use carbide_uuid::machine::MachineId;
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Display managed host information")]
    Show(ShowManagedHost),
    #[clap(
        about = "Switch a machine in/out of maintenance mode",
        subcommand,
        visible_alias = "fix"
    )]
    Maintenance(MaintenanceAction),
    #[clap(
        about = "Quarantine a host (disabling network access on host)",
        subcommand
    )]
    Quarantine(QuarantineAction),
    #[clap(about = "Reset host reprovisioning back to CheckingFirmware")]
    ResetHostReprovisioning(ResetHostReprovisioning),
    #[clap(subcommand, about = "Power Manager related settings.")]
    PowerOptions(PowerOptions),
    #[clap(about = "Start updates for machines with delayed updates, such as GB200")]
    StartUpdates(StartUpdates),
    #[clap(about = "Set the primary DPU for the managed host")]
    SetPrimaryDpu(SetPrimaryDpu),
    #[clap(about = "Download debug bundle with logs for a specific host")]
    DebugBundle(DebugBundle),
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
        default_value(None),
        help = "Show managed host specific details (using host or dpu machine id), leave empty for all"
    )]
    pub machine: Option<MachineId>,

    #[clap(
        short,
        long,
        action,
        help = "Show IP details in summary",
        conflicts_with = "machine"
    )]
    pub ips: bool,

    #[clap(
        short = 't',
        long,
        action,
        help = "Show only hosts for this instance type"
    )]
    pub instance_type_id: Option<String>,

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

    #[clap(long, action, help = "Show only hosts in quarantine")]
    pub quarantine: bool,
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

/// Enable or disable quarantine mode on a managed host.
#[derive(Parser, Debug)]
pub enum QuarantineAction {
    /// Put this machine into quarantine. Prevents any network access on the host machine.
    On(QuarantineOn),
    /// Take this machine out of quarantine
    Off(QuarantineOff),
}

/// Reset host reprovisioning state
#[derive(Parser, Debug)]
pub struct ResetHostReprovisioning {
    #[clap(long, required(true), help = "Machine ID to reset host reprovision on")]
    pub machine: MachineId,
}

#[derive(Parser, Debug)]
pub struct QuarantineOn {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: MachineId,

    #[clap(
        long,
        visible_alias = "reason",
        required(true),
        help = "Reason for quarantining this host"
    )]
    pub reason: String,
}

#[derive(Parser, Debug)]
pub struct QuarantineOff {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: MachineId,
}

#[derive(Parser, Debug)]
pub struct MaintenanceOn {
    #[clap(long, required(true), help = "Managed Host ID")]
    pub host: MachineId,

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
    pub host: MachineId,
}

#[derive(Parser, Debug)]
pub struct StartUpdates {
    #[clap(long, required(true), help = "Machine IDs to update, space separated", num_args = 1.., value_delimiter = ' ')]
    pub machines: Vec<MachineId>,
    #[clap(
        long,
        help = "Start of the maintenance window for doing the updates (default now) format 2025-01-02T03:04:05+0000 or 2025-01-02T03:04:05 for local time"
    )]
    pub start: Option<String>,
    #[clap(
        long,
        help = "End of starting new updates (default 24 hours from the start) format 2025-01-02T03:04:05+0000 or 2025-01-02T03:04:05 for local time"
    )]
    pub end: Option<String>,
    #[arg(long, help = "Cancel any new updates")]
    pub cancel: bool,
}

#[derive(Parser, Debug)]
pub enum PowerOptions {
    Show(ShowPowerOptions),
    Update(UpdatePowerOptions),
    #[clap(about = "Get machine ingestion state")]
    GetMachineIngestionState(BmcMacAddress),
    #[clap(about = "Allow a machine to power on")]
    AllowIngestionAndPowerOn(BmcMacAddress),
}

#[derive(Parser, Debug)]
pub struct ShowPowerOptions {
    #[clap(help = "ID of the host or nothing for all")]
    pub machine: Option<MachineId>,
}

#[derive(Parser, Debug)]
pub struct UpdatePowerOptions {
    #[clap(help = "ID of the host")]
    pub machine: MachineId,
    #[clap(long, short, help = "Desired Power State")]
    pub desired_power_state: DesiredPowerState,
}

#[derive(ValueEnum, Parser, Debug, Clone, PartialEq)]
pub enum DesiredPowerState {
    On,
    Off,
    PowerManagerDisabled,
}

#[derive(Parser, Debug)]
pub struct SetPrimaryDpu {
    #[clap(help = "ID of the host machine")]
    pub host_machine_id: MachineId,
    #[clap(help = "ID of the DPU machine to make primary")]
    pub dpu_machine_id: MachineId,
    #[clap(long, help = "Reboot the host after the update")]
    pub reboot: bool,
}

#[derive(Parser, Debug)]
pub struct DebugBundle {
    #[clap(help = "The host machine ID to collect logs for")]
    pub host_id: String,

    #[clap(
        long,
        help = "Start time: 'YYYY-MM-DD HH:MM:SS' or 'HH:MM:SS' (uses today's date). Default: local timezone, use --utc for UTC"
    )]
    pub start_time: String,

    #[clap(
        long,
        help = "End time: 'YYYY-MM-DD HH:MM:SS' or 'HH:MM:SS' (uses today's date). Defaults to current time if not provided. Default: local timezone, use --utc for UTC"
    )]
    pub end_time: Option<String>,

    #[clap(
        long,
        help = "Interpret start-time and end-time as UTC instead of local timezone"
    )]
    pub utc: bool,

    #[clap(
        long,
        default_value = "/tmp",
        help = "Output directory path for the debug bundle (default: /tmp)"
    )]
    pub output_path: String,

    #[clap(
        long,
        help = "Grafana base URL (e.g., https://grafana.example.com). If not provided, log collection is skipped."
    )]
    pub grafana_url: Option<String>,

    #[clap(
        long,
        default_value = "5000",
        help = "Batch size for log collection (default: 5000, max: 5000)"
    )]
    pub batch_size: u32,
}

#[derive(Parser, Debug)]
pub struct BmcMacAddress {
    #[clap(short, long, help = "MAC Address of host BMC endpoint")]
    pub mac_address: mac_address::MacAddress,
}
