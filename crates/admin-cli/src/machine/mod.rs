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

pub mod auto_update;
pub mod common;
pub mod dpu_ssh_credentials;
pub mod force_delete;
pub mod hardware_info;
pub mod health_override;
pub mod metadata;
pub mod network;
pub mod nvlink_info;
pub mod positions;
pub mod reboot;
pub mod show;

#[cfg(test)]
mod tests;

// Cross-module re-exports.
pub use auto_update::args::Args as MachineAutoupdate;
use clap::Parser;
pub use common::{MachineQuery, NetworkConfigQuery};
pub use health_override::args::HealthOverrideTemplates;
pub use health_override::cmd::get_health_report;
pub use show::args::Args as ShowMachine;
pub use show::cmd::{get_next_free_machine, handle_show};

use crate::cfg::dispatch::Dispatch;

#[derive(Parser, Debug, Dispatch)]
pub enum Cmd {
    #[clap(about = "Display Machine information")]
    Show(show::Args),
    #[clap(about = "Print DPU admin SSH username:password")]
    DpuSshCredentials(dpu_ssh_credentials::Args),
    #[clap(subcommand, about = "Networking information")]
    Network(network::Args),
    #[clap(
        about = "Health override related handling",
        subcommand,
        visible_alias = "ho"
    )]
    HealthOverride(health_override::Args),
    #[clap(about = "Reboot a machine")]
    Reboot(reboot::Args),
    #[clap(about = "Force delete a machine")]
    ForceDelete(force_delete::Args),
    #[clap(about = "Set individual machine firmware autoupdate (host only)")]
    AutoUpdate(auto_update::Args),
    #[clap(subcommand, about = "Edit Metadata associated with a Machine")]
    Metadata(metadata::Args),
    #[clap(subcommand, about = "Update/show machine hardware info")]
    HardwareInfo(hardware_info::Args),
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
    Positions(positions::Args),
    #[clap(subcommand, about = "Update/show NVLink info for an MNNVL machine")]
    NvlinkInfo(nvlink_info::Args),
}
