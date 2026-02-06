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
use clap::Parser;

use crate::machine::MachineQuery;

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
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

#[derive(Parser, Debug, Clone)]
pub enum HostReprovision {
    #[clap(about = "Set the host in reprovisioning mode.")]
    Set(HostReprovisionSet),
    #[clap(about = "Clear the reprovisioning mode.")]
    Clear(HostReprovisionClear),
    #[clap(about = "List all hosts pending reprovisioning.")]
    List,
    // TODO: Remove when manual upgrade feature is removed
    #[clap(about = "Mark manual firmware upgrade as complete for a host.")]
    MarkManualUpgradeComplete(ManualFirmwareUpgradeComplete),
}

#[derive(Parser, Debug, Clone)]
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

#[derive(Parser, Debug, Clone)]
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

#[derive(Parser, Debug, Clone)]
pub struct ManualFirmwareUpgradeComplete {
    #[clap(
        short,
        long,
        help = "Machine ID for which manual firmware upgrade should be set."
    )]
    pub id: MachineId,
}
