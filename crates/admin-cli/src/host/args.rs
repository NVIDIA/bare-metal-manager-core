/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
