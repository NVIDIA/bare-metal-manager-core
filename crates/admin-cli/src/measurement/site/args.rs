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

/*!
 *  Measured Boot CLI arguments for the `measurement site` subcommand.
 *
 * This provides the CLI subcommands and arguments for:
 *  - `site import`: Import a site model (profiles + bundles) from a file.
 *  - `site export`: Export a site model from DB -> to a file.
 *  - `site trusted-machine approve`: Create a trusted machine approval.
 *  - `site trusted-machine remove`: Remove a trusted machine approval.
 *  - `site trusted-machine list`: List all trusted machine approvals.
 *  - `site trusted-profile approve`: Create a trusted profile approval.
 *  - `site trusted-profile remove`: Remove a trusted profile approval.
 *  - `site trusted-profile list`: List all trusted profile approvals.
*/

use carbide_uuid::measured_boot::{
    MeasurementApprovedMachineId, MeasurementApprovedProfileId, MeasurementSystemProfileId,
    TrustedMachineId,
};
use clap::Parser;
use measured_boot::records::MeasurementApprovedType;

/// CmdSite provides a container for the `site` subcommand, which itself
/// contains other subcommands for working with the site (i.e. export
/// and import).
#[derive(Parser, Debug)]
pub enum CmdSite {
    #[clap(about = "Import a site from an export file.", visible_alias = "i")]
    Import(Import),

    #[clap(about = "Export a site to an export file.", visible_alias = "e")]
    Export(Export),

    #[clap(subcommand, about = "Managed trusted machines.", visible_alias = "m")]
    TrustedMachine(TrustedMachine),

    #[clap(subcommand, about = "Managed trusted profiles.", visible_alias = "p")]
    TrustedProfile(TrustedProfile),
}

/// Import imports a site from a file.
#[derive(Parser, Debug)]
pub struct Import {
    #[clap(help = "The path of the input JSON file.")]
    pub path: String,
}

/// Export exports a site to stdout, a file, etc.
#[derive(Parser, Debug)]
pub struct Export {
    #[clap(long, help = "An optional path to write the file to.")]
    pub path: Option<String>,
}

/// TrustedMachine configures trusted machine settings.
#[derive(Parser, Debug)]
pub enum TrustedMachine {
    #[clap(
        about = "Approve a trusted machine for auto-promoting its measurements.",
        visible_alias = "a"
    )]
    Approve(ApproveMachine),

    #[clap(
        subcommand,
        about = "Remove a trusted machine approval.",
        visible_alias = "r"
    )]
    Remove(RemoveMachine),

    #[clap(about = "List all active machine approvals.", visible_alias = "l")]
    List(ListMachines),
}

/// TrustedProfile configures trusted profile settings.
#[derive(Parser, Debug)]
pub enum TrustedProfile {
    #[clap(
        about = "Allow auto-promoting of measurements from machines matching a profile.",
        visible_alias = "a"
    )]
    Approve(ApproveProfile),

    #[clap(
        subcommand,
        about = "Remove a trusted profile approval.",
        visible_alias = "r"
    )]
    Remove(RemoveProfile),

    #[clap(about = "List all active profile approvals.", visible_alias = "l")]
    List(ListProfiles),
}

/// ApproveMachine approves a machine for auto-promoting its measurement
/// journal entries into a golden measurement bundle.
#[derive(Parser, Debug)]
pub struct ApproveMachine {
    #[clap(help = "The machine-id to approve (or '*' for all).")]
    pub machine_id: TrustedMachineId,

    #[clap(required = true, help = "Whether to set `oneshot` or `persist`.")]
    pub approval_type: MeasurementApprovedType,

    #[clap(long, help = "Specific PCR register selector. All if unset.")]
    pub pcr_registers: Option<String>,

    #[clap(long, help = "Optional comments about this approval.")]
    pub comments: Option<String>,
}

/// RemoveMachine removes a machine from auto-approval, by approval ID
/// or machine ID.
//
// The compiler yells it starts by "By", not really
// understanding that its a part of the CLI UX.
#[allow(clippy::enum_variant_names)]
#[derive(Parser, Debug)]
pub enum RemoveMachine {
    #[clap(about = "Remove by approval ID.")]
    ByApprovalId(RemoveMachineByApprovalId),

    #[clap(about = "Remove by machine ID.")]
    ByMachineId(RemoveMachineByMachineId),
}

/// RemoveMachineByApprovalId removes a trusted machine approval
/// for the given approval ID.
#[derive(Parser, Debug)]
pub struct RemoveMachineByApprovalId {
    #[clap(help = "The approval-id to remove.")]
    pub approval_id: MeasurementApprovedMachineId,
}

/// RemoveMachineByMachineId removes a trusted machine approval
/// for the given machine ID.
#[derive(Parser, Debug)]
pub struct RemoveMachineByMachineId {
    #[clap(help = "The machine-id to remove.")]
    pub machine_id: TrustedMachineId,
}

/// ListMachines is used to list all active machine approvals.
#[derive(Parser, Debug)]
pub struct ListMachines {}

/// ApproveProfile approves a profile for auto-promoting its
/// measurement journal entries into a golden measurement bundle.
#[derive(Parser, Debug)]
pub struct ApproveProfile {
    #[clap(help = "The profile-id to approve.")]
    pub profile_id: MeasurementSystemProfileId,

    #[clap(required = true, help = "Whether to set `oneshot` or `persist`.")]
    pub approval_type: MeasurementApprovedType,

    #[clap(long, help = "Specific PCR register selector. All if unset.")]
    pub pcr_registers: Option<String>,

    #[clap(long, help = "Optional comments about this approval.")]
    pub comments: Option<String>,
}

/// RemoveProfile removes a machine from auto-approval, by approval ID
/// or profile ID.
//
// The compiler yells it starts by "By", not really
// understanding that its a part of the CLI UX.
#[allow(clippy::enum_variant_names)]
#[derive(Parser, Debug)]
pub enum RemoveProfile {
    #[clap(about = "Remove by approval ID.")]
    ByApprovalId(RemoveProfileByApprovalId),

    #[clap(about = "Remove by profile ID.")]
    ByProfileId(RemoveProfileByProfileId),
}

/// RemoveProfileByApprovalId removes a trusted profile approval
/// for the given approval ID.
#[derive(Parser, Debug)]
pub struct RemoveProfileByApprovalId {
    #[clap(help = "The approval-id to remove.")]
    pub approval_id: MeasurementApprovedProfileId,
}

/// RemoveProfileByProfileId removes a trusted profile approval
/// for the given profile ID.
#[derive(Parser, Debug)]
pub struct RemoveProfileByProfileId {
    #[clap(help = "The profile-id to remove.")]
    pub profile_id: MeasurementSystemProfileId,
}

/// ListProfiles is used to list all active profile approvals.
#[derive(Parser, Debug)]
pub struct ListProfiles {}
