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
 *  Measured Boot CLI arguments for the `measurement report` subcommand.
 *
 * This provides the CLI subcommands and arguments for:
 *  - `report create`: Create a new machine measurement report.
 *  - `report delete`: Delete an existing machine measurement report.
 *  - `report promote`: Promote a machine measurement report to a bundle.
 *  - `report revoke`: Create a revoked measurement bundle from a report.
 *  - `report show all`: Show all info about all measurement reports.
 *  - `report show id`: Show all info about a specific report.
 *  - `report show machine`: Show all info about reports for a given machine.
 *  - `report list all`: List high level info about all reports.
 *  - `report list machine`: List all reports for a given machine.
 *  - `report match``
*/

use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::MeasurementReportId;
use clap::Parser;
use measured_boot::pcr::{PcrRegisterValue, PcrSet, parse_pcr_index_input};

use crate::cfg::measurement::parse_pcr_register_values;

// CmdReport provides a container for the `report`
// subcommand, which itself contains other subcommands
// for working with reports.
#[derive(Parser, Debug)]
pub enum CmdReport {
    #[clap(
        about = "Create a new report with a given config.",
        visible_alias = "c"
    )]
    Create(Create),

    #[clap(about = "Delete a report by ID.", visible_alias = "d")]
    Delete(Delete),

    #[clap(
        about = "Promote a specific journal entry to an active bundle",
        visible_alias = "p"
    )]
    Promote(Promote),

    #[clap(
        about = "Mark a specific journal entry as a revoked bundle.",
        visible_alias = "r"
    )]
    Revoke(Revoke),

    #[clap(
        subcommand,
        about = "Show reports in different ways.",
        visible_alias = "s"
    )]
    Show(ShowFor),

    #[clap(
        subcommand,
        about = "List reports by various ways.",
        visible_alias = "l"
    )]
    List(List),

    #[clap(
        about = "Match reports with the provided PCR register values.",
        visible_alias = "m"
    )]
    Match(Match),
}

/// Create is used for creating reports, which really
/// should be happening during machine attestation.
#[derive(Parser, Debug)]
pub struct Create {
    #[clap(help = "The machine ID of the machine to associate this report with.")]
    pub machine_id: MachineId,

    #[clap(
        required = true,
        use_value_delimiter = true,
        value_delimiter = ',',
        help = "Comma-separated list of {pcr_register:value,...} to associate with this report."
    )]
    #[arg(value_parser = parse_pcr_register_values)]
    pub values: Vec<PcrRegisterValue>,
}

/// Delete a profile by ID.
#[derive(Parser, Debug)]
pub struct Delete {
    #[clap(help = "The report ID.")]
    pub report_id: MeasurementReportId,
}

/// Promote is used to promote a report to a measurement bundle,
/// with the ability to select which PCR registers to select from the
/// report to use for creating the new bundle.
#[derive(Parser, Debug)]
pub struct Promote {
    #[clap(help = "The report ID to promote.")]
    pub report_id: MeasurementReportId,

    #[clap(
        long,
        help = "Select a specific PCR range to use for the promoted bundle."
    )]
    #[arg(value_parser = parse_pcr_index_input)]
    pub pcr_registers: Option<PcrSet>,
}

/// Revoke is used to mark a report as a revoked measurement bundle,
/// with the ability to select which PCR registers to select from the
/// report to use for creating the new (and revoked) bundle.
#[derive(Parser, Debug)]
pub struct Revoke {
    #[clap(help = "The report ID to revoke.")]
    pub report_id: MeasurementReportId,

    #[clap(
        long,
        help = "Select a specific PCR range to use for the revoked bundle."
    )]
    #[arg(value_parser = parse_pcr_index_input)]
    pub pcr_registers: Option<PcrSet>,
}

/// Show a report for an ID, reports for a machine, or all reports.
#[derive(Parser, Debug)]
pub enum ShowFor {
    #[clap(about = "Show a report ID.")]
    Id(ShowForId),

    #[clap(about = "Show reports for a machine.")]
    Machine(ShowForMachine),

    #[clap(about = "Show all reports.")]
    All,
}

/// Show a report for the given ID.
#[derive(Parser, Debug)]
pub struct ShowForId {
    #[clap(help = "The report ID.")]
    pub report_id: MeasurementReportId,
}

/// Show all reports for a machine.
#[derive(Parser, Debug)]
pub struct ShowForMachine {
    #[clap(help = "The profile name.")]
    pub machine_id: String,
}

/// List provides a few ways to list things.
#[derive(Parser, Debug)]
pub enum List {
    #[clap(about = "List all reports", visible_alias = "a")]
    All(ListAll),

    #[clap(
        about = "List all reports for a given machine ID.",
        visible_alias = "m"
    )]
    Machines(ListMachines),
}

/// ListAll will list all profiles.
#[derive(Parser, Debug)]
pub struct ListAll {}

/// ListMachines will list all machines matching this report.
#[derive(Parser, Debug)]
pub struct ListMachines {
    #[clap(help = "The machine ID.")]
    pub machine_id: MachineId,
}

/// Match is used for finding reports matching the provided PCR pairs.
#[derive(Parser, Debug)]
pub struct Match {
    #[clap(
        required = true,
        use_value_delimiter = true,
        value_delimiter = ',',
        help = "Comma-separated list of {pcr_register:value,...} to match on."
    )]
    #[arg(value_parser = parse_pcr_register_values)]
    pub values: Vec<PcrRegisterValue>,
}
