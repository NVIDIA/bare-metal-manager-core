/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/*!
 *  Measured Boot CLI arguments for the `measurement mock-machine` subcommand.
 *
 * This provides the CLI subcommands and arguments for:
 *  - `mock-machine create`: Creates a new "mock" machine.
 *  - `mock-machine delete`: Deletes an existing mock machine.
 *  - `mock-machine attest`: Sends a measurement report for a mock machine.
 *  - `mock-machine show [id]`: Shows detailed info about mock machine(s).
 *  - `mock-machine list``: Lists all mock machines.
*/

use carbide_uuid::machine::MachineId;
use clap::Parser;
use measured_boot::pcr::PcrRegisterValue;

use crate::cfg::measurement::parse_pcr_register_values;

/// CmdMachine provides a container for the `mock-machine`
/// subcommand, which itself contains other subcommands
/// for working with mock machines.
#[derive(Parser, Debug)]
pub enum CmdMachine {
    #[clap(about = "Send measurements for a machine.", visible_alias = "a")]
    Attest(Attest),

    #[clap(about = "Get all info about a machine.", visible_alias = "s")]
    Show(Show),

    #[clap(about = "List all machines + their info.", visible_alias = "l")]
    List(List),
}

/// Attest sends a measurement report for the given machine ID,
/// where the measurement report then goes through attestation in an
/// attempt to match a bundle.
#[derive(Parser, Debug)]
pub struct Attest {
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

/// List lists all candidate machines.
#[derive(Parser, Debug)]
pub struct List {}

/// Show will get a candidate machine for the given ID, or all machines
/// if no machine ID is provided.
#[derive(Parser, Debug)]
pub struct Show {
    #[clap(help = "The machine ID to show.")]
    pub machine_id: Option<MachineId>,
}
