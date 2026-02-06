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
