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

use crate::cfg::measurement::{parse_colon_pairs, parse_pcr_register_values, KvPair};
use carbide::measured_boot::dto::keys::MockMachineId;
use carbide::measured_boot::interface::common::PcrRegisterValue;
use clap::Parser;

///////////////////////////////////////////////////////////////////////////////
/// CmdMockMachine provides a container for the `mock-machine`
/// subcommand, which itself contains other subcommands
/// for working with mock machines.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub enum CmdMockMachine {
    #[clap(
        about = "Create, or 'discover', a new mock machine.",
        visible_alias = "c"
    )]
    Create(Create),

    #[clap(about = "Delete an existing mock machine.", visible_alias = "d")]
    Delete(Delete),

    #[clap(about = "Send measurements for a mock machine.", visible_alias = "a")]
    Attest(Attest),

    #[clap(about = "Get all info about a mock machine.", visible_alias = "s")]
    Show(Show),

    #[clap(about = "List all mock machines + their info.", visible_alias = "l")]
    List(List),
}

///////////////////////////////////////////////////////////////////////////////
/// Create "discovers" a new mock machine.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub struct Create {
    #[clap(help = "The machine-id to set for the machine.")]
    pub machine_id: MockMachineId,

    #[clap(required = true, help = "The vendor (e.g. dell).")]
    pub vendor: String,

    #[clap(required = true, help = "The product (e.g. poweredge_r750).")]
    pub product: String,

    /// extra_attrs are extra k:v,... attributes to be
    /// assigned to the profile. Currently the only
    /// formal attributes are vendor and product, and
    /// this is intended for testing purposes only.
    #[clap(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        help = "A comma-separated list of additional k:v,k:v,... attributes to set."
    )]
    #[arg(value_parser = parse_colon_pairs)]
    pub extra_attrs: Vec<KvPair>,
}

///////////////////////////////////////////////////////////////////////////////
/// Delete will delete a mock machine.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub struct Delete {
    #[clap(help = "The machine-id to delete.")]
    pub machine_id: MockMachineId,
}

///////////////////////////////////////////////////////////////////////////////
/// Attest sends a measurement report for the given mock machine ID,
/// where the measurement report then goes through attestation in an
/// attempt to match a bundle.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub struct Attest {
    #[clap(help = "The machine ID of the machine to associate this report with.")]
    pub machine_id: MockMachineId,

    #[clap(
        required = true,
        use_value_delimiter = true,
        value_delimiter = ',',
        help = "Comma-separated list of {pcr_register:value,...} to associate with this report."
    )]
    #[arg(value_parser = parse_pcr_register_values)]
    pub values: Vec<PcrRegisterValue>,
}

///////////////////////////////////////////////////////////////////////////////
/// List lists all mock machines.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub struct List {}

///////////////////////////////////////////////////////////////////////////////
/// Show will get a mock-machine for the given ID, or all machines
/// if no machine ID is provided.
///////////////////////////////////////////////////////////////////////////////

#[derive(Parser, Debug)]
pub struct Show {
    #[clap(help = "The machine ID to show.")]
    pub machine_id: Option<MockMachineId>,
}
