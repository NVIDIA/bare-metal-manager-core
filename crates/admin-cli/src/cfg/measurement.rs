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

/*

/// cfg/measurement.rs
/// Baseline top-level arguments for the Measured Boot CLI commands.

*/

use ::rpc::admin_cli::OutputFormat;
use clap::Parser;
use measured_boot::pcr::PcrRegisterValue;

use crate::measurement::{bundle, journal, machine, profile, report, site};

// KvPair is a really simple struct for holding
// a key/value pair, and is used for parsing
// k:v,... groupings via the CLI.
#[derive(Clone, Debug)]
pub struct KvPair {
    pub key: String,
    pub value: String,
}

pub fn parse_colon_pairs(arg: &str) -> eyre::Result<KvPair> {
    let pair: Vec<&str> = arg.split(':').collect();
    if pair.len() != 2 {
        return Err(eyre::eyre!("must be <first>:<second>"));
    }

    Ok(KvPair {
        key: pair[0].to_string(),
        value: pair[1].to_string(),
    })
}

pub fn parse_pcr_register_values(arg: &str) -> eyre::Result<PcrRegisterValue> {
    let pair: Vec<&str> = arg.split(':').collect();
    if pair.len() != 2 {
        return Err(eyre::eyre!("must be <num>:<val>"));
    }

    let pcr_register = pair[0]
        .parse::<i16>()
        .map_err(|_| eyre::eyre!("pcr_register must be a number"))?;
    let sha = pair[1].to_string();
    Ok(PcrRegisterValue {
        pcr_register,
        sha_any: sha,
    })
}

pub struct GlobalOptions {
    pub format: OutputFormat,
    pub extended: bool,
}

/// Cmd is the top-level subcommands enum, which contains mappings for all
/// top-level commands (e.g. `bundle`, `journal`, etc).

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(
        subcommand,
        about = "Work with golden measurement bundles.",
        visible_alias = "b"
    )]
    Bundle(bundle::args::CmdBundle),

    #[clap(
        subcommand,
        about = "Work with machine meausrement journals",
        visible_alias = "j"
    )]
    Journal(journal::args::CmdJournal),

    #[clap(subcommand, about = "Work with machine reports", visible_alias = "r")]
    Report(report::args::CmdReport),

    #[clap(
        subcommand,
        about = "Work with mock-machine entries",
        visible_alias = "m"
    )]
    Machine(machine::args::CmdMachine),

    #[clap(
        subcommand,
        about = "Work with machine hardware profiles",
        visible_alias = "p"
    )]
    Profile(profile::args::CmdProfile),

    #[clap(subcommand, about = "Work with site-wide things.", visible_alias = "s")]
    Site(site::args::CmdSite),
}
