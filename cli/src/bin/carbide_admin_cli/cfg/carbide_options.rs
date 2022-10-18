/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
#[clap(name = env!("CARGO_BIN_NAME"))]
#[clap(propagate_version = true)]
#[clap(author = "Slack channel #swngc-forge-dev")]
#[clap(version = "0.0.1")]
pub struct CarbideOptions {
    #[clap(short, long, multiple_values(false), env = "CARBIDE_API_URL")]
    #[clap(
        help = "Default to CARBIDE_API_URL environment variable or $HOME/.config/carbide_api_cli.json file."
    )]
    pub carbide_api: Option<String>,
    #[clap(short, long, multiple_values(false), action)]
    pub json: bool,
    #[clap(short, long, parse(from_occurrences))]
    pub debug: u8,
    #[clap(subcommand)]
    pub commands: CarbideCommand,
}

#[derive(Parser, Debug)]
pub enum CarbideCommand {
    #[clap(about = "Machine related handling", subcommand)]
    Machine(Machine),
    #[clap(about = "Instance related handling", subcommand)]
    Instance(Instance),
}

#[derive(Parser, Debug)]
pub enum Machine {
    #[clap(about = "Display Machine information")]
    Show(ShowMachine),
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_machine")
        .required(true)
        .args(&["all", "uuid"])))]
pub struct ShowMachine {
    #[clap(short, long, multiple_values(false), action)]
    pub all: bool,

    #[clap(short, long, multiple_values(false))]
    pub uuid: Option<String>,
}

#[derive(Parser, Debug)]
pub enum Instance {
    #[clap(about = "Display Instance information")]
    Show(ShowInstance),
}

#[derive(Parser, Debug)]
#[clap(group(
        ArgGroup::new("show_instance")
        .required(true)
        .args(&["all", "uuid", "machineid"])))]
pub struct ShowInstance {
    #[clap(short, long, multiple_values(false), action)]
    pub all: bool,

    #[clap(short, long, multiple_values(false))]
    pub uuid: Option<String>,

    #[clap(short, long, multiple_values(false))]
    pub machineid: Option<String>,

    #[clap(short, long, multiple_values(false), action)]
    pub extrainfo: bool,
}

impl CarbideOptions {
    pub fn load() -> Self {
        Self::parse()
    }
}
