/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use clap::Parser;

#[derive(Parser)]
#[clap(name = env!("CARGO_BIN_NAME"))]
pub(crate) struct Options {
    #[clap(short, long, parse(from_occurrences))]
    pub debug: u8,

    #[clap(
        short,
        long,
        alias("listen"),
        multiple_values(false),
        require_equals(true),
        default_value = "https://[::1]:1079"
    )]
    pub api: String,

    #[clap(subcommand)]
    pub subcmd: Command,
}

#[derive(Parser)]
pub(crate) enum Command {
    #[clap(about = "Run discovery")]
    Discovery(Discovery),
    #[clap(about = "Done provisioning")]
    Done(Done),
    #[clap(about = "Reset (deprovisioning)")]
    Reset(Reset),
}

#[derive(Parser)]
pub struct Discovery {
    #[clap(short, long, multiple_values(false), require_equals(true))]
    pub uuid: String,
}

#[derive(Parser)]
pub struct Done {
    #[clap(short, long, multiple_values(false), require_equals(true))]
    pub uuid: String,
}

#[derive(Parser)]
pub struct Reset {
    #[clap(short, long, multiple_values(false), require_equals(true))]
    pub uuid: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
