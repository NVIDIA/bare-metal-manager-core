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

//!
//! `measurement` subcommand module, containing other subcommands,
//! dispatchers, args, and backing functions.
//!

pub mod bundle;
pub mod global;
pub mod journal;
pub mod machine;
pub mod profile;
pub mod report;
pub mod site;

use crate::cfg::measurement::{Cmd, GlobalOptions};
use crate::measurement::global::cmds::get_forge_client;
use ::rpc::forge_tls_client::ApiConfig;
use utils::admin_cli::set_summary;

pub async fn dispatch(
    command: &Cmd,
    args: &GlobalOptions,
    api_config: &ApiConfig<'_>,
) -> eyre::Result<()> {
    set_summary(!args.extended);
    let mut grpc_conn = get_forge_client(api_config).await?;
    let mut cli_data = global::cmds::CliData {
        grpc_conn: &mut grpc_conn,
        args,
    };

    match command {
        // Handle everything with the `bundle` subcommand.
        Cmd::Bundle(cmd) => bundle::cmds::dispatch(cmd, &mut cli_data).await?,

        // Handle everything with the `journal` subcommand.
        Cmd::Journal(cmd) => journal::cmds::dispatch(cmd, &mut cli_data).await?,

        // Handle everything with the `profile` subcommand.
        Cmd::Profile(cmd) => profile::cmds::dispatch(cmd, &mut cli_data).await?,

        // Handle everything with the `report` subcommand.
        Cmd::Report(cmd) => report::cmds::dispatch(cmd, &mut cli_data).await?,

        // Handle everything with the `mock-machine` subcommand.
        Cmd::Scout(cmd) => machine::cmds::dispatch(cmd, &mut cli_data).await?,

        // Handle everything with the `site` subcommand.
        Cmd::Site(cmd) => site::cmds::dispatch(cmd, &mut cli_data).await?,
    }

    Ok(())
}
