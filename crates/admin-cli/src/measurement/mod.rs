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

use ::rpc::admin_cli::{CarbideCliResult, ToTable, set_summary};
use carbide_uuid::machine::MachineId;
use serde::Serialize;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::measurement::{Cmd, GlobalOptions};
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        // Build internal GlobalOptions from RuntimeContext
        let args = GlobalOptions {
            format: ctx.config.format,
            extended: ctx.config.extended,
        };
        set_summary(!args.extended);
        let mut cli_data = global::cmds::CliData {
            grpc_conn: &ctx.api_client,
            args: &args,
        };

        match self {
            // Handle everything with the `bundle` subcommand.
            Cmd::Bundle(subcmd) => bundle::cmds::dispatch(subcmd, &mut cli_data).await?,

            // Handle everything with the `journal` subcommand.
            Cmd::Journal(subcmd) => journal::cmds::dispatch(subcmd, &mut cli_data).await?,

            // Handle everything with the `profile` subcommand.
            Cmd::Profile(subcmd) => profile::cmds::dispatch(subcmd, &mut cli_data).await?,

            // Handle everything with the `report` subcommand.
            Cmd::Report(subcmd) => report::cmds::dispatch(subcmd, &mut cli_data).await?,

            // Handle everything with the `machine` subcommand.
            Cmd::Machine(subcmd) => machine::cmds::dispatch(subcmd, &mut cli_data).await?,

            // Handle everything with the `site` subcommand.
            Cmd::Site(subcmd) => site::cmds::dispatch(subcmd, &mut cli_data).await?,
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub struct MachineIdList(Vec<MachineId>);

impl ToTable for MachineIdList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["machine_id"]);
        for machine_id in self.0.iter() {
            table.add_row(prettytable::row![machine_id]);
        }
        Ok(table.to_string())
    }
}
