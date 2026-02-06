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
