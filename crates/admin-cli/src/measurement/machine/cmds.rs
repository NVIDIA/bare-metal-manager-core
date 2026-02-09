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
//! `measurement mock-machine` subcommand dispatcher + backing functions.
//!

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, ToTable, cli_output};
use ::rpc::protos::measured_boot::{
    AttestCandidateMachineRequest, ShowCandidateMachineRequest, show_candidate_machine_request,
};
use measured_boot::machine::CandidateMachine;
use measured_boot::records::CandidateMachineSummary;
use measured_boot::report::MeasurementReport;
use serde::Serialize;

use crate::measurement::global;
use crate::measurement::machine::args::{Attest, CmdMachine, Show};
use crate::rpc::ApiClient;

/// dispatch matches + dispatches the correct command
/// for the `mock-machine` subcommand.
pub async fn dispatch(
    cmd: CmdMachine,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> CarbideCliResult<()> {
    match cmd {
        CmdMachine::Attest(local_args) => {
            cli_output(
                attest(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdMachine::Show(local_args) => {
            if local_args.machine_id.is_some() {
                cli_output(
                    show_by_id(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            } else {
                cli_output(
                    show_all(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
        }
        CmdMachine::List(_) => {
            cli_output(
                list(cli.grpc_conn).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
    }
    Ok(())
}

/// attest sends attestation data for the given machine ID, as in, PCR
/// register + value pairings, which results in a journal entry being made.
pub async fn attest(grpc_conn: &ApiClient, attest: Attest) -> CarbideCliResult<MeasurementReport> {
    // Request.
    let request = AttestCandidateMachineRequest {
        machine_id: attest.machine_id.to_string(),
        pcr_values: attest.values.into_iter().map(Into::into).collect(),
    };

    // Response.
    let response = grpc_conn.0.attest_candidate_machine(request).await?;

    MeasurementReport::from_grpc(response.report.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// show_by_id shows all info about a given machine ID.
pub async fn show_by_id(grpc_conn: &ApiClient, show: Show) -> CarbideCliResult<CandidateMachine> {
    // Prepare.
    // TODO(chet): This exists just because of how I'm dispatching
    // commands, since &Show gets reused for showing all (where machine_id
    // is unset, or showing a specific machine ID). Ultimately this
    // shouldn't ever actually get hit, but it exists just incase. That
    // said, I should look into see if I can just have clap validate this.
    let Some(machine_id) = show.machine_id else {
        return Err(CarbideCliError::GenericError(String::from(
            "machine_id must be set to get a machine",
        )));
    };

    // Request.
    let request = ShowCandidateMachineRequest {
        selector: Some(show_candidate_machine_request::Selector::MachineId(
            machine_id.to_string(),
        )),
    };

    // Response.
    let response = grpc_conn.0.show_candidate_machine(request).await?;

    CandidateMachine::from_grpc(response.machine.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// show_all shows all info about all machines.
pub async fn show_all(
    grpc_conn: &ApiClient,
    _show: Show,
) -> CarbideCliResult<CandidateMachineList> {
    Ok(CandidateMachineList(
        grpc_conn
            .0
            .show_candidate_machines()
            .await?
            .machines
            .into_iter()
            .map(|machine| {
                CandidateMachine::try_from(machine)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<CandidateMachine>>>()?,
    ))
}

/// list lists all machine IDs.
pub async fn list(grpc_conn: &ApiClient) -> CarbideCliResult<CandidateMachineSummaryList> {
    Ok(CandidateMachineSummaryList(
        grpc_conn
            .0
            .list_candidate_machines()
            .await?
            .machines
            .into_iter()
            .map(|machine| {
                CandidateMachineSummary::try_from(machine)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<CandidateMachineSummary>>>()?,
    ))
}

/// CandidateMachineSummaryList just implements a newtype pattern
/// for a Vec<CandidateMachineSummary> so the ToTable trait can
/// be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct CandidateMachineSummaryList(Vec<CandidateMachineSummary>);

impl ToTable for CandidateMachineSummaryList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["machine_id", "created_ts"]);
        for rec in self.0.iter() {
            table.add_row(prettytable::row![rec.machine_id, rec.ts]);
        }
        Ok(table.to_string())
    }
}

/// CandidateMachineList just implements a newtype
/// pattern for a Vec<CandidateMachine> so the ToTable
/// trait can be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct CandidateMachineList(Vec<CandidateMachine>);

impl ToTable for CandidateMachineList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row![
            "machine_id",
            "state",
            "created_ts",
            "updated_ts",
            "journal",
            "attributes",
        ]);
        for record in self.0.iter() {
            let journal_table = match &record.journal {
                Some(journal) => journal.to_nested_prettytable(),
                None => {
                    let mut not_found = prettytable::Table::new();
                    not_found.add_row(prettytable::row!["<no journal found>"]);
                    not_found
                }
            };
            let mut attrs_table = prettytable::Table::new();
            attrs_table.add_row(prettytable::row!["name", "value"]);
            for (key, value) in record.attrs.iter() {
                attrs_table.add_row(prettytable::row![key, value]);
            }
            table.add_row(prettytable::row![
                record.machine_id,
                record.state,
                record.created_ts,
                record.updated_ts,
                journal_table,
                attrs_table,
            ]);
        }
        Ok(table.to_string())
    }
}
