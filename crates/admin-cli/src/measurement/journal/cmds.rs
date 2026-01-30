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
//! `measurement journal` subcommand dispatcher + backing functions.
//!

use ::rpc::admin_cli::{
    CarbideCliError, CarbideCliResult, ToTable, cli_output, just_print_summary,
};
use ::rpc::protos::measured_boot::{
    DeleteMeasurementJournalRequest, ListMeasurementJournalRequest, ShowMeasurementJournalRequest,
    list_measurement_journal_request, show_measurement_journal_request,
};
use measured_boot::bundle::MeasurementBundle;
use measured_boot::journal::MeasurementJournal;
use measured_boot::records::MeasurementJournalRecord;
use serde::Serialize;

use crate::measurement::global;
use crate::measurement::journal::args::{CmdJournal, Delete, List, Promote, Show};
use crate::measurement::report::args::Promote as ReportPromoteArgs;
use crate::measurement::report::cmds::promote as report_promote;
use crate::rpc::ApiClient;

/// dispatch matches + dispatches the correct command for
/// the `journal` subcommand.
pub async fn dispatch(
    cmd: CmdJournal,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> CarbideCliResult<()> {
    match cmd {
        CmdJournal::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdJournal::Show(local_args) => {
            if local_args.journal_id.is_some() {
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
        CmdJournal::List(local_args) => {
            cli_output(
                list(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdJournal::Promote(local_args) => {
            cli_output(
                promote(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
    }
    Ok(())
}

/// delete deletes an existing journal entry.
///
/// `journal delete <journal-id>`
pub async fn delete(grpc_conn: &ApiClient, delete: Delete) -> CarbideCliResult<MeasurementJournal> {
    // Request.
    let request = DeleteMeasurementJournalRequest {
        journal_id: Some(delete.journal_id),
    };

    // Response.
    let response = grpc_conn.0.delete_measurement_journal(request).await?;

    MeasurementJournal::from_grpc(response.journal.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// show_by_id shows all info about a journal entry for the provided ID.
///
/// `journal show <journal-id>`
pub async fn show_by_id(grpc_conn: &ApiClient, show: Show) -> CarbideCliResult<MeasurementJournal> {
    // Prepare.
    // TODO(chet): This exists just because of how I'm dispatching
    // commands, since &Show gets reused for showing all (where journal_id
    // is unset, or showing a specific journal ID). Ultimately this
    // shouldn't ever actually get hit, but it exists just incase. That
    // said, I should look into see if I can just have clap validate this.
    let Some(journal_id) = show.journal_id else {
        return Err(CarbideCliError::GenericError(String::from(
            "journal_id must be set to get a journal",
        )));
    };

    // Request.
    let request = ShowMeasurementJournalRequest {
        selector: Some(show_measurement_journal_request::Selector::JournalId(
            journal_id,
        )),
    };

    // Response.
    let response = grpc_conn.0.show_measurement_journal(request).await?;

    MeasurementJournal::from_grpc(response.journal.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// show_all shows all info about all journal entries.
///
/// `journal show`
pub async fn show_all(
    grpc_conn: &ApiClient,
    _show: Show,
) -> CarbideCliResult<MeasurementJournalList> {
    Ok(MeasurementJournalList(
        grpc_conn
            .0
            .show_measurement_journals()
            .await?
            .journals
            .drain(..)
            .map(|journal| {
                MeasurementJournal::from_grpc(Some(&journal))
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementJournal>>>()?,
    ))
}

/// list just lists all journal IDs.
///
/// `journal list`
pub async fn list(
    grpc_conn: &ApiClient,
    list: List,
) -> CarbideCliResult<MeasurementJournalRecordList> {
    // Request.
    let request = match list.machine_id {
        Some(machine_id) => ListMeasurementJournalRequest {
            selector: Some(list_measurement_journal_request::Selector::MachineId(
                machine_id.to_string(),
            )),
        },
        None => ListMeasurementJournalRequest { selector: None },
    };

    // Response.
    Ok(MeasurementJournalRecordList(
        grpc_conn
            .0
            .list_measurement_journal(request)
            .await?
            .journals
            .drain(..)
            .map(|journal| {
                MeasurementJournalRecord::try_from(journal)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementJournalRecord>>>()?,
    ))
}

/// promote promotes the report from a journal entry into
/// a measurement bundle.
///
/// Instead of its own dedicated API call, this makes two API
/// calls: one to get the journal data, and the other to promote
/// the report associated with the journal.
///
/// `journal promote <journal-id> [--pcr-registers <range0>,...]`
pub async fn promote(
    grpc_conn: &ApiClient,
    promote: Promote,
) -> CarbideCliResult<MeasurementBundle> {
    let journal = show_by_id(
        grpc_conn,
        Show {
            journal_id: Some(promote.journal_id),
        },
    )
    .await?;

    report_promote(
        grpc_conn,
        ReportPromoteArgs {
            report_id: journal.report_id,
            pcr_registers: promote.pcr_registers,
        },
    )
    .await
}

/// MeasurementJournalRecordList just implements a newtype pattern
/// for a Vec<MeasurementJournalRecord> so the ToTable trait can
/// be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementJournalRecordList(Vec<MeasurementJournalRecord>);

impl ToTable for MeasurementJournalRecordList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        if just_print_summary() {
            table.add_row(prettytable::row![
                "journal_id",
                "machine_id",
                "report_id",
                "state",
                "created_ts"
            ]);
        } else {
            table.add_row(prettytable::row![
                "journal_id",
                "machine_id",
                "report_id",
                "profile_id",
                "bundle_id",
                "state",
                "created_ts"
            ]);
        }
        for journal in self.0.iter() {
            let profile_id: String = match journal.profile_id {
                Some(profile_id) => profile_id.to_string(),
                None => "<none>".to_string(),
            };
            let bundle_id: String = match journal.bundle_id {
                Some(bundle_id) => bundle_id.to_string(),
                None => "<none>".to_string(),
            };
            if just_print_summary() {
                table.add_row(prettytable::row![
                    journal.journal_id,
                    journal.machine_id,
                    journal.report_id,
                    journal.state,
                    journal.ts
                ]);
            } else {
                table.add_row(prettytable::row![
                    journal.journal_id,
                    journal.machine_id,
                    journal.report_id,
                    profile_id,
                    bundle_id,
                    journal.state,
                    journal.ts
                ]);
            }
        }
        Ok(table.to_string())
    }
}

/// MeasurementJournalList just implements a newtype
/// pattern for a Vec<MeasurementJournal> so the ToTable
/// trait can be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementJournalList(Vec<MeasurementJournal>);

// When `journal show` gets called (for all entries), and the output format
// is the default table view, this gets used to print a pretty table.
impl ToTable for MeasurementJournalList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["journal_id", "details"]);
        for journal in self.0.iter() {
            let profile_id: String = match journal.profile_id {
                Some(profile_id) => profile_id.to_string(),
                None => "<none>".to_string(),
            };
            let bundle_id: String = match journal.bundle_id {
                Some(bundle_id) => bundle_id.to_string(),
                None => "<none>".to_string(),
            };
            let mut details_table = prettytable::Table::new();
            details_table.add_row(prettytable::row!["machine_id", journal.machine_id]);
            details_table.add_row(prettytable::row!["report_id", journal.report_id]);
            if !just_print_summary() {
                details_table.add_row(prettytable::row!["profile_id", profile_id]);
                details_table.add_row(prettytable::row!["bundle_id", bundle_id]);
            }
            details_table.add_row(prettytable::row!["state", journal.state]);
            details_table.add_row(prettytable::row!["created_ts", journal.ts]);
            table.add_row(prettytable::row![journal.journal_id, details_table,]);
        }
        Ok(table.to_string())
    }
}
