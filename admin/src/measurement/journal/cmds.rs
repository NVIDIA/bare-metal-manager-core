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

use crate::measurement::global;
use crate::measurement::global::cmds::cli_output;
use crate::measurement::journal::args::{CmdJournal, Delete, List, Show};
use crate::{CarbideCliError, CarbideCliResult};
use ::rpc::forge_tls_client::ForgeClientT;
use ::rpc::protos::measured_boot::list_measurement_journal_request;
use ::rpc::protos::measured_boot::show_measurement_journal_request;
use ::rpc::protos::measured_boot::{
    DeleteMeasurementJournalRequest, ListMeasurementJournalRequest, ShowMeasurementJournalRequest,
    ShowMeasurementJournalsRequest,
};
use carbide::measured_boot::dto::records::MeasurementJournalRecord;
use carbide::measured_boot::model::journal::MeasurementJournal;

/// dispatch matches + dispatches the correct command for
/// the `journal` subcommand.
pub async fn dispatch(
    cmd: &CmdJournal,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> CarbideCliResult<()> {
    match cmd {
        CmdJournal::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdJournal::Show(local_args) => {
            if local_args.journal_id.is_some() {
                cli_output(
                    show_by_id(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            } else {
                cli_output(
                    show_all(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
        }
        CmdJournal::List(local_args) => {
            cli_output(
                list(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
    }
    Ok(())
}

/// delete deletes an existing journal entry.
///
/// `journal delete <journal-id>`
pub async fn delete(
    grpc_conn: &mut ForgeClientT,
    delete: &Delete,
) -> CarbideCliResult<MeasurementJournal> {
    // Request.
    let request = DeleteMeasurementJournalRequest {
        journal_id: Some(delete.journal_id.into()),
    };

    // Response.
    let response = grpc_conn
        .delete_measurement_journal(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?;

    MeasurementJournal::from_grpc(response.get_ref().journal.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// show_by_id shows all info about a journal entry for the provided ID.
///
/// `journal show <journal-id>`
pub async fn show_by_id(
    grpc_conn: &mut ForgeClientT,
    show: &Show,
) -> CarbideCliResult<MeasurementJournal> {
    // Prepare.
    // TODO(chet): This exists just because of how I'm dispatching
    // commands, since &Show gets reused for showing all (where journal_id
    // is unset, or showing a specific journal ID). Ultimately this
    // shouldn't ever actually get hit, but it exists just incase. That
    // said, I should look into see if I can just have clap validate this.
    let Some(journal_id) = &show.journal_id else {
        return Err(CarbideCliError::GenericError(String::from(
            "journal_id must be set to get a journal",
        )));
    };

    // Request.
    let request = ShowMeasurementJournalRequest {
        selector: Some(show_measurement_journal_request::Selector::JournalId(
            (*journal_id).into(),
        )),
    };

    // Response.
    let response = grpc_conn
        .show_measurement_journal(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?;

    MeasurementJournal::from_grpc(response.get_ref().journal.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// show_all shows all info about all journal entries.
///
/// `journal show`
pub async fn show_all(
    grpc_conn: &mut ForgeClientT,
    _show: &Show,
) -> CarbideCliResult<Vec<MeasurementJournal>> {
    // Request.
    let request = ShowMeasurementJournalsRequest {};

    // Response.
    grpc_conn
        .show_measurement_journals(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?
        .get_mut()
        .journals
        .drain(..)
        .map(|journal| {
            MeasurementJournal::from_grpc(Some(&journal))
                .map_err(|e| CarbideCliError::GenericError(e.to_string()))
        })
        .collect::<CarbideCliResult<Vec<MeasurementJournal>>>()
}

/// list just lists all journal IDs.
///
/// `journal list`
pub async fn list(
    grpc_conn: &mut ForgeClientT,
    list: &List,
) -> CarbideCliResult<Vec<MeasurementJournalRecord>> {
    // Request.
    let request = match list.machine_id.clone() {
        Some(machine_id) => ListMeasurementJournalRequest {
            selector: Some(list_measurement_journal_request::Selector::MachineId(
                machine_id.to_string(),
            )),
        },
        None => ListMeasurementJournalRequest { selector: None },
    };

    // Response.
    grpc_conn
        .list_measurement_journal(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?
        .get_mut()
        .journals
        .drain(..)
        .map(|journal| {
            MeasurementJournalRecord::try_from(journal)
                .map_err(|e| CarbideCliError::GenericError(e.to_string()))
        })
        .collect::<CarbideCliResult<Vec<MeasurementJournalRecord>>>()
}
