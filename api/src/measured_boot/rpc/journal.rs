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
 * gRPC handlers for measurement journal related API calls.
 */

use crate::errors::CarbideError;
use crate::measured_boot::db;
use crate::measured_boot::interface::journal::{
    get_measurement_journal_records, get_measurement_journal_records_for_machine_id,
};
use crate::measured_boot::rpc::common::{begin_txn, commit_txn};
use forge_uuid::machine::MachineId;
use rpc::protos::measured_boot::{
    DeleteMeasurementJournalRequest, DeleteMeasurementJournalResponse,
    ListMeasurementJournalRequest, ListMeasurementJournalResponse, ShowMeasurementJournalRequest,
    ShowMeasurementJournalResponse, ShowMeasurementJournalsRequest,
    ShowMeasurementJournalsResponse,
};
use rpc::protos::measured_boot::{
    MeasurementJournalRecordPb, list_measurement_journal_request, show_measurement_journal_request,
};
use sqlx::{Pool, Postgres};
use std::str::FromStr;
use tonic::Status;

/// handle_delete_measurement_journal handles the DeleteMeasurementJournal
/// API endpoint.
pub async fn handle_delete_measurement_journal(
    db_conn: &Pool<Postgres>,
    req: DeleteMeasurementJournalRequest,
) -> Result<DeleteMeasurementJournalResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let journal = db::journal::delete_where_id(
        &mut txn,
        req.journal_id
            .ok_or(CarbideError::MissingArgument("journal_id"))?,
    )
    .await
    .map_err(|e| Status::internal(format!("failed to delete journal: {e}")))?
    .ok_or(Status::not_found("no journal found with that ID"))?;

    commit_txn(txn).await?;
    Ok(DeleteMeasurementJournalResponse {
        journal: Some(journal.into()),
    })
}

/// handle_show_measurement_journal handles the ShowMeasurementJournal
/// API endpoint.
pub async fn handle_show_measurement_journal(
    db_conn: &Pool<Postgres>,
    req: ShowMeasurementJournalRequest,
) -> Result<ShowMeasurementJournalResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let journal = match req.selector {
        Some(selector) => match selector {
            show_measurement_journal_request::Selector::JournalId(journal_id) => {
                db::journal::from_id(&mut txn, journal_id)
                    .await
                    .map_err(|e| Status::internal(format!("{e}")))?
            }
            show_measurement_journal_request::Selector::LatestForMachineId(machine_id) => {
                match db::journal::get_latest_journal_for_id(
                    &mut txn,
                    MachineId::from_str(&machine_id).map_err(|e| {
                        Status::invalid_argument(format!("Could not parse MachineId: {e}"))
                    })?,
                )
                .await
                .map_err(|e| Status::internal(format!("{e}")))?
                {
                    Some(journal) => journal,
                    None => {
                        return Ok(ShowMeasurementJournalResponse { journal: None });
                    }
                }
            }
        },
        None => return Err(Status::invalid_argument("selector must be provided")),
    };

    Ok(ShowMeasurementJournalResponse {
        journal: Some(journal.into()),
    })
}

/// handle_show_measurement_journals handles the ShowMeasurementJournals
/// API endpoint.
pub async fn handle_show_measurement_journals(
    db_conn: &Pool<Postgres>,
    _req: ShowMeasurementJournalsRequest,
) -> Result<ShowMeasurementJournalsResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    Ok(ShowMeasurementJournalsResponse {
        journals: db::journal::get_all(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch journals: {e}")))?
            .drain(..)
            .map(|journal| journal.into())
            .collect(),
    })
}

/// handle_list_measurement_journal handles the ListMeasurementJournal
/// API endpoint.
pub async fn handle_list_measurement_journal(
    db_conn: &Pool<Postgres>,
    req: ListMeasurementJournalRequest,
) -> Result<ListMeasurementJournalResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    let journals: Vec<MeasurementJournalRecordPb> = match &req.selector {
        Some(list_measurement_journal_request::Selector::MachineId(machine_id)) => {
            let machine_id = MachineId::from_str(machine_id).map_err(|e| {
                Status::internal(format!("failed to fetch journals for machine: {e}"))
            })?;

            get_measurement_journal_records_for_machine_id(&mut txn, machine_id)
                .await
                .map_err(|e| {
                    Status::internal(format!("failed to fetch journals for machine: {e}"))
                })?
                .drain(..)
                .map(|journal| journal.into())
                .collect()
        }
        None => get_measurement_journal_records(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch journals: {e}")))?
            .drain(..)
            .map(|journal| journal.into())
            .collect(),
    };

    Ok(ListMeasurementJournalResponse { journals })
}
