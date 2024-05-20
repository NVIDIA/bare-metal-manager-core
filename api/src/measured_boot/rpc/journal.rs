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

use crate::measured_boot::interface::journal::{
    get_measurement_journal_records, get_measurement_journal_records_for_machine_id,
};
use crate::measured_boot::rpc::common::begin_txn;
use crate::measured_boot::{
    dto::keys::{MeasurementJournalId, MockMachineId},
    model::journal::MeasurementJournal,
};
use rpc::protos::measured_boot::{
    list_measurement_journal_request, show_measurement_journal_request, MeasurementJournalRecordPb,
};
use rpc::protos::measured_boot::{
    DeleteMeasurementJournalRequest, DeleteMeasurementJournalResponse,
    ListMeasurementJournalRequest, ListMeasurementJournalResponse, ShowMeasurementJournalRequest,
    ShowMeasurementJournalResponse, ShowMeasurementJournalsRequest,
    ShowMeasurementJournalsResponse,
};
use sqlx::{Pool, Postgres};
use tonic::Status;

pub async fn handle_delete_measurement_journal(
    db_conn: &Pool<Postgres>,
    req: &DeleteMeasurementJournalRequest,
) -> Result<DeleteMeasurementJournalResponse, Status> {
    let journal = MeasurementJournal::delete_where_id(
        db_conn,
        MeasurementJournalId::from_grpc(req.journal_id.clone())?,
    )
    .await
    .map_err(|e| Status::internal(format!("failed to delete journal: {}", e)))?
    .ok_or(Status::not_found("no journal found with that ID"))?;

    Ok(DeleteMeasurementJournalResponse {
        journal: Some(journal.into()),
    })
}

pub async fn handle_show_measurement_journal(
    db_conn: &Pool<Postgres>,
    req: &ShowMeasurementJournalRequest,
) -> Result<ShowMeasurementJournalResponse, Status> {
    let journal = match &req.selector {
        Some(show_measurement_journal_request::Selector::JournalId(journal_uuid)) => {
            MeasurementJournal::from_id(
                db_conn,
                MeasurementJournalId::from_grpc(Some(journal_uuid.clone()))?,
            )
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
        }
        None => return Err(Status::invalid_argument("selector must be provided")),
    };

    Ok(ShowMeasurementJournalResponse {
        journal: Some(journal.into()),
    })
}

pub async fn handle_show_measurement_journals(
    db_conn: &Pool<Postgres>,
    _req: &ShowMeasurementJournalsRequest,
) -> Result<ShowMeasurementJournalsResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    Ok(ShowMeasurementJournalsResponse {
        journals: MeasurementJournal::get_all(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch journals: {}", e)))?
            .drain(..)
            .map(|journal| journal.into())
            .collect(),
    })
}

pub async fn handle_list_measurement_journal(
    db_conn: &Pool<Postgres>,
    req: &ListMeasurementJournalRequest,
) -> Result<ListMeasurementJournalResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    let journals: Vec<MeasurementJournalRecordPb> = match &req.selector {
        Some(list_measurement_journal_request::Selector::MachineId(machine_id)) => {
            get_measurement_journal_records_for_machine_id(
                &mut txn,
                MockMachineId(machine_id.clone()),
            )
            .await
            .map_err(|e| Status::internal(format!("failed to fetch journals for machine: {}", e)))?
            .drain(..)
            .map(|journal| journal.into())
            .collect()
        }
        None => get_measurement_journal_records(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("failed to fetch journals: {}", e)))?
            .drain(..)
            .map(|journal| journal.into())
            .collect(),
    };

    Ok(ListMeasurementJournalResponse { journals })
}
