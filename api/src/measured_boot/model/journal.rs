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
 *  Code for working the measuremment_journal and measurement_journal_values
 *  tables in the database, leveraging the journal-specific record types.
*/

use crate::measured_boot::dto::keys::{
    MeasurementBundleId, MeasurementJournalId, MeasurementReportId, MeasurementSystemProfileId,
    UuidEmptyStringError,
};
use crate::measured_boot::dto::records::{MeasurementJournalRecord, MeasurementMachineState};
use crate::measured_boot::interface::common;
use crate::measured_boot::interface::common::ToTable;
use crate::measured_boot::interface::journal::{
    delete_journal_where_id, get_measurement_journal_record_by_id,
    get_measurement_journal_records_for_machine_id, insert_measurement_journal_record,
};
use crate::model::machine::machine_id::MachineId;
use rpc::protos::measured_boot::{MeasurementJournalPb, MeasurementMachineStatePb};
use serde::Serialize;
use sqlx::types::chrono::Utc;
use sqlx::{Pool, Postgres, Transaction};
use std::str::FromStr;
use utils::admin_cli::{just_print_summary, serde_just_print_summary};

/// MeasurementJournal is a composition of a MeasurementJournalRecord,
/// whose attributes are essentially copied directly it, as well as
/// the associated attributes (which are complete instances of
/// MeasurementReportValueRecord, along with its UUID and timestamp).
#[derive(Debug, Serialize, Clone)]
pub struct MeasurementJournal {
    pub journal_id: MeasurementJournalId,
    pub machine_id: MachineId,
    #[serde(skip_serializing_if = "serde_just_print_summary")]
    pub report_id: MeasurementReportId,
    #[serde(skip_serializing_if = "serde_just_print_summary")]
    pub profile_id: Option<MeasurementSystemProfileId>,
    #[serde(skip_serializing_if = "serde_just_print_summary")]
    pub bundle_id: Option<MeasurementBundleId>,
    pub state: MeasurementMachineState,
    pub ts: chrono::DateTime<Utc>,
}

impl From<MeasurementJournal> for MeasurementJournalPb {
    fn from(val: MeasurementJournal) -> Self {
        let pb_state: MeasurementMachineStatePb = val.state.into();
        Self {
            journal_id: Some(val.journal_id.into()),
            machine_id: val.machine_id.to_string(),
            report_id: Some(val.report_id.into()),
            profile_id: val.profile_id.map(|profile_id| profile_id.into()),
            bundle_id: val.bundle_id.map(|bundle_id| bundle_id.into()),
            state: pb_state.into(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MeasurementJournalPb> for MeasurementJournal {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MeasurementJournalPb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }
        let state = msg.state();

        Ok(Self {
            journal_id: MeasurementJournalId::try_from(msg.journal_id)?,
            machine_id: MachineId::from_str(&msg.machine_id)?,
            report_id: MeasurementReportId::try_from(msg.report_id)?,
            profile_id: match msg.profile_id {
                Some(profile_id) => Some(MeasurementSystemProfileId::try_from(profile_id)?),
                None => None,
            },
            bundle_id: match msg.bundle_id {
                Some(bundle_id) => Some(MeasurementBundleId::try_from(bundle_id)?),
                None => None,
            },
            state: MeasurementMachineState::from(state),
            ts: chrono::DateTime::<chrono::Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

impl MeasurementJournal {
    ////////////////////////////////////////////////////////////
    /// new creates a new measurement journal entry in the
    /// database.
    ////////////////////////////////////////////////////////////

    pub async fn new(
        db_conn: &Pool<Postgres>,
        machine_id: MachineId,
        report_id: MeasurementReportId,
        profile_id: Option<MeasurementSystemProfileId>,
        bundle_id: Option<MeasurementBundleId>,
        state: MeasurementMachineState,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        Self::new_with_txn(
            &mut txn, machine_id, report_id, profile_id, bundle_id, state,
        )
        .await
    }

    pub async fn new_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MachineId,
        report_id: MeasurementReportId,
        profile_id: Option<MeasurementSystemProfileId>,
        bundle_id: Option<MeasurementBundleId>,
        state: MeasurementMachineState,
    ) -> eyre::Result<Self> {
        create_measurement_journal(txn, machine_id, report_id, profile_id, bundle_id, state).await
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////

    pub fn from_grpc(some_pb: Option<&MeasurementJournalPb>) -> eyre::Result<Self> {
        some_pb
            .ok_or(eyre::eyre!("journal is unexpectedly empty"))
            .and_then(|pb| {
                Self::try_from(pb.clone())
                    .map_err(|e| eyre::eyre!("journal failed pb->model conversion: {}", e))
            })
    }

    ////////////////////////////////////////////////////////////
    /// from_id populates an existing MeasurementJournal
    /// instance from data in the database for the given
    /// journal ID.
    ////////////////////////////////////////////////////////////

    pub async fn from_id(
        txn: &mut Transaction<'_, Postgres>,
        journal_id: MeasurementJournalId,
    ) -> eyre::Result<Self> {
        get_measurement_journal_by_id(txn, journal_id).await
    }

    pub async fn delete_where_id(
        txn: &mut Transaction<'_, Postgres>,
        journal_id: MeasurementJournalId,
    ) -> eyre::Result<Option<MeasurementJournal>> {
        let info = delete_journal_where_id(txn, journal_id).await?;
        match info {
            None => Ok(None),
            Some(info) => Ok(Some(MeasurementJournal {
                journal_id: info.journal_id,
                machine_id: info.machine_id,
                report_id: info.report_id,
                profile_id: info.profile_id,
                bundle_id: info.bundle_id,
                state: info.state,
                ts: info.ts,
            })),
        }
    }

    pub async fn get_all(
        txn: &mut Transaction<'_, Postgres>,
    ) -> eyre::Result<Vec<MeasurementJournal>> {
        get_measurement_journals(txn).await
    }

    pub async fn get_all_for_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MachineId,
    ) -> eyre::Result<Vec<MeasurementJournal>> {
        get_measurement_journals_for_machine_id(txn, machine_id).await
    }

    pub async fn get_latest_for_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MachineId,
    ) -> eyre::Result<Option<MeasurementJournal>> {
        get_latest_journal_for_id(txn, machine_id).await
    }
}

// When `journal show <journal-id>` gets called, and the output format is
// the default table view, this gets used to print a pretty table.
impl ToTable for MeasurementJournal {
    fn to_table(&self) -> eyre::Result<String> {
        let profile_id: String = match self.profile_id {
            Some(profile_id) => profile_id.to_string(),
            None => "<none>".to_string(),
        };
        let bundle_id: String = match self.bundle_id {
            Some(bundle_id) => bundle_id.to_string(),
            None => "<none>".to_string(),
        };
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["journal_id", self.journal_id]);
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        if !just_print_summary() {
            table.add_row(prettytable::row!["report_id", self.report_id]);
            table.add_row(prettytable::row!["profile_id", profile_id]);
            table.add_row(prettytable::row!["bundle_id", bundle_id]);
        }
        table.add_row(prettytable::row!["state", self.state]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        Ok(table.to_string())
    }
}

// When `journal show` gets called (for all entries), and the output format
// is the default table view, this gets used to print a pretty table.
impl ToTable for Vec<MeasurementJournal> {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["journal_id", "details"]);
        for journal in self.iter() {
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
            if !just_print_summary() {
                details_table.add_row(prettytable::row!["report_id", journal.report_id]);
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

/// create_measurement_journal handles the work of creating a new
/// measurement journal record as well as all associated value records.
async fn create_measurement_journal(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
    report_id: MeasurementReportId,
    profile_id: Option<MeasurementSystemProfileId>,
    bundle_id: Option<MeasurementBundleId>,
    state: MeasurementMachineState,
) -> eyre::Result<MeasurementJournal> {
    let info =
        insert_measurement_journal_record(txn, machine_id, report_id, profile_id, bundle_id, state)
            .await?;

    Ok(MeasurementJournal {
        journal_id: info.journal_id,
        machine_id: info.machine_id,
        report_id: info.report_id,
        profile_id: info.profile_id,
        bundle_id: info.bundle_id,
        state: info.state,
        ts: info.ts,
    })
}

/// get_measurement_journal_by_id does the work of populating a full
/// MeasurementJournal instance, with values and all.
async fn get_measurement_journal_by_id(
    txn: &mut Transaction<'_, Postgres>,
    journal_id: MeasurementJournalId,
) -> eyre::Result<MeasurementJournal> {
    match get_measurement_journal_record_by_id(txn, journal_id).await? {
        Some(info) => Ok(MeasurementJournal {
            journal_id: info.journal_id,
            machine_id: info.machine_id,
            report_id: info.report_id,
            profile_id: info.profile_id,
            bundle_id: info.bundle_id,
            state: info.state,
            ts: info.ts,
        }),
        None => Err(eyre::eyre!("no journal found with that ID")),
    }
}

/// get_measurement_journals returns all MeasurementJournal
/// instances in the database. This leverages the generic get_all_objects
/// function since its a simple/common pattern.
async fn get_measurement_journals(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementJournal>> {
    let journal_records: Vec<MeasurementJournalRecord> = common::get_all_objects(txn).await?;
    let res: Vec<MeasurementJournal> = journal_records
        .iter()
        .map(|record| MeasurementJournal {
            journal_id: record.journal_id,
            machine_id: record.machine_id.clone(),
            report_id: record.report_id,
            profile_id: record.profile_id,
            bundle_id: record.bundle_id,
            state: record.state,
            ts: record.ts,
        })
        .collect();
    Ok(res)
}

/// get_measurement_journals_for_machine_id returns all fully populated
/// journal instances for a given machine ID, which is used by the
/// `journal show` CLI option.
async fn get_measurement_journals_for_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<Vec<MeasurementJournal>> {
    let records = get_measurement_journal_records_for_machine_id(txn, machine_id).await?;
    Ok(records
        .iter()
        .map(|record| MeasurementJournal {
            journal_id: record.journal_id,
            machine_id: record.machine_id.clone(),
            report_id: record.report_id,
            profile_id: record.profile_id,
            bundle_id: record.bundle_id,
            state: record.state,
            ts: record.ts,
        })
        .collect())
}

/// get_latest_journal_for_id returns the latest journal record for the
/// provided machine ID.
pub async fn get_latest_journal_for_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<Option<MeasurementJournal>> {
    let query = "select distinct on (machine_id) * from measurement_journal where machine_id = $1 order by machine_id,ts desc";
    match sqlx::query_as::<_, MeasurementJournalRecord>(query)
        .bind(machine_id)
        .fetch_optional(&mut **txn)
        .await?
    {
        Some(info) => Ok(Some(MeasurementJournal {
            journal_id: info.journal_id,
            machine_id: info.machine_id,
            report_id: info.report_id,
            profile_id: info.profile_id,
            bundle_id: info.bundle_id,
            state: info.state,
            ts: info.ts,
        })),
        None => Ok(None),
    }
}
