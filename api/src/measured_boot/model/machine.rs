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
 *  Code for working the mock_machines and mock_machines_attrs tables in the
 *  database, leveraging the mock-machine-specific record types.
*/

use crate::measured_boot::dto::keys::{MockMachineId, UuidEmptyStringError};
use crate::measured_boot::dto::records::{
    MeasurementBundleState, MeasurementJournalRecord, MeasurementMachineState,
    MockMachineAttrRecord,
};
use crate::measured_boot::interface::common;
use crate::measured_boot::interface::common::ToTable;
use crate::measured_boot::interface::machine::{
    delete_mock_machine_attrs_where_id, delete_mock_machine_record_where_id,
    get_mock_machine_attrs_for_machine_id, get_mock_machine_by_id, get_mock_machines_records,
    insert_mock_machine_attr_records, insert_mock_machine_record,
};
use rpc::protos::measured_boot::{MeasurementMachineStatePb, MockMachinePb};
use serde::Serialize;
use sqlx::types::chrono::Utc;
use sqlx::{Pool, Postgres, Transaction};
use std::collections::HashMap;

///////////////////////////////////////////////////////////////////////////////
/// MockMachine is a composition of the MockMachineRecord along with any
/// corresponding MockMachineAttrRecords (the attributes of the machine).
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug, Serialize, Clone)]
pub struct MockMachine {
    pub machine_id: MockMachineId,
    pub ts: chrono::DateTime<Utc>,
    pub state: MeasurementMachineState,
    pub attrs: Vec<MockMachineAttrRecord>,
}

impl From<MockMachine> for MockMachinePb {
    fn from(val: MockMachine) -> Self {
        let pb_state: MeasurementMachineStatePb = val.state.into();
        Self {
            machine_id: val.machine_id.to_string(),
            state: pb_state.into(),
            attrs: val.attrs.iter().map(|attr| attr.clone().into()).collect(),
            ts: Some(val.ts.into()),
        }
    }
}

impl TryFrom<MockMachinePb> for MockMachine {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: MockMachinePb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }
        let state = msg.state();
        let attrs: eyre::Result<Vec<MockMachineAttrRecord>> = msg
            .attrs
            .iter()
            .map(|attr| match MockMachineAttrRecord::try_from(attr.clone()) {
                Ok(worked) => Ok(worked),
                Err(failed) => Err(eyre::eyre!("attr conversion failed: {}", failed)),
            })
            .collect();

        Ok(Self {
            machine_id: MockMachineId(msg.machine_id),
            state: MeasurementMachineState::from(state),
            attrs: attrs?,
            ts: chrono::DateTime::<chrono::Utc>::try_from(msg.ts.unwrap())?,
        })
    }
}

impl ToTable for MockMachine {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        let mut attrs_table = prettytable::Table::new();
        attrs_table.add_row(prettytable::row!["name", "value"]);
        for attr_record in self.attrs.iter() {
            attrs_table.add_row(prettytable::row![attr_record.key, attr_record.value]);
        }
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        table.add_row(prettytable::row!["state", self.state]);
        table.add_row(prettytable::row!["created_ts", self.ts]);
        table.add_row(prettytable::row!["attrs", attrs_table]);
        Ok(table.to_string())
    }
}

impl ToTable for Vec<MockMachine> {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row![
            "machine_id",
            "state",
            "created_ts",
            "attributes",
        ]);
        for record in self.iter() {
            let mut attrs_table = prettytable::Table::new();
            attrs_table.add_row(prettytable::row!["name", "value"]);
            for attr_record in record.attrs.iter() {
                attrs_table.add_row(prettytable::row![attr_record.key, attr_record.value]);
            }
            table.add_row(prettytable::row![
                record.machine_id,
                record.state,
                record.ts,
                attrs_table,
            ]);
        }
        Ok(table.to_string())
    }
}

impl MockMachine {
    ////////////////////////////////////////////////////////////////
    /// new creates a new MockMachine in the database,
    /// if it doesn't exist, populating the corresponding table(s),
    /// and returning the newly-inserted data.
    ////////////////////////////////////////////////////////////////

    pub async fn new(
        db_conn: &Pool<Postgres>,
        machine_id: MockMachineId,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        let machine = Self::new_with_txn(&mut txn, machine_id.clone(), attrs).await?;
        txn.commit().await?;
        Ok(machine)
    }

    pub async fn new_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MockMachineId,
        attrs: &HashMap<String, String>,
    ) -> eyre::Result<Self> {
        create_mock_machine(txn, machine_id.clone(), attrs).await
    }

    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////

    pub fn from_grpc(some_pb: Option<&MockMachinePb>) -> eyre::Result<Self> {
        some_pb
            .ok_or(eyre::eyre!("machine is unexpectedly empty"))
            .and_then(|pb| {
                Self::try_from(pb.clone())
                    .map_err(|e| eyre::eyre!("machine failed pb->model conversion: {}", e))
            })
    }

    ////////////////////////////////////////////////////////////////
    /// from_id populates a new MockMachine instance for the
    /// provided machine ID (assuming it exists).
    ////////////////////////////////////////////////////////////////

    pub async fn from_id(
        db_conn: &Pool<Postgres>,
        machine_id: MockMachineId,
    ) -> eyre::Result<Self> {
        let mut txn = db_conn.begin().await?;
        Self::from_id_with_txn(&mut txn, machine_id).await
    }

    pub async fn from_id_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MockMachineId,
    ) -> eyre::Result<Self> {
        match get_mock_machine_by_id(txn, machine_id.clone()).await? {
            Some(record) => {
                let latest_state = get_mock_machine_state(txn, machine_id.clone()).await?;
                let attrs = get_mock_machine_attrs_for_machine_id(txn, machine_id).await?;

                Ok(Self {
                    machine_id: record.machine_id.clone(),
                    ts: record.ts,
                    state: latest_state,
                    attrs,
                })
            }
            None => Err(eyre::eyre!("no machine found with that ID")),
        }
    }

    pub async fn delete_where_id(
        db_conn: &Pool<Postgres>,
        machine_id: MockMachineId,
    ) -> eyre::Result<Option<MockMachine>> {
        let mut txn = db_conn.begin().await?;
        let res = delete_machine_where_id(&mut txn, machine_id.clone()).await?;
        txn.commit().await?;
        Ok(res)
    }

    pub async fn get_all(db_conn: &Pool<Postgres>) -> eyre::Result<Vec<Self>> {
        get_mock_machines(db_conn).await
    }

    ////////////////////////////////////////////////////////////////
    /// discovery_attributes returns the mock machine attribute
    /// records into a generic "discovery attributes" hashmap,
    /// which is intended for making the transition from this PoC
    /// to actual discovery data easier.
    ////////////////////////////////////////////////////////////////

    pub fn discovery_attributes(&self) -> eyre::Result<HashMap<String, String>> {
        let total_attrs = self.attrs.len();
        let attr_map: HashMap<String, String> = self
            .attrs
            .iter()
            .map(|rec| (rec.key.clone(), rec.value.clone()))
            .collect();
        if total_attrs != attr_map.len() {
            return Err(eyre::eyre!("detected attribute key collision"));
        }
        common::filter_machine_discovery_attrs(&attr_map)
    }
}

pub fn bundle_state_to_machine_state(
    bundle_state: &MeasurementBundleState,
) -> MeasurementMachineState {
    match bundle_state {
        MeasurementBundleState::Active => MeasurementMachineState::Measured,
        MeasurementBundleState::Obsolete => MeasurementMachineState::Measured,
        MeasurementBundleState::Retired => MeasurementMachineState::MeasuringFailed,
        MeasurementBundleState::Revoked => MeasurementMachineState::MeasuringFailed,
        MeasurementBundleState::Pending => MeasurementMachineState::PendingBundle,
    }
}

///////////////////////////////////////////////////////////////////////////////
/// get_discovery_attributes returns a hashmap of values from DiscoveryInfo
/// used for matching to a machine profile.
///
/// TODO(chet): This is currently mocked out to just pull from the mock
/// machines table, but in real life, this will pull DiscoveryInfo data
/// and return a hashmap from that data.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_discovery_attributes(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<HashMap<String, String>> {
    let attrs = get_mock_machine_attrs_for_machine_id(txn, machine_id).await?;
    let total_attrs = attrs.len();
    let attr_map: HashMap<String, String> =
        attrs.into_iter().map(|rec| (rec.key, rec.value)).collect();
    if total_attrs != attr_map.len() {
        return Err(eyre::eyre!("detected attribute key collision"));
    }

    common::filter_machine_discovery_attrs(&attr_map)
}

///////////////////////////////////////////////////////////////////////////////
/// get_mock_machine_state figures out the current state of the given
/// machine ID by checking its most recent bundle (or lack thereof), and
/// using that result to give it a corresponding MockMachineState.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_mock_machine_state(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<MeasurementMachineState> {
    Ok(
        match internal_get_latest_journal_for_id(&mut *txn, machine_id).await? {
            Some(record) => record.state,
            None => MeasurementMachineState::Discovered,
        },
    )
}

///////////////////////////////////////////////////////////////////////////////
/// get_latest_journal_for_id returns the latest journal record for the
/// provided machine ID.
///////////////////////////////////////////////////////////////////////////////

async fn internal_get_latest_journal_for_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<Option<MeasurementJournalRecord>> {
    let query = "select distinct on (machine_id) * from measurement_journal where machine_id = $1 order by machine_id,ts desc";
    Ok(sqlx::query_as::<_, MeasurementJournalRecord>(query)
        .bind(machine_id)
        .fetch_optional(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// create_mock_machine creates a new mock machine and corresponding mock
/// machine attributes. The transaction is created here, and is used for
/// corresponding insert statements into both the mock_machines and
/// mock_machines_attrs tables.
///////////////////////////////////////////////////////////////////////////////

async fn create_mock_machine(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
    attrs: &HashMap<String, String>,
) -> eyre::Result<MockMachine> {
    let info = insert_mock_machine_record(txn, machine_id.clone()).await?;
    Ok(MockMachine {
        machine_id: info.machine_id,
        ts: info.ts,
        state: get_mock_machine_state(txn, machine_id.clone()).await?,
        attrs: insert_mock_machine_attr_records(txn, machine_id.clone(), attrs).await?,
    })
}

///////////////////////////////////////////////////////////////////////////////
/// delete_machine_where_id deletes a complete machine, including
/// its attributes, by ID. It returns the deleted machine for display.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_machine_where_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<Option<MockMachine>> {
    match delete_mock_machine_record_where_id(txn, machine_id.clone()).await? {
        Some(info) => Ok(Some(MockMachine {
            machine_id: info.machine_id.clone(),
            ts: info.ts,
            state: get_mock_machine_state(txn, machine_id.clone()).await?,
            attrs: delete_mock_machine_attrs_where_id(txn, machine_id.clone()).await?,
        })),
        None => Ok(None),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// get_mock_machines returns all populated MockMachine instances.
///////////////////////////////////////////////////////////////////////////////

async fn get_mock_machines(db_conn: &Pool<Postgres>) -> eyre::Result<Vec<MockMachine>> {
    let mut txn = db_conn.begin().await?;
    let mut res: Vec<MockMachine> = Vec::new();
    let mut records = get_mock_machines_records(db_conn).await?;
    for record in records.drain(..) {
        let latest_state = get_mock_machine_state(&mut txn, record.machine_id.clone()).await?;
        let attrs =
            get_mock_machine_attrs_for_machine_id(&mut txn, record.machine_id.clone()).await?;
        res.push(MockMachine {
            machine_id: record.machine_id.clone(),
            ts: record.ts,
            state: latest_state,
            attrs,
        });
    }
    Ok(res)
}
