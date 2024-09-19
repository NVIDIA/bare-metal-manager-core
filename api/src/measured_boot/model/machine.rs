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
 *  Code for working the machine_topologies table in the
 *  database to match candidate machines to profiles and bundles.
*/

use crate::db::DatabaseError;
use crate::measured_boot::dto::keys::UuidEmptyStringError;
use crate::measured_boot::dto::records::{MeasurementBundleState, MeasurementMachineState};
use crate::measured_boot::interface::bundle::get_measurement_bundle_by_id;
use crate::measured_boot::interface::common;
use crate::measured_boot::interface::machine::{
    get_candidate_machine_record_by_id, get_candidate_machine_records, get_candidate_machine_state,
};
use crate::measured_boot::model::journal::{get_latest_journal_for_id, MeasurementJournal};
use crate::{CarbideError, CarbideResult};
use forge_uuid::machine::MachineId;
use rpc::protos::measured_boot::{CandidateMachinePb, MeasurementMachineStatePb};
use serde::Serialize;
use sqlx::types::chrono::Utc;
use sqlx::{Pool, Postgres, Transaction};
use std::collections::HashMap;
use std::str::FromStr;
use utils::admin_cli::ToTable;

/// CandidateMachine describes a machine that is a candidate for attestation,
/// and is derived from machine information in the machine_toplogies table.
#[derive(Debug, Serialize, Clone)]
pub struct CandidateMachine {
    pub machine_id: MachineId,
    pub state: MeasurementMachineState,
    pub journal: Option<MeasurementJournal>,
    pub attrs: HashMap<String, String>,
    pub created_ts: chrono::DateTime<Utc>,
    pub updated_ts: chrono::DateTime<Utc>,
}

impl From<CandidateMachine> for CandidateMachinePb {
    fn from(val: CandidateMachine) -> Self {
        let pb_state: MeasurementMachineStatePb = val.state.into();
        Self {
            machine_id: val.machine_id.to_string(),
            state: pb_state.into(),
            journal: val.journal.map(|journal| journal.into()),
            attrs: val.attrs,
            created_ts: Some(val.created_ts.into()),
            updated_ts: Some(val.updated_ts.into()),
        }
    }
}

impl TryFrom<CandidateMachinePb> for CandidateMachine {
    type Error = Box<dyn std::error::Error>;

    fn try_from(msg: CandidateMachinePb) -> Result<Self, Box<dyn std::error::Error>> {
        if msg.machine_id.is_empty() {
            return Err(UuidEmptyStringError {}.into());
        }
        let state = msg.state();

        Ok(Self {
            machine_id: MachineId::from_str(&msg.machine_id)?,
            state: MeasurementMachineState::from(state),
            journal: match msg.journal {
                Some(journal_pb) => Some(MeasurementJournal::try_from(journal_pb)?),
                None => None,
            },
            attrs: msg.attrs,
            created_ts: chrono::DateTime::<chrono::Utc>::try_from(msg.created_ts.unwrap())?,
            updated_ts: chrono::DateTime::<chrono::Utc>::try_from(msg.updated_ts.unwrap())?,
        })
    }
}

impl ToTable for CandidateMachine {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        let journal_table = match &self.journal {
            Some(journal) => journal.to_nested_prettytable(),
            None => {
                let mut not_found = prettytable::Table::new();
                not_found.add_row(prettytable::row!["<no journal found>"]);
                not_found
            }
        };
        let mut attrs_table = prettytable::Table::new();
        attrs_table.add_row(prettytable::row!["name", "value"]);
        for (key, value) in self.attrs.iter() {
            attrs_table.add_row(prettytable::row![key, value]);
        }
        table.add_row(prettytable::row!["machine_id", self.machine_id]);
        table.add_row(prettytable::row!["state", self.state]);
        table.add_row(prettytable::row!["created_ts", self.created_ts]);
        table.add_row(prettytable::row!["updated_ts", self.updated_ts]);
        table.add_row(prettytable::row!["journal", journal_table]);
        table.add_row(prettytable::row!["attrs", attrs_table]);
        Ok(table.to_string())
    }
}

impl CandidateMachine {
    ////////////////////////////////////////////////////////////
    /// from_grpc takes an optional protobuf (as populated in a
    /// proto response from the API) and attempts to convert it
    /// to the backing model.
    ////////////////////////////////////////////////////////////

    pub fn from_grpc(some_pb: Option<&CandidateMachinePb>) -> eyre::Result<Self> {
        some_pb
            .ok_or(eyre::eyre!("machine is unexpectedly empty"))
            .and_then(|pb| {
                Self::try_from(pb.clone())
                    .map_err(|e| eyre::eyre!("machine failed pb->model conversion: {}", e))
            })
    }

    ////////////////////////////////////////////////////////////////
    /// from_id populates a new CandidateMachine instance for the
    /// provided machine ID (assuming it exists).
    ////////////////////////////////////////////////////////////////

    pub async fn from_id(db_conn: &Pool<Postgres>, machine_id: MachineId) -> CarbideResult<Self> {
        let mut txn = db_conn.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "CandidateMachine.from_id begin",
                e,
            ))
        })?;
        Self::from_id_with_txn(&mut txn, machine_id).await
    }

    pub async fn from_id_with_txn(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: MachineId,
    ) -> CarbideResult<Self> {
        match get_candidate_machine_record_by_id(txn, machine_id.clone()).await? {
            Some(record) => {
                let attrs = match &record.topology.discovery_data.info.dmi_data {
                    Some(dmi_data) => Ok(HashMap::from([
                        (String::from("sys_vendor"), dmi_data.sys_vendor.clone()),
                        (String::from("product_name"), dmi_data.product_name.clone()),
                        (String::from("bios_version"), dmi_data.bios_version.clone()),
                    ])),
                    None => Err(CarbideError::GenericError(String::from(
                        "machine missing dmi data",
                    ))),
                }?;

                let journal = get_latest_journal_for_id(txn, machine_id.clone()).await?;
                let state = machine_state_from_journal(&journal);

                Ok(Self {
                    machine_id: record.machine_id.clone(),
                    created_ts: record.created,
                    updated_ts: record.updated,
                    attrs,
                    state,
                    journal,
                })
            }
            None => Err(CarbideError::NotFoundError {
                kind: "CandidateMachine",
                id: machine_id.to_string(),
            }),
        }
    }

    pub async fn get_all(txn: &mut Transaction<'_, Postgres>) -> CarbideResult<Vec<Self>> {
        get_candidate_machines(txn).await
    }

    ////////////////////////////////////////////////////////////////
    /// discovery_attributes returns the mock machine attribute
    /// records into a generic "discovery attributes" hashmap,
    /// which is intended for making the transition from this PoC
    /// to actual discovery data easier.
    ////////////////////////////////////////////////////////////////

    pub fn discovery_attributes(&self) -> CarbideResult<HashMap<String, String>> {
        common::filter_machine_discovery_attrs(&self.attrs)
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

/// get_measurement_machine_state figures out the current state of the given
/// machine ID by checking its most recent bundle (or lack thereof), and
/// using that result to give it a corresponding MeasurementMachineState.
pub async fn get_measurement_machine_state(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> Result<MeasurementMachineState, DatabaseError> {
    get_candidate_machine_state(txn, machine_id).await
}

/// get_measurement_bundle_state returns the state of the current bundle
/// associated with the machine, if one exists.
pub async fn get_measurement_bundle_state(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
) -> eyre::Result<Option<MeasurementBundleState>> {
    let result = get_latest_journal_for_id(&mut *txn, machine_id.clone()).await?;
    if let Some(journal_record) = result {
        if let Some(bundle_id) = journal_record.bundle_id {
            if let Some(bundle) = get_measurement_bundle_by_id(txn, bundle_id).await? {
                return Ok(Some(bundle.state));
            }
        }
    }
    Ok(None)
}

/// get_candidate_machines returns all populated CandidateMachine instances.
async fn get_candidate_machines(
    txn: &mut Transaction<'_, Postgres>,
) -> CarbideResult<Vec<CandidateMachine>> {
    let mut res: Vec<CandidateMachine> = Vec::new();
    let mut records = get_candidate_machine_records(txn).await?;
    for record in records.drain(..) {
        let attrs = match &record.topology.discovery_data.info.dmi_data {
            Some(dmi_data) => Ok(HashMap::from([
                (String::from("sys_vendor"), dmi_data.sys_vendor.clone()),
                (String::from("product_name"), dmi_data.product_name.clone()),
                (String::from("bios_version"), dmi_data.bios_version.clone()),
            ])),
            None => Err(CarbideError::GenericError(String::from(
                "machine missing dmi data",
            ))),
        }?;

        let journal = get_latest_journal_for_id(txn, record.machine_id.clone()).await?;
        let state = machine_state_from_journal(&journal);

        res.push(CandidateMachine {
            machine_id: record.machine_id.clone(),
            created_ts: record.created,
            updated_ts: record.updated,
            attrs,
            state,
            journal,
        });
    }
    Ok(res)
}

/// machine_state_from_journal returns the computed machine
/// state for a given journal record.
pub fn machine_state_from_journal(journal: &Option<MeasurementJournal>) -> MeasurementMachineState {
    match journal {
        Some(record) => record.state,
        None => MeasurementMachineState::Discovered,
    }
}
