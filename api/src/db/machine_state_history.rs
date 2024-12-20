/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use std::collections::HashMap;
use std::ops::DerefMut;

use crate::{
    db::DatabaseError,
    model::machine::{MachineStateHistory, ManagedHostState},
};
use forge_uuid::machine::MachineId;

/// History of Machine states for a single Machine
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct DbMachineStateHistory {
    /// The ID of the machine that experienced the state change
    pub machine_id: MachineId,

    /// The state that was entered
    pub state: serde_json::Value,

    /// Current version.
    pub state_version: ConfigVersion,
    // The timestamp of the state change, currently unused
    //timestamp: DateTime<Utc>,
}

impl From<DbMachineStateHistory> for crate::model::machine::MachineStateHistory {
    fn from(event: DbMachineStateHistory) -> Self {
        Self {
            state: event.state,
            state_version: event.state_version,
        }
    }
}

/// Retrieve the machine state history for a list of Machines
///
/// It returns a [HashMap][std::collections::HashMap] keyed by the machine ID and values of
/// all states that have been entered.
///
/// Arguments:
///
/// * `txn` - A reference to an open Transaction
///
pub async fn find_by_machine_ids(
    txn: &mut Transaction<'_, Postgres>,
    ids: &[MachineId],
) -> Result<HashMap<MachineId, Vec<MachineStateHistory>>, DatabaseError> {
    let query = "SELECT machine_id, state, state_version, timestamp
        FROM machine_state_history
        WHERE machine_id=ANY($1)
        ORDER BY id ASC";
    let str_ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
    let query_results = sqlx::query_as::<_, DbMachineStateHistory>(query)
        .bind(str_ids)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    let mut histories = HashMap::new();
    for result in query_results.into_iter() {
        let events: &mut Vec<MachineStateHistory> = histories.entry(result.machine_id).or_default();
        events.push(MachineStateHistory {
            state: result.state,
            state_version: result.state_version,
        });
    }
    Ok(histories)
}

#[cfg(test)] // only used in tests today
pub async fn for_machine(
    txn: &mut Transaction<'_, Postgres>,
    id: &MachineId,
) -> Result<Vec<MachineStateHistory>, DatabaseError> {
    let query = "SELECT machine_id, state, state_version, timestamp
        FROM machine_state_history
        WHERE machine_id=$1
        ORDER BY id ASC";
    sqlx::query_as::<_, DbMachineStateHistory>(query)
        .bind(id.to_string())
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
        .map(|events| events.into_iter().map(Into::into).collect())
}

/// Store each state for debugging purpose.
pub async fn persist(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    state: ManagedHostState,
    state_version: ConfigVersion,
) -> Result<MachineStateHistory, DatabaseError> {
    let query = "INSERT INTO machine_state_history (machine_id, state, state_version)
        VALUES ($1, $2, $3)
        RETURNING machine_id, state, state_version, timestamp";
    sqlx::query_as::<_, DbMachineStateHistory>(query)
        .bind(machine_id.to_string())
        .bind(sqlx::types::Json(state))
        .bind(state_version)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
        .map(Into::into)
}

/// Renames all history entries using one Machine ID into using another Machine ID
pub async fn update_machine_ids(
    txn: &mut Transaction<'_, Postgres>,
    old_machine_id: &MachineId,
    new_machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machine_state_history SET machine_id=$1 WHERE machine_id=$2";
    sqlx::query(query)
        .bind(new_machine_id.to_string())
        .bind(old_machine_id.to_string())
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}
