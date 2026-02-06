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
use carbide_uuid::machine::MachineId;
use config_version::ConfigVersion;
use model::machine::{MachineStateHistory, ManagedHostState};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgConnection};

use crate::DatabaseError;

/// History of Machine states for a single Machine
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
struct DbMachineStateHistory {
    /// The ID of the machine that experienced the state change
    pub machine_id: MachineId,

    /// The state that was entered
    pub state: String,

    /// Current version.
    pub state_version: ConfigVersion,
    // The timestamp of the state change, currently unused
    //timestamp: DateTime<Utc>,
}

impl From<DbMachineStateHistory> for model::machine::MachineStateHistory {
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
    txn: &mut PgConnection,
    ids: &[MachineId],
) -> Result<std::collections::HashMap<MachineId, Vec<MachineStateHistory>>, DatabaseError> {
    let query = "SELECT machine_id, state::TEXT, state_version, timestamp
        FROM machine_state_history
        WHERE machine_id=ANY($1)
        ORDER BY id ASC";
    let str_ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
    let query_results = sqlx::query_as::<_, DbMachineStateHistory>(query)
        .bind(str_ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let mut histories = std::collections::HashMap::new();
    for result in query_results.into_iter() {
        let events: &mut Vec<MachineStateHistory> = histories.entry(result.machine_id).or_default();
        events.push(MachineStateHistory {
            state: result.state,
            state_version: result.state_version,
        });
    }
    Ok(histories)
}

pub async fn for_machine(
    txn: &mut PgConnection,
    id: &MachineId,
) -> Result<Vec<MachineStateHistory>, DatabaseError> {
    let query = "SELECT machine_id, state::TEXT, state_version, timestamp
        FROM machine_state_history
        WHERE machine_id=$1
        ORDER BY id ASC";
    sqlx::query_as::<_, DbMachineStateHistory>(query)
        .bind(id.to_string())
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
        .map(|events| events.into_iter().map(Into::into).collect())
}

/// Store each state for debugging purpose.
pub async fn persist(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    state: &ManagedHostState,
    state_version: ConfigVersion,
) -> Result<MachineStateHistory, DatabaseError> {
    let query = "INSERT INTO machine_state_history (machine_id, state, state_version)
        VALUES ($1, $2, $3)
        RETURNING machine_id, state::TEXT, state_version, timestamp";
    sqlx::query_as::<_, DbMachineStateHistory>(query)
        .bind(machine_id)
        .bind(sqlx::types::Json(state))
        .bind(state_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
        .map(Into::into)
}

/// Renames all history entries using one Machine ID into using another Machine ID
pub async fn update_machine_ids(
    txn: &mut PgConnection,
    old_machine_id: &MachineId,
    new_machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machine_state_history SET machine_id=$1 WHERE machine_id=$2";
    sqlx::query(query)
        .bind(new_machine_id)
        .bind(old_machine_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}
