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
use carbide_uuid::power_shelf::PowerShelfId;
use config_version::ConfigVersion;
use model::power_shelf::PowerShelfControllerState;
use model::state_history::StateHistoryRecord;
use sqlx::{FromRow, PgConnection};

use crate::{DatabaseError, DatabaseResult};

/// History of Power Shelf states for a single Power Shelf
#[derive(Debug, Clone, FromRow)]
struct DbPowerShelfStateHistoryRecord {
    /// The ID of the power shelf that experienced the state change
    power_shelf_id: PowerShelfId,

    /// The state that was entered
    state: String,

    /// Current version.
    state_version: ConfigVersion,
    // The timestamp of the state change, currently unused
    //timestamp: DateTime<Utc>,
}

impl From<DbPowerShelfStateHistoryRecord> for StateHistoryRecord {
    fn from(event: DbPowerShelfStateHistoryRecord) -> Self {
        Self {
            state: event.state,
            state_version: event.state_version,
        }
    }
}

/// Retrieve the power shelf state history for a list of Power Shelves
///
/// It returns a [HashMap][std::collections::HashMap] keyed by the power shelf ID and values of
/// all states that have been entered.
///
/// Arguments:
///
/// * `txn` - A reference to an open Transaction
pub async fn find_by_power_shelf_ids(
    txn: &mut PgConnection,
    ids: &[PowerShelfId],
) -> DatabaseResult<std::collections::HashMap<PowerShelfId, Vec<StateHistoryRecord>>> {
    let query = "SELECT power_shelf_id, state::TEXT, state_version, timestamp
        FROM power_shelf_state_history
        WHERE power_shelf_id=ANY($1)
        ORDER BY id ASC";
    let query_results = sqlx::query_as::<_, DbPowerShelfStateHistoryRecord>(query)
        .bind(ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    let mut histories = std::collections::HashMap::new();
    for result in query_results.into_iter() {
        let events: &mut Vec<StateHistoryRecord> =
            histories.entry(result.power_shelf_id).or_default();
        events.push(StateHistoryRecord {
            state: result.state,
            state_version: result.state_version,
        });
    }
    Ok(histories)
}

pub async fn for_power_shelf(
    txn: &mut PgConnection,
    id: &PowerShelfId,
) -> DatabaseResult<Vec<StateHistoryRecord>> {
    let query = "SELECT power_shelf_id, state::TEXT, state_version, timestamp
        FROM power_shelf_state_history
        WHERE power_shelf_id=$1
        ORDER BY id ASC";
    sqlx::query_as::<_, DbPowerShelfStateHistoryRecord>(query)
        .bind(id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
        .map(|events| events.into_iter().map(Into::into).collect())
}

/// Store each state for debugging purpose.
pub async fn persist(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
    state: &PowerShelfControllerState,
    state_version: ConfigVersion,
) -> DatabaseResult<StateHistoryRecord> {
    let query = "INSERT INTO power_shelf_state_history (power_shelf_id, state, state_version)
        VALUES ($1, $2, $3)
        RETURNING power_shelf_id, state::TEXT, state_version, timestamp";
    sqlx::query_as::<_, DbPowerShelfStateHistoryRecord>(query)
        .bind(power_shelf_id)
        .bind(sqlx::types::Json(state))
        .bind(state_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
        .map(Into::into)
}

/// Delete all state history entries for a power shelf.
pub async fn delete_by_power_shelf_id(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
) -> DatabaseResult<u64> {
    let query = "DELETE FROM power_shelf_state_history WHERE power_shelf_id = $1";
    let result = sqlx::query(query)
        .bind(power_shelf_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    Ok(result.rows_affected())
}
