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
use carbide_uuid::rack::RackId;
use config_version::ConfigVersion;
use model::rack::{RackState, RackStateHistory};
use model::rack_state_history::DbRackStateHistory;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

/// Retrieve the rack state history for a list of Racks
///
/// It returns a [HashMap][std::collections::HashMap] keyed by the rack ID and values of
/// all states that have been entered.
///
/// Arguments:
///
/// * `txn` - A reference to an open Transaction
///
#[allow(dead_code)]
pub async fn find_by_rack_ids(
    txn: &mut PgConnection,
    ids: &[RackId],
) -> DatabaseResult<std::collections::HashMap<RackId, Vec<RackStateHistory>>> {
    let query = "SELECT rack_id, state::TEXT, state_version, timestamp
        FROM rack_state_history
        WHERE rack_id=ANY($1)
        ORDER BY id ASC";
    let query_results = sqlx::query_as::<_, DbRackStateHistory>(query)
        .bind(ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    let mut histories = std::collections::HashMap::new();
    for result in query_results.into_iter() {
        let events: &mut Vec<RackStateHistory> = histories.entry(result.rack_id).or_default();
        events.push(RackStateHistory {
            state: result.state,
            state_version: result.state_version,
        });
    }
    Ok(histories)
}

/// Store each state for debugging purpose.
pub async fn persist(
    txn: &mut PgConnection,
    rack_id: RackId,
    state: &RackState,
    state_version: ConfigVersion,
) -> DatabaseResult<RackStateHistory> {
    let query = "INSERT INTO rack_state_history (rack_id, state, state_version)
        VALUES ($1, $2, $3)
        RETURNING rack_id, state::TEXT, state_version, timestamp";
    sqlx::query_as::<_, DbRackStateHistory>(query)
        .bind(rack_id)
        .bind(sqlx::types::Json(state))
        .bind(state_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
        .map(Into::into)
}
