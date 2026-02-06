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

use carbide_uuid::network::NetworkSegmentId;
use config_version::ConfigVersion;
use model::network_segment::NetworkSegmentControllerState;
use sqlx::PgConnection;

use super::DatabaseError;

pub async fn for_segment(
    txn: &mut PgConnection,
    segment_id: &NetworkSegmentId,
) -> Result<Vec<model::network_segment_state_history::NetworkSegmentStateHistory>, DatabaseError> {
    let query = "SELECT id, segment_id, state::TEXT, state_version, timestamp
            FROM network_segment_state_history
            WHERE segment_id=$1
            ORDER BY ID asc";
    sqlx::query_as(query)
        .bind(segment_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Store each state for debugging purpose.
pub async fn persist(
    txn: &mut PgConnection,
    segment_id: NetworkSegmentId,
    state: &NetworkSegmentControllerState,
    state_version: ConfigVersion,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO network_segment_state_history (segment_id, state, state_version)
            VALUES ($1, $2, $3)";
    sqlx::query(query)
        .bind(segment_id)
        .bind(sqlx::types::Json(state))
        .bind(state_version)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}
