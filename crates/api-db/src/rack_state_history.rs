/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
