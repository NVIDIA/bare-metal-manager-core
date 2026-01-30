/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::switch::SwitchId;
use config_version::ConfigVersion;
use model::switch::{SwitchControllerState, SwitchStateHistoryRecord};
use sqlx::{FromRow, PgConnection};

use crate::{DatabaseError, DatabaseResult};

/// History of Switch states for a single Switch
#[derive(Debug, Clone, FromRow)]
pub struct DbSwitchStateHistoryRecord {
    /// The ID of the switch that experienced the state change
    pub switch_id: SwitchId,

    /// The state that was entered
    pub state: String,

    /// Current version.
    pub state_version: ConfigVersion,
    // The timestamp of the state change, currently unused
    //timestamp: DateTime<Utc>,
}

impl From<DbSwitchStateHistoryRecord> for SwitchStateHistoryRecord {
    fn from(event: DbSwitchStateHistoryRecord) -> Self {
        Self {
            state: event.state,
            state_version: event.state_version,
        }
    }
}

/// Retrieve the switch state history for a list of Switches
///
/// It returns a [HashMap][std::collections::HashMap] keyed by the switch ID and values of
/// all states that have been entered.
///
/// Arguments:
///
/// * `txn` - A reference to an open Transaction
///
pub async fn find_by_switch_ids(
    txn: &mut PgConnection,
    ids: &[SwitchId],
) -> DatabaseResult<std::collections::HashMap<SwitchId, Vec<SwitchStateHistoryRecord>>> {
    let query = "SELECT switch_id, state::TEXT, state_version, timestamp
        FROM switch_state_history
        WHERE switch_id=ANY($1)
        ORDER BY id ASC";
    let query_results = sqlx::query_as::<_, DbSwitchStateHistoryRecord>(query)
        .bind(ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    let mut histories = std::collections::HashMap::new();
    for result in query_results.into_iter() {
        let events: &mut Vec<SwitchStateHistoryRecord> =
            histories.entry(result.switch_id).or_default();
        events.push(SwitchStateHistoryRecord {
            state: result.state,
            state_version: result.state_version,
        });
    }
    Ok(histories)
}

#[cfg(test)] // only used in tests today
#[allow(dead_code)]
pub async fn for_switch(
    txn: &mut PgConnection,
    id: &SwitchId,
) -> DatabaseResult<Vec<SwitchStateHistoryRecord>> {
    let query = "SELECT switch_id, state::TEXT, state_version, timestamp
        FROM switch_state_history
        WHERE switch_id=$1
        ORDER BY id ASC";
    sqlx::query_as::<_, DbSwitchStateHistoryRecord>(query)
        .bind(id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
        .map(|events| events.into_iter().map(Into::into).collect())
}

/// Store each state for debugging purpose.
pub async fn persist(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    state: &SwitchControllerState,
    state_version: ConfigVersion,
) -> DatabaseResult<SwitchStateHistoryRecord> {
    let query = "INSERT INTO switch_state_history (switch_id, state, state_version)
        VALUES ($1, $2, $3)
        RETURNING switch_id, state::TEXT, state_version, timestamp";
    sqlx::query_as::<_, DbSwitchStateHistoryRecord>(query)
        .bind(switch_id)
        .bind(sqlx::types::Json(state))
        .bind(state_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
        .map(Into::into)
}

/// Renames all history entries using one Switch ID into using another Switch ID
#[allow(dead_code)]
pub async fn update_switch_ids(
    txn: &mut PgConnection,
    old_switch_id: &SwitchId,
    new_switch_id: &SwitchId,
) -> DatabaseResult<()> {
    let query = "UPDATE switch_state_history SET switch_id=$1 WHERE switch_id=$2";
    sqlx::query(query)
        .bind(new_switch_id)
        .bind(old_switch_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(())
}
