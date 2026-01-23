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
use carbide_uuid::power_shelf::PowerShelfId;
use config_version::ConfigVersion;
use model::power_shelf::{PowerShelfControllerState, PowerShelfStateHistory};
use model::power_shelf_state_history::DbPowerShelfStateHistory;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

/// Retrieve the power shelf state history for a list of Power Shelves
///
/// It returns a [HashMap][std::collections::HashMap] keyed by the power shelf ID and values of
/// all states that have been entered.
///
/// Arguments:
///
/// * `txn` - A reference to an open Transaction
///
pub async fn find_by_power_shelf_ids(
    txn: &mut PgConnection,
    ids: &[PowerShelfId],
) -> DatabaseResult<std::collections::HashMap<PowerShelfId, Vec<PowerShelfStateHistory>>> {
    let query = "SELECT power_shelf_id, state::TEXT, state_version, timestamp
        FROM power_shelf_state_history
        WHERE power_shelf_id=ANY($1)
        ORDER BY id ASC";
    let query_results = sqlx::query_as::<_, DbPowerShelfStateHistory>(query)
        .bind(ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    let mut histories = std::collections::HashMap::new();
    for result in query_results.into_iter() {
        let events: &mut Vec<PowerShelfStateHistory> =
            histories.entry(result.power_shelf_id).or_default();
        events.push(PowerShelfStateHistory {
            state: result.state,
            state_version: result.state_version,
        });
    }
    Ok(histories)
}

#[allow(dead_code)]
pub async fn for_power_shelf(
    txn: &mut PgConnection,
    id: &PowerShelfId,
) -> DatabaseResult<Vec<PowerShelfStateHistory>> {
    let query = "SELECT power_shelf_id, state::TEXT, state_version, timestamp
        FROM power_shelf_state_history
        WHERE power_shelf_id=$1
        ORDER BY id ASC";
    sqlx::query_as::<_, DbPowerShelfStateHistory>(query)
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
) -> DatabaseResult<PowerShelfStateHistory> {
    let query = "INSERT INTO power_shelf_state_history (power_shelf_id, state, state_version)
        VALUES ($1, $2, $3)
        RETURNING power_shelf_id, state::TEXT, state_version, timestamp";
    sqlx::query_as::<_, DbPowerShelfStateHistory>(query)
        .bind(power_shelf_id)
        .bind(sqlx::types::Json(state))
        .bind(state_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
        .map(Into::into)
}

/// Renames all history entries using one Power Shelf ID into using another Power Shelf ID
#[allow(dead_code)]
pub async fn update_power_shelf_ids(
    txn: &mut PgConnection,
    old_power_shelf_id: &PowerShelfId,
    new_power_shelf_id: &PowerShelfId,
) -> DatabaseResult<()> {
    let query = "UPDATE power_shelf_state_history SET power_shelf_id=$1 WHERE power_shelf_id=$2";
    sqlx::query(query)
        .bind(new_power_shelf_id)
        .bind(old_power_shelf_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(())
}
