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
