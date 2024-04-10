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
use std::collections::HashMap;

use chrono::prelude::*;
use config_version::ConfigVersion;
use itertools::Itertools;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use super::DatabaseError;
use crate::model::network_segment::NetworkSegmentControllerState;

/// A record of a past state of a NetworkSegment
///
#[derive(Debug, Clone)]
pub struct NetworkSegmentStateHistory {
    /// The numeric identifier of the state change. This is a global change number
    /// for all states, and therefore not important for consumers
    _id: i64,

    /// The UUID of the network segment that experienced the state change
    segment_id: uuid::Uuid,

    /// The state that was entered
    pub state: String,
    pub state_version: ConfigVersion,

    /// The timestamp of the state change
    timestamp: DateTime<Utc>,
}

impl TryFrom<NetworkSegmentStateHistory> for rpc::forge::NetworkSegmentStateHistory {
    fn try_from(value: NetworkSegmentStateHistory) -> Result<Self, Self::Error> {
        Ok(rpc::forge::NetworkSegmentStateHistory {
            state: value.state,
            version: value.state_version.version_string(),
            time: Some(value.timestamp.into()),
        })
    }

    type Error = serde_json::Error;
}

impl<'r> FromRow<'r, PgRow> for NetworkSegmentStateHistory {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let state_version_str: &str = row.try_get("state_version")?;
        let state_version = state_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        Ok(NetworkSegmentStateHistory {
            _id: row.try_get("id")?,
            segment_id: row.try_get("segment_id")?,
            state: row.try_get("state")?,
            state_version,
            timestamp: row.try_get("timestamp")?,
        })
    }
}

impl NetworkSegmentStateHistory {
    /// Retrieve the state history for a list of NetworkSegments
    ///
    /// It returns a [HashMap][std::collections::HashMap] keyed by the segment ID and values of
    /// all states that have been entered.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to an open Transaction
    ///
    pub async fn find_by_segment_ids(
        txn: &mut Transaction<'_, Postgres>,
        ids: &[uuid::Uuid],
    ) -> Result<HashMap<uuid::Uuid, Vec<Self>>, DatabaseError> {
        let query =
            "SELECT id, segment_id, state::TEXT, state_version, timestamp FROM network_segment_state_history WHERE segment_id=ANY($1) ORDER BY ID asc";
        Ok(sqlx::query_as::<_, Self>(query)
            .bind(ids)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            .into_iter()
            .into_group_map_by(|event| event.segment_id))
    }

    pub async fn for_segment(
        txn: &mut Transaction<'_, Postgres>,
        id: &uuid::Uuid,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT id, segment_id, state::TEXT, state_version, timestamp
            FROM network_segment_state_history
            WHERE segment_id=$1::uuid
            ORDER BY ID asc";
        sqlx::query_as::<_, Self>(query)
            .bind(id)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// Store each state for debugging purpose.
    pub async fn persist(
        txn: &mut Transaction<'_, Postgres>,
        segment_id: uuid::Uuid,
        state: &NetworkSegmentControllerState,
        state_version: ConfigVersion,
    ) -> Result<(), DatabaseError> {
        let query = "INSERT INTO network_segment_state_history (segment_id, state, state_version)
            VALUES ($1, $2, $3)";
        sqlx::query(query)
            .bind(segment_id)
            .bind(sqlx::types::Json(state))
            .bind(state_version.version_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }
}
