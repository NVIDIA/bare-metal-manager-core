/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

/// A record of a past state of a NetworkSegment
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSegmentStateHistory {
    /// The numeric identifier of the state change. This is a global change number
    /// for all states, and therefore not important for consumers
    #[serde(skip)]
    _id: i64,

    /// The UUID of the network segment that experienced the state change
    segment_id: NetworkSegmentId,

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
        Ok(NetworkSegmentStateHistory {
            _id: row.try_get("id")?,
            segment_id: row.try_get("segment_id")?,
            state: row.try_get("state")?,
            state_version: row.try_get("state_version")?,
            timestamp: row.try_get("timestamp")?,
        })
    }
}
