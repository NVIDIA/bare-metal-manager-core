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
