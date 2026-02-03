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
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// History of Rack states for a single Rack
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct DbRackStateHistory {
    /// The ID of the rack that experienced the state change
    pub rack_id: RackId,

    /// The state that was entered
    pub state: String,

    /// Current version.
    pub state_version: ConfigVersion,
    // The timestamp of the state change, currently unused
    // timestamp: DateTime<Utc>,
}

impl From<DbRackStateHistory> for crate::rack::RackStateHistory {
    fn from(event: DbRackStateHistory) -> Self {
        Self {
            state: event.state,
            state_version: event.state_version,
        }
    }
}
