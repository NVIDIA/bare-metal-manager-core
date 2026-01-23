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
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// History of Power Shelf states for a single Power Shelf
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct DbPowerShelfStateHistory {
    /// The ID of the power shelf that experienced the state change
    pub power_shelf_id: PowerShelfId,

    /// The state that was entered
    pub state: String,

    /// Current version.
    pub state_version: ConfigVersion,
    // The timestamp of the state change, currently unused
    //timestamp: DateTime<Utc>,
}

impl From<DbPowerShelfStateHistory> for crate::power_shelf::PowerShelfStateHistory {
    fn from(event: DbPowerShelfStateHistory) -> Self {
        Self {
            state: event.state,
            state_version: event.state_version,
        }
    }
}
