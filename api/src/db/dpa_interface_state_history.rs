/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use chrono::prelude::*;
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

use super::DatabaseError;
use crate::model::dpa_interface::DpaInterfaceControllerState;
use forge_uuid::dpa_interface::DpaInterfaceId;

/// A record of a past state of a DpaInterface
///
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DpaInterfaceStateHistory {
    /// The UUID of the dpa interface that experienced the state change
    interface_id: DpaInterfaceId,

    /// The state that was entered
    pub state: String,
    pub state_version: ConfigVersion,

    /// The timestamp of the state change
    timestamp: DateTime<Utc>,
}

impl From<DpaInterfaceStateHistory> for rpc::forge::DpaInterfaceStateHistory {
    fn from(value: DpaInterfaceStateHistory) -> Self {
        rpc::forge::DpaInterfaceStateHistory {
            state: value.state,
            version: value.state_version.version_string(),
            time: Some(value.timestamp.into()),
        }
    }
}

impl DpaInterfaceStateHistory {
    #[cfg(test)]
    pub async fn for_interface(
        txn: &mut PgConnection,
        interface_id: &DpaInterfaceId,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT id, interface_id, state::TEXT, state_version, timestamp
            FROM dpa_interface_state_history
            WHERE interface_id=$1
            ORDER BY ID asc";
        sqlx::query_as(query)
            .bind(interface_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// Store each state for debugging purpose.
    pub async fn persist(
        txn: &mut PgConnection,
        interface_id: DpaInterfaceId,
        state: &DpaInterfaceControllerState,
        state_version: ConfigVersion,
    ) -> Result<DpaInterfaceStateHistory, DatabaseError> {
        let query = "INSERT INTO dpa_interface_state_history (interface_id, state, state_version)
            VALUES ($1, $2, $3) RETURNING interface_id, state::TEXT, state_version, timestamp";
        sqlx::query_as::<_, DpaInterfaceStateHistory>(query)
            .bind(interface_id)
            .bind(sqlx::types::Json(state))
            .bind(state_version)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}
