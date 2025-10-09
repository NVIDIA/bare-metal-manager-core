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

use config_version::ConfigVersion;
use forge_uuid::dpa_interface::DpaInterfaceId;
use sqlx::PgConnection;

use super::DatabaseError;
use crate::model::dpa_interface::{DpaInterfaceControllerState, DpaInterfaceStateHistory};

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
        .map_err(|e| DatabaseError::query(query, e))
}
