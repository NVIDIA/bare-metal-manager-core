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

use carbide_uuid::dpa_interface::DpaInterfaceId;
use config_version::ConfigVersion;
use model::dpa_interface::{DpaInterfaceControllerState, DpaInterfaceStateHistoryRecord};
use sqlx::PgConnection;

use super::DatabaseError;

/// Store each state for debugging purpose.
pub async fn persist(
    txn: &mut PgConnection,
    interface_id: DpaInterfaceId,
    state: &DpaInterfaceControllerState,
    state_version: ConfigVersion,
) -> Result<DpaInterfaceStateHistoryRecord, DatabaseError> {
    let query = "INSERT INTO dpa_interface_state_history (interface_id, state, state_version)
            VALUES ($1, $2, $3) RETURNING interface_id, state::TEXT, state_version, timestamp";
    sqlx::query_as::<_, DpaInterfaceStateHistoryRecord>(query)
        .bind(interface_id)
        .bind(sqlx::types::Json(state))
        .bind(state_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
