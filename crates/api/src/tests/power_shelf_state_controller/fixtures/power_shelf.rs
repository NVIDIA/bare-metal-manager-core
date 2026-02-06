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

use carbide_uuid::power_shelf::PowerShelfId;
use model::power_shelf::PowerShelfControllerState;
use sqlx::PgConnection;

/// Helper function to set power shelf controller state directly in database
pub async fn set_power_shelf_controller_state(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
    state: PowerShelfControllerState,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE power_shelves SET controller_state = $1 WHERE id = $2")
        .bind(serde_json::to_value(state).unwrap())
        .bind(power_shelf_id)
        .execute(txn)
        .await?;

    Ok(())
}

/// Helper function to mark power shelf as deleted
pub async fn mark_power_shelf_as_deleted(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE power_shelves SET deleted = NOW() WHERE id = $1")
        .bind(power_shelf_id)
        .execute(txn)
        .await?;

    Ok(())
}
