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
