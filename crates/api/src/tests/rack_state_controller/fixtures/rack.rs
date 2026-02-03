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
use model::rack::RackState;
use sqlx::PgConnection;

/// Helper function to set rack controller state directly in database
pub async fn set_rack_controller_state(
    txn: &mut PgConnection,
    rack_id: RackId,
    state: RackState,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE racks SET controller_state = $1 WHERE id = $2")
        .bind(serde_json::to_value(state).unwrap())
        .bind(rack_id)
        .execute(txn)
        .await?;

    Ok(())
}

/// Helper function to mark rack as deleted
pub async fn mark_rack_as_deleted(
    txn: &mut PgConnection,
    rack_id: RackId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE racks SET deleted = NOW() WHERE id = $1")
        .bind(rack_id)
        .execute(txn)
        .await?;

    Ok(())
}
