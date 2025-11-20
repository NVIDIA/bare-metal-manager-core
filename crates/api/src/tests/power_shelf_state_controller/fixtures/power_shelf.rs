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

// use crate::db::power_shelf::{PowerShelfConfig, PowerShelfStatus};
use forge_uuid::power_shelf::PowerShelfId;
use model::power_shelf::PowerShelfControllerState;
use sqlx::PgConnection;

// /// Creates a basic power shelf configuration for testing
// pub fn create_basic_power_shelf_config() -> PowerShelfConfig {
//     PowerShelfConfig {
//         name: "Basic Test Power Shelf".to_string(),
//         capacity: Some(5000), // 5kW
//         voltage: Some(240),   // 240V
//         location: Some("Data Center A, Rack 1".to_string()),
//     }
// }

// /// Creates a high-capacity power shelf configuration for testing

// pub fn create_high_capacity_power_shelf_config() -> PowerShelfConfig {
//     PowerShelfConfig {
//         name: "High Capacity Power Shelf".to_string(),
//         capacity: Some(10000), // 10kW
//         voltage: Some(480),    // 480V
//         location: Some("Data Center B, Rack 2".to_string()),
//     }
// }

// /// Creates a power shelf status for testing
// pub fn create_test_power_shelf_status() -> PowerShelfStatus {
//     PowerShelfStatus {
//         shelf_name: "Test Power Shelf".to_string(),
//         power_state: "on".to_string(),
//         health_status: "ok".to_string(),
//     }
// }

// /// Creates a power shelf status with warning health
// pub fn create_warning_power_shelf_status() -> PowerShelfStatus {
//     PowerShelfStatus {
//         shelf_name: "Warning Power Shelf".to_string(),
//         power_state: "on".to_string(),
//         health_status: "warning".to_string(),
//     }
// }

// /// Creates a power shelf status with critical health
// pub fn create_critical_power_shelf_status() -> PowerShelfStatus {
//     PowerShelfStatus {
//         shelf_name: "Critical Power Shelf".to_string(),
//         power_state: "off".to_string(),
//         health_status: "critical".to_string(),
//     }
// }

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

// /// Helper function to update power shelf status
// pub async fn update_power_shelf_status(
//     txn: &mut PgConnection,
//     power_shelf_id: &PowerShelfId,
//     status: &PowerShelfStatus,
// ) -> Result<(), sqlx::Error> {
//     sqlx::query("UPDATE power_shelf SET status = $1 WHERE id = $2")
//         .bind(serde_json::to_value(status).unwrap())
//         .bind(power_shelf_id)
//         .execute(txn)
//         .await?;

//     Ok(())
// }
