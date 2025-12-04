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

use carbide_uuid::switch::SwitchId;
use model::switch::{SwitchConfig, SwitchControllerState, SwitchStatus};
use sqlx::PgConnection;

/// Creates a basic switch configuration for testing
#[allow(dead_code)]
pub fn create_basic_switch_config() -> SwitchConfig {
    SwitchConfig {
        name: "Basic Test Switch".to_string(),
        enable_nmxc: false,
        fabric_manager_config: None,
        location: Some("Data Center A, Rack 1".to_string()),
    }
}

/// Creates an NMXC switch configuration for testing
#[allow(dead_code)]
pub fn create_nmxc_switch_config() -> SwitchConfig {
    SwitchConfig {
        name: "High Capacity Switch".to_string(),
        enable_nmxc: true,
        fabric_manager_config: None,
        location: Some("Data Center B, Rack 2".to_string()),
    }
}

/// Creates a switch status for testing
#[allow(dead_code)]
pub fn create_test_switch_status() -> SwitchStatus {
    SwitchStatus {
        switch_name: "Test Switch".to_string(),
        power_state: "on".to_string(),
        health_status: "ok".to_string(),
    }
}

/// Creates a switch status with warning health
#[allow(dead_code)]
pub fn create_warning_switch_status() -> SwitchStatus {
    SwitchStatus {
        switch_name: "Warning Switch".to_string(),
        power_state: "on".to_string(),
        health_status: "warning".to_string(),
    }
}

/// Creates a switch status with critical health
#[allow(dead_code)]
pub fn create_critical_switch_status() -> SwitchStatus {
    SwitchStatus {
        switch_name: "Critical Switch".to_string(),
        power_state: "off".to_string(),
        health_status: "critical".to_string(),
    }
}

/// Helper function to set switch controller state directly in database
pub async fn set_switch_controller_state(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    state: SwitchControllerState,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE switches SET controller_state = $1 WHERE id = $2")
        .bind(serde_json::to_value(state).unwrap())
        .bind(switch_id)
        .execute(txn)
        .await?;

    Ok(())
}

/// Helper function to mark switch as deleted
pub async fn mark_switch_as_deleted(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE switches SET deleted = NOW() WHERE id = $1")
        .bind(switch_id)
        .execute(txn)
        .await?;

    Ok(())
}

/// Helper function to update switch status
#[allow(dead_code)]
pub async fn update_switch_status(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    status: &SwitchStatus,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE switches SET status = $1 WHERE id = $2")
        .bind(serde_json::to_value(status).unwrap())
        .bind(switch_id)
        .execute(txn)
        .await?;

    Ok(())
}
