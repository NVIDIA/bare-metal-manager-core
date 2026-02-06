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
