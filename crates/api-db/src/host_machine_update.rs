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

use carbide_uuid::machine::{MachineId, MachineType};
use model::host_machine_update::HostMachineUpdate;
use model::machine::HostReprovisionRequest;
use sqlx::PgConnection;

use super::DatabaseError;

pub async fn find_upgrade_needed(
    txn: &mut PgConnection,
    global_enabled: bool,
    ready_only: bool,
) -> Result<Vec<HostMachineUpdate>, DatabaseError> {
    let from_global = if global_enabled {
        " OR machines.firmware_autoupdate IS NULL"
    } else {
        ""
    };
    let ready_only = if ready_only {
        "            AND machines.controller_state->>'state' = 'ready'"
    } else {
        ""
    };

    let host_prefix = MachineType::Host.id_prefix();

    // Both desired_firmware.versions and explored_endpoints.exploration_report->>'Versions' are sorted, and will have their keys
    // defined based on the firmware config.  If a new key (component type) is added to the configuration, we would initally flag
    // everything, but nothing would happen to them and the next time site explorer runs on those hosts they will be made to match.
    // The ORDER BY causes us to choose unassigned machines before assigned machines.
    let query = format!(
        r#"select machines.id, explored_endpoints.exploration_report->>'Vendor', explored_endpoints.exploration_report->>'Model'
        FROM explored_endpoints
        INNER JOIN machine_topologies
            ON SPLIT_PART(explored_endpoints.address::text, '/', 1) = machine_topologies.topology->'bmc_info'->>'ip'
        INNER JOIN machines
            ON machine_topologies.machine_id = machines.id
        INNER JOIN desired_firmware
            ON explored_endpoints.exploration_report->>'Vendor' = desired_firmware.vendor AND explored_endpoints.exploration_report->>'Model' = desired_firmware.model
        WHERE starts_with(machines.id, '{host_prefix}')
            {ready_only}
            AND machines.host_reprovisioning_requested IS NULL
            AND desired_firmware.versions->>'Versions' != explored_endpoints.exploration_report->>'Versions'
            AND (machines.firmware_autoupdate = TRUE{from_global})
            AND (desired_firmware.explicit_update_start_needed = false OR ($1 > machines.firmware_update_time_window_start AND $1 < machines.firmware_update_time_window_end))
        ORDER BY machines.controller_state->>'state' != 'ready'
        ;"#,
    );
    sqlx::query_as(query.as_str())
        .bind(chrono::Utc::now())
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("find_outdated_hosts", e))
}

pub async fn find_upgrade_in_progress(
    txn: &mut PgConnection,
) -> Result<Vec<HostMachineUpdate>, DatabaseError> {
    let query = "SELECT id FROM machines WHERE controller_state->'state' = '\"hostreprovision\"'";
    sqlx::query_as(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("find_upgrade_in_progress", e))
}

pub async fn find_completed_updates(
    txn: &mut PgConnection,
) -> Result<Vec<MachineId>, DatabaseError> {
    let query = r#"SELECT id FROM machines
                    WHERE host_reprovisioning_requested IS NULL
                            AND coalesce(health_report_overrides, '{"merges": {}}'::jsonb)->'merges' ? 'host-fw-update' = TRUE"#;
    sqlx::query_as::<_, MachineId>(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn trigger_host_reprovisioning_request(
    txn: &mut PgConnection,
    initiator: &str,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let req = HostReprovisionRequest {
        requested_at: chrono::Utc::now(),
        started_at: None,
        initiator: initiator.to_string(),
        user_approval_received: false,
        request_reset: Some(false),
    };

    // The WHERE on controller state means that we'll update it in the case where we were in ready, but not when assigned.
    let query = r#"UPDATE machines SET host_reprovisioning_requested=$2, update_complete = false WHERE id=$1 RETURNING id"#;
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id)
        .bind(sqlx::types::Json(req))
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn clear_host_reprovisioning_request(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET host_reprovisioning_requested = NULL WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn reset_host_reprovisioning_request(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    clear_reset: bool,
) -> Result<(), DatabaseError> {
    // The WHERE on controller state means that we'll update it in the case where we were in ready, but not when assigned.
    let query = r#"UPDATE machines SET host_reprovisioning_requested = jsonb_set(host_reprovisioning_requested, '{request_reset}', $2::jsonb) WHERE id=$1 RETURNING id"#;
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id)
        .bind(sqlx::types::Json(!clear_reset))
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn set_manual_firmware_upgrade_completed(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let query =
        "UPDATE machines SET manual_firmware_upgrade_completed = NOW() WHERE id = $1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn clear_manual_firmware_upgrade_completed(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET manual_firmware_upgrade_completed = NULL WHERE id = $1";
    sqlx::query(query)
        .bind(machine_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}
