/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use sqlx::{FromRow, Postgres, Transaction};

use super::DatabaseError;
use crate::{
    machine_update_manager::machine_update_module::create_host_update_health_report,
    model::machine::HostReprovisionRequest,
};
use forge_uuid::machine::MachineId;

#[derive(Debug, FromRow)]
pub struct HostMachineUpdate {
    pub id: MachineId,
}

impl HostMachineUpdate {
    pub async fn find_upgrade_needed(
        txn: &mut Transaction<'_, Postgres>,
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
        WHERE machines.id LIKE 'fm100h%'
            {}
            AND machines.host_reprovisioning_requested IS NULL
            AND desired_firmware.versions->>'Versions' != explored_endpoints.exploration_report->>'Versions'
            AND (machines.firmware_autoupdate = TRUE{})
        ORDER BY machines.controller_state->>'state' != 'ready'
        ;"#,
            ready_only, from_global,
        );
        sqlx::query_as(query.as_str())
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_outdated_hosts", e))
    }

    pub async fn find_upgrade_in_progress(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<HostMachineUpdate>, DatabaseError> {
        let query =
            "SELECT id FROM machines WHERE controller_state->'state' = '\"hostreprovision\"'";
        sqlx::query_as(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_outdated_hosts", e))
    }

    pub async fn find_completed_updates(
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Vec<MachineId>, DatabaseError> {
        let query = r#"SELECT id FROM machines
                    WHERE host_reprovisioning_requested IS NULL
                            AND coalesce(health_report_overrides, '{"merges": {}}'::jsonb)->'merges' ? 'host-fw-update' = TRUE"#;
        sqlx::query_as::<_, MachineId>(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

pub async fn trigger_host_reprovisioning_request(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    initiator: &str,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let req = HostReprovisionRequest {
        requested_at: chrono::Utc::now(),
        started_at: None,
        initiator: initiator.to_string(),
        user_approval_received: false,
    };

    // The WHERE on controller state means that we'll update it in the case where we were in ready, but not when assigned.
    let query = r#"UPDATE machines SET host_reprovisioning_requested=$2 WHERE id=$1 RETURNING id"#;
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .bind(sqlx::types::Json(req))
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    let health_override = create_host_update_health_report(
        Some("HostFirmware".to_string()),
        "Host firmware update".to_string(),
        true,
    );

    // Mark the Host as in update.
    // If an update is already scheduled (host-fw-update field is set),
    // then the process is aborted

    crate::db::machine::insert_health_report_override(
        txn,
        machine_id,
        health_report::OverrideMode::Merge,
        &health_override,
        true,
    )
    .await?;
    Ok(())
}

pub async fn clear_host_reprovisioning_request(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET host_reprovisioning_requested = NULL WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}
