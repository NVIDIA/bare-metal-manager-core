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

use crate::model::machine::machine_id::MachineId;

use super::DatabaseError;

#[derive(Debug, FromRow)]
pub struct HostMachineUpdate {
    pub id: MachineId,
}

impl HostMachineUpdate {
    pub async fn find_upgrade_needed(
        txn: &mut Transaction<'_, Postgres>,
        global_enabled: bool,
    ) -> Result<Vec<HostMachineUpdate>, DatabaseError> {
        let from_global = if global_enabled {
            " OR machines.firmware_autoupdate IS NULL"
        } else {
            ""
        };

        // Both desired_firmware.versions and explored_endpoints.exploration_report->>'Versions' are sorted, and will have their keys
        // defined based on the firmware config.  If a new key (component type) is added to the configuration, we would initally flag
        // everything, but nothing would happen to them and the next time site explorer runs on those hosts they will be made to match.
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
            AND machines.controller_state->>'state' = 'ready'
            AND machines.host_reprovisioning_requested IS NULL
            AND desired_firmware.versions != explored_endpoints.exploration_report->>'Versions'
            AND (machines.firmware_autoupdate = TRUE{})
        ;"#,
            from_global
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
}
