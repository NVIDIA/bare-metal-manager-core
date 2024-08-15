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
    ) -> Result<Vec<HostMachineUpdate>, DatabaseError> {
        let query = "SELECT id FROM machines WHERE host_reprovisioning_requested IS NOT NULL AND host_reprovisioning_requested != 'null';";
        sqlx::query_as::<_, HostMachineUpdate>(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_outdated_hosts", e))
    }

    pub async fn find_upgrade_in_progress(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<HostMachineUpdate>, DatabaseError> {
        let query =
            "SELECT id FROM machines WHERE controller_state->'state' = '\"hostreprovision\"';";
        sqlx::query_as::<_, HostMachineUpdate>(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_outdated_hosts", e))
    }
}
