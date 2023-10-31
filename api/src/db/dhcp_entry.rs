/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

///
/// A machine dhcp response is a representation of some booting interface by Mac Address or DUID
/// (not implemented) that returns the network information for that interface on that node, and
/// contains everything necessary to return a DHCP response
///
#[derive(Debug, FromRow)]
pub struct DhcpEntry {
    pub machine_interface_id: uuid::Uuid,
    pub vendor_string: String,
}

impl DhcpEntry {
    pub async fn find_by_interface_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: &uuid::Uuid,
    ) -> Result<Vec<DhcpEntry>, DatabaseError> {
        let query = "SELECT * FROM dhcp_entries WHERE machine_interface_id = $1::uuid";
        sqlx::query_as(query)
            .bind(machine_interface_id)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
    pub async fn find_all(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<DhcpEntry>, DatabaseError> {
        let query = "SELECT * FROM dhcp_entries";
        sqlx::query_as(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "
INSERT INTO dhcp_entries (machine_interface_id, vendor_string)
VALUES ($1::uuid, $2::varchar)
ON CONFLICT DO NOTHING";
        let _result = sqlx::query(query)
            .bind(self.machine_interface_id)
            .bind(&self.vendor_string)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }
}
