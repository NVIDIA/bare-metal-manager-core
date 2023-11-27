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

use super::{DatabaseError, UuidKeyedObjectFilter};

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
    pub async fn find_for_interfaces(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> Result<Vec<DhcpEntry>, DatabaseError> {
        let base_query = "SELECT * FROM dhcp_entries {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, DhcpEntry>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "dhcp_entries All", e))?
            }
            UuidKeyedObjectFilter::One(uuid) => sqlx::query_as::<_, DhcpEntry>(
                &base_query.replace("{where}", "WHERE machine_interface_id=$1"),
            )
            .bind(uuid)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "dhcp_entries One", e))?,
            UuidKeyedObjectFilter::List(list) => sqlx::query_as::<_, DhcpEntry>(
                &base_query.replace("{where}", "WHERE machine_interface_id=ANY($1)"),
            )
            .bind(list)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "dhcp_entries List", e))?,
        })
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
