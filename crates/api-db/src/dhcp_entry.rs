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
use carbide_uuid::machine::MachineInterfaceId;
use sqlx::{FromRow, PgConnection};

use super::DatabaseError;

/// A machine dhcp response is a representation of some booting interface by Mac Address or DUID
/// (not implemented) that returns the network information for that interface on that node, and
/// contains everything necessary to return a DHCP response
///
#[derive(Debug, FromRow)]
pub struct DhcpEntry {
    pub machine_interface_id: MachineInterfaceId,
    pub vendor_string: String,
}

#[derive(Clone, Copy)]
pub struct MachineInterfaceIdColumn;

impl super::ColumnInfo<'_> for MachineInterfaceIdColumn {
    type TableType = DhcpEntry;
    type ColumnType = MachineInterfaceId;

    fn column_name(&self) -> &'static str {
        "machine_interface_id"
    }
}

pub async fn find_by<'a, C: super::ColumnInfo<'a, TableType = DhcpEntry>>(
    txn: &mut PgConnection,
    filter: super::ObjectColumnFilter<'a, C>,
) -> Result<Vec<DhcpEntry>, DatabaseError> {
    let mut query =
        super::FilterableQueryBuilder::new("SELECT * FROM dhcp_entries").filter(&filter);

    query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

pub async fn persist(value: DhcpEntry, txn: &mut PgConnection) -> Result<(), DatabaseError> {
    let query = "
INSERT INTO dhcp_entries (machine_interface_id, vendor_string)
VALUES ($1::uuid, $2::varchar)
ON CONFLICT DO NOTHING";
    let _result = sqlx::query(query)
        .bind(value.machine_interface_id)
        .bind(&value.vendor_string)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn delete(
    txn: &mut PgConnection,
    machine_interface_id: &MachineInterfaceId,
) -> Result<(), DatabaseError> {
    let query = "
DELETE FROM dhcp_entries WHERE machine_interface_id=$1::uuid";
    sqlx::query(query)
        .bind(machine_interface_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}
