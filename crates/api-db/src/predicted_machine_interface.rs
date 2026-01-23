/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use mac_address::MacAddress;
use model::predicted_machine_interface::{NewPredictedMachineInterface, PredictedMachineInterface};
use sqlx::PgConnection;

use crate::{ColumnInfo, DatabaseError, FilterableQueryBuilder, ObjectColumnFilter};

#[derive(Clone, Copy)]
pub struct MachineIdColumn;

impl ColumnInfo<'_> for crate::predicted_machine_interface::MachineIdColumn {
    type TableType = PredictedMachineInterface;
    type ColumnType = carbide_uuid::machine::MachineId;
    fn column_name(&self) -> &'static str {
        "machine_id"
    }
}

#[derive(Clone, Copy)]
pub struct MacAddressColumn;
impl ColumnInfo<'_> for MacAddressColumn {
    type TableType = PredictedMachineInterface;
    type ColumnType = MacAddress;
    fn column_name(&self) -> &'static str {
        "mac_address"
    }
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = PredictedMachineInterface>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<PredictedMachineInterface>, DatabaseError> {
    let mut query =
        FilterableQueryBuilder::new("SELECT * FROM predicted_machine_interfaces").filter(&filter);
    query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

pub async fn delete(
    value: &PredictedMachineInterface,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM predicted_machine_interfaces WHERE id = $1";
    sqlx::query(query)
        .bind(value.id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn find_by_mac_address(
    txn: &mut PgConnection,
    mac_address: MacAddress,
) -> Result<Option<PredictedMachineInterface>, DatabaseError> {
    Ok(
        find_by(txn, ObjectColumnFilter::One(MacAddressColumn, &mac_address))
            .await?
            .into_iter()
            .next(),
    )
}

pub async fn create(
    value: NewPredictedMachineInterface<'_>,
    txn: &mut PgConnection,
) -> Result<PredictedMachineInterface, DatabaseError> {
    let query = "INSERT INTO predicted_machine_interfaces (machine_id, mac_address, expected_network_segment_type) VALUES ($1, $2, $3) RETURNING *";
    sqlx::query_as(query)
        .bind(value.machine_id)
        .bind(value.mac_address)
        .bind(value.expected_network_segment_type)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
