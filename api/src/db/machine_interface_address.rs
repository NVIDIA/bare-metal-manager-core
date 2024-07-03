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
use std::collections::HashMap;
use std::net::IpAddr;

use itertools::Itertools;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use super::{
    machine::DbMachineId,
    machine_interface::{MachineInterfaceId, MachineInterfaceIdKeyedObjectFilter},
    network_segment::NetworkSegmentType,
    DatabaseError,
};
use crate::model::machine::machine_id::MachineId;

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddress {
    pub interface_id: MachineInterfaceId,
    pub address: IpAddr,
}

impl MachineInterfaceAddress {
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

    pub async fn find_ipv4_for_interface(
        txn: &mut Transaction<'_, Postgres>,
        interface_id: MachineInterfaceId,
    ) -> Result<MachineInterfaceAddress, DatabaseError> {
        let query = "SELECT * FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = 4";
        sqlx::query_as(query)
            .bind(interface_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_for_interface(
        txn: &mut Transaction<'_, Postgres>,
        filter: MachineInterfaceIdKeyedObjectFilter<'_>,
    ) -> Result<HashMap<MachineInterfaceId, Vec<MachineInterfaceAddress>>, DatabaseError> {
        let base_query = "SELECT * FROM machine_interface_addresses mia {where}".to_owned();

        Ok(match filter {
            MachineInterfaceIdKeyedObjectFilter::All => {
                sqlx::query_as::<_, MachineInterfaceAddress>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_interface_addresses All", e)
                    })?
            }
            MachineInterfaceIdKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, MachineInterfaceAddress>(
                    &base_query.replace("{where}", "WHERE mia.interface_id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| {
                    DatabaseError::new(file!(), line!(), "machine_interface_addresses One", e)
                })?
            }
            MachineInterfaceIdKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, MachineInterfaceAddress>(
                    &base_query.replace("{where}", "WHERE mia.interface_id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| {
                    DatabaseError::new(file!(), line!(), "machine_interface_addresses List", e)
                })?
            }
        }
        .into_iter()
        .into_group_map_by(|address| address.interface_id))
    }

    pub async fn find_by_address(
        txn: &mut Transaction<'_, Postgres>,
        address: IpAddr,
    ) -> Result<Option<MachineInterfaceSearchResult>, DatabaseError> {
        let query = "SELECT mi.id, mi.machine_id, ns.name, ns.network_segment_type
            FROM machine_interface_addresses mia
            INNER JOIN machine_interfaces mi ON mi.id = mia.interface_id
            INNER JOIN network_segments ns ON ns.id = mi.segment_id
            WHERE mia.address = $1::inet
        ";
        sqlx::query_as(query)
            .bind(address)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        interface_id: MachineInterfaceId,
    ) -> Result<(), DatabaseError> {
        let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1";
        sqlx::query(query)
            .bind(interface_id)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct MachineInterfaceSearchResult {
    pub interface_id: MachineInterfaceId,
    pub machine_id: Option<MachineId>,
    pub segment_name: String,
    pub segment_type: NetworkSegmentType,
}

impl<'r> FromRow<'r, PgRow> for MachineInterfaceSearchResult {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let machine_id: Option<DbMachineId> = row.try_get("machine_id")?;
        Ok(MachineInterfaceSearchResult {
            interface_id: row.try_get("id")?,
            machine_id: machine_id.map(|id| id.into_inner()),
            segment_name: row.try_get("name")?,
            segment_type: row.try_get("network_segment_type")?,
        })
    }
}
