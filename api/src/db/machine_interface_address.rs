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
use std::str::FromStr;

use itertools::Itertools;
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{network_segment::NetworkSegmentType, DatabaseError, UuidKeyedObjectFilter};
use crate::model::machine::machine_id::MachineId;

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddress {
    pub interface_id: Uuid,
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
        interface_id: Uuid,
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
        filter: UuidKeyedObjectFilter<'_>,
    ) -> Result<HashMap<Uuid, Vec<MachineInterfaceAddress>>, DatabaseError> {
        let base_query = "SELECT * FROM machine_interface_addresses mia {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, MachineInterfaceAddress>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_interface_addresses All", e)
                    })?
            }
            UuidKeyedObjectFilter::One(uuid) => sqlx::query_as::<_, MachineInterfaceAddress>(
                &base_query.replace("{where}", "WHERE mia.interface_id=$1"),
            )
            .bind(uuid)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "machine_interface_addresses One", e)
            })?,
            UuidKeyedObjectFilter::List(list) => sqlx::query_as::<_, MachineInterfaceAddress>(
                &base_query.replace("{where}", "WHERE mia.interface_id=ANY($1)"),
            )
            .bind(list)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "machine_interface_addresses List", e)
            })?,
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
}

#[derive(Debug)]
pub struct MachineInterfaceSearchResult {
    pub interface_id: Uuid,
    pub machine_id: MachineId,
    pub segment_name: String,
    pub segment_type: NetworkSegmentType,
}

impl<'r> FromRow<'r, PgRow> for MachineInterfaceSearchResult {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let stable_string: String = row.try_get("machine_id")?;
        let machine_id = MachineId::from_str(&stable_string).unwrap();
        Ok(MachineInterfaceSearchResult {
            interface_id: row.try_get("id")?,
            machine_id,
            segment_name: row.try_get("name")?,
            segment_type: row.try_get("network_segment_type")?,
        })
    }
}
