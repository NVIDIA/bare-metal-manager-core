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
use std::{collections::HashMap, net::IpAddr};

use itertools::Itertools;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use super::{DatabaseError, UuidKeyedObjectFilter};

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
}
