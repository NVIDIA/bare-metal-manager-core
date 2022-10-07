/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use ipnetwork::IpNetwork;
use itertools::Itertools;
use sqlx::{Acquire, FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::{CarbideError, CarbideResult};

use super::{
    address_selection_strategy::AddressSelectionStrategy, machine_interface::MachineInterface,
    network_segment::NetworkSegment, UuidKeyedObjectFilter,
};

#[derive(Debug, FromRow, Clone)]
pub struct InstanceSubnetAddress {
    pub id: Uuid,
    pub instance_subnet_id: Uuid,
    pub address: IpNetwork,
}

impl InstanceSubnetAddress {
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

    pub async fn find_for_instance(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<HashMap<Uuid, Vec<InstanceSubnetAddress>>> {
        let base_query = "SELECT * FROM instance_subnet_addresses isa {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, InstanceSubnetAddress>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, InstanceSubnetAddress>(
                    &base_query.replace("{where}", "WHERE isa.instance_subnet_id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, InstanceSubnetAddress>(
                    &base_query.replace("{where}", "WHERE isa.instance_subnet_id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        }
        .into_iter()
        .into_group_map_by(|address| address.instance_subnet_id))
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        instance_subnet_id: uuid::Uuid,
    ) -> CarbideResult<()> {
        // Lock MUST be taken by calling function.
        let _: Vec<(uuid::Uuid,)> = sqlx::query_as(
            "DELETE FROM instance_subnet_addresses WHERE instance_subnet_id=$1 RETURNING id",
        )
        .bind(instance_subnet_id)
        .fetch_all(&mut *txn)
        .await?;
        Ok(())
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        segment: &NetworkSegment,
        addresses: AddressSelectionStrategy<'_>,
        instance_subnet_id: uuid::Uuid,
    ) -> CarbideResult<Vec<IpNetwork>> {
        // We're potentially about to insert a couple rows, so create a savepoint.
        let mut inner_txn = txn.begin().await?;

        let allocated_addresses =
            MachineInterface::allocate_addresses(&mut inner_txn, segment, addresses).await?;

        for address in allocated_addresses {
            sqlx::query("INSERT INTO instance_subnet_addresses (instance_subnet_id, address) VALUES ($1::uuid, $2::inet)")
                .bind(instance_subnet_id)
                .bind(address)
                .fetch_all(&mut *inner_txn).await?;
        }

        inner_txn.commit().await?;

        let assigned_addresses = InstanceSubnetAddress::find_for_instance(
            &mut *txn,
            UuidKeyedObjectFilter::One(instance_subnet_id),
        )
        .await?
        .remove(&instance_subnet_id)
        .ok_or(CarbideError::NotFoundError(instance_subnet_id))?
        .into_iter()
        .map(|isa: InstanceSubnetAddress| isa.address)
        .collect();

        Ok(assigned_addresses)
    }
}
