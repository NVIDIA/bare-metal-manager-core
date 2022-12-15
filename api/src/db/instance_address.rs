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
use sqlx::{query_as, Acquire, FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::dhcp::allocation::{IpAllocator, UsedIpResolver};
use crate::model::network_segment::NetworkSegmentControllerState;
use crate::{model::instance::config::network::InstanceNetworkConfig, CarbideError, CarbideResult};

use super::{
    address_selection_strategy::AddressSelectionStrategy, network_segment::NetworkSegment,
    UuidKeyedObjectFilter,
};

#[derive(Debug, FromRow, Clone)]
pub struct InstanceSegmentAddress {
    pub segment_id: Uuid,
    pub address: IpNetwork,
}

#[derive(Debug, FromRow, Clone)]
pub struct InstanceAddress {
    pub id: Uuid,
    pub instance_id: Uuid,
    pub circuit_id: String,
    pub address: IpNetwork,
}

impl InstanceAddress {
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

    pub async fn find_for_instance(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<HashMap<Uuid, Vec<InstanceAddress>>> {
        let base_query = "SELECT * FROM instance_addresses isa {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, InstanceAddress>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, InstanceAddress>(
                    &base_query.replace("{where}", "WHERE isa.instance_id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, InstanceAddress>(
                    &base_query.replace("{where}", "WHERE isa.instance_id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        }
        .into_iter()
        .into_group_map_by(|address| address.instance_id))
    }

    async fn get_allocated_address(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
    ) -> CarbideResult<Vec<InstanceSegmentAddress>> {
        Ok(query_as(
            r"
            SELECT network_segments.id as segment_id, instance_addresses.address as address 
            FROM instance_addresses
            INNER JOIN network_prefixes ON network_prefixes.circuit_id = instance_addresses.circuit_id
            INNER JOIN network_segments ON network_segments.id = network_prefixes.segment_id
            WHERE instance_addresses.instance_id = $1::uuid",
            )
            .bind(instance_id)
            .fetch_all(&mut *txn)
            .await?)
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
    ) -> CarbideResult<()> {
        // Lock MUST be taken by calling function.
        let _: Vec<(uuid::Uuid,)> =
            sqlx::query_as("DELETE FROM instance_addresses WHERE instance_id=$1 RETURNING id")
                .bind(instance_id)
                .fetch_all(&mut *txn)
                .await?;
        Ok(())
    }

    pub async fn allocate(
        txn: &mut Transaction<'_, Postgres>,
        instance_id: uuid::Uuid,
        instance_network: &InstanceNetworkConfig,
    ) -> CarbideResult<Vec<InstanceSegmentAddress>> {
        // We expect only one ipv4 prefix. Also Ipv6 is not supported yet.
        // We're potentially about to insert a couple rows, so create a savepoint.
        let mut inner_txn = txn.begin().await?;
        sqlx::query("LOCK TABLE instance_addresses IN ACCESS EXCLUSIVE MODE")
            .execute(&mut inner_txn)
            .await?;

        // Assign all addresses in one shot.
        for iface in &instance_network.interfaces {
            let mut segment = NetworkSegment::find(
                &mut inner_txn,
                crate::db::UuidKeyedObjectFilter::One(iface.network_segment_id),
            )
            .await?;

            if segment.is_empty() {
                return Err(CarbideError::FindOneReturnedNoResultsError(
                    iface.network_segment_id,
                ));
            }

            let segment = segment.remove(0);

            if segment.is_marked_as_deleted() {
                // TODO: Single error for not ready and deleted?
                return Err(CarbideError::NetworkSegmentNotReady(format!(
                    "Network segment {} was deleted",
                    segment.id()
                )));
            }

            match &segment.controller_state.value {
                NetworkSegmentControllerState::Ready => {}
                _ => {
                    return Err(CarbideError::NetworkSegmentNotReady(format!(
                        "Segment {} is not ready. State: {:?}",
                        segment.id(),
                        segment.controller_state.value
                    )));
                }
            }

            let mut circuit_id = segment
                .prefixes
                .iter()
                .filter_map(|x| {
                    if x.prefix.is_ipv4() {
                        x.circuit_id.to_owned()
                    } else {
                        None
                    }
                })
                .collect_vec();

            if circuit_id.is_empty() {
                log::error!("Circuit id is not yet updated for segment: {}", segment.id);
                return Err(CarbideError::FindOneReturnedNoResultsError(segment.id));
            } else if circuit_id.len() > 1 {
                return Err(CarbideError::FindOneReturnedManyResultsError(segment.id));
            }
            let circuit_id = circuit_id.remove(0);

            let dhcp_handler = UsedOverlayNetworkIpResolver {
                segment_id: segment.id,
            };

            let allocated_addresses = IpAllocator::new(
                &mut inner_txn,
                &segment,
                &dhcp_handler,
                AddressSelectionStrategy::Automatic,
            )
            .await?;

            for address in allocated_addresses {
                sqlx::query("INSERT INTO instance_addresses (instance_id, circuit_id, address) VALUES ($1::uuid, $2, $3::inet)")
                .bind(instance_id)
                .bind(circuit_id.to_owned())
                .bind(address?)
                .fetch_all(&mut *inner_txn).await?;
            }
        }

        inner_txn.commit().await?;

        InstanceAddress::get_allocated_address(&mut *txn, instance_id).await
    }
}

struct UsedOverlayNetworkIpResolver {
    segment_id: uuid::Uuid,
}

#[async_trait::async_trait]
impl UsedIpResolver for UsedOverlayNetworkIpResolver {
    async fn used_ips(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<(IpNetwork,)>> {
        let query: &str = r"
             SELECT address FROM instance_addresses
             INNER JOIN network_prefixes ON instance_addresses.circuit_id = network_prefixes.circuit_id
             INNER JOIN network_segments ON network_prefixes.segment_id = network_segments.id
             WHERE network_segments.id = $1::uuid";

        sqlx::query_as(query)
            .bind(self.segment_id)
            .fetch_all(&mut *txn)
            .await
            .map_err(CarbideError::from)
    }
}
