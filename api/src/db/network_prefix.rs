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
use std::convert::TryFrom;

use ipnetwork::IpNetwork;
use sqlx::postgres::PgRow;
use sqlx::{Acquire, FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use ::rpc::forge as rpc;

use crate::db::UuidKeyedObjectFilter;
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Clone)]
pub struct NetworkPrefix {
    pub id: uuid::Uuid,
    pub segment_id: Uuid,
    pub prefix: IpNetwork,
    pub gateway: Option<IpNetwork>,
    pub num_reserved: i32,
    pub circuit_id: Option<String>,
}

#[derive(Debug)]
pub struct NewNetworkPrefix {
    pub prefix: IpNetwork,
    pub gateway: Option<IpNetwork>,
    pub num_reserved: i32,
}

impl<'r> FromRow<'r, PgRow> for NetworkPrefix {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(NetworkPrefix {
            id: row.try_get("id")?,
            segment_id: row.try_get("segment_id")?,
            prefix: row.try_get("prefix")?,
            gateway: row.try_get("gateway")?,
            num_reserved: row.try_get("num_reserved")?,
            circuit_id: row.try_get("circuit_id")?,
        })
    }
}

impl TryFrom<rpc::NetworkPrefix> for NewNetworkPrefix {
    type Error = CarbideError;

    fn try_from(value: rpc::NetworkPrefix) -> Result<Self, Self::Error> {
        if let Some(_id) = value.id {
            return Err(CarbideError::IdentifierSpecifiedForNewObject(String::from(
                "Network Prefix",
            )));
        }

        Ok(NewNetworkPrefix {
            prefix: value.prefix.parse()?,
            gateway: match value.gateway {
                Some(g) => Some(g.parse()?),
                None => None,
            },
            num_reserved: value.reserve_first,
        })
    }
}

impl From<NetworkPrefix> for rpc::NetworkPrefix {
    fn from(src: NetworkPrefix) -> Self {
        rpc::NetworkPrefix {
            id: Some(src.id.into()),
            prefix: src.prefix.to_string(),
            gateway: src.gateway.map(|v| v.to_string()),
            reserve_first: src.num_reserved,
            state: None,
            events: vec![],
            circuit_id: src.circuit_id,
        }
    }
}

impl NetworkPrefix {
    // Search for specific prefix
    #[tracing::instrument(skip(txn))]
    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        uuid: uuid::Uuid,
    ) -> CarbideResult<NetworkPrefix> {
        Ok(
            sqlx::query_as::<_, NetworkPrefix>("select * from network_prefixes where id=$1")
                .bind(uuid)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
    /*
     * Return a list of `NetworkPrefix`es for a segment.
     */
    #[tracing::instrument(skip(filter))]
    pub async fn find_by_segment(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<Vec<NetworkPrefix>> {
        let base_query = "SELECT * FROM network_prefixes {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, NetworkPrefix>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, NetworkPrefix>(
                    &base_query.replace("{where}", "WHERE segment_id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, NetworkPrefix>(
                    &base_query.replace("{where}", "WHERE segment_id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        })
    }

    /*
     * Create a prefix for a given segment id.
     *
     * Since this function will perform muliple inserts() it wraps the actions in a sub-transaction
     * and rolls it back if any of the inserts fail and wont leave half of them written.
     *
     * # Parameters
     *
     * txn: An in-progress transaction on a connection pool
     * segment: The UUID of a network segment, must already exist and be visible to this
     * transcation
     * prefixes: A slice of the `NewNetworkPrefix` to create.
     */
    pub async fn create_for(
        txn: &mut Transaction<'_, Postgres>,
        segment: &uuid::Uuid,
        prefixes: &[NewNetworkPrefix],
    ) -> CarbideResult<Vec<NetworkPrefix>> {
        let mut inner_transaction = txn.begin().await?;

        // https://github.com/launchbadge/sqlx/issues/294
        //
        // No way to insert multiple rows easily.  This is more readable than some hack to save
        // tiny amounts of time.
        //
        let mut inserted_prefixes: Vec<NetworkPrefix> = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let new_prefix: NetworkPrefix = sqlx::query_as("INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved) VALUES ($1::uuid, $2::cidr, $3::inet, $4::integer) RETURNING *")
                .bind(segment)
                .bind(prefix.prefix)
                .bind(prefix.gateway)
                .bind(prefix.num_reserved)
                .fetch_one(&mut *inner_transaction).await?;

            inserted_prefixes.push(new_prefix);
        }

        inner_transaction.commit().await?;

        Ok(inserted_prefixes)
    }

    pub async fn update_circuit_id(
        txn: &mut Transaction<'_, Postgres>,
        segment_id: uuid::Uuid,
        dhcp_circuit_id: String,
    ) -> Result<(), sqlx::Error> {
        let _: (uuid::Uuid,) = sqlx::query_as(
            "UPDATE network_prefixes set circuit_id=$1 WHERE id=$2 RETURNING segment_id",
        )
        .bind(dhcp_circuit_id)
        .bind(segment_id)
        .fetch_one(&mut *txn)
        .await?;

        Ok(())
    }

    pub async fn delete_for_segment(
        segment_id: uuid::Uuid,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), sqlx::Error> {
        let _deleted_prefixes: Vec<NetworkPrefixId> =
            sqlx::query_as("DELETE FROM network_prefixes WHERE segment_id=$1::uuid RETURNING id")
                .bind(segment_id)
                .fetch_all(&mut *txn)
                .await?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, FromRow)]
pub struct NetworkPrefixId(uuid::Uuid);

impl From<NetworkPrefixId> for uuid::Uuid {
    fn from(id: NetworkPrefixId) -> Self {
        id.0
    }
}
