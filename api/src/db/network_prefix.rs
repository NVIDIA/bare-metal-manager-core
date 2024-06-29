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
use std::net::IpAddr;

use ::rpc::forge as rpc;
use ipnetwork::IpNetwork;
use sqlx::postgres::PgRow;
use sqlx::{Acquire, FromRow, Postgres, Row, Transaction};

use super::DatabaseError;
use crate::db::network_segment::{NetworkSegmentId, NetworkSegmentIdKeyedObjectFilter};
use crate::db::vpc::VpcId;
use crate::CarbideError;

#[derive(Debug, Clone)]
pub struct NetworkPrefix {
    pub id: uuid::Uuid,
    pub segment_id: NetworkSegmentId,
    pub prefix: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub num_reserved: i32,
    pub circuit_id: Option<String>,
    pub num_free_ips: u32,
}

#[derive(Debug)]
pub struct NewNetworkPrefix {
    pub prefix: IpNetwork,
    pub gateway: Option<IpAddr>,
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
            num_free_ips: 0,
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
            free_ip_count: src.num_free_ips,
        }
    }
}

impl NetworkPrefix {
    /// Fetch the prefix that matches, is a subnet of, or contains the given one.
    pub async fn containing_prefix(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        prefix: &str,
    ) -> Result<Option<NetworkPrefix>, DatabaseError> {
        let query = "select * from network_prefixes where prefix && $1::inet";
        let container = sqlx::query_as::<_, NetworkPrefix>(query)
            .bind(prefix)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(container)
    }

    pub fn gateway_cidr(&self) -> Option<String> {
        // TODO: This was here before, but seems broken
        // The gateway address should always be a /32
        // Should we directly return the prefix?
        self.gateway
            .map(|g| format!("{}/{}", g, self.prefix.prefix()))
    }

    // Search for specific prefix
    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        uuid: uuid::Uuid,
    ) -> Result<NetworkPrefix, DatabaseError> {
        let query = "select * from network_prefixes where id=$1";
        sqlx::query_as::<_, NetworkPrefix>(query)
            .bind(uuid)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
    /*
     * Return a list of `NetworkPrefix`es for a segment.
     */
    pub async fn find_by_segment(
        txn: &mut Transaction<'_, Postgres>,
        filter: NetworkSegmentIdKeyedObjectFilter<'_>,
    ) -> Result<Vec<NetworkPrefix>, DatabaseError> {
        let base_query = "SELECT * FROM network_prefixes {where}".to_owned();

        Ok(match filter {
            NetworkSegmentIdKeyedObjectFilter::All => {
                sqlx::query_as::<_, NetworkPrefix>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "network_prefixes All", e))?
            }
            NetworkSegmentIdKeyedObjectFilter::One(uuid) => sqlx::query_as::<_, NetworkPrefix>(
                &base_query.replace("{where}", "WHERE segment_id=$1"),
            )
            .bind(uuid)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_prefixes One", e))?,
            NetworkSegmentIdKeyedObjectFilter::List(list) => sqlx::query_as::<_, NetworkPrefix>(
                &base_query.replace("{where}", "WHERE segment_id=ANY($1)"),
            )
            .bind(list)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "network_prefixes List", e))?,
        })
    }

    // Return a list of network prefixes for a VPC. More specifically,
    // take the VPC ID, match all of the network segments under it, and then
    // all of the network prefixes from that.
    pub async fn find_by_vpc(
        txn: &mut Transaction<'_, Postgres>,
        vpc_id: VpcId,
    ) -> Result<Vec<NetworkPrefix>, DatabaseError> {
        let query = "SELECT np.* FROM network_prefixes np INNER JOIN network_segments ns ON np.segment_id = ns.id WHERE ns.vpc_id = $1";

        let prefixes = sqlx::query_as::<_, NetworkPrefix>(query)
            .bind(vpc_id)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(prefixes)
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
     * transaction
     * prefixes: A slice of the `NewNetworkPrefix` to create.
     */
    pub async fn create_for(
        txn: &mut Transaction<'_, Postgres>,
        segment_id: &NetworkSegmentId,
        vlan_id: Option<i16>,
        prefixes: &[NewNetworkPrefix],
    ) -> Result<Vec<NetworkPrefix>, DatabaseError> {
        let mut inner_transaction = txn
            .begin()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "begin", e))?;

        // https://github.com/launchbadge/sqlx/issues/294
        //
        // No way to insert multiple rows easily.  This is more readable than some hack to save
        // tiny amounts of time.
        //
        let mut inserted_prefixes: Vec<NetworkPrefix> = Vec::with_capacity(prefixes.len());
        let query =
            "INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved, circuit_id)
            VALUES ($1::uuid, $2::cidr, $3::inet, $4::integer, $5)
            RETURNING *";
        for prefix in prefixes {
            let new_prefix: NetworkPrefix = sqlx::query_as(query)
                .bind(segment_id)
                .bind(prefix.prefix)
                .bind(prefix.gateway)
                .bind(prefix.num_reserved)
                .bind(vlan_id.map(|v| format!("vlan{v}")))
                .fetch_one(&mut *inner_transaction)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

            inserted_prefixes.push(new_prefix);
        }

        inner_transaction
            .commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "commit", e))?;

        Ok(inserted_prefixes)
    }

    pub async fn delete_for_segment(
        segment_id: NetworkSegmentId,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "DELETE FROM network_prefixes WHERE segment_id=$1::uuid RETURNING id";
        let _deleted_prefixes: Vec<NetworkPrefixId> = sqlx::query_as(query)
            .bind(segment_id)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

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
