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
use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    net::IpAddr,
};

use ::rpc::forge as rpc;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Acquire, FromRow, PgConnection, Row};

use super::DatabaseError;
use crate::CarbideError;
use ::rpc::uuid::network::NetworkSegmentId;
use ::rpc::uuid::vpc::{VpcId, VpcPrefixId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPrefix {
    pub id: uuid::Uuid,
    pub segment_id: NetworkSegmentId,
    pub prefix: IpNetwork,
    pub gateway: Option<IpAddr>,
    pub num_reserved: i32,
    pub vpc_prefix_id: Option<VpcPrefixId>,
    pub vpc_prefix: Option<IpNetwork>,
    pub svi_ip: Option<IpAddr>,
    #[serde(default)]
    pub num_free_ips: u32,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub struct SegmentIdColumn;

#[cfg(test)]
impl super::ColumnInfo<'_> for SegmentIdColumn {
    type TableType = NetworkPrefix;
    type ColumnType = NetworkSegmentId;

    fn column_name(&self) -> &'static str {
        "segment_id"
    }
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
            vpc_prefix_id: row.try_get("vpc_prefix_id")?,
            vpc_prefix: row.try_get("vpc_prefix")?,
            prefix: row.try_get("prefix")?,
            gateway: row.try_get("gateway")?,
            num_reserved: row.try_get("num_reserved")?,
            svi_ip: row.try_get("svi_ip")?,
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
            free_ip_count: src.num_free_ips,
            svi_ip: src.svi_ip.map(|x| x.to_string()),
        }
    }
}

impl NetworkPrefix {
    /// Fetch the prefix that matches, is a subnet of, or contains the given one.
    pub async fn containing_prefix(
        txn: &mut PgConnection,
        prefix: &str,
    ) -> Result<Vec<NetworkPrefix>, DatabaseError> {
        let query = "select * from network_prefixes where prefix && $1::inet";
        let container = sqlx::query_as(query)
            .bind(prefix)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
        Ok(container)
    }

    /// Fetch the prefixes that matches and categories them as a Hashmap.
    pub async fn containing_prefixes(
        txn: &mut PgConnection,
        prefixes: &[IpNetwork],
    ) -> Result<HashMap<IpNetwork, Vec<Self>>, DatabaseError> {
        let query = "select * from network_prefixes where prefix <<= ANY($1)";
        let container: Vec<Self> = sqlx::query_as(query)
            .bind(prefixes)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        let value = prefixes
            .iter()
            .map(|x| {
                let prefixes = container
                    .iter()
                    .filter(|a| {
                        a.vpc_prefix
                            .map(|prefix| x.contains(prefix.network()))
                            .unwrap_or_default()
                    })
                    .cloned()
                    .collect_vec();
                (*x, prefixes)
            })
            .collect::<HashMap<IpNetwork, Vec<Self>>>();

        Ok(value)
    }

    pub fn gateway_cidr(&self) -> Option<String> {
        // TODO: This was here before, but seems broken
        // The gateway address should always be a /32
        // Should we directly return the prefix?
        self.gateway
            .map(|g| format!("{}/{}", g, self.prefix.prefix()))
    }

    // Search for specific prefix
    #[cfg(test)]
    pub async fn find(
        txn: &mut PgConnection,
        uuid: uuid::Uuid,
    ) -> Result<NetworkPrefix, DatabaseError> {
        let query = "select * from network_prefixes where id=$1";
        sqlx::query_as(query)
            .bind(uuid)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    /*
     * Return a list of `NetworkPrefix`es for a segment.
     */
    #[cfg(test)]
    pub async fn find_by<'a, C: super::ColumnInfo<'a, TableType = NetworkPrefix>>(
        txn: &mut PgConnection,
        filter: super::ObjectColumnFilter<'a, C>,
    ) -> Result<Vec<NetworkPrefix>, DatabaseError> {
        let mut query =
            super::FilterableQueryBuilder::new("SELECT * FROM network_prefixes").filter(&filter);

        query
            .build_query_as()
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query.sql(), e))
    }

    // Return a list of network segment prefixes that are associated with this
    // VPC but are _not_ associated with a VPC prefix.
    pub async fn find_by_vpc(
        txn: &mut PgConnection,
        vpc_id: VpcId,
    ) -> Result<Vec<NetworkPrefix>, DatabaseError> {
        let query = "SELECT np.* FROM network_prefixes np \
            INNER JOIN network_segments ns ON np.segment_id = ns.id \
            WHERE np.vpc_prefix_id IS NULL AND ns.vpc_id = $1 ORDER BY ns.created";

        let prefixes = sqlx::query_as(query)
            .bind(vpc_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
        Ok(prefixes)
    }

    // Return a list of network segment prefixes that are associated with any VPC in the list
    // but are _not_ associated with a VPC prefix.
    pub async fn find_by_vpcs(
        txn: &mut PgConnection,
        vpc_ids: &Vec<VpcId>,
    ) -> Result<Vec<NetworkPrefix>, DatabaseError> {
        let query = "SELECT np.* FROM network_prefixes np
            INNER JOIN network_segments ns ON np.segment_id = ns.id
            WHERE np.vpc_prefix_id IS NULL AND ns.vpc_id = ANY($1) ORDER BY ns.created";

        let prefixes = sqlx::query_as(query)
            .bind(vpc_ids)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

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
        txn: &mut PgConnection,
        segment_id: &NetworkSegmentId,
        prefixes: &[NewNetworkPrefix],
    ) -> Result<Vec<NetworkPrefix>, DatabaseError> {
        const DB_TXN_NAME: &str = "network_prefix::create_for";
        let mut inner_transaction = txn
            .begin()
            .await
            .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

        // https://github.com/launchbadge/sqlx/issues/294
        //
        // No way to insert multiple rows easily.  This is more readable than some hack to save
        // tiny amounts of time.
        //
        let mut inserted_prefixes: Vec<NetworkPrefix> = Vec::with_capacity(prefixes.len());
        let query = "INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved)
            VALUES ($1::uuid, $2::cidr, $3::inet, $4::integer)
            RETURNING *";
        for prefix in prefixes {
            let new_prefix: NetworkPrefix = sqlx::query_as(query)
                .bind(segment_id)
                .bind(prefix.prefix)
                .bind(prefix.gateway)
                .bind(prefix.num_reserved)
                .fetch_one(&mut *inner_transaction)
                .await
                .map_err(|e| DatabaseError::query(query, e))?;

            inserted_prefixes.push(new_prefix);
        }

        inner_transaction
            .commit()
            .await
            .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

        Ok(inserted_prefixes)
    }

    pub async fn delete_for_segment(
        segment_id: NetworkSegmentId,
        txn: &mut PgConnection,
    ) -> Result<(), DatabaseError> {
        let query = "DELETE FROM network_prefixes WHERE segment_id=$1::uuid RETURNING id";
        sqlx::query_as::<_, NetworkPrefixId>(query)
            .bind(segment_id)
            .fetch_all(txn)
            .await
            .map(|_| ())
            .map_err(|e| DatabaseError::query(query, e))
    }

    // Update the VPC prefix for this segment prefix using the values
    // from the specified vpc_prefix.
    pub async fn set_vpc_prefix(
        &mut self,
        txn: &mut PgConnection,
        vpc_prefix_id: &VpcPrefixId,
        prefix: &IpNetwork,
    ) -> Result<(), DatabaseError> {
        let query =
            "UPDATE network_prefixes SET vpc_prefix_id=$1, vpc_prefix=$2 WHERE id=$3 RETURNING *";
        let network_prefix = sqlx::query_as::<_, Self>(query)
            .bind(vpc_prefix_id)
            .bind(prefix)
            .bind(self.id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        self.vpc_prefix_id = network_prefix.vpc_prefix_id;
        self.vpc_prefix = network_prefix.vpc_prefix;

        Ok(())
    }

    // We use this to try to guess whether an associated segment is stretchable
    // in cases where the database doesn't contain that information.
    pub fn smells_like_fnn(&self) -> bool {
        self.vpc_prefix_id.is_some()
            && match self.prefix {
                // A 31 network prefix is used for FNN.
                IpNetwork::V4(v4) => v4.prefix() >= 30,
                IpNetwork::V6(_) => {
                    // We don't have any IPv6 segment prefixes at the time of
                    // writing so we don't really expect this arm to match, but
                    // let's provide a safe value just in case.
                    false
                }
            }
    }

    // Update the SVI IP.
    pub async fn set_svi_ip(
        txn: &mut PgConnection,
        prefix_id: uuid::Uuid,
        svi_ip: &IpAddr,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE network_prefixes SET svi_ip=$1::inet WHERE id=$2 RETURNING *";
        sqlx::query_as::<_, Self>(query)
            .bind(svi_ip)
            .bind(prefix_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(())
    }
}

// Note: we don't implement Serialize/Deserialize intentionally. We don't want to accidentally
// serialize the NewType itself, only the uuid.
#[derive(Debug, Clone, Copy, FromRow, Hash, PartialOrd, Ord, Eq, PartialEq)]
#[repr(transparent)]
pub struct NetworkPrefixId(pub uuid::Uuid);

impl Display for NetworkPrefixId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<NetworkPrefixId> for uuid::Uuid {
    fn from(id: NetworkPrefixId) -> Self {
        id.0
    }
}

impl From<&NetworkPrefixId> for uuid::Uuid {
    fn from(id: &NetworkPrefixId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for NetworkPrefixId {
    fn from(value: uuid::Uuid) -> Self {
        NetworkPrefixId(value)
    }
}

impl From<&uuid::Uuid> for NetworkPrefixId {
    fn from(value: &uuid::Uuid) -> Self {
        NetworkPrefixId(*value)
    }
}
