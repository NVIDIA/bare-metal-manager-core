/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::HashMap;
use std::net::IpAddr;

use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use model::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use sqlx::PgConnection;

use super::DatabaseError;

#[derive(Clone, Copy)]
pub struct SegmentIdColumn;

impl super::ColumnInfo<'_> for SegmentIdColumn {
    type TableType = NetworkPrefix;
    type ColumnType = NetworkSegmentId;

    fn column_name(&self) -> &'static str {
        "segment_id"
    }
}

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
) -> Result<HashMap<IpNetwork, Vec<NetworkPrefix>>, DatabaseError> {
    let query = "select * from network_prefixes where prefix <<= ANY($1)";
    let container: Vec<NetworkPrefix> = sqlx::query_as(query)
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
        .collect::<HashMap<IpNetwork, Vec<NetworkPrefix>>>();

    Ok(value)
}

// Search for specific prefix
pub async fn find(
    txn: &mut PgConnection,
    uuid: NetworkPrefixId,
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
#[allow(txn_held_across_await)]
pub async fn create_for(
    txn: &mut PgConnection,
    segment_id: &NetworkSegmentId,
    prefixes: &[NewNetworkPrefix],
) -> Result<Vec<NetworkPrefix>, DatabaseError> {
    let mut inner_transaction = crate::Transaction::begin_inner(txn).await?;

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
            .fetch_one(inner_transaction.as_pgconn())
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        inserted_prefixes.push(new_prefix);
    }

    inner_transaction.commit().await?;

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
    value: &mut NetworkPrefix,
    txn: &mut PgConnection,
    vpc_prefix_id: &VpcPrefixId,
    prefix: &IpNetwork,
) -> Result<(), DatabaseError> {
    let query =
        "UPDATE network_prefixes SET vpc_prefix_id=$1, vpc_prefix=$2 WHERE id=$3 RETURNING *";
    let network_prefix = sqlx::query_as::<_, NetworkPrefix>(query)
        .bind(vpc_prefix_id)
        .bind(prefix)
        .bind(value.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    value.vpc_prefix_id = network_prefix.vpc_prefix_id;
    value.vpc_prefix = network_prefix.vpc_prefix;

    Ok(())
}

// Update the SVI IP.
pub async fn set_svi_ip(
    txn: &mut PgConnection,
    prefix_id: NetworkPrefixId,
    svi_ip: &IpAddr,
) -> Result<(), DatabaseError> {
    let query = "UPDATE network_prefixes SET svi_ip=$1::inet WHERE id=$2 RETURNING *";
    sqlx::query_as::<_, NetworkPrefix>(query)
        .bind(svi_ip)
        .bind(prefix_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}
