/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

pub use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use model::network_prefix::NetworkPrefix;
use model::vpc_prefix::{DeleteVpcPrefix, NewVpcPrefix, PrefixMatch, UpdateVpcPrefix, VpcPrefix};
use sqlx::{FromRow, PgConnection, QueryBuilder, Row};

use super::{ColumnInfo, DatabaseError, ObjectColumnFilter};
use crate::vpc::increment_vpc_version;

async fn update_stats(
    prefixes: &mut [VpcPrefix],
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let nw_prefixes = prefixes.iter().map(|x| x.config.prefix).collect_vec();
    let sub_prefixes = crate::network_prefix::containing_prefixes(txn, &nw_prefixes).await?;

    for vpc_prefix in prefixes {
        if let IpNetwork::V4(ipv4_network) = vpc_prefix.config.prefix
            && let Some(used_prefixes) = sub_prefixes.get(&vpc_prefix.config.prefix)
        {
            let ip_net = forge_network::ip::prefix::Ipv4Net::new(
                ipv4_network.network(),
                ipv4_network.prefix(),
            )
            .map_err(|err| {
                DatabaseError::new(
                    "vpc_prefix_update_stats_ipv4_conversion",
                    sqlx::Error::Protocol(err.to_string()),
                )
            })?;

            let total_31_segments = ip_net
                .subnets(31)
                .map_err(|err| {
                    DatabaseError::new(
                        "vpc_prefix_update_stats_subnet_count",
                        sqlx::Error::Protocol(err.to_string()),
                    )
                })?
                .collect::<Vec<forge_network::ip::prefix::Ipv4Net>>();
            vpc_prefix.status.total_31_segments = total_31_segments.len() as u32;
            vpc_prefix.status.available_31_segments =
                vpc_prefix.status.total_31_segments - used_prefixes.len() as u32;
        }
    }

    Ok(())
}

// Get a list of prefixes matching a filter on the ID column.
pub async fn get_by_id<'a, C>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<VpcPrefix>, DatabaseError>
where
    C: ColumnInfo<'a, TableType = VpcPrefix>,
{
    let mut query =
        super::FilterableQueryBuilder::new("SELECT * FROM network_vpc_prefixes").filter(&filter);
    let mut container = query
        .build_query_as()
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))?;

    update_stats(&mut container, txn).await?;
    Ok(container)
}

// Get a list of prefixes matching a filter on the ID column with ROW based lock.
pub async fn get_by_id_with_row_lock(
    txn: &mut PgConnection,
    filter: &[VpcPrefixId],
) -> Result<Vec<VpcPrefix>, DatabaseError> {
    let query = "SELECT * FROM network_vpc_prefixes WHERE id=ANY($1) FOR NO KEY UPDATE";
    let mut container = sqlx::query_as(query)
        .bind(filter)
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    update_stats(&mut container, txn).await?;
    Ok(container)
}

// Find the prefixes associated with a VPC.
pub async fn find_by_vpc(
    txn: &mut PgConnection,
    vpc_id: VpcId,
) -> Result<Vec<VpcPrefix>, DatabaseError> {
    let query = "SELECT * FROM network_vpc_prefixes WHERE vpc_id=$1 \
            ORDER BY prefix";
    let mut container = sqlx::query_as(query)
        .bind(vpc_id)
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    update_stats(&mut container, txn).await?;
    Ok(container)
}

// Find all prefixes associated with any VPC in the list.
pub async fn find_by_vpcs(
    txn: &mut PgConnection,
    vpc_ids: &Vec<VpcId>,
) -> Result<Vec<VpcPrefix>, DatabaseError> {
    let query = "SELECT * FROM network_vpc_prefixes WHERE vpc_id=ANY($1) \
                ORDER BY prefix";
    sqlx::query_as(query)
        .bind(vpc_ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

// Update last used prefix.
pub async fn update_last_used_prefix(
    txn: &mut PgConnection,
    vpc_prefix_id: &VpcPrefixId,
    last_used_prefix: IpNetwork,
) -> Result<(), DatabaseError> {
    let query = "UPDATE network_vpc_prefixes SET last_used_prefix=$1 WHERE id=$2 RETURNING *";
    sqlx::query_as::<_, VpcPrefix>(query)
        .bind(last_used_prefix)
        .bind(vpc_prefix_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

// Search for VPC prefixes by the VPC they're in, name, or a match against
// the prefix (or some combination). Returns just the IDs.
pub async fn search(
    txn: &mut PgConnection,
    vpc_id: Option<VpcId>,
    name: Option<String>,
    prefix_match: Option<PrefixMatch>,
) -> Result<Vec<VpcPrefixId>, DatabaseError> {
    let mut query = QueryBuilder::new("SELECT id FROM network_vpc_prefixes WHERE true");

    if let Some(vpc_id) = vpc_id {
        query.push(" AND vpc_id=");
        query.push_bind(vpc_id);
    }

    if let Some(name) = name {
        query.push(" AND name=");
        query.push_bind(name);
    }

    if let Some(prefix_match) = prefix_match {
        use model::vpc_prefix::PrefixMatch::*;
        match prefix_match {
            Exact(prefix) => {
                query.push(" AND prefix=");
                query.push_bind(prefix);
            }
            Contains(prefix) => {
                query.push(" AND prefix>>=");
                query.push_bind(prefix);
            }
            ContainedBy(prefix) => {
                query.push(" AND prefix<<=");
                query.push_bind(prefix);
            }
        }
    }

    query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

#[derive(Clone, Copy)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = VpcPrefix;
    type ColumnType = VpcPrefixId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

pub async fn persist(
    value: NewVpcPrefix,
    txn: &mut PgConnection,
) -> Result<VpcPrefix, DatabaseError> {
    let insert_query = "INSERT INTO network_vpc_prefixes (id, prefix, name, labels, description, vpc_id) VALUES ($1, $2, $3, $4::json, $5, $6) RETURNING *";
    let vpc_prefix: VpcPrefix = sqlx::query_as(insert_query)
        .bind(value.id)
        .bind(value.config.prefix)
        .bind(&value.metadata.name)
        .bind(sqlx::types::Json(&value.metadata.labels))
        .bind(&value.metadata.description)
        .bind(value.vpc_id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(insert_query, e))?;

    increment_vpc_version(txn, value.vpc_id).await?;

    Ok(vpc_prefix)
}

// Check for existing VPC prefixes using any of our address space.
pub async fn probe(
    network: IpNetwork,
    txn: &mut PgConnection,
) -> Result<Vec<VpcPrefix>, DatabaseError> {
    let query = "SELECT * FROM network_vpc_prefixes WHERE prefix && $1";
    sqlx::query_as(query)
        .bind(network)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

// Given a new VPC prefix which has been not been persisted yet, find the
// network segment prefixes that overlap with it, along with the VPC ID each
// one is associated with. The caller should use this information to reject
// any problematic VPC prefixes, and to update any matching segment prefixes
// which should be adopted by the new VPC prefix.
pub async fn probe_segment_prefixes(
    network: IpNetwork,
    txn: &mut PgConnection,
) -> Result<Vec<(VpcId, NetworkPrefix)>, DatabaseError> {
    let query = "SELECT ns.vpc_id AS vpc_id, np.* FROM network_prefixes np \
            INNER JOIN network_segments ns ON np.segment_id = ns.id \
            WHERE np.prefix && $1 AND ns.network_segment_type='tenant'";

    sqlx::query(query)
        .bind(network)
        .try_map(|row| {
            let vpc_id: VpcId = row.try_get("vpc_id")?;
            let network_prefix = NetworkPrefix::from_row(&row)?;
            Ok((vpc_id, network_prefix))
        })
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn update(
    update: &UpdateVpcPrefix,
    txn: &mut PgConnection,
) -> Result<VpcPrefix, DatabaseError> {
    let query = "UPDATE network_vpc_prefixes SET name=$1, labels=$2::json, description=$3 WHERE id=$4 RETURNING *";
    sqlx::query_as(query)
        .bind(&update.metadata.name)
        .bind(sqlx::types::Json(&update.metadata.labels))
        .bind(&update.metadata.description)
        .bind(update.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
    // Note that if/when we add support for prefix resizing, we will need to
    // call increment_vpc_version() here.
}

pub async fn delete(
    value: &DeleteVpcPrefix,
    txn: &mut PgConnection,
) -> Result<VpcPrefixId, DatabaseError> {
    let query = "DELETE FROM network_vpc_prefixes WHERE id=$1 RETURNING *";
    let deleted_prefix: VpcPrefix = sqlx::query_as(query)
        .bind(value.id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    increment_vpc_version(txn, deleted_prefix.vpc_id).await?;

    Ok(deleted_prefix.id)
}
