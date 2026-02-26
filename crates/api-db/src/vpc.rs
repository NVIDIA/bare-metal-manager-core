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
use std::ops::DerefMut;

use ::rpc::forge as rpc;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use config_version::ConfigVersion;
use model::vpc::{NewVpc, UpdateVpc, UpdateVpcVirtualization, Vpc, VpcStatus};
use sqlx::{PgConnection, PgTransaction};

use super::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter, network_segment, vpc};
use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

#[derive(Clone, Copy)]
pub struct VniColumn;
impl ColumnInfo<'_> for crate::vpc::VniColumn {
    type TableType = Vpc;
    type ColumnType = i32;

    fn column_name(&self) -> &'static str {
        "vni"
    }
}

#[derive(Clone, Copy)]
pub struct IdColumn;
impl ColumnInfo<'_> for crate::vpc::IdColumn {
    type TableType = Vpc;
    type ColumnType = VpcId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Clone, Copy)]
pub struct NameColumn;
impl<'a> ColumnInfo<'a> for NameColumn {
    type TableType = Vpc;
    type ColumnType = &'a str;

    fn column_name(&self) -> &'static str {
        "name"
    }
}

pub async fn persist(
    value: NewVpc,
    status: VpcStatus,
    txn: &mut PgConnection,
) -> Result<Vpc, DatabaseError> {
    let query =
                "INSERT INTO vpcs (id, name, organization_id, network_security_group_id, version, network_virtualization_type,
                description,
                labels, routing_profile_type, vni, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *";
    sqlx::query_as(query)
        .bind(value.id)
        .bind(&value.metadata.name)
        .bind(&value.tenant_organization_id)
        .bind(&value.network_security_group_id)
        .bind(ConfigVersion::initial())
        .bind(value.network_virtualization_type)
        .bind(&value.metadata.description)
        .bind(sqlx::types::Json(&value.metadata.labels))
        .bind(value.routing_profile_type.map(|p| p.to_string()))
        .bind(value.vni)
        .bind(sqlx::types::Json(&status))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_ids(
    txn: impl DbReader<'_>,
    filter: rpc::VpcSearchFilter,
) -> Result<Vec<VpcId>, DatabaseError> {
    // build query
    let mut builder = sqlx::QueryBuilder::new("SELECT id FROM vpcs WHERE ");
    let mut has_filter = false;
    if let Some(name) = &filter.name {
        builder.push("name = ");
        builder.push_bind(name);
        has_filter = true;
    }
    if let Some(tenant_org_id) = &filter.tenant_org_id {
        if has_filter {
            builder.push(" AND ");
        }
        builder.push("organization_id = ");
        builder.push_bind(tenant_org_id);
        has_filter = true;
    }
    if let Some(label) = filter.label {
        if has_filter {
            builder.push(" AND ");
        }
        match (label.key.is_empty(), label.value) {
            // Label key is empty, label value is set.
            (true, Some(value)) => {
                builder.push(
                    " EXISTS (
                        SELECT 1
                        FROM jsonb_each_text(labels) AS kv
                        WHERE kv.value = ",
                );
                builder.push_bind(value);
                builder.push(")");
                has_filter = true;
            }
            // Label key is empty, label value is not set.
            (true, None) => {
                return Err(DatabaseError::InvalidArgument(
                    "finding VPCs based on label needs either key or a value.".to_string(),
                ));
            }
            // Label key is not empty, label value is not set.
            (false, None) => {
                builder.push(" labels ->> ");
                builder.push_bind(label.key);
                builder.push(" IS NOT NULL");
                has_filter = true;
            }
            // Label key is not empty, label value is set.
            (false, Some(value)) => {
                builder.push(" labels ->> ");
                builder.push_bind(label.key);
                builder.push(" = ");
                builder.push_bind(value);
                has_filter = true;
            }
        }
    }
    if has_filter {
        builder.push(" AND ");
    }
    builder.push("deleted IS NULL");

    let query = builder.build_query_as();
    let ids: Vec<VpcId> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("vpc::find_ids", e))?;

    Ok(ids)
}

// Note: Following find function should not be used to search based on vpc labels.
// Recommended approach to filter by labels is to first find VPC ids.
pub async fn find_by<'a, C: ColumnInfo<'a, TableType = Vpc>>(
    txn: impl DbReader<'_>,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<Vpc>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new("SELECT * FROM vpcs").filter(&filter);

    query
        .push(" AND deleted IS NULL")
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

pub async fn find_by_vni(txn: &mut PgConnection, vni: i32) -> Result<Vec<Vpc>, DatabaseError> {
    let query = "SELECT * from vpcs WHERE (status->>'vni')::integer = $1 AND DELETED IS NULL";

    sqlx::query_as(query)
        .bind(vni)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_by_name(txn: impl DbReader<'_>, name: &str) -> Result<Vec<Vpc>, DatabaseError> {
    find_by(txn, ObjectColumnFilter::One(NameColumn, &name)).await
}

pub async fn find_by_segment(
    txn: impl DbReader<'_>,
    segment_id: NetworkSegmentId,
) -> Result<Vpc, DatabaseError> {
    let mut query = FilterableQueryBuilder::new(
        "SELECT v.* from vpcs v INNER JOIN network_segments s ON v.id = s.vpc_id",
    )
    .filter_relation(
        &ObjectColumnFilter::One(network_segment::IdColumn, &segment_id),
        Some("s"),
    );
    query.push(" LIMIT 1");

    query
        .build_query_as()
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

/// Tries to deletes a VPC
///
/// If the VPC existed at the point of deletion this returns the last known information about the VPC
/// If the VPC already had been delete, this returns Ok(`None`)
pub async fn try_delete(txn: &mut PgConnection, id: VpcId) -> Result<Option<Vpc>, DatabaseError> {
    // TODO: Should this update the version?
    let query =
        "UPDATE vpcs SET updated=NOW(), deleted=NOW() WHERE id=$1 AND deleted is null RETURNING *";
    match sqlx::query_as(query).bind(id).fetch_one(txn).await {
        Ok(vpc) => Ok(Some(vpc)),
        Err(sqlx::Error::RowNotFound) => Ok(None),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

pub async fn update(value: &UpdateVpc, txn: &mut PgConnection) -> DatabaseResult<Vpc> {
    // TODO: Should this check for deletion?
    let current_version = match value.if_version_match {
        Some(version) => version,
        None => {
            let vpcs =
                find_by(&mut *txn, ObjectColumnFilter::One(vpc::IdColumn, &value.id)).await?;
            if vpcs.len() != 1 {
                return Err(DatabaseError::FindOneReturnedManyResultsError(
                    value.id.into(),
                ));
            }
            vpcs[0].version
        }
    };
    let next_version = current_version.increment();

    // network_virtualization_type cannot be changed currently
    // TODO check number of changed rows
    let query = "UPDATE vpcs
            SET name=$1, version=$2, description=$3, network_security_group_id=$4, labels=$5::json, updated=NOW()
            WHERE id=$6 AND version=$7 AND deleted is null
            RETURNING *";
    let query_result = sqlx::query_as(query)
        .bind(&value.metadata.name)
        .bind(next_version)
        .bind(&value.metadata.description)
        .bind(&value.network_security_group_id)
        .bind(sqlx::types::Json(&value.metadata.labels))
        .bind(value.id)
        .bind(current_version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok(r) => Ok(r),
        Err(sqlx::Error::RowNotFound) => {
            // TODO: This can actually happen on both invalid ID and invalid version
            // So maybe this should be `ObjectNotFoundOrModifiedError`
            Err(DatabaseError::ConcurrentModificationError(
                "vpc",
                current_version.to_string(),
            ))
        }
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

pub async fn update_virtualization(
    value: &UpdateVpcVirtualization,
    // Note: This is a PgTransaction, not a PgConnection, because we will be doing table locking,
    // which must happen in a transaction.
    txn: &mut PgTransaction<'_>,
) -> DatabaseResult<Vpc> {
    let query = "UPDATE vpcs
            SET version=$1, network_virtualization_type=$2, updated=NOW()
            WHERE id=$3 AND version=$4 AND deleted is null
            RETURNING *";

    let current_version = match value.if_version_match {
        Some(version) => version,
        None => {
            let vpcs = find_by(
                txn.as_mut(),
                ObjectColumnFilter::One(vpc::IdColumn, &value.id),
            )
            .await?;
            if vpcs.len() != 1 {
                return Err(DatabaseError::FindOneReturnedManyResultsError(
                    value.id.into(),
                ));
            }
            vpcs[0].version
        }
    };
    let next_version = current_version.increment();

    let query_result = sqlx::query_as(query)
        .bind(next_version)
        .bind(value.network_virtualization_type)
        .bind(value.id)
        .bind(current_version)
        .fetch_one(txn.deref_mut())
        .await;

    let vpc: Vpc = match query_result {
        Ok(r) => Ok(r),
        Err(sqlx::Error::RowNotFound) => {
            // TODO(chet): This can actually happen on both invalid ID and invalid
            // version, so maybe this should be `ObjectNotFoundOrModifiedError`
            // or similar.
            Err(DatabaseError::ConcurrentModificationError(
                "vpc",
                current_version.to_string(),
            ))
        }
        Err(e) => Err(DatabaseError::query(query, e)),
    }?;

    // Update SVI IP for stretchable segments.
    let network_segments = crate::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(network_segment::VpcColumn, &vpc.id),
        model::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;

    for network_segment in network_segments {
        if !network_segment.can_stretch.unwrap_or_default() {
            continue;
        }

        let Some(prefix) = network_segment.prefixes.iter().find(|x| x.prefix.is_ipv4()) else {
            return Err(DatabaseError::internal(format!(
                "NetworkSegment {} does not have Ipv4 Prefix attached.",
                network_segment.id
            )));
        };

        if prefix.svi_ip.is_none() {
            // If we can't update SVI IP in any of these segment, we have to fail whole operation.
            crate::network_segment::allocate_svi_ip(&network_segment, txn).await?;
        }
    }

    Ok(vpc)
}

// Increments the VPC version field. This is used when modifying resources that
// are attached to this VPC but are not directly part of the `vpcs` table (e.g.
// VPC prefixes).
pub async fn increment_vpc_version(
    txn: &mut PgConnection,
    id: VpcId,
) -> Result<ConfigVersion, DatabaseError> {
    let read_query = "SELECT version FROM vpcs WHERE id=$1";
    let current_version: ConfigVersion = sqlx::query_as(read_query)
        .bind(id)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(read_query, e))?;

    let new_version = current_version.increment();

    let update_query = "UPDATE vpcs SET version = $1 WHERE id = $2 RETURNING version";
    sqlx::query_as(update_query)
        .bind(new_version)
        .bind(id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(update_query, e))
}
