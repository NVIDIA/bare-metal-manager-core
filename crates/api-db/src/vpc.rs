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
use std::ops::DerefMut;

use ::rpc::forge as rpc;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use config_version::ConfigVersion;
use model::resource_pool;
use model::resource_pool::ResourcePool;
use model::vpc::{NewVpc, UpdateVpc, UpdateVpcVirtualization, Vpc};
use sqlx::{PgConnection, PgTransaction};

use super::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter, network_segment, vpc};
use crate::resource_pool::ResourcePoolDatabaseError;
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

pub async fn persist(value: NewVpc, txn: &mut PgConnection) -> Result<Vpc, DatabaseError> {
    let query =
                "INSERT INTO vpcs (id, name, organization_id, network_security_group_id, version, network_virtualization_type,
                description,
                labels, routing_profile_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *";
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
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_ids(
    txn: &mut PgConnection,
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
        if label.key.is_empty() && label.value.is_some() {
            builder.push(
                " EXISTS (
                        SELECT 1
                        FROM jsonb_each_text(labels) AS kv
                        WHERE kv.value = ",
            );
            builder.push_bind(label.value.unwrap());
            builder.push(")");
            has_filter = true;
        } else if label.key.is_empty() && label.value.is_none() {
            return Err(DatabaseError::InvalidArgument(
                "finding VPCs based on label needs either key or a value.".to_string(),
            ));
        } else if !label.key.is_empty() && label.value.is_none() {
            builder.push(" labels ->> ");
            builder.push_bind(label.key);
            builder.push(" IS NOT NULL");
            has_filter = true;
        } else if !label.key.is_empty() && label.value.is_some() {
            builder.push(" labels ->> ");
            builder.push_bind(label.key);
            builder.push(" = ");
            builder.push_bind(label.value.unwrap());
            has_filter = true;
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

pub async fn set_vni(txn: &mut PgConnection, id: VpcId, vni: i32) -> Result<(), DatabaseError> {
    let query = "UPDATE vpcs SET vni = $1 WHERE id = $2 AND vni IS NULL";
    let _ = sqlx::query(query)
        .bind(vni)
        .bind(id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn allocate_dpa_vni(
    txn: &mut PgConnection,
    mut value: Vpc,
    dpa_vni_resource_pool: &ResourcePool<i32>,
) -> Result<(), DatabaseError> {
    if let Some(dpa_vni) = value.dpa_vni
        && dpa_vni != 0
    {
        return Ok(());
    };

    let owner_id = value.id.to_string();

    // VPC does not have dpa_vni associated with it. Allocate an dpa_vni for VPC now.
    value.dpa_vni = match crate::resource_pool::allocate(
        dpa_vni_resource_pool,
        txn,
        resource_pool::OwnerType::Dpa,
        &value.id.to_string(),
    )
    .await
    {
        Ok(val) => Some(val),
        Err(ResourcePoolDatabaseError::ResourcePool(resource_pool::ResourcePoolError::Empty)) => {
            tracing::error!(
                owner_id,
                pool = "dpa_vni",
                "Pool exhausted, cannot allocate"
            );
            return Err(DatabaseError::ResourceExhausted("pool dpa_vni".to_string()));
        }
        Err(err) => {
            tracing::error!(owner_id, error = %err, pool = "dpa_vni", "Error allocating from resource pool");
            return Err(err.into());
        }
    };

    set_dpa_vni(txn, value.id, value.dpa_vni.unwrap()).await?;

    Ok(())
}

// Update the DPA_VNI field of the VPC entry in the DB specified by the given ID
pub async fn set_dpa_vni(txn: &mut PgConnection, id: VpcId, vni: i32) -> Result<(), DatabaseError> {
    let query = "UPDATE vpcs SET dpa_vni = $1 WHERE id = $2 AND dpa_vni IS NULL";
    let _ = sqlx::query(query)
        .bind(vni)
        .bind(id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

// Note: Following find function should not be used to search based on vpc labels.
// Recommended approach to filter by labels is to first find VPC ids.
pub async fn find_by<'a, C: ColumnInfo<'a, TableType = Vpc>>(
    txn: &mut PgConnection,
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
    find_by(txn, ObjectColumnFilter::One(VniColumn, &vni)).await
}

pub async fn find_by_name(txn: &mut PgConnection, name: &str) -> Result<Vec<Vpc>, DatabaseError> {
    find_by(txn, ObjectColumnFilter::One(NameColumn, &name)).await
}

pub async fn find_by_segment(
    txn: &mut PgConnection,
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
            let vpcs = find_by(txn, ObjectColumnFilter::One(vpc::IdColumn, &value.id)).await?;
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
            let vpcs = find_by(txn, ObjectColumnFilter::One(vpc::IdColumn, &value.id)).await?;
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
