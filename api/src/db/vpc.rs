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
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use ::rpc::uuid::network_security_group::NetworkSecurityGroupIdParseError;
use ::rpc::uuid::{machine::MachineId, network_security_group::NetworkSecurityGroupId};
use chrono::prelude::*;
use config_version::ConfigVersion;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use super::network_segment::NetworkSegment;
use super::{
    ColumnInfo, DatabaseError, FilterableQueryBuilder, ObjectColumnFilter, network_segment, vpc,
};
use crate::api::Api;
use crate::model::metadata::Metadata;
use crate::{CarbideError, CarbideResult, db};
use ::rpc::uuid::{network::NetworkSegmentId, vpc::VpcId};
use forge_network::virtualization::{DEFAULT_NETWORK_VIRTUALIZATION_TYPE, VpcVirtualizationType};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vpc {
    pub id: VpcId,
    pub tenant_organization_id: String,
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub tenant_keyset_id: Option<String>,
    pub network_virtualization_type: VpcVirtualizationType,
    // Option because we can't allocate it until DB generates an id for us
    pub vni: Option<i32>,
    pub dpa_vni: Option<i32>,
    pub metadata: Metadata,
}

#[derive(Clone, Copy)]
pub struct VniColumn;
impl ColumnInfo<'_> for crate::db::vpc::VniColumn {
    type TableType = Vpc;
    type ColumnType = i32;

    fn column_name(&self) -> &'static str {
        "vni"
    }
}

#[derive(Clone, Copy)]
pub struct IdColumn;
impl ColumnInfo<'_> for crate::db::vpc::IdColumn {
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

#[derive(Clone, Debug)]
pub struct NewVpc {
    pub id: VpcId,
    pub tenant_organization_id: String,
    pub network_virtualization_type: VpcVirtualizationType,
    pub metadata: Metadata,
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
}

#[derive(Clone, Debug)]
pub struct UpdateVpc {
    pub id: VpcId,
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
    pub if_version_match: Option<ConfigVersion>,
    pub metadata: Metadata,
}

/// UpdateVpcVirtualization exists as a mechanism to translate
/// an incoming VpcUpdateVirtualizationRequest and turn it
/// into something we can `update()` to the database.
#[derive(Clone, Debug)]
pub struct UpdateVpcVirtualization {
    pub id: VpcId,
    pub if_version_match: Option<ConfigVersion>,
    pub network_virtualization_type: VpcVirtualizationType,
}

impl<'r> sqlx::FromRow<'r, PgRow> for Vpc {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let vpc_labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;

        let metadata = Metadata {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            labels: vpc_labels.0,
        };

        // TODO(chet): Once `tenant_keyset_id` is taken care of,
        // this entire FromRow implementation can go away with a
        // rename of `tenant_organization_id` to match (or just
        // a rename of the `organization_id` column).
        Ok(Vpc {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            tenant_organization_id: row.try_get("organization_id")?,
            network_security_group_id: row.try_get("network_security_group_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            tenant_keyset_id: None, //TODO: fix this once DB gets updated
            network_virtualization_type: row.try_get("network_virtualization_type")?,
            vni: row.try_get("vni")?,
            dpa_vni: row.try_get("dpa_vni")?,
            metadata,
        })
    }
}

impl NewVpc {
    pub async fn persist(&self, txn: &mut PgConnection) -> Result<Vpc, DatabaseError> {
        let query =
                "INSERT INTO vpcs (id, name, organization_id, network_security_group_id, version, network_virtualization_type,
                description,
                labels) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *";
        sqlx::query_as(query)
            .bind(self.id)
            .bind(&self.metadata.name)
            .bind(&self.tenant_organization_id)
            .bind(&self.network_security_group_id)
            .bind(ConfigVersion::initial())
            .bind(self.network_virtualization_type)
            .bind(&self.metadata.description)
            .bind(sqlx::types::Json(&self.metadata.labels))
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }
}

impl Vpc {
    pub async fn find_ids(
        txn: &mut PgConnection,
        filter: rpc::VpcSearchFilter,
    ) -> Result<Vec<VpcId>, CarbideError> {
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
                return Err(CarbideError::InvalidArgument(
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
        mut self,
        txn: &mut PgConnection,
        api: &Api,
    ) -> Result<(), CarbideError> {
        if let Some(dpa_vni) = self.dpa_vni {
            if dpa_vni != 0 {
                return Ok(());
            };
        };

        // VPC does not have dpa_vni associated with it. Allocate an dpa_vni for VPC now.

        self.dpa_vni = Some(api.pool_allocate_dpa_vni(txn, &self.id.to_string()).await?);
        Vpc::set_dpa_vni(txn, self.id, self.dpa_vni.unwrap()).await?;

        Ok(())
    }

    // Update the DPA_VNI field of the VPC entry in the DB specified by the given ID
    pub async fn set_dpa_vni(
        txn: &mut PgConnection,
        id: VpcId,
        vni: i32,
    ) -> Result<(), DatabaseError> {
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
        Self::find_by(txn, ObjectColumnFilter::One(VniColumn, &vni)).await
    }

    pub async fn find_by_name(
        txn: &mut PgConnection,
        name: &str,
    ) -> Result<Vec<Vpc>, DatabaseError> {
        Self::find_by(txn, ObjectColumnFilter::One(NameColumn, &name)).await
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
    pub async fn try_delete(
        txn: &mut PgConnection,
        id: VpcId,
    ) -> Result<Option<Self>, DatabaseError> {
        // TODO: Should this update the version?
        let query = "UPDATE vpcs SET updated=NOW(), deleted=NOW() WHERE id=$1 AND deleted is null RETURNING *";
        match sqlx::query_as(query).bind(id).fetch_one(txn).await {
            Ok(vpc) => Ok(Some(vpc)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(DatabaseError::query(query, e)),
        }
    }
}

impl From<Vpc> for rpc::Vpc {
    fn from(src: Vpc) -> Self {
        rpc::Vpc {
            id: Some(src.id),
            version: src.version.version_string(),
            name: src.metadata.name.clone(),
            tenant_organization_id: src.tenant_organization_id,
            network_security_group_id: src
                .network_security_group_id
                .map(|nsg_id| nsg_id.to_string()),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            tenant_keyset_id: src.tenant_keyset_id,
            vni: src.vni.map(|x| x as u32),
            dpa_vni: src.dpa_vni.map(|x| x as u32),
            network_virtualization_type: Some(
                rpc::VpcVirtualizationType::from(src.network_virtualization_type).into(),
            ),
            metadata: {
                Some(rpc::Metadata {
                    name: src.metadata.name,
                    description: src.metadata.description,
                    labels: src
                        .metadata
                        .labels
                        .iter()
                        .map(|(key, value)| rpc::Label {
                            key: key.clone(),
                            value: if value.clone().is_empty() {
                                None
                            } else {
                                Some(value.clone())
                            },
                        })
                        .collect(),
                })
            },
        }
    }
}

impl TryFrom<rpc::VpcCreationRequest> for NewVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::VpcCreationRequest) -> Result<Self, Self::Error> {
        let virt_type = match value.network_virtualization_type {
            None => DEFAULT_NETWORK_VIRTUALIZATION_TYPE,
            Some(v) => v.try_into()?,
        };
        let id = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        // If Metadata isn't passed or empty, then use the old name field
        let use_legacy_name = if let Some(metadata) = &value.metadata {
            metadata.name.is_empty()
        } else {
            true
        };

        let mut metadata = match value.metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };
        if use_legacy_name {
            metadata.name = value.name;
        }

        metadata.validate(true).map_err(|e| {
            CarbideError::InvalidArgument(format!("VPC metadata is not valid: {e}"))
        })?;

        Ok(NewVpc {
            id,
            tenant_organization_id: value.tenant_organization_id,
            network_security_group_id: value
                .network_security_group_id
                .map(|nsg_id| nsg_id.parse())
                .transpose()
                .map_err(|e: NetworkSecurityGroupIdParseError| {
                    CarbideError::from(RpcDataConversionError::InvalidNetworkSecurityGroupId(
                        e.value(),
                    ))
                })?,
            network_virtualization_type: virt_type,
            metadata,
        })
    }
}

impl TryFrom<rpc::VpcUpdateRequest> for UpdateVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::VpcUpdateRequest) -> Result<Self, Self::Error> {
        let if_version_match: Option<ConfigVersion> = match &value.if_version_match {
            Some(version) => Some(version.parse::<ConfigVersion>()?),
            None => None,
        };

        // If Metadata isn't passed or empty, then use the old name field
        let use_legacy_name = if let Some(metadata) = &value.metadata {
            metadata.name.is_empty()
        } else {
            true
        };

        let mut metadata = match value.metadata {
            Some(metadata) => metadata.try_into()?,
            None => Metadata::new_with_default_name(),
        };
        if use_legacy_name {
            metadata.name = value.name;
        }

        metadata.validate(true).map_err(|e| {
            CarbideError::InvalidArgument(format!("VPC metadata is not valid: {e}"))
        })?;

        Ok(UpdateVpc {
            id: value.id.ok_or(CarbideError::MissingArgument("id"))?,
            network_security_group_id: value
                .network_security_group_id
                .map(|nsg_id| nsg_id.parse())
                .transpose()
                .map_err(|e: NetworkSecurityGroupIdParseError| {
                    CarbideError::from(RpcDataConversionError::InvalidNetworkSecurityGroupId(
                        e.value(),
                    ))
                })?,
            if_version_match,
            metadata,
        })
    }
}

impl TryFrom<rpc::VpcUpdateVirtualizationRequest> for UpdateVpcVirtualization {
    type Error = CarbideError;

    fn try_from(value: rpc::VpcUpdateVirtualizationRequest) -> Result<Self, Self::Error> {
        let if_version_match: Option<ConfigVersion> = match &value.if_version_match {
            Some(version) => Some(version.parse::<ConfigVersion>()?),
            None => None,
        };

        let network_virtualization_type = match value.network_virtualization_type {
            Some(v) => v.try_into()?,
            None => {
                return Err(CarbideError::MissingArgument("network_virtualization_type"));
            }
        };

        Ok(UpdateVpcVirtualization {
            id: value.id.ok_or(CarbideError::MissingArgument("id"))?,
            if_version_match,
            network_virtualization_type,
        })
    }
}

impl From<Vpc> for rpc::VpcDeletionResult {
    fn from(_src: Vpc) -> Self {
        rpc::VpcDeletionResult {}
    }
}

impl UpdateVpc {
    pub async fn update(&self, txn: &mut PgConnection) -> CarbideResult<Vpc> {
        // TODO: Should this check for deletion?
        let current_version = match self.if_version_match {
            Some(version) => version,
            None => {
                let vpcs =
                    Vpc::find_by(txn, ObjectColumnFilter::One(vpc::IdColumn, &self.id)).await?;
                if vpcs.len() != 1 {
                    return Err(CarbideError::FindOneReturnedManyResultsError(
                        self.id.into(),
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
            .bind(&self.metadata.name)
            .bind(next_version)
            .bind(&self.metadata.description)
            .bind(&self.network_security_group_id)
            .bind(sqlx::types::Json(&self.metadata.labels))
            .bind(self.id)
            .bind(current_version)
            .fetch_one(txn)
            .await;

        match query_result {
            Ok(r) => Ok(r),
            Err(sqlx::Error::RowNotFound) => {
                // TODO: This can actually happen on both invalid ID and invalid version
                // So maybe this should be `ObjectNotFoundOrModifiedError`
                Err(CarbideError::ConcurrentModificationError(
                    "vpc",
                    current_version.to_string(),
                ))
            }
            Err(e) => Err(DatabaseError::query(query, e).into()),
        }
    }
}

impl UpdateVpcVirtualization {
    pub async fn update(&self, txn: &mut PgConnection) -> CarbideResult<Vpc> {
        let query = "UPDATE vpcs
            SET version=$1, network_virtualization_type=$2, updated=NOW()
            WHERE id=$3 AND version=$4 AND deleted is null
            RETURNING *";

        let current_version = match self.if_version_match {
            Some(version) => version,
            None => {
                let vpcs =
                    Vpc::find_by(txn, ObjectColumnFilter::One(vpc::IdColumn, &self.id)).await?;
                if vpcs.len() != 1 {
                    return Err(CarbideError::FindOneReturnedManyResultsError(
                        self.id.into(),
                    ));
                }
                vpcs[0].version
            }
        };
        let next_version = current_version.increment();

        let query_result = sqlx::query_as(query)
            .bind(next_version)
            .bind(self.network_virtualization_type)
            .bind(self.id)
            .bind(current_version)
            .fetch_one(&mut *txn)
            .await;

        let vpc: Vpc = match query_result {
            Ok(r) => Ok(r),
            Err(sqlx::Error::RowNotFound) => {
                // TODO(chet): This can actually happen on both invalid ID and invalid
                // version, so maybe this should be `ObjectNotFoundOrModifiedError`
                // or similar.
                Err(CarbideError::ConcurrentModificationError(
                    "vpc",
                    current_version.to_string(),
                ))
            }
            Err(e) => Err(DatabaseError::query(query, e).into()),
        }?;

        // Update SVI IP for stretchable segments.
        let network_segments = NetworkSegment::find_by(
            txn,
            ObjectColumnFilter::One(network_segment::VpcColumn, &vpc.id),
            network_segment::NetworkSegmentSearchConfig::default(),
        )
        .await?;

        for network_segment in network_segments {
            if !network_segment.can_stretch.unwrap_or_default() {
                continue;
            }

            let Some(prefix) = network_segment.prefixes.iter().find(|x| x.prefix.is_ipv4()) else {
                return Err(CarbideError::internal(format!(
                    "NetworkSegment {} does not have Ipv4 Prefix attached.",
                    network_segment.id
                )));
            };

            if prefix.svi_ip.is_none() {
                // If we can't update SVI IP in any of these segment, we have to fail whole operation.
                network_segment.allocate_svi_ip(txn).await?;
            }
        }

        Ok(vpc)
    }
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

#[derive(Clone, Debug, FromRow)]
pub struct VpcDpuLoopback {
    pub dpu_id: MachineId,
    pub vpc_id: VpcId,
    pub loopback_ip: IpAddr,
}

impl VpcDpuLoopback {
    pub fn new(dpu_id: MachineId, vpc_id: VpcId, loopback_ip: IpAddr) -> Self {
        Self {
            dpu_id,
            vpc_id,
            loopback_ip,
        }
    }

    pub async fn persist(&self, txn: &mut PgConnection) -> Result<Self, DatabaseError> {
        let query = "INSERT INTO vpc_dpu_loopbacks (dpu_id, vpc_id, loopback_ip) 
                           VALUES ($1, $2, $3) RETURNING *";
        sqlx::query_as(query)
            .bind(self.dpu_id)
            .bind(self.vpc_id)
            .bind(self.loopback_ip)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    pub async fn delete_and_deallocate(
        common_pools: &crate::resource_pool::common::CommonPools,
        dpu_id: &MachineId,
        txn: &mut PgConnection,
        delete_admin_loopback_also: bool,
    ) -> Result<(), CarbideError> {
        let mut admin_vpc = None;
        let query = if !delete_admin_loopback_also {
            let admin_segment = NetworkSegment::admin(txn).await?;
            admin_vpc = admin_segment.vpc_id;
            if admin_vpc.is_some() {
                "DELETE FROM vpc_dpu_loopbacks WHERE dpu_id=$1 AND vpc_id != $2 RETURNING *"
            } else {
                tracing::warn!("No VPC is attached to admin segment {}.", admin_segment.id);
                "DELETE FROM vpc_dpu_loopbacks WHERE dpu_id=$1 RETURNING *"
            }
        } else {
            "DELETE FROM vpc_dpu_loopbacks WHERE dpu_id=$1 RETURNING *"
        };

        let mut sqlx_query = sqlx::query_as::<_, Self>(query).bind(dpu_id);

        if let Some(admin_vpc) = admin_vpc {
            sqlx_query = sqlx_query.bind(admin_vpc);
        }

        let deleted_loopbacks = sqlx_query
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        for value in deleted_loopbacks {
            // We deleted a IP from vpc_dpu_loopback table. Deallocate this IP from common pool.
            let ipv4_addr = match value.loopback_ip {
                IpAddr::V4(ipv4_addr) => ipv4_addr,
                IpAddr::V6(_) => {
                    return Err(CarbideError::InvalidArgument(
                        "Ipv6 is not supported.".to_string(),
                    ));
                }
            };

            common_pools
                .ethernet
                .pool_vpc_dpu_loopback_ip
                .release(txn, ipv4_addr)
                .await?;
        }

        Ok(())
    }

    pub async fn find(
        txn: &mut PgConnection,
        dpu_id: &MachineId,
        vpc_id: &VpcId,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = "SELECT * from vpc_dpu_loopbacks WHERE dpu_id=$1 AND vpc_id=$2";

        sqlx::query_as(query)
            .bind(dpu_id)
            .bind(vpc_id)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }

    /// Allocate loopback ip for a vpc and dpu if not allocated yet.
    /// If already allocated, return the value.
    pub async fn get_or_allocate_loopback_ip_for_vpc(
        common_pools: &crate::resource_pool::common::CommonPools,
        txn: &mut PgConnection,
        dpu_id: &MachineId,
        vpc_id: &VpcId,
    ) -> Result<Ipv4Addr, CarbideError> {
        let loopback_ip = match VpcDpuLoopback::find(txn, dpu_id, vpc_id).await? {
            Some(x) => match x.loopback_ip {
                IpAddr::V4(ipv4_addr) => ipv4_addr,
                IpAddr::V6(_) => {
                    return Err(CarbideError::NotImplemented);
                }
            },
            None => {
                let loopback_ip =
                    db::machine::allocate_vpc_dpu_loopback(common_pools, txn, &dpu_id.to_string())
                        .await?;
                let vpc_dpu_loopback =
                    VpcDpuLoopback::new(*dpu_id, *vpc_id, IpAddr::V4(loopback_ip));
                vpc_dpu_loopback.persist(txn).await?;

                loopback_ip
            }
        };

        Ok(loopback_ip)
    }
}
