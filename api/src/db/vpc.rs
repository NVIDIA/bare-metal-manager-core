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
use std::fmt;
use std::ops::DerefMut;
use std::str::FromStr;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgHasArrayType, PgRow, PgTypeInfo};
use sqlx::{FromRow, Postgres, Row, Transaction, Type};

use super::DatabaseError;
use crate::db::network_segment::NetworkSegmentId;
use crate::model::metadata::Metadata;
use crate::{CarbideError, CarbideResult};
use ::rpc::errors::RpcDataConversionError;
use forge_network::virtualization::{VpcVirtualizationType, DEFAULT_NETWORK_VIRTUALIZATION_TYPE};

/// VpcId is a strongly typed UUID specific to a VPC ID, with
/// trait implementations allowing it to be passed around as
/// a UUID, an RPC UUID, bound to sqlx queries, etc.
#[derive(Debug, Clone, Copy, FromRow, Type, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[sqlx(type_name = "UUID")]
pub struct VpcId(pub uuid::Uuid);

impl From<VpcId> for uuid::Uuid {
    fn from(id: VpcId) -> Self {
        id.0
    }
}

impl From<uuid::Uuid> for VpcId {
    fn from(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }
}

impl FromStr for VpcId {
    type Err = RpcDataConversionError;
    fn from_str(input: &str) -> Result<Self, RpcDataConversionError> {
        Ok(Self(uuid::Uuid::parse_str(input).map_err(|_| {
            RpcDataConversionError::InvalidUuid("VpcId", input.to_string())
        })?))
    }
}

impl fmt::Display for VpcId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<VpcId> for ::rpc::common::Uuid {
    fn from(val: VpcId) -> Self {
        Self {
            value: val.to_string(),
        }
    }
}

impl TryFrom<::rpc::common::Uuid> for VpcId {
    type Error = RpcDataConversionError;
    fn try_from(msg: ::rpc::common::Uuid) -> Result<Self, RpcDataConversionError> {
        Self::from_str(msg.value.as_str())
    }
}

impl TryFrom<Option<::rpc::common::Uuid>> for VpcId {
    type Error = Box<dyn std::error::Error>;
    fn try_from(msg: Option<::rpc::common::Uuid>) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(input_uuid) = msg else {
            return Err(CarbideError::MissingArgument("VpcId").into());
        };
        Ok(Self::try_from(input_uuid)?)
    }
}

impl PgHasArrayType for VpcId {
    fn array_type_info() -> PgTypeInfo {
        <sqlx::types::Uuid as PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &PgTypeInfo) -> bool {
        <sqlx::types::Uuid as PgHasArrayType>::array_compatible(ty)
    }
}

///
/// A parameter to find() to filter resources by VpcId;
///
#[derive(Clone)]
pub enum VpcIdKeyedObjectFilter<'a> {
    /// Don't filter by VpcId
    All,

    /// Filter by a list of VpcIds
    List(&'a [VpcId]),

    /// Retrieve a single resource
    One(VpcId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vpc {
    pub id: VpcId,
    pub tenant_organization_id: String,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub tenant_keyset_id: Option<String>,
    pub network_virtualization_type: VpcVirtualizationType,
    // Option because we can't allocate it until DB generates an id for us
    pub vni: Option<i32>,
    pub metadata: Metadata,
}

#[derive(Clone, Debug)]
pub struct NewVpc {
    pub id: VpcId,
    pub tenant_organization_id: String,
    pub network_virtualization_type: VpcVirtualizationType,
    pub metadata: Metadata,
}

#[derive(Clone, Debug)]
pub struct UpdateVpc {
    pub id: VpcId,
    pub if_version_match: Option<ConfigVersion>,
    pub name: String,
    pub tenant_organization_id: String,
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

#[derive(Clone, Debug)]
pub struct VpcSearchQuery {
    pub id: Option<VpcId>,
    pub string: Option<String>,
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
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            tenant_keyset_id: None, //TODO: fix this once DB gets updated
            network_virtualization_type: row.try_get("network_virtualization_type")?,
            vni: row.try_get("vni")?,
            metadata,
        })
    }
}

impl NewVpc {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Vpc, DatabaseError> {
        let query =
            "INSERT INTO vpcs (id, name, organization_id, version, network_virtualization_type,
                description, 
                labels) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *";
        sqlx::query_as(query)
            .bind(self.id)
            .bind(&self.metadata.name)
            .bind(&self.tenant_organization_id)
            .bind(ConfigVersion::initial())
            .bind(self.network_virtualization_type)
            .bind(&self.metadata.description)
            .bind(sqlx::types::Json(&self.metadata.labels))
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

impl Vpc {
    pub async fn find_ids(
        txn: &mut Transaction<'_, Postgres>,
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
        if has_filter {
            builder.push(" AND ");
        }
        builder.push("deleted IS NULL");

        let query = builder.build_query_as();
        let ids: Vec<VpcId> = query
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "vpc::find_ids", e))?;

        Ok(ids)
    }

    pub async fn set_vni(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        id: VpcId,
        vni: i32,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE vpcs SET vni = $1 WHERE id = $2 AND vni IS NULL";
        let _ = sqlx::query(query)
            .bind(vni)
            .bind(id)
            .execute(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: VpcIdKeyedObjectFilter<'_>,
    ) -> Result<Vec<Vpc>, DatabaseError> {
        let results: Vec<Vpc> = match filter {
            VpcIdKeyedObjectFilter::All => {
                let query = "SELECT * FROM vpcs WHERE deleted is NULL";
                sqlx::query_as(query)
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            VpcIdKeyedObjectFilter::One(uuid) => {
                let query = "SELECT * FROM vpcs WHERE id = $1 and deleted is NULL";
                sqlx::query_as(query)
                    .bind(uuid)
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            VpcIdKeyedObjectFilter::List(list) => {
                let query = "select * from vpcs WHERE id = ANY($1) and deleted is NULL";
                sqlx::query_as(query)
                    .bind(list)
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
        };

        Ok(results)
    }

    pub async fn find_by_name(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        name: &str,
    ) -> Result<Vec<Vpc>, DatabaseError> {
        let query = "SELECT * FROM vpcs WHERE name = $1 and deleted is NULL";
        sqlx::query_as(query)
            .bind(name)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_segment(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        segment_id: NetworkSegmentId,
    ) -> Result<Vpc, DatabaseError> {
        let query = "SELECT * from vpcs v
            INNER JOIN network_segments s ON v.id = s.vpc_id
            WHERE s.id = $1
            LIMIT 1";
        sqlx::query_as(query)
            .bind(segment_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// Tries to deletes a VPC
    ///
    /// If the VPC existed at the point of deletion this returns the last known information about the VPC
    /// If the VPC already had been delete, this returns Ok(`None`)
    pub async fn try_delete(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        id: VpcId,
    ) -> Result<Option<Self>, DatabaseError> {
        // TODO: Should this update the version?
        let query = "UPDATE vpcs SET updated=NOW(), deleted=NOW() WHERE id=$1 AND deleted is null RETURNING *";
        match sqlx::query_as(query)
            .bind(id)
            .fetch_one(txn.deref_mut())
            .await
        {
            Ok(vpc) => Ok(Some(vpc)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }
}

impl From<Vpc> for rpc::Vpc {
    fn from(src: Vpc) -> Self {
        rpc::Vpc {
            id: Some(src.id.into()),
            version: src.version.version_string(),
            name: src.metadata.name.clone(),
            tenant_organization_id: src.tenant_organization_id,
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            tenant_keyset_id: src.tenant_keyset_id,
            vni: src.vni.map(|x| x as u32),
            network_virtualization_type: Some(src.network_virtualization_type as i32),
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
        let id = match value.id {
            Some(v) => VpcId::try_from(v)?,
            None => VpcId::from(uuid::Uuid::new_v4()),
        };

        let vpc_name: String = if let Some(metadata) = &value.metadata {
            if !metadata.name.is_empty() {
                metadata.name.clone()
            } else {
                value.name.clone()
            }
        } else {
            value.name.clone()
        };

        let metadata = Metadata {
            name: vpc_name,
            description: value
                .metadata
                .clone()
                .map(|m| m.description.clone())
                .unwrap_or("".to_owned()),
            labels: value.metadata.clone().map_or(HashMap::new(), |m| {
                m.labels
                    .iter()
                    .map(|label| {
                        (
                            label.key.clone(),
                            label.value.clone().unwrap_or("".to_owned()),
                        )
                    })
                    .collect()
            }),
        };

        Ok(NewVpc {
            id,
            tenant_organization_id: value.tenant_organization_id,
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

        Ok(UpdateVpc {
            id: value
                .id
                .ok_or(CarbideError::MissingArgument("id"))?
                .try_into()?,
            if_version_match,
            name: value.name,
            tenant_organization_id: value.tenant_organization_id,
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
            id: value
                .id
                .ok_or(CarbideError::MissingArgument("id"))?
                .try_into()?,
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
    pub async fn update(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Vpc> {
        // TODO: Should this check for deletion?
        let current_version = match self.if_version_match {
            Some(version) => version,
            None => {
                let vpcs = Vpc::find(txn, VpcIdKeyedObjectFilter::One(self.id)).await?;
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
            SET name=$1, organization_id=$2, version=$3, updated=NOW()
            WHERE id=$4 AND version=$5 AND deleted is null
            RETURNING *";
        let query_result = sqlx::query_as(query)
            .bind(&self.name)
            .bind(&self.tenant_organization_id)
            .bind(next_version)
            .bind(self.id)
            .bind(current_version)
            .fetch_one(txn.deref_mut())
            .await;

        match query_result {
            Ok(r) => Ok(r),
            Err(sqlx::Error::RowNotFound) => {
                // TODO: This can actually happen on both invalid ID and invalid version
                // So maybe this should be `ObjectNotFoundOrModifiedError`
                Err(CarbideError::ConcurrentModificationError(
                    "vpc",
                    current_version,
                ))
            }
            Err(e) => Err(CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                query,
                e,
            ))),
        }
    }
}

impl UpdateVpcVirtualization {
    pub async fn update(&self, txn: &mut sqlx::Transaction<'_, Postgres>) -> CarbideResult<Vpc> {
        let query = "UPDATE vpcs
            SET version=$1, network_virtualization_type=$2, updated=NOW()
            WHERE id=$3 AND version=$4 AND deleted is null
            RETURNING *";

        let current_version = match self.if_version_match {
            Some(version) => version,
            None => {
                let vpcs = Vpc::find(txn, VpcIdKeyedObjectFilter::One(self.id)).await?;
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
            .fetch_one(txn.deref_mut())
            .await;

        match query_result {
            Ok(r) => Ok(r),
            Err(sqlx::Error::RowNotFound) => {
                // TODO(chet): This can actually happen on both invalid ID and invalid
                // version, so maybe this should be `ObjectNotFoundOrModifiedError`
                // or similar.
                Err(CarbideError::ConcurrentModificationError(
                    "vpc",
                    current_version,
                ))
            }
            Err(e) => Err(CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                query,
                e,
            ))),
        }
    }
}
