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
use std::fmt;
use std::str::FromStr;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::ConfigVersion;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use super::DatabaseError;
use crate::db::UuidKeyedObjectFilter;
use crate::model::RpcDataConversionError;
use crate::{CarbideError, CarbideResult};

// What to use if Cloud UI doesn't send it, which it never does so this is used for all vpcs / instances.
// Keep in sync with bluefield/agent/src/lib.rs
//
// Currently this is only used to populate the database. The value itself is never read, instead
// we use config file's `nvue_enabled`.
// Once we do FNN this might be used once more.
const DEFAULT_NETWORK_VIRTUALIZATION_TYPE: VpcVirtualizationType =
    VpcVirtualizationType::EthernetVirtualizer;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vpc {
    pub id: uuid::Uuid,
    pub name: String,
    pub tenant_organization_id: String,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub tenant_keyset_id: Option<String>,
    pub network_virtualization_type: VpcVirtualizationType,
    // Option because we can't allocate it until DB generates an id for us
    pub vni: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "network_virtualization_type_t")]
#[allow(clippy::enum_variant_names)]
pub enum VpcVirtualizationType {
    #[sqlx(rename = "etv")]
    EthernetVirtualizer = 0,
    #[sqlx(rename = "etv_nvue")]
    EthernetVirtualizerWithNvue = 2,
}

impl fmt::Display for VpcVirtualizationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EthernetVirtualizer => write!(f, "etv"),
            Self::EthernetVirtualizerWithNvue => write!(f, "etv_nvue"),
        }
    }
}

impl TryFrom<i32> for VpcVirtualizationType {
    type Error = RpcDataConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == rpc::VpcVirtualizationType::EthernetVirtualizer as i32 => {
                Self::EthernetVirtualizer
            }
            x if x == rpc::VpcVirtualizationType::EthernetVirtualizerWithNvue as i32 => {
                Self::EthernetVirtualizerWithNvue
            }
            _ => {
                return Err(RpcDataConversionError::InvalidVpcVirtualizationType(value));
            }
        })
    }
}

impl FromStr for VpcVirtualizationType {
    type Err = CarbideError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "etv" => Ok(Self::EthernetVirtualizer),
            "etv_nvue" => Ok(Self::EthernetVirtualizerWithNvue),
            x => Err(CarbideError::GenericError(format!(
                "Unknown virt type {}",
                x
            ))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NewVpc {
    pub id: uuid::Uuid,
    pub name: String,
    pub tenant_organization_id: String,
    pub network_virtualization_type: VpcVirtualizationType,
}

#[derive(Clone, Debug)]
pub struct UpdateVpc {
    pub id: uuid::Uuid,
    pub if_version_match: Option<ConfigVersion>,
    pub name: String,
    pub tenant_organization_id: String,
}

#[derive(Clone, Debug)]
pub struct VpcSearchQuery {
    pub id: Option<uuid::Uuid>,
    pub string: Option<String>,
}

impl<'r> sqlx::FromRow<'r, PgRow> for Vpc {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config_version_str: &str = row.try_get("version")?;
        let version = config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        Ok(Vpc {
            id: row.try_get("id")?,
            version,
            name: row.try_get("name")?,
            tenant_organization_id: row.try_get("organization_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            tenant_keyset_id: None, //TODO: fix this once DB gets updated
            network_virtualization_type: row.try_get("network_virtualization_type")?,
            vni: row.try_get("vni")?,
        })
    }
}

impl NewVpc {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Vpc, DatabaseError> {
        let version = ConfigVersion::initial();
        let version_string = version.version_string();

        let query =
            "INSERT INTO vpcs (id, name, organization_id, version, network_virtualization_type) VALUES ($1, $2, $3, $4, $5) RETURNING *";
        sqlx::query_as(query)
            .bind(self.id)
            .bind(&self.name)
            .bind(&self.tenant_organization_id)
            .bind(&version_string)
            .bind(self.network_virtualization_type)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

impl Vpc {
    pub async fn find_ids(
        txn: &mut Transaction<'_, Postgres>,
        search_config: rpc::VpcSearchConfig,
    ) -> Result<Vec<uuid::Uuid>, CarbideError> {
        #[derive(Debug, Clone, Copy, FromRow)]
        pub struct VpcId(uuid::Uuid);

        // build query
        let mut builder = sqlx::QueryBuilder::new("SELECT id FROM vpcs WHERE ");
        let mut has_filter = false;
        if search_config.name.is_some() {
            builder.push("name = ");
            builder.push_bind(search_config.name.unwrap());
            has_filter = true;
        }
        if has_filter {
            builder.push(" AND");
        }
        builder.push(" deleted IS NULL");

        let query = builder.build_query_as();
        let ids: Vec<VpcId> = query
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "vpc::find_ids", e))?;

        Ok(ids.into_iter().map(|id| id.0).collect())
    }

    pub async fn set_vni(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        id: uuid::Uuid,
        vni: i32,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE vpcs SET vni = $1 WHERE id = $2 AND vni IS NULL";
        let _ = sqlx::query(query)
            .bind(vni)
            .bind(id)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> Result<Vec<Vpc>, DatabaseError> {
        let results: Vec<Vpc> = match filter {
            UuidKeyedObjectFilter::All => {
                let query = "SELECT * FROM vpcs WHERE deleted is NULL";
                sqlx::query_as(query)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                let query = "SELECT * FROM vpcs WHERE id = $1 and deleted is NULL";
                sqlx::query_as(query)
                    .bind(uuid)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            UuidKeyedObjectFilter::List(list) => {
                let query = "select * from vpcs WHERE id = ANY($1) and deleted is NULL";
                sqlx::query_as(query)
                    .bind(list)
                    .fetch_all(&mut **txn)
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
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_segment(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        segment_id: uuid::Uuid,
    ) -> Result<Vpc, DatabaseError> {
        let query = "SELECT * from vpcs v
            INNER JOIN network_segments s ON v.id = s.vpc_id
            WHERE s.id = $1
            LIMIT 1";
        sqlx::query_as(query)
            .bind(segment_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// Tries to deletes a VPC
    ///
    /// If the VPC existed at the point of deletion this returns the last known information about the VPC
    /// If the VPC already had been delete, this returns Ok(`None`)
    pub async fn try_delete(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        id: uuid::Uuid,
    ) -> Result<Option<Self>, DatabaseError> {
        // TODO: Should this update the version?
        let query = "UPDATE vpcs SET updated=NOW(), deleted=NOW() WHERE id=$1 AND deleted is null RETURNING *";
        match sqlx::query_as(query).bind(id).fetch_one(&mut **txn).await {
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
            name: src.name,
            tenant_organization_id: src.tenant_organization_id,
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            tenant_keyset_id: src.tenant_keyset_id,
            vni: src.vni.map(|x| x as u32),
            network_virtualization_type: Some(src.network_virtualization_type as i32),
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
            Some(v) => uuid::Uuid::try_from(v)?,
            None => uuid::Uuid::new_v4(),
        };
        Ok(NewVpc {
            id,
            name: value.name,
            tenant_organization_id: value.tenant_organization_id,
            network_virtualization_type: virt_type,
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
                let vpcs = Vpc::find(txn, UuidKeyedObjectFilter::One(self.id)).await?;
                if vpcs.len() != 1 {
                    return Err(CarbideError::FindOneReturnedManyResultsError(self.id));
                }
                vpcs[0].version
            }
        };
        let current_version_str = current_version.version_string();
        let next_version = current_version.increment();
        let next_version_str = next_version.version_string();

        // network_virtualization_type cannot be changed currently
        // TODO check number of changed rows
        let query = "UPDATE vpcs
            SET name=$1, organization_id=$2, version=$3, updated=NOW()
            WHERE id=$4 AND version=$5 AND deleted is null
            RETURNING *";
        let query_result = sqlx::query_as(query)
            .bind(&self.name)
            .bind(&self.tenant_organization_id)
            .bind(&next_version_str)
            .bind(self.id)
            .bind(&current_version_str)
            .fetch_one(&mut **txn)
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
