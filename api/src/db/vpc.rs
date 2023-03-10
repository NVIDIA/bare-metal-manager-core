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
use std::convert::TryInto;

use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};
use uuid::Uuid;

use crate::db::UuidKeyedObjectFilter;
use crate::model::config_version::ConfigVersion;
use crate::{CarbideError, CarbideResult};

use super::DatabaseError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeysetIdentifier {
    pub organization_id: String,
    pub keyset_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantPublicKey {
    pub public_key: String,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeysetContent {
    pub public_keys: Vec<TenantPublicKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyset {
    pub keyset_identifier: TenantKeysetIdentifier,
    pub keyset_content: TenantKeysetContent,
    pub version: String,
}

impl From<rpc::forge::TenantPublicKey> for TenantPublicKey {
    fn from(src: rpc::forge::TenantPublicKey) -> Self {
        Self {
            public_key: src.public_key,
            comment: src.comment,
        }
    }
}

impl From<TenantPublicKey> for rpc::forge::TenantPublicKey {
    fn from(src: TenantPublicKey) -> Self {
        Self {
            public_key: src.public_key,
            comment: src.comment,
        }
    }
}

impl From<rpc::forge::TenantKeysetContent> for TenantKeysetContent {
    fn from(src: rpc::forge::TenantKeysetContent) -> Self {
        Self {
            public_keys: src.public_keys.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<TenantKeysetContent> for rpc::forge::TenantKeysetContent {
    fn from(src: TenantKeysetContent) -> Self {
        Self {
            public_keys: src.public_keys.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<rpc::forge::TenantKeysetIdentifier> for TenantKeysetIdentifier {
    fn from(src: rpc::forge::TenantKeysetIdentifier) -> Self {
        Self {
            organization_id: src.organization_id,
            keyset_id: src.keyset_id,
        }
    }
}

impl From<TenantKeysetIdentifier> for rpc::forge::TenantKeysetIdentifier {
    fn from(src: TenantKeysetIdentifier) -> Self {
        Self {
            organization_id: src.organization_id,
            keyset_id: src.keyset_id,
        }
    }
}

impl TryFrom<rpc::forge::TenantKeyset> for TenantKeyset {
    type Error = CarbideError;

    fn try_from(src: rpc::forge::TenantKeyset) -> Result<Self, Self::Error> {
        let keyset_identifier: TenantKeysetIdentifier = src
            .keyset_identifier
            .ok_or_else(|| CarbideError::MissingArgument("tenant keyset identifier"))?
            .into();

        let keyset_content: TenantKeysetContent = src
            .keyset_content
            .ok_or_else(|| CarbideError::MissingArgument("tenant keyset content"))?
            .into();

        Ok(Self {
            keyset_content,
            keyset_identifier,
            version: src.version,
        })
    }
}

impl From<TenantKeyset> for rpc::forge::TenantKeyset {
    fn from(src: TenantKeyset) -> Self {
        Self {
            keyset_identifier: Some(src.keyset_identifier.into()),
            keyset_content: Some(src.keyset_content.into()),
            version: src.version,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vpc {
    pub id: Uuid,
    pub name: String,
    pub tenant_organization_id: String,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub tenant_keyset_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NewVpc {
    pub name: String,
    pub tenant_organization_id: String,
}

#[derive(Clone, Debug)]
pub struct UpdateVpc {
    pub id: Uuid,
    pub if_version_match: Option<ConfigVersion>,
    pub name: String,
    pub tenant_organization_id: String,
}

#[derive(Clone, Debug)]
pub struct DeleteVpc {
    pub id: Uuid,
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
        })
    }
}

impl NewVpc {
    pub async fn persist(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Vpc, DatabaseError> {
        let version = ConfigVersion::initial();
        let version_string = version.to_version_string();

        let query =
            "INSERT INTO vpcs (name, organization_id, version) VALUES ($1, $2, $3) RETURNING *";
        sqlx::query_as(query)
            .bind(&self.name)
            .bind(&self.tenant_organization_id)
            .bind(&version_string)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

impl Vpc {
    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> Result<Vec<Vpc>, DatabaseError> {
        let results: Vec<Vpc> = match filter {
            UuidKeyedObjectFilter::All => {
                let query = "SELECT * FROM vpcs WHERE deleted is NULL";
                sqlx::query_as(query)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                let query = "SELECT * FROM vpcs WHERE id = $1 and deleted is NULL";
                sqlx::query_as(query)
                    .bind(uuid)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
            UuidKeyedObjectFilter::List(list) => {
                let query = "select * from vpcs WHERE id = ANY($1) and deleted is NULL";
                sqlx::query_as(query)
                    .bind(list)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            }
        };

        Ok(results)
    }
    pub async fn find_by_name(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        name: String,
    ) -> Result<Vec<Vpc>, DatabaseError> {
        let query = "SELECT * FROM vpcs WHERE name = $1 and deleted is NULL";
        sqlx::query_as(query)
            .bind(name)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

impl From<Vpc> for rpc::forge::Vpc {
    fn from(src: Vpc) -> Self {
        rpc::forge::Vpc {
            id: Some(src.id.into()),
            version: src.version.to_version_string(),
            name: src.name,
            tenant_organization_id: src.tenant_organization_id,
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            tenant_keyset_id: src.tenant_keyset_id,
        }
    }
}

impl TryFrom<rpc::forge::VpcCreationRequest> for NewVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::forge::VpcCreationRequest) -> Result<Self, Self::Error> {
        Ok(NewVpc {
            name: value.name,
            tenant_organization_id: value.tenant_organization_id,
        })
    }
}

impl TryFrom<rpc::forge::VpcUpdateRequest> for UpdateVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::forge::VpcUpdateRequest) -> Result<Self, Self::Error> {
        let if_version_match: Option<ConfigVersion> = match &value.if_version_match {
            Some(version) => Some(version.parse::<ConfigVersion>()?),
            None => None,
        };

        Ok(UpdateVpc {
            id: value
                .id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
            if_version_match,
            name: value.name,
            tenant_organization_id: value.tenant_organization_id,
        })
    }
}

impl TryFrom<rpc::forge::VpcDeletionRequest> for DeleteVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::forge::VpcDeletionRequest) -> Result<Self, Self::Error> {
        Ok(DeleteVpc {
            id: value
                .id
                .ok_or_else(CarbideError::IdentifierNotSpecifiedForObject)?
                .try_into()?,
        })
    }
}

impl From<Vpc> for rpc::forge::VpcDeletionResult {
    fn from(_src: Vpc) -> Self {
        rpc::forge::VpcDeletionResult {}
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
        let current_version_str = current_version.to_version_string();
        let next_version = current_version.increment();
        let next_version_str = next_version.to_version_string();

        // TODO check number of changed rows
        let query = "UPDATE vpcs
            SET name=$1, organization_id=$2, version=$3, updated=NOW()
            WHERE id=$4 AND version=$5
            RETURNING *";
        let query_result = sqlx::query_as(query)
            .bind(&self.name)
            .bind(&self.tenant_organization_id)
            .bind(&next_version_str)
            .bind(self.id)
            .bind(&current_version_str)
            .fetch_one(&mut *txn)
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

impl DeleteVpc {
    pub async fn delete(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Vpc, DatabaseError> {
        // TODO: Should this update the version?
        let query = "UPDATE vpcs SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
        sqlx::query_as(query)
            .bind(self.id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}
