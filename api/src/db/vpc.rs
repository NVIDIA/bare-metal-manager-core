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
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};
use uuid::Uuid;

use super::DatabaseError;
use crate::db::UuidKeyedObjectFilter;
use crate::model::config_version::ConfigVersion;
use crate::{CarbideError, CarbideResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vpc {
    pub id: Uuid,
    pub name: String,
    pub organization_id: String,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct NewVpc {
    pub name: String,
    pub organization: String,
}

#[derive(Clone, Debug)]
pub struct UpdateVpc {
    pub id: Uuid,
    pub if_version_match: Option<ConfigVersion>,
    pub name: String,
    pub organization: String,
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
            organization_id: row.try_get("organization_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
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
            .bind(&self.organization)
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
            organization: src.organization_id,
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
        }
    }
}

impl TryFrom<rpc::forge::VpcCreationRequest> for NewVpc {
    type Error = CarbideError;

    fn try_from(value: rpc::forge::VpcCreationRequest) -> Result<Self, Self::Error> {
        Ok(NewVpc {
            name: value.name,
            organization: value.organization,
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
            organization: value.organization,
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
            .bind(&self.organization)
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
