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

use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row};

use crate::db::DatabaseError;
use crate::model::config_version::ConfigVersion;
use crate::model::tenant::{Tenant, TenantKeyset, TenantKeysetContent, TenantKeysetIdentifier};
use crate::{CarbideError, CarbideResult};

impl Tenant {
    pub async fn create_and_persist(
        organization_id: String,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Self, DatabaseError> {
        let version = ConfigVersion::initial();
        let version_string = version.version_string();
        let query = "INSERT INTO tenants (organization_id, version) VALUES ($1, $2) RETURNING *";

        sqlx::query_as(query)
            .bind(organization_id)
            .bind(&version_string)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find<S: AsRef<str>>(
        organization_id: S,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = "SELECT * FROM tenants WHERE organization_id = $1";
        let results = sqlx::query_as(query)
            .bind(organization_id.as_ref())
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(results)
    }

    pub async fn update(
        organization_id: String,
        if_version_match: Option<ConfigVersion>,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<Self> {
        let current_version = match if_version_match {
            Some(version) => version,
            None => {
                if let Some(tenant) = Tenant::find(organization_id.as_str(), txn).await? {
                    tenant.version
                } else {
                    return Err(CarbideError::NotFoundError {
                        id: organization_id,
                        kind: "tenant",
                    });
                }
            }
        };
        let current_version_str = current_version.version_string();
        let next_version = current_version.increment();
        let next_version_str = next_version.version_string();

        let query = "UPDATE tenants
            SET version=$1
            WHERE organization_id=$2 AND version=$3
            RETURNING *";

        sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(organization_id)
            .bind(&current_version_str)
            .fetch_one(txn)
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => {
                    CarbideError::ConcurrentModificationError("tenant", current_version)
                }
                error => CarbideError::from(DatabaseError::new(file!(), line!(), query, error)),
            })
    }
}
impl<'r> sqlx::FromRow<'r, PgRow> for Tenant {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config_version_str: &str = row.try_get("version")?;
        let version = config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let organization_id: String = row.try_get("organization_id")?;
        Ok(Self {
            organization_id: organization_id
                .try_into()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            version,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for TenantKeyset {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config_version_str: &str = row.try_get("version")?;
        let version = config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let tenant_keyset_content: sqlx::types::Json<TenantKeysetContent> =
            row.try_get("content")?;

        let organization_id: String = row.try_get("organization_id")?;
        Ok(Self {
            version,
            keyset_content: tenant_keyset_content.0,
            keyset_identifier: TenantKeysetIdentifier {
                organization_id: organization_id
                    .try_into()
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
                keyset_id: row.try_get("keyset_id")?,
            },
        })
    }
}

impl TenantKeyset {
    pub fn find(_organization_id: String, _keyset_id: String) -> CarbideResult<Self> {
        todo!()
    }
}
