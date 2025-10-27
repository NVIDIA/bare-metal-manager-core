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

use ::rpc::forge as rpc;
use config_version::ConfigVersion;
use model::metadata::Metadata;
use model::tenant::{Tenant, TenantPublicKeyValidationRequest};
use sqlx::PgConnection;

use super::ObjectFilter;
use crate::{DatabaseError, DatabaseResult};

type OrganizationID = String;

pub async fn create_and_persist(
    organization_id: String,
    metadata: Metadata,
    txn: &mut PgConnection,
) -> Result<Tenant, DatabaseError> {
    let version = ConfigVersion::initial();
    let query = "INSERT INTO tenants (organization_id, organization_name, version) VALUES ($1, $2, $3) RETURNING *";

    sqlx::query_as(query)
        .bind(organization_id)
        .bind(metadata.name)
        .bind(version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find<S: AsRef<str>>(
    organization_id: S,
    txn: &mut PgConnection,
) -> Result<Option<Tenant>, DatabaseError> {
    let query = "SELECT * FROM tenants WHERE organization_id = $1";
    let results = sqlx::query_as(query)
        .bind(organization_id.as_ref())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(results)
}

pub async fn update(
    organization_id: String,
    metadata: Metadata,
    if_version_match: Option<ConfigVersion>,
    txn: &mut PgConnection,
) -> DatabaseResult<Tenant> {
    let current_version = match if_version_match {
        Some(version) => version,
        None => {
            if let Some(tenant) = find(organization_id.as_str(), txn).await? {
                tenant.version
            } else {
                return Err(DatabaseError::NotFoundError {
                    id: organization_id,
                    kind: "tenant",
                });
            }
        }
    };
    let next_version = current_version.increment();

    let query = "UPDATE tenants
            SET version=$1, organization_name=$2
            WHERE organization_id=$3 AND version=$4
            RETURNING *";

    sqlx::query_as(query)
        .bind(next_version)
        .bind(metadata.name)
        .bind(organization_id)
        .bind(current_version)
        .fetch_one(txn)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => {
                DatabaseError::ConcurrentModificationError("tenant", current_version.to_string())
            }
            error => DatabaseError::query(query, error),
        })
}

pub async fn find_tenant_organization_ids(
    txn: &mut PgConnection,
    search_config: rpc::TenantSearchFilter,
) -> Result<Vec<OrganizationID>, DatabaseError> {
    let mut qb = sqlx::QueryBuilder::new("SELECT organization_id FROM tenants");

    if let Some(tenant_org_name) = &search_config.tenant_organization_name {
        qb.push(" WHERE organization_name = ");
        qb.push_bind(tenant_org_name);
    }

    let tenant_organization_ids: Vec<OrganizationID> = qb
        .build_query_as::<(String,)>()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("find_tenant_organization_ids", e))?
        .into_iter()
        .map(|row| row.0)
        .collect();

    Ok(tenant_organization_ids)
}

pub async fn validate_public_key(
    request: &TenantPublicKeyValidationRequest,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let instance = crate::instance::find_by_id(txn, request.instance_id)
        .await?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "instance",
            id: request.instance_id.to_string(),
        })?;

    let keysets = crate::tenant_keyset::find(
        Some(instance.config.tenant.tenant_organization_id.to_string()),
        ObjectFilter::List(&instance.config.tenant.tenant_keyset_ids),
        true,
        txn,
    )
    .await?;

    request.validate_key(keysets).map_err(DatabaseError::from)
}

pub async fn load_by_organization_ids(
    txn: &mut PgConnection,
    organization_ids: &[String],
) -> Result<Vec<Tenant>, DatabaseError> {
    let query = "SELECT * from tenants WHERE organization_id = ANY($1)";
    sqlx::query_as(query)
        .bind(organization_ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

#[cfg(test)]
mod tests {
    use std::ops::DerefMut;

    #[crate::sqlx_test]
    async fn test_null_organization_name(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        let result = sqlx::query(
            r#"
            INSERT INTO tenants (organization_id, version, organization_name)
            VALUES
            ('zqrrhxea4ktv', 'V1-T1733777281821769', NULL)
            "#,
        )
        .execute(txn.deref_mut())
        .await;
        let Err(sqlx::Error::Database(e)) = result else {
            panic!("Inserting a NULL should have failed");
        };
        assert!(matches!(e.kind(), sqlx::error::ErrorKind::NotNullViolation));
    }
}
