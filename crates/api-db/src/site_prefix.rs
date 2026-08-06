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

use std::collections::HashMap;

use carbide_uuid::site_prefix::SitePrefixId;
use config_version::ConfigVersion;
use ipnetwork::IpNetwork;
use model::site_prefix::{
    NewSitePrefix, NewTenantManagedSitePrefix, PrefixMatch, RetireTenantManagedSitePrefix,
    SitePrefix, SitePrefixAuthority, SitePrefixLifecycleState, SitePrefixRoutingScope,
    SitePrefixSearchFilter, UpdateSitePrefixMetadata,
};
use model::tenant::TenantOrganizationId;
use sqlx::{PgConnection, QueryBuilder};

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

const TENANT_PREFIX_EXCLUSION: &str = "site_prefixes_tenant_prefix_excl";
const TENANT_ADMISSION_CHECK: &str = "site_prefixes_tenant_admission_check";
const OPERATOR_MANAGED_PREFIX_UNIQUE: &str = "site_prefixes_operator_managed_prefix_key";
// `Configured` describes the config-file source here. Keep the key stable so
// every reconciler uses the same advisory lock.
const CONFIGURED_RECONCILE_LOCK: &str = "site_prefixes:configured_reconcile";

fn tenant_prefix_overlap_error(prefix: &IpNetwork) -> DatabaseError {
    DatabaseError::InvalidArgument(format!(
        "site prefix {prefix} overlaps another site prefix owned by the same tenant"
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateDisposition {
    Created,
    Existing,
}

#[derive(Clone, Debug)]
pub struct CreateResult {
    pub site_prefix: SitePrefix,
    pub disposition: CreateDisposition,
}

async fn lock_site_prefix_id(
    site_prefix_id: SitePrefixId,
    txn: &mut PgConnection,
) -> DatabaseResult<()> {
    let query = r#"
        SELECT pg_advisory_xact_lock(
            hashtextextended('site_prefixes:id:' || $1, 0)
        )
    "#;
    sqlx::query(query)
        .bind(site_prefix_id.to_string())
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|error| DatabaseError::query(query, error))
}

/// Runs tenant prefix writes serially per tenant so concurrent overlaps reach
/// the exclusion constraint instead of deadlocking each other.
async fn lock_tenant_prefix_writes(
    tenant_organization_id: &str,
    txn: &mut PgConnection,
) -> DatabaseResult<()> {
    let query = r#"
        SELECT pg_advisory_xact_lock(
            hashtextextended('site_prefixes:tenant:' || $1, 0)
        )
    "#;
    sqlx::query(query)
        .bind(tenant_organization_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|error| DatabaseError::query(query, error))
}

async fn insert(value: NewSitePrefix, txn: &mut PgConnection) -> DatabaseResult<SitePrefix> {
    value.validate()?;

    let version = ConfigVersion::initial();
    let query = r#"
        INSERT INTO site_prefixes (
            id,
            prefix,
            authority,
            tenant_organization_id,
            routing_scope,
            lifecycle_state,
            name,
            description,
            labels,
            version
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
        RETURNING *
    "#;

    let site_prefix: SitePrefix = sqlx::query_as(query)
        .bind(value.id)
        .bind(value.config.prefix)
        .bind(value.status.authority)
        .bind(&value.config.tenant_organization_id)
        .bind(value.config.routing_scope)
        .bind(value.status.lifecycle_state)
        .bind(&value.metadata.name)
        .bind(&value.metadata.description)
        .bind(sqlx::types::Json(&value.metadata.labels))
        .bind(version)
        .fetch_one(&mut *txn)
        .await
        .map_err(|error| {
            let constraint = match &error {
                sqlx::Error::Database(database_error) => database_error.constraint(),
                _ => None,
            };

            match constraint {
                Some(TENANT_PREFIX_EXCLUSION) => tenant_prefix_overlap_error(&value.config.prefix),
                Some(OPERATOR_MANAGED_PREFIX_UNIQUE) => DatabaseError::AlreadyFoundError {
                    kind: "operator-managed site prefix",
                    id: value.config.prefix.to_string(),
                },
                // Supported tenant writers validate before insert. Preserve
                // an actionable error for direct or future writers caught by
                // the database's defense-in-depth policy constraint.
                Some(TENANT_ADMISSION_CHECK) => DatabaseError::InvalidArgument(format!(
                    "site prefix {} does not satisfy the tenant address policy",
                    value.config.prefix
                )),
                _ => DatabaseError::query(query, error),
            }
        })?;

    crate::state_history::persist(
        txn,
        crate::state_history::StateHistoryTableId::SitePrefix,
        &site_prefix.id,
        &site_prefix.status.lifecycle_state,
        site_prefix.version,
    )
    .await?;

    Ok(site_prefix)
}

/// Creates one tenant-managed SitePrefix or returns the current resource
/// already using the caller's ID when its immutable fields match. Create
/// metadata is not reapplied on an idempotent retry; callers use the metadata
/// update API for that mutable state.
pub async fn create_tenant_managed(
    value: NewTenantManagedSitePrefix,
    quota_limit: u32,
    txn: &mut PgConnection,
) -> DatabaseResult<CreateResult> {
    value.validate()?;

    lock_site_prefix_id(value.id, txn).await?;
    lock_tenant_prefix_writes(value.tenant_organization_id.as_str(), txn).await?;

    if crate::tenant::find(value.tenant_organization_id.as_str(), false, txn)
        .await?
        .is_none()
    {
        return Err(DatabaseError::NotFoundError {
            kind: "tenant",
            id: value.tenant_organization_id.to_string(),
        });
    }

    if let Some(existing) = find_by_id_for_update(txn, value.id).await? {
        let immutable_fields_match = existing.status.authority
            == SitePrefixAuthority::TenantManaged
            && existing.config.tenant_organization_id.as_ref()
                == Some(&value.tenant_organization_id)
            && existing.config.prefix == value.prefix
            && existing.config.routing_scope == SitePrefixRoutingScope::DatacenterOnly;

        if immutable_fields_match {
            return Ok(CreateResult {
                site_prefix: existing,
                disposition: CreateDisposition::Existing,
            });
        }

        return Err(DatabaseError::AlreadyFoundError {
            kind: "site prefix",
            id: value.id.to_string(),
        });
    }

    let used = count_tenant_managed(&mut *txn, &value.tenant_organization_id).await?;
    if used >= quota_limit {
        return Err(DatabaseError::TenantSitePrefixQuotaExceeded {
            used,
            limit: quota_limit,
        });
    }

    let overlap_query = r#"
        SELECT EXISTS (
            SELECT 1
            FROM site_prefixes
            WHERE authority = $1
              AND tenant_organization_id = $2
              AND prefix && $3
        )
    "#;
    let overlaps: bool = sqlx::query_scalar(overlap_query)
        .bind(SitePrefixAuthority::TenantManaged)
        .bind(&value.tenant_organization_id)
        .bind(value.prefix)
        .fetch_one(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(overlap_query, error))?;
    if overlaps {
        return Err(tenant_prefix_overlap_error(&value.prefix));
    }

    let site_prefix = insert(value.into_new_site_prefix(), txn).await?;
    Ok(CreateResult {
        site_prefix,
        disposition: CreateDisposition::Created,
    })
}

async fn lock_configured_reconciliation(txn: &mut PgConnection) -> DatabaseResult<()> {
    let query = "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))";
    sqlx::query(query)
        .bind(CONFIGURED_RECONCILE_LOCK)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|error| DatabaseError::query(query, error))
}

/// Reconciles config-file site fabric prefixes into operator-managed rows.
///
/// The canonical CIDR is the current configuration identity. Existing rows are
/// reactivated in place, new rows receive a generated ID, and absent rows move
/// to Deleting so later lifecycle work can decide when final removal is safe.
pub async fn reconcile_configured(
    txn: &mut PgConnection,
    configured_prefixes: &[IpNetwork],
) -> DatabaseResult<()> {
    lock_configured_reconciliation(txn).await?;

    let mut configured_prefixes: Vec<IpNetwork> = configured_prefixes
        .iter()
        .map(|prefix| NewSitePrefix::configured(*prefix).config.prefix)
        .collect();
    configured_prefixes.sort_by_cached_key(ToString::to_string);
    configured_prefixes.dedup();

    let find_query = "SELECT * FROM site_prefixes WHERE authority = $1 FOR UPDATE";
    let stored: Vec<SitePrefix> = sqlx::query_as(find_query)
        .bind(SitePrefixAuthority::OperatorManaged)
        .fetch_all(&mut *txn)
        .await
        .map_err(|error| DatabaseError::query(find_query, error))?;
    let mut stored: HashMap<IpNetwork, SitePrefix> = stored
        .into_iter()
        .map(|site_prefix| (site_prefix.config.prefix, site_prefix))
        .collect();

    for prefix in configured_prefixes {
        let desired = NewSitePrefix::configured(prefix);
        desired.validate()?;

        match stored.remove(&prefix) {
            Some(current)
                if current.config == desired.config
                    && current.metadata == desired.metadata
                    && current.status == desired.status => {}
            Some(current) => {
                let next_version = current.version.increment();
                let query = r#"
                    UPDATE site_prefixes
                    SET routing_scope = $1,
                        lifecycle_state = $2,
                        name = $3,
                        description = $4,
                        labels = $5::jsonb,
                        version = $6,
                        updated_at = now()
                    WHERE id = $7
                "#;
                sqlx::query(query)
                    .bind(desired.config.routing_scope)
                    .bind(desired.status.lifecycle_state)
                    .bind(&desired.metadata.name)
                    .bind(&desired.metadata.description)
                    .bind(sqlx::types::Json(&desired.metadata.labels))
                    .bind(next_version)
                    .bind(current.id)
                    .execute(&mut *txn)
                    .await
                    .map_err(|error| DatabaseError::query(query, error))?;

                if current.status.lifecycle_state != desired.status.lifecycle_state {
                    crate::state_history::persist(
                        txn,
                        crate::state_history::StateHistoryTableId::SitePrefix,
                        &current.id,
                        &desired.status.lifecycle_state,
                        next_version,
                    )
                    .await?;
                }
            }
            None => {
                insert(desired, &mut *txn).await?;
            }
        }
    }

    for current in stored.into_values() {
        if current.status.lifecycle_state == SitePrefixLifecycleState::Deleting {
            continue;
        }

        let query = r#"
            UPDATE site_prefixes
            SET lifecycle_state = $1,
                version = $2,
                updated_at = now()
            WHERE id = $3
        "#;
        let next_version = current.version.increment();
        sqlx::query(query)
            .bind(SitePrefixLifecycleState::Deleting)
            .bind(next_version)
            .bind(current.id)
            .execute(&mut *txn)
            .await
            .map_err(|error| DatabaseError::query(query, error))?;

        crate::state_history::persist(
            txn,
            crate::state_history::StateHistoryTableId::SitePrefix,
            &current.id,
            &SitePrefixLifecycleState::Deleting,
            next_version,
        )
        .await?;
    }

    Ok(())
}

/// Locks and returns one SitePrefix for a caller that is about to mutate it.
pub async fn find_by_id_for_update(
    txn: &mut PgConnection,
    site_prefix_id: SitePrefixId,
) -> DatabaseResult<Option<SitePrefix>> {
    let query = "SELECT * FROM site_prefixes WHERE id = $1 FOR UPDATE";
    sqlx::query_as(query)
        .bind(site_prefix_id)
        .fetch_optional(txn)
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

/// Counts every tenant-managed row for one tenant. Rows remain in this count
/// through `Deleting` because their address space is still reserved.
pub async fn count_tenant_managed(
    db: impl DbReader<'_>,
    tenant_organization_id: &TenantOrganizationId,
) -> DatabaseResult<u32> {
    let query = r#"
        SELECT count(*)
        FROM site_prefixes
        WHERE authority = $1
          AND tenant_organization_id = $2
    "#;
    let used: i64 = sqlx::query_scalar(query)
        .bind(SitePrefixAuthority::TenantManaged)
        .bind(tenant_organization_id)
        .fetch_one(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))?;

    u32::try_from(used)
        .map_err(|_| DatabaseError::internal(format!("invalid SitePrefix count {used}")))
}

/// Returns tenant quota use for the owners present in one inventory response.
pub async fn count_tenant_managed_by_organizations(
    db: impl DbReader<'_>,
    tenant_organization_ids: &[TenantOrganizationId],
) -> DatabaseResult<HashMap<String, u32>> {
    if tenant_organization_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let tenant_organization_ids: Vec<&str> = tenant_organization_ids
        .iter()
        .map(TenantOrganizationId::as_str)
        .collect();
    let query = r#"
        SELECT tenant_organization_id, count(*)
        FROM site_prefixes
        WHERE authority = $1
          AND tenant_organization_id = ANY($2)
        GROUP BY tenant_organization_id
    "#;
    let counts: Vec<(String, i64)> = sqlx::query_as(query)
        .bind(SitePrefixAuthority::TenantManaged)
        .bind(&tenant_organization_ids)
        .fetch_all(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))?;

    counts
        .into_iter()
        .map(|(tenant_organization_id, used)| {
            u32::try_from(used)
                .map(|used| (tenant_organization_id, used))
                .map_err(|_| DatabaseError::internal(format!("invalid SitePrefix count {used}")))
        })
        .collect()
}

/// Updates only the caller-controlled metadata on a tenant-managed SitePrefix.
pub async fn update_tenant_metadata(
    value: &UpdateSitePrefixMetadata,
    expected_version: ConfigVersion,
    txn: &mut PgConnection,
) -> DatabaseResult<SitePrefix> {
    value.metadata.validate(true)?;

    let next_version = expected_version.increment();
    let query = r#"
        UPDATE site_prefixes
        SET name = $1,
            description = $2,
            labels = $3::jsonb,
            version = $4,
            updated_at = now()
        WHERE id = $5
          AND tenant_organization_id = $6
          AND authority = $7
          AND lifecycle_state <> $8
          AND version = $9
        RETURNING *
    "#;
    sqlx::query_as(query)
        .bind(&value.metadata.name)
        .bind(&value.metadata.description)
        .bind(sqlx::types::Json(&value.metadata.labels))
        .bind(next_version)
        .bind(value.id)
        .bind(&value.tenant_organization_id)
        .bind(SitePrefixAuthority::TenantManaged)
        .bind(SitePrefixLifecycleState::Deleting)
        .bind(expected_version)
        .fetch_one(txn)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => DatabaseError::ConcurrentModificationError(
                "site prefix",
                expected_version.to_string(),
            ),
            error => DatabaseError::query(query, error),
        })
}

/// Records retirement intent without releasing the row, quota slot, or CIDR.
pub async fn retire_tenant_managed(
    value: &RetireTenantManagedSitePrefix,
    current: &SitePrefix,
    txn: &mut PgConnection,
) -> DatabaseResult<SitePrefix> {
    if current.id != value.id {
        return Err(DatabaseError::InvalidArgument(format!(
            "retirement request ID {} does not match locked SitePrefix {}",
            value.id, current.id
        )));
    }
    if current.status.authority != SitePrefixAuthority::TenantManaged {
        return Err(DatabaseError::FailedPrecondition(
            "operator-managed SitePrefixes cannot be retired through the tenant API".to_string(),
        ));
    }
    if current.config.tenant_organization_id.as_ref() != Some(&value.tenant_organization_id) {
        return Err(DatabaseError::FailedPrecondition(
            "the SitePrefix is not owned by the requested tenant".to_string(),
        ));
    }
    if current.status.lifecycle_state == SitePrefixLifecycleState::Deleting {
        return Ok(current.clone());
    }

    let next_version = current.version.increment();
    let query = r#"
        UPDATE site_prefixes
        SET lifecycle_state = $1,
            version = $2,
            updated_at = now()
        WHERE id = $3
          AND tenant_organization_id = $4
          AND authority = $5
          AND version = $6
        RETURNING *
    "#;
    let site_prefix: SitePrefix = sqlx::query_as(query)
        .bind(SitePrefixLifecycleState::Deleting)
        .bind(next_version)
        .bind(value.id)
        .bind(&value.tenant_organization_id)
        .bind(SitePrefixAuthority::TenantManaged)
        .bind(current.version)
        .fetch_one(&mut *txn)
        .await
        .map_err(|error| match error {
            sqlx::Error::RowNotFound => DatabaseError::ConcurrentModificationError(
                "site prefix",
                current.version.to_string(),
            ),
            error => DatabaseError::query(query, error),
        })?;

    crate::state_history::persist(
        txn,
        crate::state_history::StateHistoryTableId::SitePrefix,
        &site_prefix.id,
        &site_prefix.status.lifecycle_state,
        site_prefix.version,
    )
    .await?;

    Ok(site_prefix)
}

pub async fn find_ids(
    db: impl DbReader<'_>,
    filter: SitePrefixSearchFilter,
) -> DatabaseResult<Vec<SitePrefixId>> {
    let SitePrefixSearchFilter {
        tenant_organization_id,
        authority,
        routing_scope,
        lifecycle_state,
        prefix_match,
    } = filter;

    let mut query = QueryBuilder::new("SELECT id FROM site_prefixes WHERE true");

    if let Some(tenant_organization_id) = tenant_organization_id {
        query.push(" AND tenant_organization_id = ");
        query.push_bind(tenant_organization_id);
    }
    if let Some(authority) = authority {
        query.push(" AND authority = ");
        query.push_bind(authority);
    }
    if let Some(routing_scope) = routing_scope {
        query.push(" AND routing_scope = ");
        query.push_bind(routing_scope);
    }
    if let Some(lifecycle_state) = lifecycle_state {
        query.push(" AND lifecycle_state = ");
        query.push_bind(lifecycle_state);
    }
    if let Some(prefix_match) = prefix_match {
        match prefix_match {
            PrefixMatch::Exact(prefix) => {
                query.push(" AND prefix = ");
                query.push_bind(prefix);
            }
            PrefixMatch::Contains(prefix) => {
                query.push(" AND prefix >>= ");
                query.push_bind(prefix);
            }
            PrefixMatch::ContainedBy(prefix) => {
                query.push(" AND prefix <<= ");
                query.push_bind(prefix);
            }
        }
    }

    query.push(" ORDER BY id");
    query
        .build_query_as()
        .fetch_all(db)
        .await
        .map_err(|error| DatabaseError::query(query.sql(), error))
}

pub async fn find_by_ids(
    db: impl DbReader<'_>,
    site_prefix_ids: &[SitePrefixId],
) -> DatabaseResult<Vec<SitePrefix>> {
    let query = "SELECT * FROM site_prefixes WHERE id = ANY($1) ORDER BY id";
    sqlx::query_as(query)
        .bind(site_prefix_ids)
        .fetch_all(db)
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::{Fails, Yields};
    use carbide_test_support::{Case, check_cases_async};
    use model::metadata::Metadata;
    use model::site_prefix::NewTenantManagedSitePrefix;
    use model::tenant::TenantOrganizationId;

    use super::*;

    fn tenant_managed(prefix: &str, tenant_organization_id: &str) -> NewTenantManagedSitePrefix {
        NewTenantManagedSitePrefix {
            id: SitePrefixId::new(),
            prefix: prefix.parse().unwrap(),
            tenant_organization_id: tenant_organization_id.parse().unwrap(),
            metadata: Metadata {
                name: prefix.to_string(),
                ..Metadata::default()
            },
        }
    }

    async fn create_tenant(
        pool: &sqlx::PgPool,
        tenant_organization_id: &str,
    ) -> Result<(), DatabaseError> {
        let mut txn = crate::Transaction::begin(pool).await?;
        crate::tenant::create_and_persist(
            tenant_organization_id.to_string(),
            Metadata {
                name: tenant_organization_id.to_string(),
                ..Metadata::default()
            },
            None,
            txn.as_pgconn(),
        )
        .await?;
        txn.commit().await?;
        Ok(())
    }

    async fn create(
        pool: &sqlx::PgPool,
        value: NewTenantManagedSitePrefix,
        quota_limit: u32,
    ) -> Result<CreateResult, DatabaseError> {
        let mut txn = crate::Transaction::begin(pool).await?;
        let result = create_tenant_managed(value, quota_limit, txn.as_pgconn()).await?;
        txn.commit().await?;
        Ok(result)
    }

    async fn history(
        pool: &sqlx::PgPool,
        site_prefix_id: SitePrefixId,
    ) -> Result<Vec<model::state_history::StateHistoryRecord>, DatabaseError> {
        let mut txn = crate::Transaction::begin(pool).await?;
        crate::state_history::for_object(
            txn.as_pgconn(),
            crate::state_history::StateHistoryTableId::SitePrefix,
            &site_prefix_id,
        )
        .await
    }

    #[crate::sqlx_test]
    async fn configured_reconciliation_preserves_identity_and_tenant_rows(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;

        let configured_prefix: IpNetwork = "10.0.0.0/8".parse()?;
        let equivalent_noncanonical_prefix: IpNetwork = "10.1.2.3/8".parse()?;
        let other_configured_prefix: IpNetwork = "192.168.0.0/16".parse()?;

        let mut txn = pool.begin().await?;
        reconcile_configured(
            &mut txn,
            &[
                configured_prefix,
                equivalent_noncanonical_prefix,
                other_configured_prefix,
            ],
        )
        .await?;
        txn.commit().await?;

        let mut txn = pool.begin().await?;
        let tenant_prefix =
            create_tenant_managed(tenant_managed("10.0.0.0/8", "tenant-a"), 8, &mut txn)
                .await?
                .site_prefix;
        txn.commit().await?;

        let configured_ids = find_ids(
            &pool,
            SitePrefixSearchFilter {
                authority: Some(SitePrefixAuthority::OperatorManaged),
                ..Default::default()
            },
        )
        .await?;
        assert_eq!(configured_ids.len(), 2);
        let configured_rows = find_by_ids(&pool, &configured_ids).await?;
        let configured_before = configured_rows
            .iter()
            .find(|site_prefix| site_prefix.config.prefix == configured_prefix)
            .unwrap()
            .clone();
        let configured_id = configured_before.id;
        assert_eq!(history(&pool, configured_id).await?.len(), 1);

        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[other_configured_prefix, configured_prefix]).await?;
        txn.commit().await?;

        let rows = find_by_ids(&pool, &[configured_id, tenant_prefix.id]).await?;
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter()
                .find(|site_prefix| site_prefix.id == configured_id)
                .unwrap(),
            &configured_before
        );
        assert_eq!(
            rows.iter()
                .find(|site_prefix| site_prefix.id == tenant_prefix.id)
                .unwrap(),
            &tenant_prefix
        );
        assert_eq!(history(&pool, configured_id).await?.len(), 1);

        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[]).await?;
        txn.commit().await?;

        let rows = find_by_ids(&pool, &[configured_id, tenant_prefix.id]).await?;
        assert!(rows.iter().any(|site_prefix| {
            site_prefix.id == configured_id
                && site_prefix.status.lifecycle_state == SitePrefixLifecycleState::Deleting
        }));
        assert!(rows.iter().any(|site_prefix| {
            site_prefix.id == tenant_prefix.id
                && site_prefix.status.lifecycle_state == SitePrefixLifecycleState::Provisioning
        }));
        assert_eq!(
            rows.iter()
                .find(|site_prefix| site_prefix.id == tenant_prefix.id)
                .unwrap(),
            &tenant_prefix
        );
        assert_eq!(history(&pool, configured_id).await?.len(), 2);

        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[configured_prefix]).await?;
        txn.commit().await?;

        let row = find_by_ids(&pool, &[configured_id]).await?.pop().unwrap();
        assert_eq!(row.id, configured_id);
        assert_eq!(row.status.lifecycle_state, SitePrefixLifecycleState::Ready);
        assert_eq!(history(&pool, configured_id).await?.len(), 3);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn duplicate_operator_managed_prefix_reports_its_authority(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let prefix: IpNetwork = "10.0.0.0/8".parse()?;

        let mut txn = pool.begin().await?;
        insert(NewSitePrefix::configured(prefix), &mut txn).await?;
        txn.commit().await?;

        let mut txn = pool.begin().await?;
        let error = insert(NewSitePrefix::configured(prefix), &mut txn)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DatabaseError::AlreadyFoundError { kind, id }
                if kind == "operator-managed site prefix" && id == prefix.to_string()
        ));
        txn.rollback().await?;

        Ok(())
    }

    #[crate::sqlx_test]
    async fn different_tenants_and_operator_can_reuse_a_prefix(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;
        create_tenant(&pool, "tenant-b").await?;

        let prefix: IpNetwork = "10.0.0.0/8".parse()?;
        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[prefix]).await?;
        let tenant_a = create_tenant_managed(tenant_managed("10.0.0.0/8", "tenant-a"), 8, &mut txn)
            .await?
            .site_prefix;
        let tenant_b = create_tenant_managed(tenant_managed("10.0.0.0/8", "tenant-b"), 8, &mut txn)
            .await?
            .site_prefix;
        txn.commit().await?;

        let rows = find_by_ids(&pool, &[tenant_a.id, tenant_b.id]).await?;
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].config.prefix, rows[1].config.prefix);
        assert_ne!(
            rows[0].config.tenant_organization_id,
            rows[1].config.tenant_organization_id
        );

        Ok(())
    }

    #[crate::sqlx_test]
    async fn configured_reconciliation_supports_existing_address_families_and_cidr_edits(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let public_prefix: IpNetwork = "203.0.113.0/24".parse()?;
        let nested_prefix: IpNetwork = "203.0.113.0/25".parse()?;
        let ipv6_prefix: IpNetwork = "2001:db8::/32".parse()?;
        let replacement_prefix: IpNetwork = "198.51.100.0/24".parse()?;

        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[public_prefix, nested_prefix, ipv6_prefix]).await?;
        txn.commit().await?;

        let original_ids = find_ids(
            &pool,
            SitePrefixSearchFilter {
                authority: Some(SitePrefixAuthority::OperatorManaged),
                ..Default::default()
            },
        )
        .await?;
        let original_rows = find_by_ids(&pool, &original_ids).await?;
        assert_eq!(original_rows.len(), 3);
        assert!(original_rows.iter().any(|row| row.config.prefix.is_ipv6()));
        let public_id = original_rows
            .iter()
            .find(|row| row.config.prefix == public_prefix)
            .unwrap()
            .id;

        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[replacement_prefix]).await?;
        txn.commit().await?;

        let all_ids = find_ids(&pool, SitePrefixSearchFilter::default()).await?;
        let all_rows = find_by_ids(&pool, &all_ids).await?;
        assert_eq!(all_rows.len(), 4);
        assert!(all_rows.iter().any(|row| {
            row.id == public_id && row.status.lifecycle_state == SitePrefixLifecycleState::Deleting
        }));
        let replacement = all_rows
            .iter()
            .find(|row| row.config.prefix == replacement_prefix)
            .unwrap();
        assert_ne!(replacement.id, public_id);
        assert_eq!(
            replacement.status.lifecycle_state,
            SitePrefixLifecycleState::Ready
        );

        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[replacement_prefix, public_prefix]).await?;
        txn.commit().await?;

        let public = find_by_ids(&pool, &[public_id]).await?.pop().unwrap();
        assert_eq!(public.id, public_id);
        assert_eq!(
            public.status.lifecycle_state,
            SitePrefixLifecycleState::Ready
        );

        Ok(())
    }

    #[crate::sqlx_test]
    async fn concurrent_configured_reconciliation_reuses_one_row(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        async fn reconcile(pool: sqlx::PgPool, prefix: IpNetwork) -> DatabaseResult<()> {
            let mut txn = crate::Transaction::begin(&pool).await?;
            reconcile_configured(txn.as_pgconn(), &[prefix]).await?;
            txn.commit().await
        }

        let prefix: IpNetwork = "10.0.0.0/8".parse()?;
        let (first, second) = tokio::join!(
            reconcile(pool.clone(), prefix),
            reconcile(pool.clone(), prefix),
        );
        first?;
        second?;

        let ids = find_ids(&pool, SitePrefixSearchFilter::default()).await?;
        assert_eq!(ids.len(), 1);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn same_tenant_overlap_is_rejected_concurrently(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;

        async fn insert(
            pool: sqlx::PgPool,
            value: NewTenantManagedSitePrefix,
        ) -> Result<SitePrefix, DatabaseError> {
            let mut txn = crate::Transaction::begin(&pool).await?;
            match create_tenant_managed(value, 8, txn.as_pgconn()).await {
                Ok(result) => {
                    txn.commit().await?;
                    Ok(result.site_prefix)
                }
                Err(error) => Err(error),
            }
        }

        let (first, second) = tokio::join!(
            insert(pool.clone(), tenant_managed("10.0.0.0/8", "tenant-a")),
            insert(pool.clone(), tenant_managed("10.1.0.0/16", "tenant-a")),
        );

        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let error = first.err().or_else(|| second.err()).unwrap();
        assert!(
            matches!(error, DatabaseError::InvalidArgument(_)),
            "unexpected overlap error: {error:?}"
        );

        Ok(())
    }

    #[crate::sqlx_test]
    async fn tenant_create_is_idempotent_and_serializes_identical_retries(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;

        let value = tenant_managed("10.0.0.0/24", "tenant-a");
        let site_prefix_id = value.id;
        let (first, second) = tokio::join!(
            create(&pool, value.clone(), 8),
            create(&pool, value.clone(), 8),
        );
        let first = first?;
        let second = second?;

        assert_eq!(first.site_prefix.id, site_prefix_id);
        assert_eq!(second.site_prefix.id, site_prefix_id);
        assert_eq!(
            [first.disposition, second.disposition]
                .into_iter()
                .filter(|result| *result == CreateDisposition::Created)
                .count(),
            1
        );
        assert_eq!(
            [first.disposition, second.disposition]
                .into_iter()
                .filter(|result| *result == CreateDisposition::Existing)
                .count(),
            1
        );
        assert_eq!(history(&pool, site_prefix_id).await?.len(), 1);

        let ids = find_ids(&pool, SitePrefixSearchFilter::default()).await?;
        assert_eq!(ids, vec![site_prefix_id]);

        let mut conflicting = value.clone();
        conflicting.prefix = "10.0.1.0/24".parse()?;
        let error = create(&pool, conflicting, 8).await.unwrap_err();
        assert!(matches!(error, DatabaseError::AlreadyFoundError { .. }));

        // A real retry is resolved before quota admission, so lowering the
        // limit cannot make an existing resource disappear behind an error.
        let retry = create(&pool, value, 0).await?;
        assert_eq!(retry.disposition, CreateDisposition::Existing);
        assert_eq!(retry.site_prefix.id, site_prefix_id);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn concurrent_distinct_creates_cannot_overrun_tenant_quota(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;

        let first_value = tenant_managed("10.0.0.0/24", "tenant-a");
        let second_value = tenant_managed("10.0.1.0/24", "tenant-a");
        let first_id = first_value.id;
        let second_id = second_value.id;
        let (first, second) = tokio::join!(
            create(&pool, first_value, 1),
            create(&pool, second_value, 1),
        );

        let (winner_id, loser_id, error) = match (first, second) {
            (Ok(first), Err(error)) => (first.site_prefix.id, second_id, error),
            (Err(error), Ok(second)) => (second.site_prefix.id, first_id, error),
            results => panic!("expected one admitted prefix and one quota error: {results:?}"),
        };
        assert!(matches!(
            error,
            DatabaseError::TenantSitePrefixQuotaExceeded { used: 1, limit: 1 }
        ));
        assert_eq!(count_tenant_managed(&pool, &"tenant-a".parse()?).await?, 1);
        assert_eq!(history(&pool, winner_id).await?.len(), 1);
        assert!(history(&pool, loser_id).await?.is_empty());

        Ok(())
    }

    #[crate::sqlx_test]
    async fn tenant_quota_counts_every_retained_lifecycle_state(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;
        create_tenant(&pool, "tenant-b").await?;

        let states = [
            SitePrefixLifecycleState::Provisioning,
            SitePrefixLifecycleState::Ready,
            SitePrefixLifecycleState::Error,
            SitePrefixLifecycleState::Deleting,
        ];
        for (index, state) in states.into_iter().enumerate() {
            let value = tenant_managed(&format!("10.0.{index}.0/24"), "tenant-a");
            let site_prefix = create(&pool, value, 4).await?.site_prefix;
            sqlx::query("UPDATE site_prefixes SET lifecycle_state = $1 WHERE id = $2")
                .bind(state)
                .bind(site_prefix.id)
                .execute(&pool)
                .await?;
        }

        assert_eq!(count_tenant_managed(&pool, &"tenant-a".parse()?).await?, 4);
        let error = create(&pool, tenant_managed("10.0.4.0/24", "tenant-a"), 4)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            DatabaseError::TenantSitePrefixQuotaExceeded { used: 4, limit: 4 }
        ));

        // Quota and overlap are tenant-scoped; tenant B can reuse tenant A's
        // first root and starts with its own count.
        create(&pool, tenant_managed("10.0.0.0/24", "tenant-b"), 4).await?;
        assert_eq!(count_tenant_managed(&pool, &"tenant-b".parse()?).await?, 1);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn metadata_update_and_retirement_preserve_immutable_identity(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;

        let create_value = tenant_managed("192.168.0.0/24", "tenant-a");
        let created = create(&pool, create_value.clone(), 8).await?.site_prefix;
        let updated_metadata = Metadata {
            name: "updated prefix".to_string(),
            description: "metadata update".to_string(),
            labels: HashMap::from([("env".to_string(), "test".to_string())]),
        };
        let update = UpdateSitePrefixMetadata {
            id: created.id,
            tenant_organization_id: "tenant-a".parse()?,
            metadata: updated_metadata.clone(),
            if_version_match: Some(created.version),
        };

        let mut txn = pool.begin().await?;
        let updated = update_tenant_metadata(&update, created.version, &mut txn).await?;
        txn.commit().await?;
        assert_eq!(updated.metadata, updated_metadata);
        assert_eq!(updated.config, created.config);
        assert_eq!(updated.status, created.status);
        assert_ne!(updated.version, created.version);
        assert_eq!(history(&pool, created.id).await?.len(), 1);

        let mut txn = pool.begin().await?;
        let stale_error = update_tenant_metadata(&update, created.version, &mut txn)
            .await
            .unwrap_err();
        assert!(matches!(
            stale_error,
            DatabaseError::ConcurrentModificationError("site prefix", _)
        ));
        txn.rollback().await?;

        let retry = create(&pool, create_value.clone(), 8).await?;
        assert_eq!(retry.disposition, CreateDisposition::Existing);
        assert_eq!(retry.site_prefix.metadata, updated_metadata);

        let retire = RetireTenantManagedSitePrefix {
            id: created.id,
            tenant_organization_id: "tenant-a".parse()?,
        };
        let mut txn = pool.begin().await?;
        let current = find_by_id_for_update(&mut txn, created.id).await?.unwrap();
        let deleting = retire_tenant_managed(&retire, &current, &mut txn).await?;
        txn.commit().await?;
        assert_eq!(
            deleting.status.lifecycle_state,
            SitePrefixLifecycleState::Deleting
        );
        assert_ne!(deleting.version, updated.version);

        let mut txn = pool.begin().await?;
        let current = find_by_id_for_update(&mut txn, created.id).await?.unwrap();
        let retry = retire_tenant_managed(&retire, &current, &mut txn).await?;
        txn.commit().await?;
        assert_eq!(retry.version, deleting.version);
        assert_eq!(count_tenant_managed(&pool, &"tenant-a".parse()?).await?, 1);

        // Retirement keeps the CIDR reserved even when the tenant has quota
        // for another resource.
        let overlap_error = create(&pool, tenant_managed("192.168.0.0/24", "tenant-a"), 8)
            .await
            .unwrap_err();
        assert!(matches!(
            overlap_error,
            DatabaseError::InvalidArgument(message)
                if message.contains("overlaps another site prefix")
        ));

        let history = history(&pool, created.id).await?;
        assert_eq!(history.len(), 2);
        let history_states = history
            .iter()
            .map(|record| serde_json::from_str(&record.state))
            .collect::<Result<Vec<SitePrefixLifecycleState>, _>>()?;
        assert_eq!(
            history_states,
            [
                SitePrefixLifecycleState::Provisioning,
                SitePrefixLifecycleState::Deleting
            ]
        );

        // Retirement keeps the row and its identity reserved. A repeated
        // create therefore returns the current Deleting representation.
        let retry = create(&pool, create_value, 0).await?;
        assert_eq!(retry.disposition, CreateDisposition::Existing);
        assert_eq!(retry.site_prefix, deleting);

        Ok(())
    }

    struct OwnershipCase {
        prefix: &'static str,
        authority: SitePrefixAuthority,
        tenant_organization_id: Option<TenantOrganizationId>,
        lifecycle_state: SitePrefixLifecycleState,
    }

    #[crate::sqlx_test]
    async fn database_enforces_authority_owner_and_lifecycle(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;

        check_cases_async(
            [
                Case {
                    scenario: "operator-managed without owner",
                    input: OwnershipCase {
                        prefix: "10.0.0.0/8",
                        authority: SitePrefixAuthority::OperatorManaged,
                        tenant_organization_id: None,
                        lifecycle_state: SitePrefixLifecycleState::Ready,
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "tenant-managed with owner",
                    input: OwnershipCase {
                        prefix: "10.0.0.0/8",
                        authority: SitePrefixAuthority::TenantManaged,
                        tenant_organization_id: Some("tenant-a".parse()?),
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "operator-managed with owner",
                    input: OwnershipCase {
                        prefix: "10.0.0.0/8",
                        authority: SitePrefixAuthority::OperatorManaged,
                        tenant_organization_id: Some("tenant-a".parse()?),
                        lifecycle_state: SitePrefixLifecycleState::Ready,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "tenant-managed without owner",
                    input: OwnershipCase {
                        prefix: "10.0.0.0/8",
                        authority: SitePrefixAuthority::TenantManaged,
                        tenant_organization_id: None,
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "operator-managed provisioning",
                    input: OwnershipCase {
                        prefix: "10.0.0.0/8",
                        authority: SitePrefixAuthority::OperatorManaged,
                        tenant_organization_id: None,
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "operator-managed public IPv4 remains valid",
                    input: OwnershipCase {
                        prefix: "203.0.113.0/24",
                        authority: SitePrefixAuthority::OperatorManaged,
                        tenant_organization_id: None,
                        lifecycle_state: SitePrefixLifecycleState::Ready,
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "operator-managed IPv6 remains valid",
                    input: OwnershipCase {
                        prefix: "2001:db8::/32",
                        authority: SitePrefixAuthority::OperatorManaged,
                        tenant_organization_id: None,
                        lifecycle_state: SitePrefixLifecycleState::Ready,
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "tenant-managed public IPv4",
                    input: OwnershipCase {
                        prefix: "203.0.113.0/24",
                        authority: SitePrefixAuthority::TenantManaged,
                        tenant_organization_id: Some("tenant-a".parse()?),
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "tenant-managed IPv6",
                    input: OwnershipCase {
                        prefix: "2001:db8::/32",
                        authority: SitePrefixAuthority::TenantManaged,
                        tenant_organization_id: Some("tenant-a".parse()?),
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "tenant-managed prefix shorter than /8",
                    input: OwnershipCase {
                        prefix: "10.0.0.0/7",
                        authority: SitePrefixAuthority::TenantManaged,
                        tenant_organization_id: Some("tenant-a".parse()?),
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "tenant-managed /32",
                    input: OwnershipCase {
                        prefix: "10.0.0.1/32",
                        authority: SitePrefixAuthority::TenantManaged,
                        tenant_organization_id: Some("tenant-a".parse()?),
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Fails,
                },
            ],
            |case| {
                let pool = pool.clone();
                async move {
                    let mut txn = pool.begin().await.map_err(drop)?;
                    let query = r#"
                        INSERT INTO site_prefixes (
                            id,
                            prefix,
                            authority,
                            tenant_organization_id,
                            routing_scope,
                            lifecycle_state,
                            name,
                            version
                        )
                        VALUES ($1, $2::cidr, $3, $4, $5, $6, 'test', $7)
                    "#;
                    sqlx::query(query)
                        .bind(SitePrefixId::new())
                        .bind(case.prefix)
                        .bind(case.authority)
                        .bind(case.tenant_organization_id)
                        .bind(SitePrefixRoutingScope::DatacenterOnly)
                        .bind(case.lifecycle_state)
                        .bind(ConfigVersion::initial())
                        .execute(&mut *txn)
                        .await
                        .map(|_| ())
                        .map_err(drop)
                }
            },
        )
        .await;

        Ok(())
    }

    #[crate::sqlx_test]
    async fn tenant_overlap_constraint_uses_public_btree_gist(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let extension_schema: String = sqlx::query_scalar(
            r#"
                SELECT namespace.nspname
                FROM pg_extension extension
                JOIN pg_namespace namespace
                    ON namespace.oid = extension.extnamespace
                WHERE extension.extname = 'btree_gist'
            "#,
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(extension_schema, "public");

        let constraint_definition: String = sqlx::query_scalar(
            r#"
                SELECT pg_get_constraintdef(oid)
                FROM pg_constraint
                WHERE conname = 'site_prefixes_tenant_prefix_excl'
            "#,
        )
        .fetch_one(&pool)
        .await?;
        assert!(constraint_definition.contains("EXCLUDE USING gist"));
        assert!(constraint_definition.contains("tenant_organization_id WITH ="));
        assert!(constraint_definition.contains("prefix inet_ops WITH &&"));
        assert!(constraint_definition.contains("authority = 'tenant_managed'"));

        Ok(())
    }
}
