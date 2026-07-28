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
    NewSitePrefix, PrefixMatch, SitePrefix, SitePrefixAuthority, SitePrefixLifecycleState,
    SitePrefixSearchFilter,
};
use sqlx::{PgConnection, QueryBuilder};

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

const TENANT_PREFIX_EXCLUSION: &str = "site_prefixes_tenant_prefix_excl";
const CONFIGURED_PREFIX_UNIQUE: &str = "site_prefixes_configured_prefix_key";
const CONFIGURED_RECONCILE_LOCK: &str = "site_prefixes:configured_reconcile";

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

/// Persists a site prefix after checking model-level invariants.
pub async fn persist(value: NewSitePrefix, txn: &mut PgConnection) -> DatabaseResult<SitePrefix> {
    value.validate()?;

    if let Some(tenant_organization_id) = &value.config.tenant_organization_id {
        lock_tenant_prefix_writes(tenant_organization_id.as_str(), txn).await?;
    }

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

    sqlx::query_as(query)
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
        .fetch_one(txn)
        .await
        .map_err(|error| {
            let constraint = match &error {
                sqlx::Error::Database(database_error) => database_error.constraint(),
                _ => None,
            };

            match constraint {
                Some(TENANT_PREFIX_EXCLUSION) => DatabaseError::InvalidArgument(format!(
                    "site prefix {} overlaps another site prefix owned by the same tenant",
                    value.config.prefix
                )),
                Some(CONFIGURED_PREFIX_UNIQUE) => DatabaseError::AlreadyFoundError {
                    kind: "configured site prefix",
                    id: value.config.prefix.to_string(),
                },
                _ => DatabaseError::query(query, error),
            }
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

/// Reconciles the complete set of configuration-owned site prefixes.
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
        .bind(SitePrefixAuthority::Configured)
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
                    .bind(current.version.increment())
                    .bind(current.id)
                    .execute(&mut *txn)
                    .await
                    .map_err(|error| DatabaseError::query(query, error))?;
            }
            None => {
                persist(desired, &mut *txn).await?;
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
        sqlx::query(query)
            .bind(SitePrefixLifecycleState::Deleting)
            .bind(current.version.increment())
            .bind(current.id)
            .execute(&mut *txn)
            .await
            .map_err(|error| DatabaseError::query(query, error))?;
    }

    Ok(())
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
    use model::site_prefix::{SitePrefixConfig, SitePrefixRoutingScope, SitePrefixStatus};
    use model::tenant::TenantOrganizationId;

    use super::*;

    fn tenant_managed(prefix: &str, tenant_organization_id: &str) -> NewSitePrefix {
        NewSitePrefix {
            id: SitePrefixId::new(),
            config: SitePrefixConfig {
                prefix: prefix.parse().unwrap(),
                tenant_organization_id: Some(tenant_organization_id.parse().unwrap()),
                routing_scope: SitePrefixRoutingScope::DatacenterOnly,
            },
            metadata: Metadata {
                name: prefix.to_string(),
                ..Metadata::default()
            },
            status: SitePrefixStatus {
                authority: SitePrefixAuthority::TenantManaged,
                lifecycle_state: SitePrefixLifecycleState::Provisioning,
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
        let tenant_prefix = persist(tenant_managed("10.0.0.0/8", "tenant-a"), &mut txn).await?;
        txn.commit().await?;

        let configured_ids = find_ids(
            &pool,
            SitePrefixSearchFilter {
                authority: Some(SitePrefixAuthority::Configured),
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

        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[configured_prefix]).await?;
        txn.commit().await?;

        let row = find_by_ids(&pool, &[configured_id]).await?.pop().unwrap();
        assert_eq!(row.id, configured_id);
        assert_eq!(row.status.lifecycle_state, SitePrefixLifecycleState::Ready);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn different_tenants_and_config_can_reuse_a_prefix(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        create_tenant(&pool, "tenant-a").await?;
        create_tenant(&pool, "tenant-b").await?;

        let prefix: IpNetwork = "10.0.0.0/8".parse()?;
        let mut txn = pool.begin().await?;
        reconcile_configured(&mut txn, &[prefix]).await?;
        let tenant_a = persist(tenant_managed("10.0.0.0/8", "tenant-a"), &mut txn).await?;
        let tenant_b = persist(tenant_managed("10.0.0.0/8", "tenant-b"), &mut txn).await?;
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
                authority: Some(SitePrefixAuthority::Configured),
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
            value: NewSitePrefix,
        ) -> Result<SitePrefix, DatabaseError> {
            let mut txn = crate::Transaction::begin(&pool).await?;
            match persist(value, txn.as_pgconn()).await {
                Ok(site_prefix) => {
                    txn.commit().await?;
                    Ok(site_prefix)
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

    struct OwnershipCase {
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
                    scenario: "configured without owner",
                    input: OwnershipCase {
                        authority: SitePrefixAuthority::Configured,
                        tenant_organization_id: None,
                        lifecycle_state: SitePrefixLifecycleState::Ready,
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "tenant-managed with owner",
                    input: OwnershipCase {
                        authority: SitePrefixAuthority::TenantManaged,
                        tenant_organization_id: Some("tenant-a".parse()?),
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "configured with owner",
                    input: OwnershipCase {
                        authority: SitePrefixAuthority::Configured,
                        tenant_organization_id: Some("tenant-a".parse()?),
                        lifecycle_state: SitePrefixLifecycleState::Ready,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "tenant-managed without owner",
                    input: OwnershipCase {
                        authority: SitePrefixAuthority::TenantManaged,
                        tenant_organization_id: None,
                        lifecycle_state: SitePrefixLifecycleState::Provisioning,
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "configured provisioning",
                    input: OwnershipCase {
                        authority: SitePrefixAuthority::Configured,
                        tenant_organization_id: None,
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
                        VALUES ($1, '10.0.0.0/8', $2, $3, $4, $5, 'test', $6)
                    "#;
                    sqlx::query(query)
                        .bind(SitePrefixId::new())
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
