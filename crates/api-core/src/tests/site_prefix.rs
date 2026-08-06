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

use std::collections::{HashMap, HashSet};

use carbide_uuid::site_prefix::SitePrefixId;
use model::metadata::Metadata;
use model::site_prefix::{
    NewTenantManagedSitePrefix, SitePrefix, SitePrefixAuthority, SitePrefixLifecycleState,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    Label, Metadata as RpcMetadata, PrefixMatchType, SitePrefixAuthority as RpcSitePrefixAuthority,
    SitePrefixCreationRequest, SitePrefixDeletionRequest,
    SitePrefixLifecycleState as RpcSitePrefixLifecycleState,
    SitePrefixRoutingScope as RpcSitePrefixRoutingScope, SitePrefixSearchFilter,
    SitePrefixStateHistoriesRequest, SitePrefixUpdateRequest, SitePrefixesByIdsRequest,
};
use tonic::{Code, Request};

use crate::tests::common::api_fixtures::tenant::create_fixture_tenant;
use crate::tests::common::api_fixtures::{
    TestEnv, TestEnvOverrides, create_test_env, create_test_env_with_overrides, get_config,
};

fn tenant_managed_site_prefix(
    prefix: &str,
    tenant_organization_id: &str,
) -> NewTenantManagedSitePrefix {
    NewTenantManagedSitePrefix {
        id: SitePrefixId::new(),
        prefix: prefix.parse().unwrap(),
        tenant_organization_id: tenant_organization_id.parse().unwrap(),
        metadata: Metadata {
            name: format!("{tenant_organization_id} prefix"),
            description: "tenant-managed test prefix".to_string(),
            labels: HashMap::from([("owner".to_string(), tenant_organization_id.to_string())]),
        },
    }
}

async fn persist_tenant_site_prefix(
    env: &TestEnv,
    value: NewTenantManagedSitePrefix,
    lifecycle_state: SitePrefixLifecycleState,
) -> SitePrefix {
    let mut txn = env.pool.begin().await.unwrap();
    let site_prefix = db::site_prefix::create_tenant_managed(
        value,
        env.config.max_site_prefixes_per_tenant,
        &mut txn,
    )
    .await
    .unwrap()
    .site_prefix;
    if lifecycle_state != SitePrefixLifecycleState::Provisioning {
        sqlx::query("UPDATE site_prefixes SET lifecycle_state = $1 WHERE id = $2")
            .bind(lifecycle_state)
            .bind(site_prefix.id)
            .execute(&mut *txn)
            .await
            .unwrap();
    }
    txn.commit().await.unwrap();
    db::site_prefix::find_by_ids(&env.pool, &[site_prefix.id])
        .await
        .unwrap()
        .pop()
        .unwrap()
}

async fn persist_configured_site_prefix(env: &TestEnv, prefix: &str) -> SitePrefix {
    // `reconcile_configured` treats this one prefix as the complete configured
    // set, so this helper must be called at most once in a test.
    let prefix = prefix.parse().unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    db::site_prefix::reconcile_configured(&mut txn, &[prefix])
        .await
        .unwrap();
    txn.commit().await.unwrap();
    let id = db::site_prefix::find_ids(
        &env.pool,
        model::site_prefix::SitePrefixSearchFilter {
            authority: Some(SitePrefixAuthority::OperatorManaged),
            prefix_match: Some(model::site_prefix::PrefixMatch::Exact(prefix)),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .pop()
    .unwrap();
    db::site_prefix::find_by_ids(&env.pool, &[id])
        .await
        .unwrap()
        .pop()
        .unwrap()
}

fn filter_ids(ids: &[SitePrefixId]) -> HashSet<SitePrefixId> {
    ids.iter().copied().collect()
}

fn rpc_metadata(name: &str) -> RpcMetadata {
    RpcMetadata {
        name: name.to_string(),
        description: "tenant-managed SitePrefix".to_string(),
        labels: vec![Label {
            key: "env".to_string(),
            value: Some("test".to_string()),
        }],
    }
}

fn creation_request(
    id: SitePrefixId,
    tenant_organization_id: &str,
    prefix: &str,
) -> SitePrefixCreationRequest {
    SitePrefixCreationRequest {
        id: Some(id),
        tenant_organization_id: tenant_organization_id.to_string(),
        prefix: prefix.to_string(),
        metadata: Some(rpc_metadata("tenant prefix")),
    }
}

#[crate::sqlx_test]
async fn empty_site_prefix_inventory_and_missing_get_are_valid(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let ids = env
        .api
        .find_site_prefix_ids(Request::new(SitePrefixSearchFilter::default()))
        .await
        .unwrap()
        .into_inner();
    assert!(ids.site_prefix_ids.is_empty());

    let site_prefixes = env
        .api
        .find_site_prefixes_by_ids(Request::new(SitePrefixesByIdsRequest {
            site_prefix_ids: vec![SitePrefixId::new()],
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(site_prefixes.site_prefixes.is_empty());

    let error = env
        .api
        .find_site_prefixes_by_ids(Request::new(SitePrefixesByIdsRequest {
            site_prefix_ids: vec![],
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.message(), "at least one ID must be provided");
}

#[crate::sqlx_test]
async fn site_prefix_filters_and_readback_return_complete_inventory(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    create_fixture_tenant(&env, "tenant-a").await.unwrap();
    create_fixture_tenant(&env, "tenant-b").await.unwrap();

    let configured = persist_configured_site_prefix(&env, "10.0.0.0/8").await;
    let tenant_a = persist_tenant_site_prefix(
        &env,
        tenant_managed_site_prefix("192.168.0.0/16", "tenant-a"),
        SitePrefixLifecycleState::Provisioning,
    )
    .await;
    let tenant_b = persist_tenant_site_prefix(
        &env,
        tenant_managed_site_prefix("172.16.0.0/12", "tenant-b"),
        SitePrefixLifecycleState::Error,
    )
    .await;

    let all_ids = filter_ids(&[configured.id, tenant_a.id, tenant_b.id]);
    let cases = [
        ("all", SitePrefixSearchFilter::default(), all_ids.clone()),
        (
            "tenant owner",
            SitePrefixSearchFilter {
                tenant_organization_id: Some("tenant-a".to_string()),
                ..Default::default()
            },
            filter_ids(&[tenant_a.id]),
        ),
        (
            "operator-managed authority",
            SitePrefixSearchFilter {
                authority: Some(RpcSitePrefixAuthority::OperatorManaged as i32),
                ..Default::default()
            },
            filter_ids(&[configured.id]),
        ),
        (
            "exact prefix",
            SitePrefixSearchFilter {
                prefix_match: Some("10.0.0.0/8".to_string()),
                prefix_match_type: Some(PrefixMatchType::PrefixExact as i32),
                ..Default::default()
            },
            filter_ids(&[configured.id]),
        ),
        (
            "routing scope",
            SitePrefixSearchFilter {
                routing_scope: Some(RpcSitePrefixRoutingScope::DatacenterOnly as i32),
                ..Default::default()
            },
            all_ids.clone(),
        ),
        (
            "error lifecycle",
            SitePrefixSearchFilter {
                lifecycle_state: Some(RpcSitePrefixLifecycleState::Error as i32),
                ..Default::default()
            },
            filter_ids(&[tenant_b.id]),
        ),
        (
            "stored prefix contains query",
            SitePrefixSearchFilter {
                prefix_match: Some("192.168.1.0/24".to_string()),
                prefix_match_type: Some(PrefixMatchType::PrefixContains as i32),
                ..Default::default()
            },
            filter_ids(&[tenant_a.id]),
        ),
        (
            "stored prefix is contained by query",
            SitePrefixSearchFilter {
                prefix_match: Some("172.16.0.0/11".to_string()),
                prefix_match_type: Some(PrefixMatchType::PrefixContainedBy as i32),
                ..Default::default()
            },
            filter_ids(&[tenant_b.id]),
        ),
    ];

    for (scenario, filter, expected) in cases {
        let result = env
            .api
            .find_site_prefix_ids(Request::new(filter))
            .await
            .unwrap_or_else(|error| panic!("{scenario}: {error}"))
            .into_inner();
        assert_eq!(filter_ids(&result.site_prefix_ids), expected, "{scenario}");
    }

    let missing_id = SitePrefixId::new();
    let response = env
        .api
        .find_site_prefixes_by_ids(Request::new(SitePrefixesByIdsRequest {
            site_prefix_ids: vec![configured.id, tenant_a.id, tenant_b.id, missing_id],
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.site_prefixes.len(), 3);

    let configured_rpc = response
        .site_prefixes
        .iter()
        .find(|site_prefix| site_prefix.id == Some(configured.id))
        .expect("configured prefix should be returned");
    assert_eq!(
        configured_rpc.config.as_ref().unwrap().prefix,
        configured.config.prefix.to_string()
    );
    assert_eq!(
        configured_rpc.status.as_ref().unwrap().authority,
        RpcSitePrefixAuthority::OperatorManaged as i32
    );
    assert_eq!(
        configured_rpc.status.as_ref().unwrap().lifecycle_state,
        RpcSitePrefixLifecycleState::Ready as i32
    );
    assert!(configured_rpc.status.as_ref().unwrap().quota.is_none());
    assert_eq!(
        configured_rpc.metadata.as_ref().unwrap().description,
        configured.metadata.description
    );
    assert!(!configured_rpc.version.is_empty());
    assert!(configured_rpc.created_at.is_some());
    assert!(configured_rpc.updated_at.is_some());

    let tenant_rpc = response
        .site_prefixes
        .iter()
        .find(|site_prefix| site_prefix.id == Some(tenant_a.id))
        .expect("tenant prefix should be returned");
    assert_eq!(
        tenant_rpc
            .config
            .as_ref()
            .unwrap()
            .tenant_organization_id
            .as_deref(),
        Some("tenant-a")
    );
    assert_eq!(
        tenant_rpc.config.as_ref().unwrap().routing_scope,
        RpcSitePrefixRoutingScope::DatacenterOnly as i32
    );
    let quota = tenant_rpc.status.as_ref().unwrap().quota.as_ref().unwrap();
    assert_eq!(
        (quota.used, quota.limit),
        (1, env.config.max_site_prefixes_per_tenant)
    );
    assert_eq!(tenant_rpc.metadata.as_ref().unwrap().labels[0].key, "owner");
}

#[crate::sqlx_test]
async fn site_prefix_get_enforces_max_find_by_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let site_prefix_ids = (0..=env.config.max_find_by_ids)
        .map(|_| SitePrefixId::new())
        .collect();

    let error = env
        .api
        .find_site_prefixes_by_ids(Request::new(SitePrefixesByIdsRequest { site_prefix_ids }))
        .await
        .expect_err("over-limit SitePrefix lookup should fail");
    assert_eq!(error.code(), Code::InvalidArgument);
}

#[crate::sqlx_test]
async fn site_prefix_create_derives_policy_and_enforces_tenant_admission(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    create_fixture_tenant(&env, "tenant-a").await.unwrap();
    create_fixture_tenant(&env, "tenant-b").await.unwrap();

    let site_prefix_id = SitePrefixId::new();
    let request = creation_request(site_prefix_id, "tenant-a", "10.0.0.0/24");
    let created = env
        .api
        .create_site_prefix(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(created.id, Some(site_prefix_id));
    let config = created.config.as_ref().unwrap();
    assert_eq!(config.prefix, "10.0.0.0/24");
    assert_eq!(config.tenant_organization_id.as_deref(), Some("tenant-a"));
    assert_eq!(
        config.routing_scope,
        RpcSitePrefixRoutingScope::DatacenterOnly as i32
    );
    let status = created.status.as_ref().unwrap();
    assert_eq!(
        status.authority,
        RpcSitePrefixAuthority::TenantManaged as i32
    );
    assert_eq!(
        status.lifecycle_state,
        RpcSitePrefixLifecycleState::Provisioning as i32
    );
    assert_eq!(status.quota.as_ref().unwrap().used, 1);
    assert_eq!(
        status.quota.as_ref().unwrap().limit,
        env.config.max_site_prefixes_per_tenant
    );

    // Immutable create identity, rather than mutable metadata, makes a retry
    // idempotent. The current persisted representation is returned and the
    // retry does not create another history entry.
    let mut retry_request = request;
    retry_request.metadata = Some(rpc_metadata("ignored retry metadata"));
    let retry = env
        .api
        .create_site_prefix(Request::new(retry_request))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(retry, created);

    let error = env
        .api
        .create_site_prefix(Request::new(creation_request(
            site_prefix_id,
            "tenant-a",
            "10.0.1.0/24",
        )))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::AlreadyExists);

    let error = env
        .api
        .create_site_prefix(Request::new(creation_request(
            SitePrefixId::new(),
            "tenant-a",
            "10.0.0.128/25",
        )))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert!(error.message().contains("overlaps"));

    // Overlap and quota are scoped to one tenant. Another tenant may own the
    // same private CIDR in this Core site.
    let tenant_b = env
        .api
        .create_site_prefix(Request::new(creation_request(
            SitePrefixId::new(),
            "tenant-b",
            "10.0.0.0/24",
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        tenant_b
            .config
            .as_ref()
            .unwrap()
            .tenant_organization_id
            .as_deref(),
        Some("tenant-b")
    );
    assert_eq!(
        tenant_b
            .status
            .as_ref()
            .unwrap()
            .quota
            .as_ref()
            .unwrap()
            .used,
        1
    );

    let error = env
        .api
        .create_site_prefix(Request::new(creation_request(
            SitePrefixId::new(),
            "missing-tenant",
            "192.168.0.0/24",
        )))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::NotFound);

    let histories = env
        .api
        .find_site_prefix_state_histories(Request::new(SitePrefixStateHistoriesRequest {
            site_prefix_ids: vec![site_prefix_id],
        }))
        .await
        .unwrap()
        .into_inner();
    let records = &histories.histories[&site_prefix_id.to_string()].records;
    assert_eq!(records.len(), 1);
    assert!(records[0].state.contains("provisioning"));
}

#[crate::sqlx_test]
async fn site_prefix_quota_retains_deleting_rows(pool: sqlx::PgPool) {
    let mut config = get_config();
    config.max_site_prefixes_per_tenant = 2;
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;
    create_fixture_tenant(&env, "tenant-a").await.unwrap();

    let first_id = SitePrefixId::new();
    let first = env
        .api
        .create_site_prefix(Request::new(creation_request(
            first_id,
            "tenant-a",
            "10.0.0.0/24",
        )))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        first.status.as_ref().unwrap().quota.as_ref().unwrap().used,
        1
    );

    let second = env
        .api
        .create_site_prefix(Request::new(creation_request(
            SitePrefixId::new(),
            "tenant-a",
            "10.0.1.0/24",
        )))
        .await
        .unwrap()
        .into_inner();
    let quota = second.status.as_ref().unwrap().quota.as_ref().unwrap();
    assert_eq!((quota.used, quota.limit), (2, 2));

    let error = env
        .api
        .create_site_prefix(Request::new(creation_request(
            SitePrefixId::new(),
            "tenant-a",
            "10.0.2.0/24",
        )))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
    assert_eq!(
        error.message(),
        "tenant SitePrefix quota reached: 2 of 2 retained SitePrefixes are in use"
    );
    assert_eq!(
        error
            .metadata()
            .get("nico-error-mitigation")
            .unwrap()
            .to_str()
            .unwrap(),
        "Review the tenant's retained SitePrefixes; complete removal of an unneeded prefix or \
         increase max_site_prefixes_per_tenant if additional roots are intended."
    );

    let deleting = env
        .api
        .delete_site_prefix(Request::new(SitePrefixDeletionRequest {
            id: Some(first_id),
            tenant_organization_id: "tenant-a".to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .site_prefix
        .unwrap();
    assert_eq!(
        deleting.status.as_ref().unwrap().lifecycle_state,
        RpcSitePrefixLifecycleState::Deleting as i32
    );
    assert_eq!(
        deleting
            .status
            .as_ref()
            .unwrap()
            .quota
            .as_ref()
            .unwrap()
            .used,
        2
    );

    let error = env
        .api
        .create_site_prefix(Request::new(creation_request(
            SitePrefixId::new(),
            "tenant-a",
            "10.0.2.0/24",
        )))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::ResourceExhausted);
}

#[crate::sqlx_test]
async fn site_prefix_update_retirement_and_history_enforce_ownership(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    create_fixture_tenant(&env, "tenant-a").await.unwrap();
    create_fixture_tenant(&env, "tenant-b").await.unwrap();

    let site_prefix_id = SitePrefixId::new();
    let created = env
        .api
        .create_site_prefix(Request::new(creation_request(
            site_prefix_id,
            "tenant-a",
            "192.168.0.0/24",
        )))
        .await
        .unwrap()
        .into_inner();
    let configured = persist_configured_site_prefix(&env, "203.0.113.0/24").await;

    let updated = env
        .api
        .update_site_prefix(Request::new(SitePrefixUpdateRequest {
            id: Some(site_prefix_id),
            tenant_organization_id: "tenant-a".to_string(),
            metadata: Some(rpc_metadata("updated prefix")),
            if_version_match: Some(created.version.clone()),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(updated.metadata.as_ref().unwrap().name, "updated prefix");
    assert_eq!(updated.config, created.config);
    assert_eq!(updated.status, created.status);
    assert_ne!(updated.version, created.version);

    let error = env
        .api
        .update_site_prefix(Request::new(SitePrefixUpdateRequest {
            id: Some(site_prefix_id),
            tenant_organization_id: "tenant-a".to_string(),
            metadata: Some(rpc_metadata("stale update")),
            if_version_match: Some(created.version.clone()),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);

    let error = env
        .api
        .update_site_prefix(Request::new(SitePrefixUpdateRequest {
            id: Some(site_prefix_id),
            tenant_organization_id: "tenant-b".to_string(),
            metadata: Some(rpc_metadata("wrong owner")),
            if_version_match: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);

    let error = env
        .api
        .update_site_prefix(Request::new(SitePrefixUpdateRequest {
            id: Some(configured.id),
            tenant_organization_id: "tenant-a".to_string(),
            metadata: Some(rpc_metadata("configured root")),
            if_version_match: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "operator-managed SitePrefixes cannot be changed through the tenant API"
    );

    let error = env
        .api
        .delete_site_prefix(Request::new(SitePrefixDeletionRequest {
            id: Some(site_prefix_id),
            tenant_organization_id: "tenant-b".to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::PermissionDenied);

    let error = env
        .api
        .delete_site_prefix(Request::new(SitePrefixDeletionRequest {
            id: Some(configured.id),
            tenant_organization_id: "tenant-a".to_string(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "operator-managed SitePrefixes cannot be changed through the tenant API"
    );

    let retire_request = SitePrefixDeletionRequest {
        id: Some(site_prefix_id),
        tenant_organization_id: "tenant-a".to_string(),
    };
    let deleting = env
        .api
        .delete_site_prefix(Request::new(retire_request.clone()))
        .await
        .unwrap()
        .into_inner()
        .site_prefix
        .unwrap();
    assert_eq!(
        deleting.status.as_ref().unwrap().lifecycle_state,
        RpcSitePrefixLifecycleState::Deleting as i32
    );
    assert_ne!(deleting.version, updated.version);
    assert_eq!(
        deleting
            .status
            .as_ref()
            .unwrap()
            .quota
            .as_ref()
            .unwrap()
            .used,
        1
    );

    let retry = env
        .api
        .delete_site_prefix(Request::new(retire_request))
        .await
        .unwrap()
        .into_inner()
        .site_prefix
        .unwrap();
    assert_eq!(retry, deleting);

    let error = env
        .api
        .update_site_prefix(Request::new(SitePrefixUpdateRequest {
            id: Some(site_prefix_id),
            tenant_organization_id: "tenant-a".to_string(),
            metadata: Some(rpc_metadata("too late")),
            if_version_match: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);

    let histories = env
        .api
        .find_site_prefix_state_histories(Request::new(SitePrefixStateHistoriesRequest {
            site_prefix_ids: vec![site_prefix_id],
        }))
        .await
        .unwrap()
        .into_inner();
    let records = &histories.histories[&site_prefix_id.to_string()].records;
    assert_eq!(records.len(), 2);
    assert!(records[0].state.contains("provisioning"));
    assert!(records[1].state.contains("deleting"));
    assert_eq!(records[0].version, created.version);
    assert_eq!(records[1].version, deleting.version);

    let error = env
        .api
        .find_site_prefix_state_histories(Request::new(SitePrefixStateHistoriesRequest {
            site_prefix_ids: vec![],
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);

    let error = env
        .api
        .find_site_prefix_state_histories(Request::new(SitePrefixStateHistoriesRequest {
            site_prefix_ids: (0..=env.config.max_find_by_ids)
                .map(|_| SitePrefixId::new())
                .collect(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
}
