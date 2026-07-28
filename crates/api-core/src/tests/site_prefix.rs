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
    NewSitePrefix, SitePrefix, SitePrefixAuthority, SitePrefixConfig, SitePrefixLifecycleState,
    SitePrefixRoutingScope, SitePrefixStatus,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    PrefixMatchType, SitePrefixAuthority as RpcSitePrefixAuthority,
    SitePrefixLifecycleState as RpcSitePrefixLifecycleState,
    SitePrefixRoutingScope as RpcSitePrefixRoutingScope, SitePrefixSearchFilter,
    SitePrefixesByIdsRequest,
};
use tonic::{Code, Request};

use crate::tests::common::api_fixtures::tenant::create_fixture_tenant;
use crate::tests::common::api_fixtures::{TestEnv, create_test_env};

fn tenant_managed_site_prefix(
    prefix: &str,
    tenant_organization_id: &str,
    lifecycle_state: SitePrefixLifecycleState,
) -> NewSitePrefix {
    NewSitePrefix {
        id: SitePrefixId::new(),
        config: SitePrefixConfig {
            prefix: prefix.parse().unwrap(),
            tenant_organization_id: Some(tenant_organization_id.parse().unwrap()),
            routing_scope: SitePrefixRoutingScope::DatacenterOnly,
        },
        metadata: Metadata {
            name: format!("{tenant_organization_id} prefix"),
            description: "tenant-managed test prefix".to_string(),
            labels: HashMap::from([("owner".to_string(), tenant_organization_id.to_string())]),
        },
        status: SitePrefixStatus {
            authority: SitePrefixAuthority::TenantManaged,
            lifecycle_state,
        },
    }
}

async fn persist_site_prefix(env: &TestEnv, value: NewSitePrefix) -> SitePrefix {
    let mut txn = env.pool.begin().await.unwrap();
    let site_prefix = db::site_prefix::persist(value, &mut txn).await.unwrap();
    txn.commit().await.unwrap();
    site_prefix
}

fn filter_ids(ids: &[SitePrefixId]) -> HashSet<SitePrefixId> {
    ids.iter().copied().collect()
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

    let mut configured = NewSitePrefix::configured("10.0.0.0/8".parse().unwrap());
    configured.metadata.description = "configured test prefix".to_string();
    let configured = persist_site_prefix(&env, configured).await;
    let tenant_a = persist_site_prefix(
        &env,
        tenant_managed_site_prefix(
            "192.168.0.0/16",
            "tenant-a",
            SitePrefixLifecycleState::Provisioning,
        ),
    )
    .await;
    let tenant_b = persist_site_prefix(
        &env,
        tenant_managed_site_prefix("172.16.0.0/12", "tenant-b", SitePrefixLifecycleState::Error),
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
            "configured authority",
            SitePrefixSearchFilter {
                authority: Some(RpcSitePrefixAuthority::Configured as i32),
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
        RpcSitePrefixAuthority::Configured as i32
    );
    assert_eq!(
        configured_rpc.status.as_ref().unwrap().lifecycle_state,
        RpcSitePrefixLifecycleState::Ready as i32
    );
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
