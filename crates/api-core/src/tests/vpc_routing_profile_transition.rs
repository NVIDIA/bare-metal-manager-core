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
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use carbide_uuid::vpc_routing_profile_transition::VpcRoutingProfileTransitionId;
use config_version::ConfigVersion;
use model::resource_pool::OwnerType;
use model::site_prefix::{SitePrefixAuthority, SitePrefixLifecycleState, SitePrefixRoutingScope};
use rpc::forge::forge_server::Forge;
use tonic::{Code, Request, Status};

use super::common::api_fixtures::{TestEnv, TestEnvOverrides, create_test_env_with_overrides};
use crate::cfg::file::{FnnConfig, FnnRoutingProfileConfig, VpcIsolationBehaviorType};

const TENANT_ORGANIZATION_ID: &str = "routing-profile-transition-test-tenant";
const INTERNAL_PROFILE: &str = "INTERNAL";
const EXTERNAL_PROFILE: &str = "EXTERNAL";
const OVERLAP_PROFILE: &str = "OVERLAP";

fn metadata(name: &str) -> rpc::forge::Metadata {
    rpc::forge::Metadata {
        name: name.to_string(),
        description: String::new(),
        labels: Vec::new(),
    }
}

fn overrides(leak_default_route_from_underlay: bool) -> rpc::forge::VpcRoutingProfileOverrides {
    rpc::forge::VpcRoutingProfileOverrides {
        leak_default_route_from_underlay: Some(leak_default_route_from_underlay),
        ..Default::default()
    }
}

async fn create_transition_env(pool: sqlx::PgPool) -> TestEnv {
    let env =
        create_test_env_with_overrides(pool, TestEnvOverrides::default().with_fnn_config(None))
            .await;
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORGANIZATION_ID.to_string(),
            routing_profile_type: Some(INTERNAL_PROFILE.to_string()),
            metadata: Some(metadata("routing transition tenant")),
        }))
        .await
        .expect("create INTERNAL fixture tenant");
    env
}

fn overlap_transition_env_overrides() -> TestEnvOverrides {
    let mut config = crate::test_support::default_config::get();
    config.tenant_prefix_overlap_enabled = true;
    config.vpc_isolation_behavior = VpcIsolationBehaviorType::MutualIsolation;

    let mut overrides = TestEnvOverrides::with_config(config).with_fnn_config(Some(FnnConfig {
        admin_vpc: None,
        common_internal_route_target: None,
        additional_route_target_imports: vec![],
        routing_profiles: HashMap::from([
            (
                OVERLAP_PROFILE.to_string(),
                FnnRoutingProfileConfig {
                    tenant_prefix_overlap_eligible: true,
                    internal: Some(true),
                    access_tier: Some(0),
                    ..Default::default()
                },
            ),
            (
                EXTERNAL_PROFILE.to_string(),
                FnnRoutingProfileConfig {
                    internal: Some(false),
                    access_tier: Some(1),
                    ..Default::default()
                },
            ),
        ]),
        use_vpc_vrf_loopback: false,
    }));
    overrides.create_network_segments = Some(false);
    overrides.site_prefixes = Some(vec!["10.0.0.0/8".parse().expect("valid site prefix")]);
    overrides
}

async fn create_profile_tenant(env: &TestEnv, organization_id: &str) {
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: organization_id.to_string(),
            routing_profile_type: Some(OVERLAP_PROFILE.to_string()),
            metadata: Some(metadata(organization_id)),
        }))
        .await
        .expect("create overlap-eligible fixture tenant");
}

async fn create_profile_vpc(env: &TestEnv, organization_id: &str, name: &str) -> rpc::forge::Vpc {
    env.api
        .create_vpc(Request::new(rpc::forge::VpcCreationRequest {
            tenant_organization_id: organization_id.to_string(),
            network_virtualization_type: Some(rpc::forge::VpcVirtualizationType::Fnn as i32),
            metadata: Some(metadata(name)),
            routing_profile_type: Some(OVERLAP_PROFILE.to_string()),
            ..Default::default()
        }))
        .await
        .expect("create overlap-eligible fixture VPC")
        .into_inner()
}

async fn seed_tenant_site_prefix(
    env: &TestEnv,
    organization_id: &str,
    prefix: &str,
) -> SitePrefixId {
    let id = SitePrefixId::new();
    sqlx::query(
        r#"
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
            VALUES ($1, $2::cidr, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(id)
    .bind(prefix)
    .bind(SitePrefixAuthority::TenantManaged)
    .bind(organization_id)
    .bind(SitePrefixRoutingScope::DatacenterOnly)
    .bind(SitePrefixLifecycleState::Ready)
    .bind(format!("tenant SitePrefix {prefix}"))
    .bind(ConfigVersion::initial())
    .execute(&env.pool)
    .await
    .expect("persist tenant-managed SitePrefix fixture");
    id
}

async fn seed_exact_cross_tenant_overlap(
    env: &TestEnv,
    first: (VpcId, SitePrefixId),
    second: (VpcId, SitePrefixId),
    prefix: &str,
) {
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("begin overlap fixture transaction");

    // Exact cross-tenant reuse is still blocked by the legacy database
    // exclusion. Reconstruct the future allowed state in this isolated test
    // database, as the prefix-allocation tests do, to protect transition
    // admission before that schema cutover lands.
    sqlx::query(
        "ALTER TABLE network_vpc_prefixes \
         DROP CONSTRAINT IF EXISTS network_vpc_prefixes_globally_unique",
    )
    .execute(&mut *txn)
    .await
    .expect("drop legacy prefix exclusion in isolated test database");

    for (vpc_id, site_prefix_id) in [first, second] {
        sqlx::query(
            "INSERT INTO network_vpc_prefixes (id, prefix, name, vpc_id, site_prefix_id) \
             VALUES ($1, $2::cidr, $3, $4, $5)",
        )
        .bind(VpcPrefixId::new())
        .bind(prefix)
        .bind(format!("overlap fixture {prefix}"))
        .bind(vpc_id)
        .bind(site_prefix_id)
        .execute(&mut *txn)
        .await
        .expect("persist exact cross-tenant VPC-prefix fixture");
    }

    txn.commit()
        .await
        .expect("commit overlap fixture transaction");
}

async fn create_internal_vpc(
    env: &TestEnv,
    name: &str,
    requested_vni: Option<u32>,
    routing_profile_overrides: Option<rpc::forge::VpcRoutingProfileOverrides>,
) -> rpc::forge::Vpc {
    env.api
        .create_vpc(Request::new(rpc::forge::VpcCreationRequest {
            tenant_organization_id: TENANT_ORGANIZATION_ID.to_string(),
            network_virtualization_type: Some(rpc::forge::VpcVirtualizationType::Fnn as i32),
            metadata: Some(metadata(name)),
            vni: requested_vni,
            routing_profile_type: Some(INTERNAL_PROFILE.to_string()),
            routing_profile_overrides,
            ..Default::default()
        }))
        .await
        .expect("create INTERNAL fixture VPC")
        .into_inner()
}

fn begin_request(
    id: VpcRoutingProfileTransitionId,
    vpc_id: VpcId,
    vpc_version: &str,
    target_vni: Option<u32>,
    target_overrides: Option<rpc::forge::VpcRoutingProfileOverrides>,
    reason: &str,
    adopt_existing_target_allocation: bool,
) -> rpc::forge::BeginVpcRoutingProfileTransitionRequest {
    rpc::forge::BeginVpcRoutingProfileTransitionRequest {
        id: Some(id),
        vpc_id: Some(vpc_id),
        if_vpc_version_match: vpc_version.to_string(),
        target_routing_profile_type: EXTERNAL_PROFILE.to_string(),
        target_vni,
        target_routing_profile_overrides: target_overrides,
        reason: reason.to_string(),
        adopt_existing_target_allocation,
    }
}

fn transition_state(
    transition: &rpc::forge::VpcRoutingProfileTransition,
) -> rpc::forge::VpcRoutingProfileTransitionState {
    rpc::forge::VpcRoutingProfileTransitionState::try_from(transition.state)
        .expect("known transition state")
}

fn assert_vpc_endpoint(
    vpc: &rpc::forge::Vpc,
    profile: &str,
    requested_vni: Option<u32>,
    actual_vni: u32,
    expected_overrides: Option<&rpc::forge::VpcRoutingProfileOverrides>,
) {
    let config = vpc.config.as_ref().expect("VPC config");
    assert_eq!(config.routing_profile_type.as_deref(), Some(profile));
    assert_eq!(config.vni, requested_vni);
    assert_eq!(
        config.routing_profile_overrides.as_ref(),
        expected_overrides
    );
    assert_eq!(
        vpc.status.as_ref().and_then(|status| status.vni),
        Some(actual_vni)
    );
}

async fn owner_allocation(env: &TestEnv, internal: bool, owner_id: &str) -> Option<i32> {
    let pool = if internal {
        &env.common_pools.ethernet.pool_vpc_vni
    } else {
        &env.common_pools.ethernet.pool_external_vpc_vni
    };
    let mut txn = env.pool.begin().await.expect("begin pool read transaction");
    let allocation =
        db::resource_pool::find_owned_allocation(pool, &mut txn, OwnerType::Vpc, owner_id)
            .await
            .expect("read owner allocation");
    txn.rollback()
        .await
        .expect("rollback pool read transaction");
    allocation
}

async fn assert_both_leases(env: &TestEnv, owner_id: &str, internal_vni: u32, external_vni: u32) {
    assert_eq!(
        owner_allocation(env, true, owner_id).await,
        Some(internal_vni as i32)
    );
    assert_eq!(
        owner_allocation(env, false, owner_id).await,
        Some(external_vni as i32)
    );
}

async fn reserve_external_vni(env: &TestEnv, owner_id: &str, vni: i32) {
    let mut txn = env.pool.begin().await.expect("begin exact allocation");
    db::resource_pool::allocate_exact(
        &env.common_pools.ethernet.pool_external_vpc_vni,
        &mut txn,
        OwnerType::Vpc,
        owner_id,
        vni,
    )
    .await
    .expect("reserve fixture external VNI");
    txn.commit().await.expect("commit exact allocation");
}

async fn current_vpc(env: &TestEnv, vpc_id: VpcId) -> rpc::forge::Vpc {
    env.api
        .find_vpcs_by_ids(Request::new(rpc::forge::VpcsByIdsRequest {
            vpc_ids: vec![vpc_id],
        }))
        .await
        .expect("find fixture VPC")
        .into_inner()
        .vpcs
        .pop()
        .expect("fixture VPC exists")
}

async fn transition_history(
    env: &TestEnv,
    vpc_id: VpcId,
    active_only: Option<bool>,
) -> Vec<rpc::forge::VpcRoutingProfileTransition> {
    env.api
        .find_vpc_routing_profile_transitions(Request::new(
            rpc::forge::VpcRoutingProfileTransitionSearchFilter {
                id: None,
                vpc_id: Some(vpc_id),
                active_only,
            },
        ))
        .await
        .expect("find routing-profile transitions")
        .into_inner()
        .transitions
}

fn expect_status<T>(result: Result<T, Status>, code: Code) -> Status {
    match result {
        Ok(_) => panic!("request unexpectedly succeeded"),
        Err(error) => {
            assert_eq!(error.code(), code, "unexpected status: {error}");
            error
        }
    }
}

#[crate::sqlx_test]
async fn exact_cutover_is_idempotent_and_round_trips_through_rollback_and_recutover(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_transition_env(pool).await;
    let source_overrides = overrides(false);
    let target_overrides = overrides(true);
    let created = create_internal_vpc(
        &env,
        "exact transition VPC",
        Some(60_001),
        Some(source_overrides.clone()),
    )
    .await;
    let vpc_id = created.id.expect("created VPC ID");
    let owner_id = vpc_id.to_string();
    assert_vpc_endpoint(
        &created,
        INTERNAL_PROFILE,
        Some(60_001),
        60_001,
        Some(&source_overrides),
    );

    let transition_id = VpcRoutingProfileTransitionId::new();
    let request = begin_request(
        transition_id,
        vpc_id,
        &created.version,
        Some(50_001),
        Some(target_overrides.clone()),
        "exact transition lifecycle",
        false,
    );
    let begun = env
        .api
        .begin_vpc_routing_profile_transition(Request::new(request.clone()))
        .await?
        .into_inner();
    let begun_transition = begun.transition.as_ref().expect("begin transition");
    let cutover_vpc = begun.vpc.as_ref().expect("cutover VPC");
    assert_eq!(
        transition_state(begun_transition),
        rpc::forge::VpcRoutingProfileTransitionState::CutoverPendingFinalize
    );
    assert_eq!(begun_transition.source_vni_pool, "vpc-vni");
    assert_eq!(begun_transition.target_vni_pool, "external-vpc-vni");
    assert_eq!(begun_transition.source_vni, 60_001);
    assert_eq!(begun_transition.target_vni, 50_001);
    assert_eq!(begun_transition.source_requested_vni, Some(60_001));
    assert_eq!(begun_transition.target_requested_vni, Some(50_001));
    assert_vpc_endpoint(
        cutover_vpc,
        EXTERNAL_PROFILE,
        Some(50_001),
        50_001,
        Some(&target_overrides),
    );
    assert_both_leases(&env, &owner_id, 60_001, 50_001).await;

    let begun_transition_version = begun_transition.version.clone();
    let cutover_vpc_version = cutover_vpc.version.clone();
    let replayed = env
        .api
        .begin_vpc_routing_profile_transition(Request::new(request.clone()))
        .await?
        .into_inner();
    assert_eq!(
        replayed
            .transition
            .as_ref()
            .expect("replayed transition")
            .version,
        begun_transition_version
    );
    assert_eq!(
        replayed.vpc.as_ref().expect("replayed VPC").version,
        cutover_vpc_version
    );

    let mut different_intent = request;
    different_intent.reason = "different intent".to_string();
    expect_status(
        env.api
            .begin_vpc_routing_profile_transition(Request::new(different_intent))
            .await,
        Code::AlreadyExists,
    );
    assert_both_leases(&env, &owner_id, 60_001, 50_001).await;

    let rolled_back = env
        .api
        .rollback_vpc_routing_profile_transition(Request::new(
            rpc::forge::RollbackVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: begun_transition_version.clone(),
            },
        ))
        .await?
        .into_inner();
    let rollback_transition = rolled_back
        .transition
        .as_ref()
        .expect("rollback transition");
    assert_eq!(
        transition_state(rollback_transition),
        rpc::forge::VpcRoutingProfileTransitionState::RollbackPendingFinalize
    );
    assert_vpc_endpoint(
        rolled_back.vpc.as_ref().expect("rollback VPC"),
        INTERNAL_PROFILE,
        Some(60_001),
        60_001,
        Some(&source_overrides),
    );
    assert_both_leases(&env, &owner_id, 60_001, 50_001).await;

    let rollback_replay = env
        .api
        .rollback_vpc_routing_profile_transition(Request::new(
            rpc::forge::RollbackVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: begun_transition_version.clone(),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(
        rollback_replay
            .transition
            .as_ref()
            .expect("rollback replay transition")
            .version,
        rollback_transition.version
    );
    assert_both_leases(&env, &owner_id, 60_001, 50_001).await;

    expect_status(
        env.api
            .recutover_vpc_routing_profile_transition(Request::new(
                rpc::forge::RecutoverVpcRoutingProfileTransitionRequest {
                    id: Some(transition_id),
                    if_version_match: begun_transition_version,
                },
            ))
            .await,
        Code::FailedPrecondition,
    );
    assert_vpc_endpoint(
        &current_vpc(&env, vpc_id).await,
        INTERNAL_PROFILE,
        Some(60_001),
        60_001,
        Some(&source_overrides),
    );

    let recutover = env
        .api
        .recutover_vpc_routing_profile_transition(Request::new(
            rpc::forge::RecutoverVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: rollback_transition.version.clone(),
            },
        ))
        .await?
        .into_inner();
    let recutover_transition = recutover.transition.as_ref().expect("recutover transition");
    assert_eq!(
        transition_state(recutover_transition),
        rpc::forge::VpcRoutingProfileTransitionState::CutoverPendingFinalize
    );
    assert_vpc_endpoint(
        recutover.vpc.as_ref().expect("recutover VPC"),
        EXTERNAL_PROFILE,
        Some(50_001),
        50_001,
        Some(&target_overrides),
    );
    assert_both_leases(&env, &owner_id, 60_001, 50_001).await;

    let recutover_replay = env
        .api
        .recutover_vpc_routing_profile_transition(Request::new(
            rpc::forge::RecutoverVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: rollback_transition.version.clone(),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(
        recutover_replay
            .transition
            .as_ref()
            .expect("recutover replay transition")
            .version,
        recutover_transition.version
    );
    assert_both_leases(&env, &owner_id, 60_001, 50_001).await;

    expect_status(
        env.api
            .finalize_vpc_routing_profile_transition(Request::new(
                rpc::forge::FinalizeVpcRoutingProfileTransitionRequest {
                    id: Some(transition_id),
                    if_version_match: recutover_transition.version.clone(),
                    convergence_confirmed: false,
                },
            ))
            .await,
        Code::InvalidArgument,
    );
    assert_both_leases(&env, &owner_id, 60_001, 50_001).await;

    let finalized = env
        .api
        .finalize_vpc_routing_profile_transition(Request::new(
            rpc::forge::FinalizeVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: recutover_transition.version.clone(),
                convergence_confirmed: true,
            },
        ))
        .await?
        .into_inner();
    let finalized_transition = finalized.transition.as_ref().expect("finalized transition");
    assert_eq!(
        transition_state(finalized_transition),
        rpc::forge::VpcRoutingProfileTransitionState::Finalized
    );
    assert!(finalized_transition.completed.is_some());
    assert_vpc_endpoint(
        finalized.vpc.as_ref().expect("finalized VPC"),
        EXTERNAL_PROFILE,
        Some(50_001),
        50_001,
        Some(&target_overrides),
    );
    assert_eq!(owner_allocation(&env, true, &owner_id).await, None);
    assert_eq!(owner_allocation(&env, false, &owner_id).await, Some(50_001));

    let finalize_replay = env
        .api
        .finalize_vpc_routing_profile_transition(Request::new(
            rpc::forge::FinalizeVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: recutover_transition.version.clone(),
                convergence_confirmed: true,
            },
        ))
        .await?
        .into_inner();
    assert_eq!(
        finalize_replay
            .transition
            .as_ref()
            .expect("finalize replay transition")
            .version,
        finalized_transition.version
    );
    assert_eq!(owner_allocation(&env, true, &owner_id).await, None);
    assert_eq!(owner_allocation(&env, false, &owner_id).await, Some(50_001));
    assert!(
        transition_history(&env, vpc_id, Some(true))
            .await
            .is_empty()
    );
    assert_eq!(transition_history(&env, vpc_id, None).await.len(), 1);

    env.api
        .delete_vpc(Request::new(rpc::forge::VpcDeletionRequest {
            id: Some(vpc_id),
        }))
        .await?;
    // DeleteVpc soft-deletes VPCs. Exercise the FK's physical-delete behavior
    // explicitly, since ON DELETE CASCADE does not run on that soft delete.
    assert_eq!(transition_history(&env, vpc_id, None).await.len(), 1);
    let deleted = sqlx::query("DELETE FROM vpcs WHERE id = $1")
        .bind(vpc_id)
        .execute(&env.pool)
        .await?;
    assert_eq!(deleted.rows_affected(), 1);
    assert!(transition_history(&env, vpc_id, None).await.is_empty());

    Ok(())
}

#[crate::sqlx_test]
async fn external_to_internal_cutover_retains_both_leases_then_releases_external_source(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_transition_env(pool).await;
    let source_overrides = overrides(true);
    let target_overrides = overrides(false);
    let created = env
        .api
        .create_vpc(Request::new(rpc::forge::VpcCreationRequest {
            tenant_organization_id: TENANT_ORGANIZATION_ID.to_string(),
            network_virtualization_type: Some(rpc::forge::VpcVirtualizationType::Fnn as i32),
            metadata: Some(metadata("reverse transition VPC")),
            routing_profile_type: Some(EXTERNAL_PROFILE.to_string()),
            routing_profile_overrides: Some(source_overrides.clone()),
            ..Default::default()
        }))
        .await?
        .into_inner();
    let vpc_id = created.id.expect("created VPC ID");
    let owner_id = vpc_id.to_string();
    let external_source_vni = created
        .status
        .as_ref()
        .and_then(|status| status.vni)
        .expect("auto-allocated external source VNI");
    assert_vpc_endpoint(
        &created,
        EXTERNAL_PROFILE,
        None,
        external_source_vni,
        Some(&source_overrides),
    );
    assert_eq!(owner_allocation(&env, true, &owner_id).await, None);
    assert_eq!(
        owner_allocation(&env, false, &owner_id).await,
        Some(external_source_vni as i32)
    );

    let transition_id = VpcRoutingProfileTransitionId::new();
    let begun = env
        .api
        .begin_vpc_routing_profile_transition(Request::new(
            rpc::forge::BeginVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                vpc_id: Some(vpc_id),
                if_vpc_version_match: created.version.clone(),
                target_routing_profile_type: INTERNAL_PROFILE.to_string(),
                target_vni: Some(60_001),
                target_routing_profile_overrides: Some(target_overrides.clone()),
                reason: "reverse-direction exact cutover".to_string(),
                adopt_existing_target_allocation: false,
            },
        ))
        .await?
        .into_inner();
    let transition = begun.transition.as_ref().expect("begin transition");
    assert_eq!(
        transition_state(transition),
        rpc::forge::VpcRoutingProfileTransitionState::CutoverPendingFinalize
    );
    assert_eq!(transition.source_vni_pool, "external-vpc-vni");
    assert_eq!(transition.target_vni_pool, "vpc-vni");
    assert_eq!(transition.source_vni, external_source_vni);
    assert_eq!(transition.source_requested_vni, None);
    assert_eq!(transition.target_vni, 60_001);
    assert_eq!(transition.target_requested_vni, Some(60_001));
    assert_vpc_endpoint(
        begun.vpc.as_ref().expect("cutover VPC"),
        INTERNAL_PROFILE,
        Some(60_001),
        60_001,
        Some(&target_overrides),
    );
    assert_both_leases(&env, &owner_id, 60_001, external_source_vni).await;

    let finalized = env
        .api
        .finalize_vpc_routing_profile_transition(Request::new(
            rpc::forge::FinalizeVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: transition.version.clone(),
                convergence_confirmed: true,
            },
        ))
        .await?
        .into_inner();
    assert_eq!(
        transition_state(finalized.transition.as_ref().expect("final transition")),
        rpc::forge::VpcRoutingProfileTransitionState::Finalized
    );
    assert_vpc_endpoint(
        finalized.vpc.as_ref().expect("final VPC"),
        INTERNAL_PROFILE,
        Some(60_001),
        60_001,
        Some(&target_overrides),
    );
    assert_eq!(owner_allocation(&env, true, &owner_id).await, Some(60_001));
    assert_eq!(owner_allocation(&env, false, &owner_id).await, None);

    Ok(())
}

#[crate::sqlx_test]
async fn automatic_cutover_blocks_vpc_mutations_and_finalize_rollback_releases_only_target(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_transition_env(pool).await;
    let created = create_internal_vpc(&env, "automatic transition VPC", None, None).await;
    let vpc_id = created.id.expect("created VPC ID");
    let owner_id = vpc_id.to_string();
    let source_vni = created
        .status
        .as_ref()
        .and_then(|status| status.vni)
        .expect("auto-allocated source VNI");
    assert_vpc_endpoint(&created, INTERNAL_PROFILE, None, source_vni, None);

    let transition_id = VpcRoutingProfileTransitionId::new();
    let begun = env
        .api
        .begin_vpc_routing_profile_transition(Request::new(begin_request(
            transition_id,
            vpc_id,
            &created.version,
            None,
            None,
            "automatic rollback lifecycle",
            false,
        )))
        .await?
        .into_inner();
    let begun_transition = begun.transition.as_ref().expect("begin transition");
    let target_vni = begun_transition.target_vni;
    assert_eq!(begun_transition.source_requested_vni, None);
    assert_eq!(begun_transition.target_requested_vni, None);
    let cutover_vpc = begun.vpc.as_ref().expect("cutover VPC");
    assert_vpc_endpoint(cutover_vpc, EXTERNAL_PROFILE, None, target_vni, None);
    assert_both_leases(&env, &owner_id, source_vni, target_vni).await;

    let update_error = expect_status(
        env.api
            .update_vpc(Request::new(rpc::forge::VpcUpdateRequest {
                id: Some(vpc_id),
                if_version_match: Some(cutover_vpc.version.clone()),
                metadata: Some(metadata("blocked update")),
                ..Default::default()
            }))
            .await,
        Code::FailedPrecondition,
    );
    assert!(update_error.message().contains("transition"));
    let delete_error = expect_status(
        env.api
            .delete_vpc(Request::new(rpc::forge::VpcDeletionRequest {
                id: Some(vpc_id),
            }))
            .await,
        Code::FailedPrecondition,
    );
    assert!(delete_error.message().contains("transition"));
    let virtualization_error = expect_status(
        env.api
            .update_vpc_virtualization(Request::new(rpc::forge::VpcUpdateVirtualizationRequest {
                id: Some(vpc_id),
                if_version_match: Some(cutover_vpc.version.clone()),
                network_virtualization_type: Some(rpc::forge::VpcVirtualizationType::Fnn as i32),
            }))
            .await,
        Code::FailedPrecondition,
    );
    assert!(virtualization_error.message().contains("transition"));
    assert_eq!(current_vpc(&env, vpc_id).await.version, cutover_vpc.version);
    assert_both_leases(&env, &owner_id, source_vni, target_vni).await;

    let rolled_back = env
        .api
        .rollback_vpc_routing_profile_transition(Request::new(
            rpc::forge::RollbackVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: begun_transition.version.clone(),
            },
        ))
        .await?
        .into_inner();
    let rollback_transition = rolled_back
        .transition
        .as_ref()
        .expect("rollback transition");
    assert_vpc_endpoint(
        rolled_back.vpc.as_ref().expect("rollback VPC"),
        INTERNAL_PROFILE,
        None,
        source_vni,
        None,
    );
    assert_both_leases(&env, &owner_id, source_vni, target_vni).await;

    let finalized = env
        .api
        .finalize_vpc_routing_profile_transition(Request::new(
            rpc::forge::FinalizeVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: rollback_transition.version.clone(),
                convergence_confirmed: true,
            },
        ))
        .await?
        .into_inner();
    let finalized_transition = finalized
        .transition
        .as_ref()
        .expect("finalized rollback transition");
    assert_eq!(
        transition_state(finalized_transition),
        rpc::forge::VpcRoutingProfileTransitionState::RolledBack
    );
    assert_vpc_endpoint(
        finalized.vpc.as_ref().expect("rolled-back VPC"),
        INTERNAL_PROFILE,
        None,
        source_vni,
        None,
    );
    assert_eq!(
        owner_allocation(&env, true, &owner_id).await,
        Some(source_vni as i32)
    );
    assert_eq!(owner_allocation(&env, false, &owner_id).await, None);

    Ok(())
}

#[crate::sqlx_test]
async fn failed_exact_target_allocations_leave_vpc_leases_and_history_unchanged(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_transition_env(pool).await;
    let created = create_internal_vpc(&env, "failed transition VPC", Some(60_002), None).await;
    let vpc_id = created.id.expect("created VPC ID");
    let owner_id = vpc_id.to_string();

    let missing_id = VpcRoutingProfileTransitionId::new();
    expect_status(
        env.api
            .begin_vpc_routing_profile_transition(Request::new(begin_request(
                missing_id,
                vpc_id,
                &created.version,
                Some(59_999),
                None,
                "missing exact target",
                false,
            )))
            .await,
        Code::NotFound,
    );
    let after_missing = current_vpc(&env, vpc_id).await;
    assert_eq!(after_missing.version, created.version);
    assert_vpc_endpoint(&after_missing, INTERNAL_PROFILE, Some(60_002), 60_002, None);
    assert_eq!(owner_allocation(&env, true, &owner_id).await, Some(60_002));
    assert_eq!(owner_allocation(&env, false, &owner_id).await, None);
    assert!(transition_history(&env, vpc_id, None).await.is_empty());

    reserve_external_vni(&env, "different-vpc-owner", 50_003).await;
    let collision_id = VpcRoutingProfileTransitionId::new();
    expect_status(
        env.api
            .begin_vpc_routing_profile_transition(Request::new(begin_request(
                collision_id,
                vpc_id,
                &created.version,
                Some(50_003),
                None,
                "allocated exact target",
                false,
            )))
            .await,
        Code::FailedPrecondition,
    );
    let after_collision = current_vpc(&env, vpc_id).await;
    assert_eq!(after_collision.version, created.version);
    assert_vpc_endpoint(
        &after_collision,
        INTERNAL_PROFILE,
        Some(60_002),
        60_002,
        None,
    );
    assert_eq!(owner_allocation(&env, true, &owner_id).await, Some(60_002));
    assert_eq!(owner_allocation(&env, false, &owner_id).await, None);
    assert_eq!(
        owner_allocation(&env, false, "different-vpc-owner").await,
        Some(50_003)
    );
    assert!(transition_history(&env, vpc_id, None).await.is_empty());

    Ok(())
}

#[crate::sqlx_test]
async fn preexisting_same_owner_target_lease_requires_explicit_adoption(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_transition_env(pool).await;
    let created = create_internal_vpc(&env, "adopt transition VPC", Some(60_003), None).await;
    let vpc_id = created.id.expect("created VPC ID");
    let owner_id = vpc_id.to_string();
    reserve_external_vni(&env, &owner_id, 50_002).await;
    assert_both_leases(&env, &owner_id, 60_003, 50_002).await;

    let transition_id = VpcRoutingProfileTransitionId::new();
    let request = begin_request(
        transition_id,
        vpc_id,
        &created.version,
        Some(50_002),
        None,
        "adopt manually prepared lease",
        false,
    );
    expect_status(
        env.api
            .begin_vpc_routing_profile_transition(Request::new(request.clone()))
            .await,
        Code::FailedPrecondition,
    );
    let after_rejection = current_vpc(&env, vpc_id).await;
    assert_eq!(after_rejection.version, created.version);
    assert_vpc_endpoint(
        &after_rejection,
        INTERNAL_PROFILE,
        Some(60_003),
        60_003,
        None,
    );
    assert_both_leases(&env, &owner_id, 60_003, 50_002).await;
    assert!(transition_history(&env, vpc_id, None).await.is_empty());

    let mut missing_exact_vni = request.clone();
    missing_exact_vni.target_vni = None;
    missing_exact_vni.adopt_existing_target_allocation = true;
    let missing_exact_vni_error = expect_status(
        env.api
            .begin_vpc_routing_profile_transition(Request::new(missing_exact_vni))
            .await,
        Code::InvalidArgument,
    );
    assert!(missing_exact_vni_error.message().contains("target_vni"));
    assert_both_leases(&env, &owner_id, 60_003, 50_002).await;
    assert!(transition_history(&env, vpc_id, None).await.is_empty());

    let delete_error = expect_status(
        env.api
            .delete_vpc(Request::new(rpc::forge::VpcDeletionRequest {
                id: Some(vpc_id),
            }))
            .await,
        Code::FailedPrecondition,
    );
    assert!(delete_error.message().contains("owns both internal VNI"));
    assert!(delete_error.message().contains("adopt"));
    assert_both_leases(&env, &owner_id, 60_003, 50_002).await;

    let adopted = env
        .api
        .begin_vpc_routing_profile_transition(Request::new(
            rpc::forge::BeginVpcRoutingProfileTransitionRequest {
                adopt_existing_target_allocation: true,
                ..request
            },
        ))
        .await?
        .into_inner();
    let adopted_transition = adopted.transition.as_ref().expect("adopted transition");
    assert_eq!(adopted_transition.target_vni, 50_002);
    assert_eq!(
        transition_state(adopted_transition),
        rpc::forge::VpcRoutingProfileTransitionState::CutoverPendingFinalize
    );
    assert_vpc_endpoint(
        adopted.vpc.as_ref().expect("adopted cutover VPC"),
        EXTERNAL_PROFILE,
        Some(50_002),
        50_002,
        None,
    );
    assert_both_leases(&env, &owner_id, 60_003, 50_002).await;

    Ok(())
}

#[crate::sqlx_test]
async fn begin_rejects_ineligible_profile_for_existing_cross_tenant_prefix_overlap_atomically(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, overlap_transition_env_overrides()).await;
    let first_tenant = "transition-overlap-begin-a";
    let second_tenant = "transition-overlap-begin-b";
    create_profile_tenant(&env, first_tenant).await;
    create_profile_tenant(&env, second_tenant).await;
    let candidate = create_profile_vpc(&env, first_tenant, "overlap transition candidate").await;
    let counterpart =
        create_profile_vpc(&env, second_tenant, "overlap transition counterpart").await;
    let candidate_id = candidate.id.expect("candidate VPC ID");
    let counterpart_id = counterpart.id.expect("counterpart VPC ID");
    let candidate_source_vni = candidate
        .status
        .as_ref()
        .and_then(|status| status.vni)
        .expect("candidate source VNI");
    let candidate_root = seed_tenant_site_prefix(&env, first_tenant, "10.200.0.0/16").await;
    let counterpart_root = seed_tenant_site_prefix(&env, second_tenant, "10.200.0.0/16").await;
    seed_exact_cross_tenant_overlap(
        &env,
        (candidate_id, candidate_root),
        (counterpart_id, counterpart_root),
        "10.200.1.0/24",
    )
    .await;

    let transition_id = VpcRoutingProfileTransitionId::new();
    let error = expect_status(
        env.api
            .begin_vpc_routing_profile_transition(Request::new(begin_request(
                transition_id,
                candidate_id,
                &candidate.version,
                None,
                None,
                "unsafe profile for overlapping prefix",
                false,
            )))
            .await,
        Code::InvalidArgument,
    );
    assert!(error.message().contains("not eligible for reuse"));

    let after_rejection = current_vpc(&env, candidate_id).await;
    assert_eq!(after_rejection.version, candidate.version);
    assert_vpc_endpoint(
        &after_rejection,
        OVERLAP_PROFILE,
        None,
        candidate_source_vni,
        None,
    );
    assert_eq!(
        owner_allocation(&env, true, &candidate_id.to_string()).await,
        Some(candidate_source_vni as i32)
    );
    assert_eq!(
        owner_allocation(&env, false, &candidate_id.to_string()).await,
        None
    );
    assert!(
        transition_history(&env, candidate_id, None)
            .await
            .is_empty()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn rollback_rechecks_cross_tenant_prefix_overlap_before_switching_endpoint(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, overlap_transition_env_overrides()).await;
    let first_tenant = "transition-overlap-rollback-a";
    let second_tenant = "transition-overlap-rollback-b";
    create_profile_tenant(&env, first_tenant).await;
    create_profile_tenant(&env, second_tenant).await;
    let candidate = create_profile_vpc(&env, first_tenant, "rollback overlap candidate").await;
    let counterpart = create_profile_vpc(&env, second_tenant, "rollback overlap counterpart").await;
    let candidate_id = candidate.id.expect("candidate VPC ID");
    let counterpart_id = counterpart.id.expect("counterpart VPC ID");
    let source_vni = candidate
        .status
        .as_ref()
        .and_then(|status| status.vni)
        .expect("candidate source VNI");

    let transition_id = VpcRoutingProfileTransitionId::new();
    let begun = env
        .api
        .begin_vpc_routing_profile_transition(Request::new(begin_request(
            transition_id,
            candidate_id,
            &candidate.version,
            None,
            None,
            "rollback overlap revalidation",
            false,
        )))
        .await?
        .into_inner();
    let begun_transition = begun.transition.as_ref().expect("begin transition");
    let target_vni = begun_transition.target_vni;
    let cutover_vpc = begun.vpc.as_ref().expect("cutover VPC");

    env.api
        .update_vpc(Request::new(rpc::forge::VpcUpdateRequest {
            id: Some(counterpart_id),
            if_version_match: Some(counterpart.version.clone()),
            routing_profile_overrides: Some(overrides(true)),
            ..Default::default()
        }))
        .await
        .expect("make counterpart profile overlap-ineligible before overlap exists");
    let candidate_root = seed_tenant_site_prefix(&env, first_tenant, "10.201.0.0/16").await;
    let counterpart_root = seed_tenant_site_prefix(&env, second_tenant, "10.201.0.0/16").await;
    seed_exact_cross_tenant_overlap(
        &env,
        (candidate_id, candidate_root),
        (counterpart_id, counterpart_root),
        "10.201.1.0/24",
    )
    .await;

    let error = expect_status(
        env.api
            .rollback_vpc_routing_profile_transition(Request::new(
                rpc::forge::RollbackVpcRoutingProfileTransitionRequest {
                    id: Some(transition_id),
                    if_version_match: begun_transition.version.clone(),
                },
            ))
            .await,
        Code::InvalidArgument,
    );
    assert!(error.message().contains("not eligible for reuse"));

    let after_rejection = current_vpc(&env, candidate_id).await;
    assert_eq!(after_rejection.version, cutover_vpc.version);
    assert_vpc_endpoint(&after_rejection, EXTERNAL_PROFILE, None, target_vni, None);
    assert_both_leases(&env, &candidate_id.to_string(), source_vni, target_vni).await;
    let history = transition_history(&env, candidate_id, None).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].version, begun_transition.version);
    assert_eq!(
        transition_state(&history[0]),
        rpc::forge::VpcRoutingProfileTransitionState::CutoverPendingFinalize
    );

    Ok(())
}

#[crate::sqlx_test]
async fn recutover_rechecks_allowed_cross_tenant_prefix_overlap_before_switching_endpoint(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, overlap_transition_env_overrides()).await;
    let first_tenant = "transition-overlap-recutover-a";
    let second_tenant = "transition-overlap-recutover-b";
    create_profile_tenant(&env, first_tenant).await;
    create_profile_tenant(&env, second_tenant).await;
    let candidate = create_profile_vpc(&env, first_tenant, "recutover overlap candidate").await;
    let counterpart =
        create_profile_vpc(&env, second_tenant, "recutover overlap counterpart").await;
    let candidate_id = candidate.id.expect("candidate VPC ID");
    let counterpart_id = counterpart.id.expect("counterpart VPC ID");
    let source_vni = candidate
        .status
        .as_ref()
        .and_then(|status| status.vni)
        .expect("candidate source VNI");

    let transition_id = VpcRoutingProfileTransitionId::new();
    let begun = env
        .api
        .begin_vpc_routing_profile_transition(Request::new(begin_request(
            transition_id,
            candidate_id,
            &candidate.version,
            None,
            None,
            "recutover overlap revalidation",
            false,
        )))
        .await?
        .into_inner();
    let begun_transition = begun.transition.as_ref().expect("begin transition");
    let target_vni = begun_transition.target_vni;
    let rolled_back = env
        .api
        .rollback_vpc_routing_profile_transition(Request::new(
            rpc::forge::RollbackVpcRoutingProfileTransitionRequest {
                id: Some(transition_id),
                if_version_match: begun_transition.version.clone(),
            },
        ))
        .await?
        .into_inner();
    let rollback_transition = rolled_back
        .transition
        .as_ref()
        .expect("rollback transition");
    let rollback_vpc = rolled_back.vpc.as_ref().expect("rollback VPC");

    let candidate_root = seed_tenant_site_prefix(&env, first_tenant, "10.202.0.0/16").await;
    let counterpart_root = seed_tenant_site_prefix(&env, second_tenant, "10.202.0.0/16").await;
    seed_exact_cross_tenant_overlap(
        &env,
        (candidate_id, candidate_root),
        (counterpart_id, counterpart_root),
        "10.202.1.0/24",
    )
    .await;

    let error = expect_status(
        env.api
            .recutover_vpc_routing_profile_transition(Request::new(
                rpc::forge::RecutoverVpcRoutingProfileTransitionRequest {
                    id: Some(transition_id),
                    if_version_match: rollback_transition.version.clone(),
                },
            ))
            .await,
        Code::InvalidArgument,
    );
    assert!(error.message().contains("not eligible for reuse"));

    let after_rejection = current_vpc(&env, candidate_id).await;
    assert_eq!(after_rejection.version, rollback_vpc.version);
    assert_vpc_endpoint(&after_rejection, OVERLAP_PROFILE, None, source_vni, None);
    assert_both_leases(&env, &candidate_id.to_string(), source_vni, target_vni).await;
    let history = transition_history(&env, candidate_id, None).await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].version, rollback_transition.version);
    assert_eq!(
        transition_state(&history[0]),
        rpc::forge::VpcRoutingProfileTransitionState::RollbackPendingFinalize
    );

    Ok(())
}
