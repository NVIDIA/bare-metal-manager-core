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

use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use rpc::Metadata;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    PrefixMatchType, VpcDeletionRequest, VpcPrefixCreationRequest, VpcPrefixDeletionRequest,
    VpcPrefixSearchQuery,
};
use sqlx::PgPool;
use tonic::Request;

use crate::test_support::network_segment::FIXTURE_TENANT_ORG_ID;
use crate::tests::common::api_fixtures::instance::{
    default_os_config, default_tenant_config, single_interface_network_config_with_vpc_prefix,
};
use crate::tests::common::api_fixtures::{
    self, TEST_SITE_PREFIXES, TestEnv, TestEnvOverrides, create_managed_host, create_test_env,
    create_test_env_with_overrides, get_vpc_fixture_id,
};

const REFERENCED_VPC_PREFIX: &str = "192.0.4.0/24";
const UNREFERENCED_VPC_PREFIX: &str = "192.1.4.0/27";

#[derive(serde::Deserialize)]
struct LifecycleStateJson {
    state: String,
}

/// Builds and submits the common structured create request used by lifecycle tests.
async fn create_vpc_prefix(env: &TestEnv, vpc_id: VpcId, prefix: &str) -> rpc::forge::VpcPrefix {
    // Send a normal create request so handler validation and response conversion are covered.
    env.api
        .create_vpc_prefix(Request::new(VpcPrefixCreationRequest {
            id: None,
            prefix: String::new(),
            vpc_id: Some(vpc_id),
            config: Some(rpc::forge::VpcPrefixConfig {
                prefix: prefix.into(),
            }),
            metadata: Some(rpc::forge::Metadata {
                name: format!("VPC prefix {prefix}"),
                description: String::from("lifecycle test prefix"),
                labels: vec![rpc::forge::Label {
                    key: "test".into(),
                    value: Some("vpc-prefix-lifecycle".into()),
                }],
            }),
        }))
        .await
        .expect("Could not create VPC prefix")
        .into_inner()
}

/// Returns one VPC prefix from the default get API, if it is visible.
async fn find_vpc_prefix(env: &TestEnv, id: VpcPrefixId) -> Option<rpc::forge::VpcPrefix> {
    // Use the default API path because soft-deleted prefixes should be omitted from normal reads.
    let mut prefixes = env
        .api
        .get_vpc_prefixes(Request::new(rpc::forge::VpcPrefixGetRequest {
            vpc_prefix_ids: vec![id],
            deleted: rpc::forge::DeletedFilter::Exclude as i32,
        }))
        .await
        .expect("Could not find VPC prefixes")
        .into_inner()
        .vpc_prefixes;
    assert!(
        prefixes.len() <= 1,
        "a single VPC prefix ID should return at most one object"
    );
    prefixes.pop()
}

/// Asserts lifecycle fields and family-aware VPC-prefix utilization counters.
fn assert_status_with_lifecycle_and_linknet_counters(
    prefix: &rpc::forge::VpcPrefix,
    expected_state: &str,
    expected_total_linknets: u64,
    expected_available_linknets: u64,
) {
    let status = prefix
        .status
        .as_ref()
        .expect("VPC prefix status should be populated");

    // Verify lifecycle status is present and points at the expected controller state.
    let lifecycle_status = status
        .lifecycle
        .as_ref()
        .expect("VPC prefix status should include lifecycle");
    let lifecycle_state: LifecycleStateJson =
        serde_json::from_str(&lifecycle_status.state).expect("lifecycle state should be JSON");
    assert_eq!(lifecycle_state.state, expected_state);
    assert!(
        !lifecycle_status.version.is_empty(),
        "lifecycle version should be populated"
    );
    assert!(
        lifecycle_status.sla.is_some(),
        "lifecycle SLA should be populated"
    );

    // Verify the existing utilization counters are still present alongside lifecycle.
    assert_eq!(status.total_linknet_segments, expected_total_linknets);
    assert_eq!(
        status.available_linknet_segments,
        expected_available_linknets
    );
}

/// Returns the number of backing VPC-prefix rows for an ID, including soft-deleted rows.
async fn stored_vpc_prefix_count(env: &TestEnv, id: VpcPrefixId) -> i64 {
    // Query the backing table directly because public get intentionally hides deleted prefixes.
    sqlx::query_scalar("SELECT COUNT(*) FROM network_vpc_prefixes WHERE id = $1")
        .bind(id)
        .fetch_one(&env.pool)
        .await
        .expect("Could not count stored VPC prefixes")
}

/// Returns whether a backing VPC-prefix row is marked deleted.
async fn stored_vpc_prefix_is_deleted(env: &TestEnv, id: VpcPrefixId) -> bool {
    // Inspect the soft-delete marker that the public get API omits.
    sqlx::query_scalar("SELECT deleted IS NOT NULL FROM network_vpc_prefixes WHERE id = $1")
        .bind(id)
        .fetch_one(&env.pool)
        .await
        .expect("Could not read VPC prefix deleted marker")
}

/// Returns the stored top-level controller state for a VPC prefix row.
async fn stored_vpc_prefix_controller_state(env: &TestEnv, id: VpcPrefixId) -> Option<String> {
    // Inspect controller-owned JSON because public get hides deleted rows.
    sqlx::query_scalar("SELECT controller_state->>'state' FROM network_vpc_prefixes WHERE id = $1")
        .bind(id)
        .fetch_optional(&env.pool)
        .await
        .expect("Could not read stored VPC prefix controller state")
        .flatten()
}

/// Returns the number of network_prefix rows still referencing a VPC prefix.
async fn network_prefix_ref_count(env: &TestEnv, id: VpcPrefixId) -> i64 {
    // Count durable prefix references, which are the controller's deletion gate.
    sqlx::query_scalar("SELECT COUNT(*) FROM network_prefixes WHERE vpc_prefix_id = $1")
        .bind(id)
        .fetch_one(&env.pool)
        .await
        .expect("Could not count network prefixes for VPC prefix")
}

/// Drives the manual VPC-prefix controller until the prefix is ready.
async fn drive_vpc_prefix_to_ready(env: &TestEnv, id: VpcPrefixId) -> rpc::forge::VpcPrefix {
    // Run the controller once to process the initial Provisioning state.
    env.run_vpc_prefix_controller_iteration().await;

    // Verify the transition using the public API.
    let prefix = find_vpc_prefix(env, id)
        .await
        .expect("VPC prefix should be visible through the public get API");
    let status = prefix
        .status
        .as_ref()
        .expect("VPC prefix status should be populated");
    let lifecycle_status = status
        .lifecycle
        .as_ref()
        .expect("VPC prefix status should include lifecycle");
    let lifecycle_state: LifecycleStateJson =
        serde_json::from_str(&lifecycle_status.state).expect("lifecycle state should be JSON");
    assert_eq!(lifecycle_state.state, "ready");
    prefix
}

#[crate::sqlx_test]
async fn test_create_and_delete_vpc_prefix_deprecated_fields(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let ip_prefix = UNREFERENCED_VPC_PREFIX;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create with the deprecated flat prefix field to preserve compatibility coverage.
    let new_vpc_prefix = VpcPrefixCreationRequest {
        id: None,
        prefix: ip_prefix.into(),
        metadata: Some(Metadata {
            name: "Test VPC prefix".to_string(),
            ..Default::default()
        }),
        vpc_id: Some(vpc_id),
        ..Default::default()
    };
    let request = Request::new(new_vpc_prefix);
    let response = env.api.create_vpc_prefix(request).await;
    let vpc_prefix = response.expect("Could not create VPC prefix").into_inner();

    // Assert the create response still mirrors the requested deprecated field.
    assert_eq!(
        vpc_prefix.prefix.as_str(),
        ip_prefix,
        "The prefix after resource creation was different from what we requested"
    );

    let id = vpc_prefix
        .id
        .expect("The id field on the new VPC prefix is missing (this should be impossible)");

    // Verify persistence through the public get API after checking the create response.
    let persisted = find_vpc_prefix(&env, id)
        .await
        .expect("VPC prefix should be visible through the public get API");
    assert_eq!(persisted.prefix.as_str(), ip_prefix);

    // Delete marks the prefix deleted; it should no longer be public but should still exist.
    let delete_by_id = VpcPrefixDeletionRequest { id: Some(id) };
    let request = Request::new(delete_by_id);
    let response = env.api.delete_vpc_prefix(request).await;
    let _deletion_result = response.expect("Could not delete VPC prefix").into_inner();

    // Verify public reads hide the soft-deleted prefix.
    assert!(find_vpc_prefix(&env, id).await.is_none());

    // Verify controller-backed deletion has not hard-deleted the row yet.
    assert_eq!(stored_vpc_prefix_count(&env, id).await, 1);
    assert!(stored_vpc_prefix_is_deleted(&env, id).await);
    assert_eq!(network_prefix_ref_count(&env, id).await, 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_create_and_delete_vpc_prefix(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let ip_prefix = UNREFERENCED_VPC_PREFIX;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create with the structured config field used by current clients.
    let new_vpc_prefix = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Test VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request = Request::new(new_vpc_prefix);
    let response = env.api.create_vpc_prefix(request).await;
    let vpc_prefix = response.expect("Could not create VPC prefix").into_inner();

    // Assert the create response mirrors the requested prefix.
    assert_eq!(
        vpc_prefix.prefix.as_str(),
        ip_prefix,
        "The prefix after resource creation was different from what we requested"
    );

    let id = vpc_prefix
        .id
        .expect("The id field on the new VPC prefix is missing (this should be impossible)");

    // Verify persistence through the public get API after checking the create response.
    let persisted = find_vpc_prefix(&env, id)
        .await
        .expect("VPC prefix should be visible through the public get API");
    assert_eq!(persisted.prefix.as_str(), ip_prefix);

    // Delete marks the prefix deleted; it should no longer be public but should still exist.
    let delete_by_id = VpcPrefixDeletionRequest { id: Some(id) };
    let request = Request::new(delete_by_id);
    let response = env.api.delete_vpc_prefix(request).await;
    let _deletion_result = response.expect("Could not delete VPC prefix").into_inner();

    // Verify public reads hide the soft-deleted prefix.
    assert!(find_vpc_prefix(&env, id).await.is_none());

    // Verify controller-backed deletion has not hard-deleted the row yet.
    assert_eq!(stored_vpc_prefix_count(&env, id).await, 1);
    assert!(stored_vpc_prefix_is_deleted(&env, id).await);
    assert_eq!(network_prefix_ref_count(&env, id).await, 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_prefix_create_returns_initial_lifecycle_state(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create a prefix that has no existing network-prefix references.
    let created = create_vpc_prefix(&env, vpc_id, UNREFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");

    // Verify the create response reports the initial controller state and counters.
    assert_status_with_lifecycle_and_linknet_counters(&created, "provisioning", 16, 16);

    // Verify the same lifecycle state was persisted through the public get API.
    let persisted = find_vpc_prefix(&env, id)
        .await
        .expect("VPC prefix should be visible through the public get API");
    assert_status_with_lifecycle_and_linknet_counters(&persisted, "provisioning", 16, 16);

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_prefix_controller_transitions_provisioning_to_ready(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create the prefix and capture the initial lifecycle version.
    let created = create_vpc_prefix(&env, vpc_id, UNREFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");
    let created_status = created
        .status
        .as_ref()
        .expect("VPC prefix status should be populated");
    let initial_version = created_status
        .lifecycle
        .as_ref()
        .expect("VPC prefix status should include lifecycle")
        .version
        .clone();

    // Drive the controller and verify the persisted state transitions to Ready.
    let ready = drive_vpc_prefix_to_ready(&env, id).await;
    let ready_status = ready
        .status
        .as_ref()
        .expect("VPC prefix status should be populated");
    let ready_lifecycle = ready_status
        .lifecycle
        .as_ref()
        .expect("VPC prefix status should include lifecycle");
    assert_ne!(
        ready_lifecycle.version, initial_version,
        "controller transition should increment the lifecycle version"
    );
    assert!(
        ready_lifecycle.state_reason.is_some(),
        "controller outcome should be exposed as lifecycle state_reason"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_prefix_delete_soft_deletes_with_network_prefix_refs(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create a VPC prefix covering the tenant segment fixture so a network_prefix row references it.
    let created = create_vpc_prefix(&env, vpc_id, REFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");
    drive_vpc_prefix_to_ready(&env, id).await;
    assert!(network_prefix_ref_count(&env, id).await > 0);

    // Request deletion while durable network-prefix references still exist.
    env.api
        .delete_vpc_prefix(Request::new(VpcPrefixDeletionRequest { id: Some(id) }))
        .await
        .expect("delete should soft-delete referenced VPC prefixes");

    // Verify public active-only reads hide the soft-deleted prefix.
    assert!(find_vpc_prefix(&env, id).await.is_none());
    let active_search_ids = env
        .api
        .search_vpc_prefixes(Request::new(VpcPrefixSearchQuery {
            vpc_id: Some(vpc_id),
            deleted: rpc::forge::DeletedFilter::Exclude as i32,
            ..Default::default()
        }))
        .await
        .expect("active-only search should succeed")
        .into_inner()
        .vpc_prefix_ids;
    assert!(
        !active_search_ids.contains(&id),
        "active-only VPC-prefix search should hide soft-deleted prefixes"
    );

    // Verify the backing row remains soft-deleted while references still exist.
    assert_eq!(stored_vpc_prefix_count(&env, id).await, 1);
    assert!(stored_vpc_prefix_is_deleted(&env, id).await);
    assert!(network_prefix_ref_count(&env, id).await > 0);

    // Drive the controller and verify the FK-backed references keep the row alive.
    env.run_vpc_prefix_controller_iteration().await;
    env.run_vpc_prefix_controller_iteration().await;
    assert_eq!(
        stored_vpc_prefix_controller_state(&env, id)
            .await
            .as_deref(),
        Some("deleting")
    );
    assert_eq!(stored_vpc_prefix_count(&env, id).await, 1);
    assert!(network_prefix_ref_count(&env, id).await > 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_deleted_provisioning_vpc_prefix_enters_deleting_on_first_controller_pass(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Delete the prefix before the controller has transitioned it out of Provisioning.
    let created = create_vpc_prefix(&env, vpc_id, UNREFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");
    env.api
        .delete_vpc_prefix(Request::new(VpcPrefixDeletionRequest { id: Some(id) }))
        .await
        .expect("delete should mark the VPC prefix deleted");

    assert!(find_vpc_prefix(&env, id).await.is_none());
    let include_deleted_prefixes = env
        .api
        .get_vpc_prefixes(Request::new(rpc::forge::VpcPrefixGetRequest {
            vpc_prefix_ids: vec![id],
            deleted: rpc::forge::DeletedFilter::Include as i32,
        }))
        .await
        .expect("Could not find VPC prefix including deleted")
        .into_inner()
        .vpc_prefixes;
    assert_eq!(
        include_deleted_prefixes.len(),
        1,
        "include-deleted get should return the soft-deleted VPC prefix"
    );

    // The first controller pass should enter Deleting directly rather than recording Ready.
    env.run_vpc_prefix_controller_iteration().await;
    assert_eq!(
        stored_vpc_prefix_controller_state(&env, id)
            .await
            .as_deref(),
        Some("deleting")
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vpc_prefix_state_history \
             WHERE object_id = $1 AND state->>'state' = 'ready'",
        )
        .bind(id.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("Could not count ready history records"),
        0
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_deleted_vpc_prefix_cannot_allocate_new_instance_interface(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create and ready a prefix before marking it deleted.
    let created = create_vpc_prefix(&env, vpc_id, UNREFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");
    drive_vpc_prefix_to_ready(&env, id).await;
    env.api
        .delete_vpc_prefix(Request::new(VpcPrefixDeletionRequest { id: Some(id) }))
        .await
        .expect("delete should mark the VPC prefix deleted");

    // Attempt to allocate a new instance interface from the deleted prefix.
    let managed_host = create_managed_host(&env).await;
    let allocation = env
        .api
        .allocate_instance(Request::new(rpc::forge::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(managed_host.host().id),
            instance_type_id: None,
            config: Some(rpc::forge::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config_with_vpc_prefix(id)),
                infiniband: None,
                network_security_group_id: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            metadata: None,
            allow_unhealthy_machine: false,
        }))
        .await;

    // Verify allocation rejects deleted prefixes instead of generating a new segment.
    assert!(
        allocation.is_err(),
        "deleted VPC prefixes must not be usable for new interface allocation"
    );
    assert_eq!(network_prefix_ref_count(&env, id).await, 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_prefix_final_delete_after_generated_segment_cleanup(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            network_segments_drain_period: Some(chrono::Duration::seconds(0)),
            vpc_prefixes_drain_period: Some(chrono::Duration::seconds(0)),
            ..Default::default()
        },
    )
    .await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create a ready prefix that instance allocation will use to generate a segment.
    let created = create_vpc_prefix(&env, vpc_id, UNREFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");
    drive_vpc_prefix_to_ready(&env, id).await;

    // Allocate an instance so the generated segment creates network-prefix references.
    let managed_host = create_managed_host(&env).await;
    let (instance, rpc_instance) = managed_host
        .instance_builer(&env)
        .network(single_interface_network_config_with_vpc_prefix(id))
        .build_and_return()
        .await;
    let generated_segment_id = rpc_instance.config().network().interfaces[0]
        .network_segment_id
        .expect("VPC-prefix allocation should assign a generated segment");
    assert!(network_prefix_ref_count(&env, id).await > 0);

    // Delete while the generated segment still references this VPC prefix.
    env.api
        .delete_vpc_prefix(Request::new(VpcPrefixDeletionRequest { id: Some(id) }))
        .await
        .expect("delete should soft-delete referenced VPC prefixes");
    assert_eq!(stored_vpc_prefix_count(&env, id).await, 1);
    assert!(stored_vpc_prefix_is_deleted(&env, id).await);
    assert!(network_prefix_ref_count(&env, id).await > 0);

    // Verify the controller will not hard-delete while FK-backed references remain.
    env.run_vpc_prefix_controller_iteration().await;
    env.run_vpc_prefix_controller_iteration().await;
    assert_eq!(stored_vpc_prefix_count(&env, id).await, 1);
    assert!(network_prefix_ref_count(&env, id).await > 0);

    // Release the instance so generated segment cleanup removes the prefix references.
    instance.delete().await;
    assert_eq!(network_prefix_ref_count(&env, id).await, 0);

    // Run VPC-prefix cleanup to advance through DBDelete after dependencies drain.
    env.run_vpc_prefix_controller_iteration().await;
    env.run_vpc_prefix_controller_iteration().await;
    env.run_vpc_prefix_controller_iteration().await;

    // Verify the prefix is finally hard-deleted after generated segment cleanup.
    assert!(find_vpc_prefix(&env, id).await.is_none());
    assert_eq!(stored_vpc_prefix_count(&env, id).await, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM network_segments WHERE id = $1")
            .bind(generated_segment_id)
            .fetch_one(&env.pool)
            .await
            .expect("Could not count generated network segment rows"),
        0
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_repeat_vpc_prefix_delete_returns_not_found_while_soft_deleted(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create a prefix and submit the first delete request.
    let created = create_vpc_prefix(&env, vpc_id, UNREFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");
    env.api
        .delete_vpc_prefix(Request::new(VpcPrefixDeletionRequest { id: Some(id) }))
        .await
        .expect("first delete should mark the VPC prefix deleted");

    // Submit the same delete again while the row is still soft-deleted.
    let err = env
        .api
        .delete_vpc_prefix(Request::new(VpcPrefixDeletionRequest { id: Some(id) }))
        .await
        .expect_err("repeat delete should return NotFound while soft-deleted");

    // Verify repeat delete follows the active-only public API behavior.
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert!(find_vpc_prefix(&env, id).await.is_none());
    assert_eq!(stored_vpc_prefix_count(&env, id).await, 1);
    assert!(stored_vpc_prefix_is_deleted(&env, id).await);

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_delete_rejects_existing_vpc_prefix(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Any VPC-prefix row, active or soft-deleted, keeps the parent VPC from being deleted.
    let created = create_vpc_prefix(&env, vpc_id, UNREFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");

    let err = env
        .api
        .delete_vpc(Request::new(VpcDeletionRequest { id: Some(vpc_id) }))
        .await
        .expect_err("VPC delete should be rejected while a VPC prefix exists");

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(
        find_vpc_prefix(&env, id).await.is_some(),
        "rejected parent VPC delete must not remove the VPC prefix"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_prefix_rpc_status_includes_lifecycle_and_counters(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    // Create and ready a prefix that adopts an existing tenant segment reference.
    let created = create_vpc_prefix(&env, vpc_id, REFERENCED_VPC_PREFIX).await;
    let id = created.id.expect("created VPC prefix should include an id");
    let ready = drive_vpc_prefix_to_ready(&env, id).await;

    // Verify lifecycle fields and existing utilization counters share the RPC status.
    assert_status_with_lifecycle_and_linknet_counters(&ready, "ready", 128, 127);
    let status = ready
        .status
        .as_ref()
        .expect("VPC prefix status should be populated");
    assert_eq!(u64::from(status.total_31_segments), 128);
    assert_eq!(u64::from(status.available_31_segments), 127);
    let lifecycle_status = status
        .lifecycle
        .as_ref()
        .expect("VPC prefix status should include lifecycle");
    assert!(
        lifecycle_status.state_reason.is_some(),
        "RPC lifecycle status should expose controller reason"
    );

    Ok(())
}

/// Verifies that large IPv6 VPC prefixes report saturated linknet counters.
///
/// A /48 contains 2^79 /127 linknets, which does not fit in the u64 RPC/status
/// fields. The DB layer should cap these display counters at u64::MAX and
/// persist that value through the public API instead of overflowing or
/// attempting to enumerate the linknets.
#[crate::sqlx_test]
async fn test_ipv6_vpc_prefix_linknet_counters_cap_large_prefix(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Extend the test fabric with IPv6 so the VPC-prefix validator accepts the /48.
    let mut site_prefixes = TEST_SITE_PREFIXES.clone();
    site_prefixes.push("2001:db8::/32".parse().unwrap());
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            site_prefixes: Some(site_prefixes),
            create_network_segments: Some(false),
            ..Default::default()
        },
    )
    .await;
    let (_, vpc) = api_fixtures::vpc::create_flat_vpc(
        &env,
        "flat-large-v6".to_string(),
        Some("2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string()),
    )
    .await;
    let vpc_id = vpc.id.expect("flat VPC should include an id");

    // Create a large IPv6 prefix whose /127 linknet count exceeds u64.
    let created = create_vpc_prefix(&env, vpc_id, "2001:db8:1000::/48").await;
    let id = created.id.expect("created VPC prefix should include an id");
    assert_status_with_lifecycle_and_linknet_counters(&created, "provisioning", u64::MAX, u64::MAX);

    // Re-read through the public API to verify the capped counters persisted.
    let persisted = find_vpc_prefix(&env, id)
        .await
        .expect("VPC prefix should be visible through the public get API");
    assert_status_with_lifecycle_and_linknet_counters(
        &persisted,
        "provisioning",
        u64::MAX,
        u64::MAX,
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_overlapping_vpc_prefixes(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    let ip_prefix = "192.0.2.128/25";
    let overlapping_ip_prefix = "192.0.2.192/26";

    let new_vpc_prefix = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Test VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request = Request::new(new_vpc_prefix);
    let response = env.api.create_vpc_prefix(request).await;
    assert!(response.is_ok());

    let overlapping_vpc_prefix = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: overlapping_ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "Overlapping VPC prefix".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request = Request::new(overlapping_vpc_prefix);
    let response = env.api.create_vpc_prefix(request).await;
    assert!(response.is_err());

    Ok(())
}

#[crate::sqlx_test]
async fn test_reject_create_with_invalid_metadata(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    let ip_prefix = "192.0.2.0/24";

    let new_vpc_prefix = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: ip_prefix.into(),
        }),
        metadata: Some(rpc::forge::Metadata {
            name: "".into(),
            description: String::from("some description"),
            labels: vec![rpc::forge::Label {
                key: "example_key".into(),
                value: Some("example_value".into()),
            }],
        }),
    };
    let request = Request::new(new_vpc_prefix);
    let response = env.api.create_vpc_prefix(request).await;
    let error = response
        .expect_err("expected create create vpc prefix to fail")
        .to_string();
    assert!(
        error.contains("invalid value"),
        "error message should contain 'invalid value', but is {error}"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_invalid_vpc_prefixes(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    for (prefix, description) in [
        (
            "198.51.100.0/24",
            "This VPC prefix is not within the site prefixes",
        ),
        (
            "2001:db8::/64",
            "This IPv6 VPC prefix is also not within the site prefixes",
        ),
        (
            "192.0.2.255/25",
            "This VPC prefix is not specified in canonical form (bits after the prefix are set to 1)",
        ),
    ] {
        let bad_vpc_prefix = VpcPrefixCreationRequest {
            id: None,
            prefix: String::new(),
            vpc_id: Some(vpc_id),

            config: Some(rpc::forge::VpcPrefixConfig {
                prefix: prefix.into(),
            }),
            metadata: Some(rpc::forge::Metadata {
                name: description.into(),
                ..Default::default()
            }),
        };
        let request = Request::new(bad_vpc_prefix);
        let response = env.api.create_vpc_prefix(request).await;

        assert!(
            response.is_err(),
            "A prefix ({prefix}) with description \"{description}\" was accepted when it should have been rejected"
        );
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_vpc_prefix_search(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    let p1 = "192.0.2.0/25";
    let p2 = "192.0.2.128/25";
    let create_p1 = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig { prefix: p1.into() }),
        metadata: Some(rpc::forge::Metadata {
            name: "VPC prefix p1".into(),
            ..Default::default()
        }),
    };
    let create_p2 = VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        vpc_id: Some(vpc_id),
        config: Some(rpc::forge::VpcPrefixConfig { prefix: p2.into() }),
        metadata: Some(rpc::forge::Metadata {
            name: "VPC prefix p2".into(),
            ..Default::default()
        }),
    };
    let p1_request = Request::new(create_p1);
    let p2_request = Request::new(create_p2);
    let p1_response = env.api.create_vpc_prefix(p1_request).await;
    let p2_response = env.api.create_vpc_prefix(p2_request).await;
    let p1 = p1_response
        .expect("Couldn't create a VPC prefix ({p1})")
        .into_inner();
    let p2 = p2_response
        .expect("Couldn't create a VPC prefix ({p2})")
        .into_inner();

    // Search for each prefix by exact prefix match.
    for (prefix, vpc_prefix_id) in [(p1.prefix.as_str(), p1.id), (p2.prefix.as_str(), p2.id)] {
        dbg!(&vpc_prefix_id);
        dbg!(vpc_id);
        let prefix_query = VpcPrefixSearchQuery {
            vpc_id: Some(vpc_id),
            tenant_prefix_id: None,
            name: None,
            prefix_match: Some(prefix.into()),
            prefix_match_type: Some(PrefixMatchType::PrefixExact as i32),
            deleted: rpc::forge::DeletedFilter::Exclude as i32,
        };
        let search_request = Request::new(prefix_query);
        let search_response = env.api.search_vpc_prefixes(search_request).await;
        let vpc_prefix_id_list = search_response
            .expect("Couldn't execute VPC prefix search")
            .into_inner();
        // Each search should return a single ID matching the ID we already
        // know.
        let expected = vpc_prefix_id_list.vpc_prefix_ids.as_slice();
        let found = vpc_prefix_id.as_slice();
        assert_eq!(
            expected, found,
            "When searching for an exact prefix {prefix}, we expected a single \
            VPC prefix ID ({expected:?}) but found {found:?}",
        );
    }

    // Search for each prefix by an address it contains.
    for (prefix, vpc_prefix_id) in [
        // A bare address should be treated the same as an explicit /32.
        ("192.0.2.85", p1.id),
        ("192.0.2.170/32", p2.id),
    ] {
        dbg!(&vpc_prefix_id);
        dbg!(vpc_id);
        let prefix_query = VpcPrefixSearchQuery {
            vpc_id: Some(vpc_id),
            tenant_prefix_id: None,
            name: None,
            prefix_match: Some(prefix.into()),
            prefix_match_type: Some(PrefixMatchType::PrefixContains as i32),
            deleted: rpc::forge::DeletedFilter::Exclude as i32,
        };
        let search_request = Request::new(prefix_query);
        let search_response = env.api.search_vpc_prefixes(search_request).await;
        let vpc_prefix_id_list = search_response
            .expect("Couldn't execute VPC prefix search")
            .into_inner();
        // Each search should return a single ID matching the ID we already
        // know.
        let expected = vpc_prefix_id_list.vpc_prefix_ids.as_slice();
        let found = vpc_prefix_id.as_slice();
        assert_eq!(
            expected, found,
            "When searching for a contained prefix {prefix}, we expected a \
            single VPC prefix ID ({expected:?}) but found {found:?}",
        );
    }

    // Search for both prefixes by searching for a network prefix containing
    // both of them.
    let prefix = "192.0.2.0/24";
    let prefix_query = VpcPrefixSearchQuery {
        vpc_id: Some(vpc_id),
        tenant_prefix_id: None,
        name: None,
        prefix_match: Some(prefix.into()),
        prefix_match_type: Some(PrefixMatchType::PrefixContainedBy as i32),
        deleted: rpc::forge::DeletedFilter::Exclude as i32,
    };
    let search_request = Request::new(prefix_query);
    let search_response = env.api.search_vpc_prefixes(search_request).await;
    let vpc_prefix_id_list = search_response
        .expect("Couldn't execute VPC prefix search")
        .into_inner();
    let returned_vpc_prefix_ids = vpc_prefix_id_list.vpc_prefix_ids;
    for expected_vpc_prefix in [&p1, &p2] {
        let expected_id = expected_vpc_prefix.id.unwrap();
        let expected_prefix = expected_vpc_prefix.prefix.as_str();
        assert!(
            returned_vpc_prefix_ids.contains(&expected_id),
            "We expected to find the VPC prefix id {expected_id} for prefix {expected_prefix} in the search results ({returned_vpc_prefix_ids:?}), but it was absent"
        );
    }

    Ok(())
}

#[crate::sqlx_test]
async fn flat_vpc_accepts_ipv4_prefix(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // Flat VPCs should accept IPv4 prefixes just like every other VPC type.
    let env = create_test_env(pool).await;
    let (_, vpc) = api_fixtures::vpc::create_flat_vpc(
        &env,
        "flat".to_string(),
        Some(FIXTURE_TENANT_ORG_ID.to_string()),
    )
    .await;

    let request = Request::new(VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        vpc_id: vpc.id,
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: "192.0.2.0/25".to_string(),
        }),
        metadata: Some(Metadata {
            name: "flat-v4".to_string(),
            ..Default::default()
        }),
    });

    env.api
        .create_vpc_prefix(request)
        .await
        .expect("Flat VPC should accept IPv4 prefix");

    Ok(())
}

#[crate::sqlx_test]
async fn flat_vpc_accepts_ipv6_prefix(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // Flat VPCs are allowed IPv6 prefixes alongside FNN -- ETV is the only
    // type that rejects IPv6 prefixes. Extend the site fabric prefixes with an
    // IPv6 range since the default test fabric is IPv4-only.
    let mut site_prefixes = TEST_SITE_PREFIXES.clone();
    site_prefixes.push("2001:db8::/32".parse().unwrap());
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            site_prefixes: Some(site_prefixes),
            create_network_segments: Some(false),
            ..Default::default()
        },
    )
    .await;
    let (_, vpc) = api_fixtures::vpc::create_flat_vpc(
        &env,
        "flat".to_string(),
        Some(FIXTURE_TENANT_ORG_ID.to_string()),
    )
    .await;

    let request = Request::new(VpcPrefixCreationRequest {
        id: None,
        prefix: String::new(),
        vpc_id: vpc.id,
        config: Some(rpc::forge::VpcPrefixConfig {
            prefix: "2001:db8::/64".to_string(),
        }),
        metadata: Some(Metadata {
            name: "flat-v6".to_string(),
            ..Default::default()
        }),
    });

    env.api
        .create_vpc_prefix(request)
        .await
        .expect("Flat VPC should accept IPv6 prefix");

    Ok(())
}
