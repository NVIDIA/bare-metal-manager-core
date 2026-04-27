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

use carbide_uuid::network::NetworkSegmentId;
use rpc::forge::forge_server::Forge;
use tonic::{Code, Request};
use uuid::Uuid;

use crate::cfg::file::ComputeAllocationEnforcement;
use crate::tests::common::api_fixtures::instance::{
    default_os_config, single_interface_network_config,
};
use crate::tests::common::api_fixtures::{
    TestEnv, TestEnvOverrides, TestManagedHost, create_managed_host, create_test_env,
    create_test_env_with_overrides, get_instance_type_fixture_id,
};
use crate::tests::common::rpc_builder::{
    ComputeAllocationAttributes, CreateComputeAllocationRequest, DeleteComputeAllocationRequest,
    UpdateComputeAllocationRequest,
};

const TENANT_ORG: &str = "2829bbe3-c169-4cd9-8b2a-19a8b1618a93";

fn metadata(name: impl Into<String>) -> rpc::forge::Metadata {
    rpc::forge::Metadata {
        name: name.into(),
        description: String::new(),
        labels: vec![],
    }
}

async fn create_compute_allocation(
    env: &TestEnv,
    instance_type_id: &str,
    count: u32,
    name: &str,
) -> rpc::forge::ComputeAllocation {
    // Create allocation for this scenario.
    // Expect success: tenant and type are valid.
    env.api
        .create_compute_allocation(
            CreateComputeAllocationRequest::builder(TENANT_ORG)
                .created_by("tests")
                .metadata(metadata(name))
                .attributes(ComputeAllocationAttributes::builder(instance_type_id, count).rpc())
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .allocation
        .unwrap()
}

async fn allocate_instance(
    env: &TestEnv,
    host: &TestManagedHost,
    instance_type_id: Option<&str>,
    segment_id: NetworkSegmentId,
) -> Result<tonic::Response<rpc::forge::Instance>, tonic::Status> {
    // Attempt instance allocation for this case.
    // Caller asserts expected success/failure.
    env.api
        .allocate_instance(Request::new(rpc::forge::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(host.id),
            instance_type_id: instance_type_id.map(str::to_string),
            config: Some(rpc::forge::InstanceConfig {
                tenant: Some(rpc::forge::TenantConfig {
                    tenant_organization_id: TENANT_ORG.to_string(),
                    tenant_keyset_ids: vec![],
                    hostname: None,
                }),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(segment_id)),
                infiniband: None,
                nvlink: None,
                network_security_group_id: None,
                dpu_extension_services: None,
            }),
            metadata: None,
            allow_unhealthy_machine: false,
        }))
        .await
}

async fn update_compute_allocation(
    env: &TestEnv,
    allocation: &rpc::forge::ComputeAllocation,
    count: u32,
    name: &str,
) -> Result<tonic::Response<rpc::forge::UpdateComputeAllocationResponse>, tonic::Status> {
    // Attempt allocation update for this case.
    // Caller asserts expected success/failure.
    env.api
        .update_compute_allocation(
            UpdateComputeAllocationRequest::builder(TENANT_ORG)
                .id(allocation.id.unwrap())
                .metadata(metadata(name))
                .attributes(
                    ComputeAllocationAttributes::builder(
                        &allocation.attributes.as_ref().unwrap().instance_type_id,
                        count,
                    )
                    .rpc(),
                )
                .updated_by("tests")
                .tonic_request(),
        )
        .await
}

#[crate::sqlx_test]
async fn test_compute_allocation_basic_actions(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host = create_managed_host(&env).await;
    // Bind host to this instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host.id.to_string()],
            },
        ))
        .await
        .unwrap();

    let allocation_name = format!("alloc-basic-{}", Uuid::new_v4());
    // Make one allocation for basic CRUD checks.
    // Expect success with valid tenant/type.
    let allocation = create_compute_allocation(&env, &instance_type_id, 1, &allocation_name).await;

    // Query IDs for the created allocation.
    // Expect one ID due to exact filters.
    let found_ids = env
        .api
        .find_compute_allocation_ids(Request::new(rpc::forge::FindComputeAllocationIdsRequest {
            name: Some(allocation_name.clone()),
            tenant_organization_id: Some(TENANT_ORG.to_string()),
            instance_type_id: Some(instance_type_id.clone()),
        }))
        .await
        .unwrap()
        .into_inner()
        .ids;
    assert_eq!(found_ids, vec![allocation.id.unwrap()]);

    // Fetch allocation by known unique ID.
    // Expect one active record.
    let found_allocations = env
        .api
        .find_compute_allocations_by_ids(Request::new(
            rpc::forge::FindComputeAllocationsByIdsRequest {
                ids: vec![allocation.id.unwrap()],
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .allocations;
    assert_eq!(found_allocations.len(), 1);
    assert_eq!(found_allocations[0].id, allocation.id);

    let updated_name = format!("alloc-basic-updated-{}", Uuid::new_v4());
    // Update metadata on existing allocation.
    // Expect success for owned record.
    let updated = update_compute_allocation(&env, &allocation, 1, &updated_name)
        .await
        .unwrap()
        .into_inner()
        .allocation
        .unwrap();
    assert_eq!(updated.metadata.unwrap().name, updated_name);

    // Delete the allocation owned by tenant.
    // Expect success: record exists.
    env.api
        .delete_compute_allocation(
            DeleteComputeAllocationRequest::builder(TENANT_ORG)
                .id(updated.id.unwrap())
                .tonic_request(),
        )
        .await
        .unwrap();

    // Re-query IDs after delete.
    // Expect none: deleted rows are filtered.
    let post_delete_ids = env
        .api
        .find_compute_allocation_ids(Request::new(rpc::forge::FindComputeAllocationIdsRequest {
            name: Some(updated_name),
            tenant_organization_id: Some(TENANT_ORG.to_string()),
            instance_type_id: Some(instance_type_id),
        }))
        .await
        .unwrap()
        .into_inner()
        .ids;
    assert!(post_delete_ids.is_empty());

    Ok(())
}

async fn test_create_instance_no_allocations(
    pool: sqlx::PgPool,
    enforcement: ComputeAllocationEnforcement,
    should_pass: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build env with selected enforcement mode.
    // Expect success with valid test config.
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            ..Default::default()
        }
        .with_compute_allocation_enforcement(enforcement),
    )
    .await;

    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host = create_managed_host(&env).await;
    // Bind host to this instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Try allocation with no existing limits.
    // Expected pass/fail depends on mode.
    let result = allocate_instance(&env, &host, Some(instance_type_id.as_str()), segment_id).await;
    if should_pass {
        result.unwrap();
    } else {
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_create_instance_no_allocations_warn_only(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_no_allocations(pool, ComputeAllocationEnforcement::WarnOnly, true).await
}

#[crate::sqlx_test]
async fn test_create_instance_no_allocations_enforce_if_present(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_no_allocations(pool, ComputeAllocationEnforcement::EnforceIfPresent, true)
        .await
}

#[crate::sqlx_test]
async fn test_create_instance_no_allocations_always(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_no_allocations(pool, ComputeAllocationEnforcement::Always, false).await
}

async fn test_create_instance_without_instance_type_id_no_allocations(
    pool: sqlx::PgPool,
    enforcement: ComputeAllocationEnforcement,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build env with selected enforcement mode.
    // Expect success because omitted instance type IDs skip allocation enforcement.
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            ..Default::default()
        }
        .with_compute_allocation_enforcement(enforcement),
    )
    .await;

    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host = create_managed_host(&env).await;
    // Bind host to this instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Allocate without sending instance_type_id.
    // Expect success even in enforcing modes.
    let instance = allocate_instance(&env, &host, None, segment_id)
        .await
        .unwrap()
        .into_inner();

    // Verify the immediate response.
    // Expect no explicit instance type on the created instance.
    assert!(instance.instance_type_id.is_none());

    // Read the instance back from the API.
    // Expect no explicit instance type to be persisted.
    let persisted = env
        .api
        .find_instances_by_ids(Request::new(rpc::forge::InstancesByIdsRequest {
            instance_ids: vec![instance.id.unwrap()],
        }))
        .await
        .unwrap()
        .into_inner()
        .instances
        .pop()
        .unwrap();
    assert!(persisted.instance_type_id.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_create_instance_no_allocations_without_instance_type_id_enforce_if_present(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_without_instance_type_id_no_allocations(
        pool,
        ComputeAllocationEnforcement::EnforceIfPresent,
    )
    .await
}

#[crate::sqlx_test]
async fn test_create_instance_no_allocations_without_instance_type_id_always(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_without_instance_type_id_no_allocations(
        pool,
        ComputeAllocationEnforcement::Always,
    )
    .await
}

async fn test_create_instance_with_enough_allocations(
    pool: sqlx::PgPool,
    enforcement: ComputeAllocationEnforcement,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build env with selected enforcement mode.
    // Expect success with valid test config.
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            ..Default::default()
        }
        .with_compute_allocation_enforcement(enforcement),
    )
    .await;

    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host = create_managed_host(&env).await;
    // Bind host to this instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let alloc_name = format!("alloc-enough-{}", Uuid::new_v4());
    // Seed one allocation for this tenant/type.
    // Expect success with valid tenant/type.
    let _allocation = create_compute_allocation(&env, &instance_type_id, 1, &alloc_name).await;

    // Allocate one instance against limit 1.
    // Expect success in all enforcement modes.
    allocate_instance(&env, &host, Some(instance_type_id.as_str()), segment_id)
        .await
        .unwrap();

    Ok(())
}

#[crate::sqlx_test]
async fn test_create_instance_enough_allocations_warn_only(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_with_enough_allocations(pool, ComputeAllocationEnforcement::WarnOnly).await
}

#[crate::sqlx_test]
async fn test_create_instance_enough_allocations_enforce_if_present(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_with_enough_allocations(
        pool,
        ComputeAllocationEnforcement::EnforceIfPresent,
    )
    .await
}

#[crate::sqlx_test]
async fn test_create_instance_enough_allocations_always(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_with_enough_allocations(pool, ComputeAllocationEnforcement::Always).await
}

async fn test_create_instance_with_insufficient_allocations(
    pool: sqlx::PgPool,
    enforcement: ComputeAllocationEnforcement,
    second_should_pass: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build env with selected enforcement mode.
    // Expect success with valid test config.
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            ..Default::default()
        }
        .with_compute_allocation_enforcement(enforcement),
    )
    .await;

    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host_1 = create_managed_host(&env).await;
    // Bind first host to the instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_1.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let host_2 = create_managed_host(&env).await;
    // Bind second host to the instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_2.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let alloc_name = format!("alloc-insufficient-{}", Uuid::new_v4());
    // Seed one allocation for this tenant/type.
    // Expect success with valid tenant/type.
    let _allocation = create_compute_allocation(&env, &instance_type_id, 1, &alloc_name).await;

    // First allocation consumes full limit.
    // Expect success.
    allocate_instance(&env, &host_1, Some(instance_type_id.as_str()), segment_id)
        .await
        .unwrap();

    // Second allocation exceeds limit=1.
    // Outcome depends on enforcement mode.
    let second =
        allocate_instance(&env, &host_2, Some(instance_type_id.as_str()), segment_id).await;
    if second_should_pass {
        second.unwrap();
    } else {
        let err = second.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_create_instance_insufficient_allocations_warn_only(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_with_insufficient_allocations(
        pool,
        ComputeAllocationEnforcement::WarnOnly,
        true,
    )
    .await
}

#[crate::sqlx_test]
async fn test_create_instance_insufficient_allocations_enforce_if_present(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_with_insufficient_allocations(
        pool,
        ComputeAllocationEnforcement::EnforceIfPresent,
        false,
    )
    .await
}

#[crate::sqlx_test]
async fn test_create_instance_insufficient_allocations_always(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_with_insufficient_allocations(
        pool,
        ComputeAllocationEnforcement::Always,
        false,
    )
    .await
}

async fn test_create_instance_without_instance_type_id_skips_insufficient_allocations(
    pool: sqlx::PgPool,
    enforcement: ComputeAllocationEnforcement,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build env with selected enforcement mode.
    // Expect omitted instance type IDs to bypass allocation enforcement.
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            ..Default::default()
        }
        .with_compute_allocation_enforcement(enforcement),
    )
    .await;

    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host_1 = create_managed_host(&env).await;
    let host_2 = create_managed_host(&env).await;
    // Bind both hosts to the same instance type.
    // Expect success for fresh hosts.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_1.id.to_string(), host_2.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let alloc_name = format!("alloc-insufficient-omit-type-{}", Uuid::new_v4());
    // Seed one allocation for this tenant/type.
    // Expect success with valid tenant/type.
    let _allocation = create_compute_allocation(&env, &instance_type_id, 1, &alloc_name).await;

    // Consume the single allocation using an explicit instance type ID.
    // Expect success.
    allocate_instance(&env, &host_1, Some(instance_type_id.as_str()), segment_id)
        .await
        .unwrap();

    // Allocate without sending instance_type_id after the limit is exhausted.
    // Expect success because omitted instance type IDs skip enforcement.
    let instance = allocate_instance(&env, &host_2, None, segment_id)
        .await
        .unwrap()
        .into_inner();

    // Verify the immediate response.
    // Expect no explicit instance type on the created instance.
    assert!(instance.instance_type_id.is_none());

    // Read the instance back from the API.
    // Expect no explicit instance type to be persisted.
    let persisted = env
        .api
        .find_instances_by_ids(Request::new(rpc::forge::InstancesByIdsRequest {
            instance_ids: vec![instance.id.unwrap()],
        }))
        .await
        .unwrap()
        .into_inner()
        .instances
        .pop()
        .unwrap();
    assert!(persisted.instance_type_id.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_create_instance_insufficient_allocations_without_instance_type_id_enforce_if_present(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_without_instance_type_id_skips_insufficient_allocations(
        pool,
        ComputeAllocationEnforcement::EnforceIfPresent,
    )
    .await
}

#[crate::sqlx_test]
async fn test_create_instance_insufficient_allocations_without_instance_type_id_always(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_create_instance_without_instance_type_id_skips_insufficient_allocations(
        pool,
        ComputeAllocationEnforcement::Always,
    )
    .await
}

#[crate::sqlx_test]
async fn test_delete_allocation_when_instances_not_present_passes(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host = create_managed_host(&env).await;
    // Bind host to this instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host.id.to_string()],
            },
        ))
        .await
        .unwrap();

    let alloc_name = format!("alloc-delete-no-instances-{}", Uuid::new_v4());
    // Seed allocation before delete scenario.
    // Expect success with valid tenant/type.
    let allocation = create_compute_allocation(&env, &instance_type_id, 1, &alloc_name).await;

    // Delete allocation with zero instances.
    // Expect success: no lower-bound conflict.
    env.api
        .delete_compute_allocation(
            DeleteComputeAllocationRequest::builder(TENANT_ORG)
                .id(allocation.id.unwrap())
                .tonic_request(),
        )
        .await
        .unwrap();

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_allocation_when_instances_present_and_sufficient_remain_passes(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host_1 = create_managed_host(&env).await;
    // Bind first host to the instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_1.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let host_2 = create_managed_host(&env).await;
    // Bind second host to the instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_2.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // First allocation for delete-cap test.
    // Expect success with valid tenant/type.
    let alloc_1 = create_compute_allocation(
        &env,
        &instance_type_id,
        1,
        &format!("alloc-delete-enough-1-{}", Uuid::new_v4()),
    )
    .await;
    // Second allocation keeps remaining cap >= use.
    // Expect success with valid tenant/type.
    let _alloc_2 = create_compute_allocation(
        &env,
        &instance_type_id,
        1,
        &format!("alloc-delete-enough-2-{}", Uuid::new_v4()),
    )
    .await;

    // Create one active instance before delete.
    // Expect success with cap=2.
    allocate_instance(&env, &host_1, Some(instance_type_id.as_str()), segment_id)
        .await
        .unwrap();

    // Delete one allocation with spare capacity.
    // Expect success: remaining cap is enough.
    env.api
        .delete_compute_allocation(
            DeleteComputeAllocationRequest::builder(TENANT_ORG)
                .id(alloc_1.id.unwrap())
                .tonic_request(),
        )
        .await
        .unwrap();

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_allocation_when_instances_present_and_insufficient_remain_fails(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host = create_managed_host(&env).await;
    // Bind host to this instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Seed single allocation for fail case.
    // Expect success with valid tenant/type.
    let allocation = create_compute_allocation(
        &env,
        &instance_type_id,
        1,
        &format!("alloc-delete-insufficient-{}", Uuid::new_v4()),
    )
    .await;

    // Create one active instance before delete.
    // Expect success with cap=1.
    allocate_instance(&env, &host, Some(instance_type_id.as_str()), segment_id)
        .await
        .unwrap();

    let err = env
        .api
        // Delete only allocation under active instance.
        // Expect fail: would drop below usage.
        .delete_compute_allocation(
            DeleteComputeAllocationRequest::builder(TENANT_ORG)
                .id(allocation.id.unwrap())
                .tonic_request(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);

    Ok(())
}

#[crate::sqlx_test]
async fn test_update_allocation_reduce_when_sufficient_remains_passes(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host_1 = create_managed_host(&env).await;
    // Bind first host to the instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_1.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let host_2 = create_managed_host(&env).await;
    // Bind second host to the instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_2.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Seed allocation count=2 for reduce test.
    // Expect success with valid tenant/type.
    let allocation = create_compute_allocation(
        &env,
        &instance_type_id,
        2,
        &format!("alloc-update-reduce-pass-{}", Uuid::new_v4()),
    )
    .await;

    // Create one active instance first.
    // Expect success with cap=2.
    allocate_instance(&env, &host_1, Some(instance_type_id.as_str()), segment_id)
        .await
        .unwrap();

    // Reduce count from 2 to 1.
    // Expect success: still >= active instances.
    let updated = update_compute_allocation(
        &env,
        &allocation,
        1,
        &format!("alloc-update-reduce-pass-updated-{}", Uuid::new_v4()),
    )
    .await
    .unwrap()
    .into_inner()
    .allocation
    .unwrap();

    assert_eq!(updated.attributes.unwrap().count, 1);

    Ok(())
}

#[crate::sqlx_test]
async fn test_update_allocation_reduce_when_insufficient_remains_fails(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host = create_managed_host(&env).await;
    // Bind host to this instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Seed allocation count=1 for fail case.
    // Expect success with valid tenant/type.
    let allocation = create_compute_allocation(
        &env,
        &instance_type_id,
        1,
        &format!("alloc-update-reduce-fail-{}", Uuid::new_v4()),
    )
    .await;

    // Create one active instance first.
    // Expect success with cap=1.
    allocate_instance(&env, &host, Some(instance_type_id.as_str()), segment_id)
        .await
        .unwrap();

    // Reduce count from 1 to 0.
    // Expect fail: would drop below usage.
    let err = update_compute_allocation(
        &env,
        &allocation,
        0,
        &format!("alloc-update-reduce-fail-updated-{}", Uuid::new_v4()),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), Code::FailedPrecondition);

    Ok(())
}

#[crate::sqlx_test]
async fn test_update_allocation_increase_when_sufficient_machines_remain_passes(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host_1 = create_managed_host(&env).await;
    // Bind first host to the instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_1.id.to_string()],
            },
        ))
        .await
        .unwrap();
    let host_2 = create_managed_host(&env).await;
    // Bind second host to the instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host_2.id.to_string()],
            },
        ))
        .await
        .unwrap();

    // Seed allocation count=1 for increase test.
    // Expect success with valid tenant/type.
    let allocation = create_compute_allocation(
        &env,
        &instance_type_id,
        1,
        &format!("alloc-update-increase-pass-{}", Uuid::new_v4()),
    )
    .await;

    // Increase count from 1 to 2.
    // Expect success: two machines are present.
    let updated = update_compute_allocation(
        &env,
        &allocation,
        2,
        &format!("alloc-update-increase-pass-updated-{}", Uuid::new_v4()),
    )
    .await
    .unwrap()
    .into_inner()
    .allocation
    .unwrap();

    assert_eq!(updated.attributes.unwrap().count, 2);

    Ok(())
}

#[crate::sqlx_test]
async fn test_update_allocation_increase_when_insufficient_machines_remain_fails(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let host = create_managed_host(&env).await;
    // Bind host to this instance type.
    // Expect success for a fresh host.
    env.api
        .associate_machines_with_instance_type(Request::new(
            rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                instance_type_id: instance_type_id.clone(),
                machine_ids: vec![host.id.to_string()],
            },
        ))
        .await
        .unwrap();

    // Seed allocation count=1 for fail case.
    // Expect success with valid tenant/type.
    let allocation = create_compute_allocation(
        &env,
        &instance_type_id,
        1,
        &format!("alloc-update-increase-fail-{}", Uuid::new_v4()),
    )
    .await;

    // Increase count from 1 to 2.
    // Expect fail: only one machine is present.
    let err = update_compute_allocation(
        &env,
        &allocation,
        2,
        &format!("alloc-update-increase-fail-updated-{}", Uuid::new_v4()),
    )
    .await
    .unwrap_err();

    assert_eq!(err.code(), Code::FailedPrecondition);

    Ok(())
}

async fn test_remove_machine_association(
    pool: sqlx::PgPool,
    enforcement: ComputeAllocationEnforcement,
    associated_machine_count: usize,
    allocation_count: Option<u32>,
    should_pass: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            ..Default::default()
        }
        .with_compute_allocation_enforcement(enforcement),
    )
    .await;

    let instance_type_id = get_instance_type_fixture_id(&env).await;
    // Create tenant for allocation FK checks.
    // Expect success in isolated test DB.
    env.api
        .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
            organization_id: TENANT_ORG.to_string(),
            routing_profile_type: None,
            metadata: Some(metadata("compute-allocation-test-tenant")),
        }))
        .await
        .unwrap();

    let mut hosts = Vec::new();
    for _ in 0..associated_machine_count {
        let host = create_managed_host(&env).await;
        // Bind host to this instance type.
        // Expect success for a fresh host.
        env.api
            .associate_machines_with_instance_type(Request::new(
                rpc::forge::AssociateMachinesWithInstanceTypeRequest {
                    instance_type_id: instance_type_id.clone(),
                    machine_ids: vec![host.id.to_string()],
                },
            ))
            .await
            .unwrap();
        hosts.push(host);
    }

    if let Some(count) = allocation_count {
        // Seed allocation for removal checks.
        // Expect success with valid tenant/type.
        let _allocation = create_compute_allocation(
            &env,
            &instance_type_id,
            count,
            &format!("alloc-remove-assoc-{}", Uuid::new_v4()),
        )
        .await;
    }

    let host_to_remove = hosts.first().unwrap();
    // Try removing host association.
    // Result depends on enforcement mode.
    let result = env
        .api
        .remove_machine_instance_type_association(Request::new(
            rpc::forge::RemoveMachineInstanceTypeAssociationRequest {
                machine_id: host_to_remove.id.to_string(),
            },
        ))
        .await;

    if should_pass {
        result.unwrap();
    } else {
        let err = result.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_remove_machine_association_no_allocations_warn_only(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(pool, ComputeAllocationEnforcement::WarnOnly, 1, None, true)
        .await
}

#[crate::sqlx_test]
async fn test_remove_machine_association_no_allocations_enforce_if_present(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(
        pool,
        ComputeAllocationEnforcement::EnforceIfPresent,
        1,
        None,
        true,
    )
    .await
}

#[crate::sqlx_test]
async fn test_remove_machine_association_no_allocations_always(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(pool, ComputeAllocationEnforcement::Always, 2, None, true).await
}

#[crate::sqlx_test]
async fn test_remove_machine_association_allocations_less_than_remaining_warn_only(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(
        pool,
        ComputeAllocationEnforcement::WarnOnly,
        3,
        Some(1),
        true,
    )
    .await
}

#[crate::sqlx_test]
async fn test_remove_machine_association_allocations_less_than_remaining_enforce_if_present(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(
        pool,
        ComputeAllocationEnforcement::EnforceIfPresent,
        3,
        Some(1),
        true,
    )
    .await
}

#[crate::sqlx_test]
async fn test_remove_machine_association_allocations_less_than_remaining_always(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(pool, ComputeAllocationEnforcement::Always, 3, Some(1), true)
        .await
}

#[crate::sqlx_test]
async fn test_remove_machine_association_allocations_greater_than_remaining_warn_only(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(
        pool,
        ComputeAllocationEnforcement::WarnOnly,
        2,
        Some(2),
        true,
    )
    .await
}

#[crate::sqlx_test]
async fn test_remove_machine_association_allocations_greater_than_remaining_enforce_if_present(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(
        pool,
        ComputeAllocationEnforcement::EnforceIfPresent,
        2,
        Some(2),
        false,
    )
    .await
}

#[crate::sqlx_test]
async fn test_remove_machine_association_allocations_greater_than_remaining_always(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_remove_machine_association(
        pool,
        ComputeAllocationEnforcement::Always,
        2,
        Some(2),
        false,
    )
    .await
}
