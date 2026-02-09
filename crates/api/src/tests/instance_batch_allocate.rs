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

//! Tests for batch instance allocation API

use ::rpc::forge::forge_server::Forge;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network::NetworkSegmentId;
use common::api_fixtures::instance::{
    default_os_config, default_tenant_config, single_interface_network_config,
};
use common::api_fixtures::{
    TestEnv, create_managed_host, create_test_env, populate_network_security_groups,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use crate::tests::common;
use crate::tests::common::api_fixtures::TestManagedHost;

/// Allocate 3 instances in a single batch request.
/// Expect all 3 instances to be created with correct machine_id and network config.
#[crate::sqlx_test]
async fn test_batch_allocate_instances_success(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Create 3 managed hosts
    let mh1 = create_managed_host(&env).await;
    let mh2 = create_managed_host(&env).await;
    let mh3 = create_managed_host(&env).await;

    // Build batch allocation request
    let batch_request = rpc::forge::BatchInstanceAllocationRequest {
        instance_requests: vec![
            build_test_instance_allocation_request(&env, &mh1, segment_id),
            build_test_instance_allocation_request(&env, &mh2, segment_id),
            build_test_instance_allocation_request(&env, &mh3, segment_id),
        ],
    };

    // Call batch API
    let response = env
        .api
        .allocate_instances(tonic::Request::new(batch_request))
        .await
        .unwrap()
        .into_inner();

    // Verify response
    assert_eq!(response.instances.len(), 3);

    // Verify all instances are in the database
    let mut txn = env.db_txn().await;
    for instance in &response.instances {
        let machine_id = *instance.machine_id.as_ref().unwrap();
        let snapshot = db::managed_host::load_snapshot(
            &mut txn,
            &machine_id,
            model::machine::LoadSnapshotOptions::default(),
        )
        .await
        .unwrap();

        assert!(snapshot.is_some());
        let snapshot = snapshot.unwrap();
        assert!(snapshot.instance.is_some());

        let instance_snapshot = snapshot.instance.unwrap();
        assert_eq!(instance_snapshot.machine_id, machine_id);
        assert!(!instance_snapshot.config.network.interfaces.is_empty());
    }
}

/// Include an invalid machine ID in a batch of 3 requests.
/// Expect the entire batch to fail and all allocations to be rolled back.
#[crate::sqlx_test]
async fn test_batch_allocate_instances_rollback_on_failure(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let mh1 = create_managed_host(&env).await;
    let mh2 = create_managed_host(&env).await;

    // Create an invalid machine ID that doesn't exist
    #[allow(deprecated)]
    let invalid_machine_id = MachineId::default();

    let batch_request = rpc::forge::BatchInstanceAllocationRequest {
        instance_requests: vec![
            build_test_instance_allocation_request(&env, &mh1, segment_id),
            // Invalid request - machine doesn't exist
            rpc::forge::InstanceAllocationRequest {
                machine_id: Some(invalid_machine_id),
                config: Some(rpc::forge::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(single_interface_network_config(segment_id)),
                    infiniband: None,
                    network_security_group_id: None,
                    dpu_extension_services: None,
                    nvlink: None,
                }),
                instance_id: None,
                instance_type_id: None,
                metadata: Some(rpc::forge::Metadata {
                    name: "test-instance-invalid".to_string(),
                    description: "".to_string(),
                    labels: vec![],
                }),
                allow_unhealthy_machine: false,
            },
            build_test_instance_allocation_request(&env, &mh2, segment_id),
        ],
    };

    // Call should fail
    let result = env
        .api
        .allocate_instances(tonic::Request::new(batch_request))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.message().contains("Machine") || err.message().contains("not found"),
        "Expected error about machine not found, got: {}",
        err.message()
    );

    // Verify that the first instance was NOT created (transaction rolled back)
    let mut txn = env.db_txn().await;
    let snapshot1 = db::managed_host::load_snapshot(
        &mut txn,
        &mh1.host().id,
        model::machine::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    assert!(
        snapshot1.instance.is_none(),
        "Instance should not exist - transaction should have rolled back"
    );

    // Verify that the third instance was also NOT created
    let snapshot2 = db::managed_host::load_snapshot(
        &mut txn,
        &mh2.host().id,
        model::machine::LoadSnapshotOptions::default(),
    )
    .await
    .unwrap()
    .unwrap();

    assert!(
        snapshot2.instance.is_none(),
        "Instance should not exist - transaction should have rolled back"
    );
}

/// Send an empty batch request with no instances.
/// Expect an error indicating at least one instance is required.
#[crate::sqlx_test]
async fn test_batch_allocate_instances_empty_request(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;

    let batch_request = rpc::forge::BatchInstanceAllocationRequest {
        instance_requests: vec![],
    };

    let result = env
        .api
        .allocate_instances(tonic::Request::new(batch_request))
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.message().contains("at least one instance"),
        "Expected error about empty request, got: {}",
        err.message()
    );
}

/// Allocate 2 instances sharing the same NSG in one batch.
/// Expect both instances to be created successfully with the shared NSG.
#[crate::sqlx_test]
async fn test_batch_allocate_instances_with_same_nsg(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    // Populate network security groups
    populate_network_security_groups(env.api.clone()).await;

    let mh1 = create_managed_host(&env).await;
    let mh2 = create_managed_host(&env).await;

    // Get an NSG ID that was created by populate_network_security_groups
    let nsg_id = "fd3ab096-d811-11ef-8fe9-7be4b2483448".to_string();

    // Build requests with the same NSG
    let mut req1 = build_test_instance_allocation_request(&env, &mh1, segment_id);
    req1.config.as_mut().unwrap().network_security_group_id = Some(nsg_id.clone());

    let mut req2 = build_test_instance_allocation_request(&env, &mh2, segment_id);
    req2.config.as_mut().unwrap().network_security_group_id = Some(nsg_id);

    let batch_request = rpc::forge::BatchInstanceAllocationRequest {
        instance_requests: vec![req1, req2],
    };

    // Call batch API - should succeed with shared NSG validation
    let response = env
        .api
        .allocate_instances(tonic::Request::new(batch_request))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.instances.len(), 2);
}

// Helper function to build a test instance allocation request
fn build_test_instance_allocation_request(
    _env: &TestEnv,
    mh: &TestManagedHost,
    segment_id: NetworkSegmentId,
) -> rpc::forge::InstanceAllocationRequest {
    rpc::forge::InstanceAllocationRequest {
        machine_id: Some(mh.host().id),
        config: Some(rpc::forge::InstanceConfig {
            tenant: Some(default_tenant_config()),
            os: Some(default_os_config()),
            network: Some(single_interface_network_config(segment_id)),
            infiniband: None,
            network_security_group_id: None,
            dpu_extension_services: None,
            nvlink: None,
        }),
        instance_id: None,
        instance_type_id: None,
        metadata: Some(rpc::forge::Metadata {
            name: format!("test-instance-{}", uuid::Uuid::new_v4()),
            description: "Test instance for batch allocation".to_string(),
            labels: vec![],
        }),
        allow_unhealthy_machine: false,
    }
}
