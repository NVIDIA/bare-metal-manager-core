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

use common::api_fixtures::{
    TestEnvOverrides, create_managed_host, create_managed_host_with_config, create_test_env,
    create_test_env_with_overrides,
};
use ipnetwork::IpNetwork;
use model::machine::{InstanceState, ManagedHostState, SpdmMeasuringState};
use model::test_support::ManagedHostConfig;
use rpc::forge::forge_server::Forge;
use tonic::IntoRequest;

use crate::CarbideError;
use crate::handlers::client_resolution::resolve_machine_interface;
use crate::test_support::fixture_config::ManagedHostConfigExt as _;
use crate::tests::common;
use crate::tests::common::api_fixtures::instance::{
    default_os_config, default_tenant_config, single_interface_network_config,
};
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    create_host_inband_network_segment,
};

// A client_ip that matches a row in machine_interface_addresses (the
// common admin/host case) should resolve directly to that interface.
#[crate::sqlx_test]
async fn test_resolve_machine_interface_via_direct_admin_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[mh.host().id])
        .await
        .unwrap();
    let host_iface = &interfaces[&mh.host().id][0];
    let admin_ip = host_iface.addresses[0];
    let expected_interface_id = host_iface.id;
    txn.rollback().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let resolved = resolve_machine_interface(txn.as_mut(), admin_ip)
        .await
        .expect("admin IP should resolve to its machine_interface");
    txn.rollback().await.unwrap();

    assert_eq!(resolved.id, expected_interface_id);
}

// A client_ip that maps to a tenant-allocated instance_address (rather
// than a machine_interface_addresses entry) should resolve to the
// host's admin machine_interface via instance -> host_machine_id ->
// host_interfaces. This is the "PXE-booting an assigned host over its
// tenant network" path that the find_by_ip fallback was added for.
#[crate::sqlx_test]
async fn test_resolve_machine_interface_via_instance_address(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[mh.host().id])
        .await
        .unwrap();
    let expected_interface_id = interfaces[&mh.host().id][0].id;
    txn.rollback().await.unwrap();

    let config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
        spxconfig: None,
    };
    let tinstance = mh.instance_builer(&env).config(config).build().await;

    // Look up the tenant IP carbide-api allocated to the instance.
    let mut txn = env.pool.begin().await.unwrap();
    let inst_addr = db::instance_address::find_by_instance_id_and_segment_id(
        txn.as_mut(),
        &tinstance.id,
        &segment_id,
    )
    .await
    .unwrap()
    .expect("instance should have a tenant address on the segment");
    let tenant_ip = inst_addr.address;

    let resolved = resolve_machine_interface(txn.as_mut(), tenant_ip)
        .await
        .expect("tenant IP should resolve to the host's admin machine_interface");
    txn.rollback().await.unwrap();

    // The resolved interface is the host's admin interface -- the same one
    // we'd have hit if the request had come in on the admin IP directly.
    assert_eq!(resolved.id, expected_interface_id);
}

// A client_ip that isn't in either table should NotFound cleanly.
#[crate::sqlx_test]
async fn test_resolve_machine_interface_unknown_ip_returns_not_found(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let mut txn = env.pool.begin().await.unwrap();
    let result = resolve_machine_interface(txn.as_mut(), "203.0.113.99".parse().unwrap()).await;
    txn.rollback().await.unwrap();

    let err = result.expect_err("expected NotFound for unknown client IP");
    match err {
        CarbideError::NotFoundError { kind, .. } => {
            assert_eq!(kind, "Client", "expected NotFound kind=Client, got {kind}")
        }
        other => panic!("expected NotFoundError, got {other:?}"),
    }
}

#[crate::sqlx_test]
async fn test_zero_dpu_cloud_init_prefers_instance_when_ip_matches_host_interface(
    pool: sqlx::PgPool,
) {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            ..Default::default()
        },
    )
    .await;
    create_host_inband_network_segment(&env.api, None).await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    let mh = create_managed_host_with_config(&env, ManagedHostConfig::with_dpus(Vec::new())).await;
    assert!(
        mh.dpu_ids.is_empty(),
        "zero-DPU fixture should produce no DPU machines"
    );

    let mut txn = env.pool.begin().await.unwrap();
    let host_interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[mh.host().id])
        .await
        .unwrap();
    let host_ip = host_interfaces[&mh.host().id][0].addresses[0];
    txn.rollback().await.unwrap();

    let tenant_user_data = "#cloud-config\ntenant-user-data";
    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            machine_id: Some(mh.host().id),
            instance_type_id: None,
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(rpc::forge::InstanceOperatingSystemConfig {
                    user_data: Some(tenant_user_data.to_string()),
                    ..default_os_config()
                }),
                network: Some(rpc::forge::InstanceNetworkConfig {
                    interfaces: vec![],
                    auto: true,
                }),
                infiniband: None,
                network_security_group_id: None,
                dpu_extension_services: None,
                nvlink: None,
                spxconfig: None,
            }),
            instance_id: None,
            metadata: None,
            allow_unhealthy_machine: false,
        }))
        .await
        .expect("zero-DPU instance allocation should succeed")
        .into_inner();
    let instance_id = instance.id.expect("allocated instance should have an ID");

    let instance_address = db::instance_address::find_by_address(&env.pool, host_ip)
        .await
        .unwrap()
        .expect("zero-DPU instance should reuse the host interface IP");
    assert_eq!(instance_address.instance_id, instance_id);

    // When not ready yet, we should get discovery cloud-init instructions
    {
        env.run_machine_state_controller_iteration_until_state_matches(
            &mh.host().id,
            50,
            ManagedHostState::PreAssignedMeasuring {
                spdm_measuring_state: SpdmMeasuringState::TriggerMeasurements,
            },
        )
        .await;

        let cloud_init = env
            .api
            .get_cloud_init_instructions(
                rpc::forge::CloudInitInstructionsRequest {
                    ip: host_ip.to_string(),
                }
                .into_request(),
            )
            .await
            .expect("get_cloud_init_instructions returned an error")
            .into_inner();

        assert!(
            cloud_init.custom_cloud_init.is_none(),
            "Should not get tenant instructions when machine is in PreAssignedMeasuring"
        );
        assert!(
            cloud_init.discovery_instructions.is_some(),
            "Should get discovery instructions when machine is in PreAssignedMeasuring"
        );
    }

    // When the instance is ready, we should get tenant cloud-init instructions
    for instance_state in [InstanceState::WaitingForRebootToReady, InstanceState::Ready] {
        env.run_machine_state_controller_iteration_until_state_matches(
            &mh.host().id,
            10,
            ManagedHostState::Assigned { instance_state },
        )
        .await;

        let cloud_init = env
            .api
            .get_cloud_init_instructions(tonic::Request::new(
                rpc::forge::CloudInitInstructionsRequest {
                    ip: host_ip.to_string(),
                },
            ))
            .await
            .expect("get_cloud_init_instructions returned an error")
            .into_inner();

        assert_eq!(
            cloud_init.custom_cloud_init.as_deref(),
            Some(tenant_user_data)
        );
        assert!(
            cloud_init.discovery_instructions.is_none(),
            "tenant cloud-init must not render discovery instructions for the shared zero-DPU IP"
        );
        assert_eq!(
            cloud_init
                .metadata
                .expect("tenant cloud-init should include metadata")
                .instance_id,
            instance_id.to_string()
        );
    }
}
