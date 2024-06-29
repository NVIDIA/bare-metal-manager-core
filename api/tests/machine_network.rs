/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::time::SystemTime;

use ::rpc::forge::{
    DpuNetworkStatus, ManagedHostNetworkConfigRequest, ManagedHostNetworkStatusRequest,
    NetworkHealth,
};
use rpc::forge::forge_server::Forge;

pub mod common;
use common::api_fixtures::{self, dpu, instance, network_segment::FIXTURE_NETWORK_SEGMENT_ID};
#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_managed_host_network_config(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id = dpu::create_dpu_machine(&env, &host_sim.config).await;

    // Fetch a Machines network config
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id),
        }))
        .await;

    assert!(response.is_ok());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_managed_host_network_status(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = api_fixtures::create_managed_host(&env).await;

    // We have the initial status that moved DPU from WaitingForLeafCreation to WaitingForDiscovery
    let response = env
        .api
        .get_all_managed_host_network_status(tonic::Request::new(
            ManagedHostNetworkStatusRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.all.len(), 1);

    // Add an instance
    let physical = rpc::InterfaceFunctionType::Physical as i32;
    let instance_network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: physical,
            network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID).into()),
        }],
    });
    let (instance_id, instance) = instance::create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        instance_network,
        None,
        vec![],
    )
    .await;

    // Tell API about latest network config and machine health
    let network_config_version = response.all[0].network_config_version.clone().unwrap();
    let hs = NetworkHealth {
        is_healthy: true,
        passed: vec!["ContainerExists".to_string(), "checkTwo".to_string()],
        failed: vec!["".to_string()],
        message: None,
    };
    env.api
        .record_dpu_network_status(tonic::Request::new(DpuNetworkStatus {
            dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
            observed_at: Some(SystemTime::now().into()),
            health: Some(hs),
            network_config_version: Some(network_config_version.clone()),
            instance_id: Some(instance_id.into()),
            instance_config_version: Some(instance.network_config_version),
            interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                function_type: physical,
                virtual_function_id: None,
                mac_address: None,
                addresses: vec!["1.2.3.4".to_string()],
            }],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
        }))
        .await
        .unwrap();

    // And query again
    let response = env
        .api
        .get_all_managed_host_network_status(tonic::Request::new(
            ManagedHostNetworkStatusRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.all.len(), 1);

    let health = response.all[0].health.as_ref().unwrap();
    assert!(health.is_healthy);
    assert_eq!(health.passed[0], "ContainerExists");

    assert_eq!(
        response.all[0].network_config_version,
        Some(network_config_version),
    );

    // Now fetch the instance and check that knows it's configs have synced
    let response = env
        .api
        .find_instance_by_machine_id(tonic::Request::new(host_machine_id.to_string().into()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.instances.len(), 1);
    let instance = &response.instances[0];
    tracing::info!(
        "instance_config_version: {}",
        instance.network_config_version
    );
    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced,
        rpc::SyncState::Synced as i32
    );
}
