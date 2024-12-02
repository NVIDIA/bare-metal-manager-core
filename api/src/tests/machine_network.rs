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
};
use rpc::forge::forge_server::Forge;

use crate::tests::common;
use common::api_fixtures::{
    self, create_managed_host, dpu, instance, network_configured_with_health,
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};
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
async fn test_managed_host_network_config_multi_dpu(pool: sqlx::PgPool) {
    // Given: A managed host with 2 DPUs
    let env = api_fixtures::create_test_env(pool).await;
    let managed_host_id = api_fixtures::managed_host::create_managed_host_multi_dpu(&env, 2).await;
    let host_machine = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![managed_host_id.to_string().into()],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);

    let dpu_1_id = host_machine.associated_dpu_machine_ids[0].clone();
    let dpu_2_id = host_machine.associated_dpu_machine_ids[1].clone();

    // Then: Get the managed host network config version via DPU 1's ID and DPU 2's ID
    let dpu_1_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_1_id),
        }))
        .await
        .expect("Error getting DPU1 network config")
        .into_inner();
    let dpu_2_network_config = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_2_id),
        }))
        .await
        .expect("Error getting DPU1 network config")
        .into_inner();

    // Assert: They should not have the same config version, since the managed_host_config_version
    // represents the health of that particular DPU.
    assert!(dpu_1_network_config
        .managed_host_config_version
        .ne(&dpu_2_network_config.managed_host_config_version));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_managed_host_network_status(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // Add an instance
    let instance_network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some((*FIXTURE_NETWORK_SEGMENT_ID).into()),
            network_details: None,
        }],
    });
    let (_instance_id, _instance) = instance::create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        instance_network,
        None,
        None,
        vec![],
    )
    .await;

    let response = env
        .api
        .get_all_managed_host_network_status(tonic::Request::new(
            ManagedHostNetworkStatusRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.all.len(), 1);

    // Tell API about latest network config and machine health
    let dpu_health = rpc::health::HealthReport {
        source: "should-get-updated".to_string(),
        observed_at: None,
        successes: vec![
            rpc::health::HealthProbeSuccess {
                id: "ContainerExists".to_string(),
                target: Some("c1".to_string()),
            },
            rpc::health::HealthProbeSuccess {
                id: "checkTwo".to_string(),
                target: None,
            },
        ],
        alerts: vec![],
    };
    network_configured_with_health(&env, &dpu_machine_id, Some(dpu_health.clone())).await;

    // Query the aggregate health.
    let reported_health = env
        .api
        .get_machine(tonic::Request::new(dpu_machine_id.to_string().into()))
        .await
        .unwrap()
        .into_inner()
        .health;
    let mut reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    reported_health.observed_at = None;
    reported_health.source = "should-get-updated".to_string();
    assert_eq!(reported_health, dpu_health);

    // Now fetch the instance and check that knows its configs have synced
    let response = env
        .api
        .find_instance_by_machine_id(tonic::Request::new(host_machine_id.to_string().into()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.instances.len(), 1);
    let instance = &response.instances[0];
    tracing::info!(
        "instance_network_config_version: {}",
        instance.network_config_version
    );
    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced,
        rpc::SyncState::Synced as i32
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_dpu_health_is_required(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id.to_string().into()),
        }))
        .await
        .unwrap()
        .into_inner();

    let admin_if = response.admin_interface.as_ref().unwrap();

    // dpu-health is not updated here
    let err = env
        .api
        .record_dpu_network_status(tonic::Request::new(DpuNetworkStatus {
            dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
            observed_at: Some(SystemTime::now().into()),
            dpu_health: None,
            network_config_version: Some(response.managed_host_config_version.clone()),
            instance_id: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                function_type: admin_if.function_type,
                virtual_function_id: None,
                mac_address: None,
                addresses: vec![admin_if.ip.clone()],
                prefixes: vec![admin_if.interface_prefix.clone()],
                gateways: vec![admin_if.gateway.clone()],
            }],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
            fabric_interfaces: vec![],
            last_dhcp_requests: vec![],
        }))
        .await
        .expect_err("Should fail");

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(err.message(), "dpu_health");
}

/// Tests whether the in_alert_since field will be correctly populated
/// in case the DPU sends multiple reports using the same alarm
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_retain_in_alert_since(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let dpu_health = rpc::health::HealthReport {
        source: "should-get-updated".to_string(),
        observed_at: None,
        successes: vec![rpc::health::HealthProbeSuccess {
            id: "SuccessA".to_string(),
            target: None,
        }],
        alerts: vec![rpc::health::HealthProbeAlert {
            id: "AlertA".to_string(),
            target: None,
            in_alert_since: None,
            message: "AlertA".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_host_state_changes().to_string(),
            ],
        }],
    };

    network_configured_with_health(&env, &dpu_machine_id, Some(dpu_health.clone())).await;

    // Query the new HealthReport format
    let reported_health = env
        .api
        .get_machine(tonic::Request::new(dpu_machine_id.to_string().into()))
        .await
        .unwrap()
        .into_inner()
        .health;

    let reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    assert_eq!(reported_health.successes.len(), 1);
    assert_eq!(reported_health.alerts.len(), 1);
    let mut reported_alert = reported_health.alerts[0].clone();
    assert!(reported_alert.in_alert_since.is_some());
    let in_alert_since = reported_alert.in_alert_since.unwrap();
    reported_alert.in_alert_since = None;
    assert_eq!(reported_alert, dpu_health.alerts[0].clone());

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Report health again. The in_alert_since date should not have been updated
    network_configured_with_health(&env, &dpu_machine_id, Some(dpu_health.clone())).await;
    let reported_health = env
        .api
        .get_machine(tonic::Request::new(dpu_machine_id.to_string().into()))
        .await
        .unwrap()
        .into_inner()
        .health;
    let reported_health = reported_health.unwrap();
    assert!(reported_health.observed_at.is_some());
    assert_eq!(reported_health.successes.len(), 1);
    assert_eq!(reported_health.alerts.len(), 1);
    let mut reported_alert = reported_health.alerts[0].clone();
    assert_eq!(reported_alert.in_alert_since.unwrap(), in_alert_since);
    reported_alert.in_alert_since = None;
    assert_eq!(reported_alert, dpu_health.alerts[0].clone());
}
