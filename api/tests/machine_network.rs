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
use carbide::db::machine::MachineSearchConfig;
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
async fn test_managed_host_network_config_multi_dpu(pool: sqlx::PgPool) {
    // Given: A managed host with 2 DPUs
    let env = api_fixtures::create_test_env(pool).await;
    let managed_host_id = api_fixtures::managed_host::create_managed_host_multi_dpu(&env, 2).await;
    let host_machine = env
        .api
        .get_machine(tonic::Request::new(rpc::MachineId {
            id: managed_host_id.to_string(),
        }))
        .await
        .expect("Cannot look up the machine we just created")
        .into_inner();

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
    let (host_machine_id, dpu_machine_id) = api_fixtures::create_managed_host(&env).await;

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
    let dpu_health = rpc::health::HealthReport {
        source: "should-get-updated".to_string(),
        observed_at: None,
        successes: vec![
            rpc::health::HealthProbeSuccess {
                id: "ContainerExists".to_string(),
            },
            rpc::health::HealthProbeSuccess {
                id: "checkTwo".to_string(),
            },
        ],
        alerts: vec![],
    };
    env.api
        .record_dpu_network_status(tonic::Request::new(DpuNetworkStatus {
            dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
            observed_at: Some(SystemTime::now().into()),
            dpu_health: Some(dpu_health.clone()),
            health: Some(hs),
            network_config_version: Some(network_config_version.clone()),
            instance_id: Some(instance_id.into()),
            instance_config_version: Some(instance.config_version),
            instance_network_config_version: Some(instance.network_config_version),
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

    // Query the new HealthReport format - this is at this time only stored in
    // the database
    let mut txn = env.pool.begin().await.unwrap();

    let machine = carbide::db::machine::Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_dpus: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    txn.commit().await.unwrap();
    let mut health_report = machine.dpu_agent_health_report().unwrap().clone();
    assert!(health_report.observed_at.is_some());
    assert_eq!(health_report.source, "forge-dpu-agent");
    health_report.source = "should-get-updated".to_string();
    health_report.observed_at = None;
    assert_eq!(rpc::health::HealthReport::from(health_report), dpu_health);

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
        "instance_network_config_version: {}",
        instance.network_config_version
    );
    assert_eq!(
        instance.status.as_ref().unwrap().configs_synced,
        rpc::SyncState::Synced as i32
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_sending_only_network_health_updates_dpu_agent_health(pool: sqlx::PgPool) {
    let env = api_fixtures::create_test_env(pool).await;
    let (_host_machine_id, dpu_machine_id) = api_fixtures::create_managed_host(&env).await;

    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(dpu_machine_id.to_string().into()),
        }))
        .await
        .unwrap()
        .into_inner();

    // Tell API about latest network config and machine health
    let hs = NetworkHealth {
        is_healthy: false,
        passed: vec!["Success2".to_string()],
        failed: vec!["Fail1".to_string()],
        message: None,
    };

    let admin_if = response.admin_interface.as_ref().unwrap();

    // dpu-health is not updated here
    // We still expect forge-api to write it
    env.api
        .record_dpu_network_status(tonic::Request::new(DpuNetworkStatus {
            dpu_machine_id: Some(dpu_machine_id.to_string().into()),
            dpu_agent_version: Some(dpu::TEST_DPU_AGENT_VERSION.to_string()),
            observed_at: Some(SystemTime::now().into()),
            dpu_health: None,
            health: Some(hs),
            network_config_version: Some(response.managed_host_config_version.clone()),
            instance_id: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![rpc::InstanceInterfaceStatusObservation {
                function_type: admin_if.function_type,
                virtual_function_id: None,
                mac_address: None,
                addresses: vec![admin_if.ip.clone()],
            }],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
        }))
        .await
        .unwrap();

    // Query the new HealthReport format - this is at this time only stored in
    // the database
    let mut txn = env.pool.begin().await.unwrap();

    let machine = carbide::db::machine::Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_dpus: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    txn.commit().await.unwrap();
    let mut health_report = machine.dpu_agent_health_report().unwrap().clone();
    assert!(health_report.observed_at.is_some());
    health_report.observed_at = None;
    assert_eq!(health_report.alerts.len(), 1);
    assert!(health_report.alerts[0].in_alert_since.is_some());
    health_report.alerts[0].in_alert_since = None;
    assert_eq!(
        rpc::health::HealthReport::from(health_report),
        rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            observed_at: None,
            successes: vec![rpc::health::HealthProbeSuccess {
                id: "Success2".to_string()
            }],
            alerts: vec![rpc::health::HealthProbeAlert {
                id: "Fail1".to_string(),
                in_alert_since: None,
                message: "Fail1".to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_host_state_changes()
                        .to_string()
                ]
            }]
        }
    );
}
