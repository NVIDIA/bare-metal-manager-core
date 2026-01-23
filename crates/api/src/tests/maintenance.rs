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

use carbide_uuid::machine::MachineId;
use common::api_fixtures::create_test_env;
use common::api_fixtures::instance::{
    default_os_config, default_tenant_config, single_interface_network_config,
};
use rpc::forge as rpcf;
use rpc::forge::forge_server::Forge;

use crate::tests::common;
use crate::tests::common::api_fixtures::{create_managed_host, create_managed_host_multi_dpu};

#[crate::sqlx_test]
async fn test_maintenance(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    // Create a machine
    let (host_id, _dpu_machine_id) = create_managed_host(&env).await.into();
    let (_host_id_2, _dpu_machine_id_2) = create_managed_host(&env).await.into();
    let rpc_host_id: MachineId = host_id;

    // enable maintenance mode
    let req = rpcf::MaintenanceRequest {
        operation: rpcf::MaintenanceOperation::Enable.into(),
        host_id: Some(rpc_host_id),
        reference: Some("https://jira.example.com/ABC-123".to_string()),
    };
    env.api
        .set_maintenance(tonic::Request::new(req))
        .await
        .unwrap();

    // Check that the expected alert is set on the Machine
    let mut host_machine = env.find_machine(rpc_host_id).await.remove(0);
    assert_eq!(
        host_machine.maintenance_reference.clone().unwrap(),
        "https://jira.example.com/ABC-123"
    );
    assert!(host_machine.maintenance_start_time.is_some());
    let alerts = &mut host_machine.health.as_mut().unwrap().alerts;
    assert_eq!(alerts.len(), 1);
    let alert = &mut alerts[0];
    assert!(alert.in_alert_since.is_some());
    alert.in_alert_since = None;
    assert_eq!(
        *alert,
        rpc::health::HealthProbeAlert {
            id: "Maintenance".to_string(),
            target: None,
            in_alert_since: None,
            message: "https://jira.example.com/ABC-123".to_string(),
            tenant_message: None,
            classifications: vec![
                "PreventAllocations".to_string(),
                "SuppressExternalAlerting".to_string()
            ]
        }
    );

    let instance_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        nvlink: None,
        network_security_group_id: None,
        dpu_extension_services: None,
    };

    // allocate: should fail
    let req = rpcf::InstanceAllocationRequest {
        instance_id: None,
        machine_id: Some(rpc_host_id),
        instance_type_id: None,
        config: Some(instance_config.clone()),
        metadata: Some(rpcf::Metadata {
            name: "test_instance".to_string(),
            description: "tests/maintenance".to_string(),
            labels: Vec::new(),
        }),
        allow_unhealthy_machine: false,
    };
    match env.api.allocate_instance(tonic::Request::new(req)).await {
        Ok(_) => {
            panic!("Allocating an instance on host in maintenance mode should fail");
        }
        Err(status) if status.code() == tonic::Code::FailedPrecondition => {
            // Expected
        }
        Err(err) => {
            eyre::bail!("allocate_instance unexpected status {err}");
        }
    }

    // list: should be included
    let machine_ids = env
        .api
        .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
            include_dpus: true,
            include_predicted_host: true,
            only_maintenance: true,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .machine_ids;
    assert_eq!(machine_ids.len(), 1); // Host
    assert_eq!(
        machine_ids[0], rpc_host_id,
        "Listing maintenance machines return incorrectly machines"
    );

    // disable maintenance
    let req = tonic::Request::new(rpcf::MaintenanceRequest {
        operation: rpcf::MaintenanceOperation::Disable.into(),
        host_id: Some(rpc_host_id),
        reference: None,
    });
    env.api.set_maintenance(req).await.unwrap();

    // Maintenance reference is cleared and there's no alarm anymore
    let host_machine = env.find_machine(rpc_host_id).await.remove(0);
    assert!(host_machine.maintenance_reference.is_none());
    assert!(host_machine.maintenance_start_time.is_none());
    let alerts = &host_machine.health.as_ref().unwrap().alerts;
    assert!(alerts.is_empty());

    // There are now no machines in maintenance mode
    let machine_ids = env
        .api
        .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
            include_dpus: true,
            include_predicted_host: true,
            only_maintenance: true,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .machine_ids;
    assert!(machine_ids.is_empty());

    // allocate: should succeed
    let req = rpcf::InstanceAllocationRequest {
        instance_id: None,
        machine_id: Some(rpc_host_id),
        instance_type_id: None,
        config: Some(instance_config),
        metadata: Some(rpc::Metadata {
            name: "test_instance".to_string(),
            description: "tests/maintenance".to_string(),
            labels: Vec::new(),
        }),
        allow_unhealthy_machine: false,
    };
    env.api.allocate_instance(tonic::Request::new(req)).await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_maintenance_multi_dpu(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    // Create a machine
    let mh = create_managed_host_multi_dpu(&env, 2).await;

    // enable maintenance mode
    let req = rpcf::MaintenanceRequest {
        operation: rpcf::MaintenanceOperation::Enable.into(),
        host_id: Some(mh.host().id),
        reference: Some("https://jira.example.com/ABC-123".to_string()),
    };
    env.api
        .set_maintenance(tonic::Request::new(req))
        .await
        .unwrap();

    let instance_config = rpcf::InstanceConfig {
        tenant: Some(default_tenant_config()),
        network: Some(single_interface_network_config(segment_id)),
        os: Some(default_os_config()),
        infiniband: None,
        nvlink: None,
        network_security_group_id: None,
        dpu_extension_services: None,
    };

    // allocate: should fail
    let req = rpcf::InstanceAllocationRequest {
        instance_id: None,
        machine_id: Some(mh.host().id),
        instance_type_id: None,
        config: Some(instance_config.clone()),
        metadata: Some(rpcf::Metadata {
            name: "test_instance".to_string(),
            description: "tests/maintenance".to_string(),
            labels: Vec::new(),
        }),
        allow_unhealthy_machine: false,
    };
    match env.api.allocate_instance(tonic::Request::new(req)).await {
        Ok(_) => {
            panic!("Allocating an instance on host in maintenance mode should fail");
        }
        Err(status) if status.code() == tonic::Code::FailedPrecondition => {
            // Expected
        }
        Err(err) => {
            eyre::bail!("allocate_instance unexpected status {err}");
        }
    }

    // list: should be included
    let machine_ids = env
        .api
        .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
            include_dpus: true,
            include_predicted_host: true,
            only_maintenance: true,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .machine_ids;

    assert_eq!(machine_ids.len(), 1); // Host
    assert_eq!(
        machine_ids[0],
        mh.host().id,
        "Listing maintenance machines return incorrectly machines"
    );

    // disable maintenance
    let req = tonic::Request::new(rpcf::MaintenanceRequest {
        operation: rpcf::MaintenanceOperation::Disable.into(),
        host_id: Some(mh.host().id),
        reference: None,
    });
    env.api.set_maintenance(req).await.unwrap();

    // There are now no machines in maintenance mode
    let machines_ids = env
        .api
        .find_machine_ids(tonic::Request::new(rpc::forge::MachineSearchConfig {
            include_dpus: true,
            include_predicted_host: true,
            only_maintenance: true,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .machine_ids;
    assert!(machines_ids.is_empty());

    // allocate: should succeed
    let req = rpcf::InstanceAllocationRequest {
        instance_id: None,
        machine_id: Some(mh.host().id),
        instance_type_id: None,
        config: Some(instance_config),
        metadata: Some(rpc::Metadata {
            name: "test_instance".to_string(),
            description: "tests/maintenance".to_string(),
            labels: Vec::new(),
        }),
        allow_unhealthy_machine: false,
    };
    env.api.allocate_instance(tonic::Request::new(req)).await?;

    Ok(())
}
