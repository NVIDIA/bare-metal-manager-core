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

use rpc::forge as rpcf;
use rpc::forge::forge_server::Forge;
use std::collections::HashSet;

mod common;
use common::api_fixtures::{
    create_test_env,
    instance::{default_tenant_config, single_interface_network_config},
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

use crate::common::api_fixtures::create_managed_host;
use crate::common::api_fixtures::managed_host::create_managed_host_multi_dpu;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_maintenance(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;

    // Create a machine
    let (host_id, dpu_machine_id) = create_managed_host(&env).await;
    let rpc_host_id: rpc::MachineId = host_id.to_string().into();
    let rpc_dpu_machine_id = dpu_machine_id.to_string().into();

    // enable maintenance mode
    let req = rpcf::MaintenanceRequest {
        operation: rpcf::MaintenanceOperation::Enable.into(),
        host_id: Some(rpc_host_id.clone()),
        reference: Some("https://jira.example.com/ABC-123".to_string()),
    };
    env.api
        .set_maintenance(tonic::Request::new(req))
        .await
        .unwrap();

    let instance_config = rpcf::InstanceConfig {
        tenant: Some(default_tenant_config()),
        network: Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    // allocate: should fail
    let req = rpcf::InstanceAllocationRequest {
        instance_id: None,
        machine_id: Some(rpc_host_id.clone()),
        config: Some(instance_config.clone()),
        metadata: Some(rpcf::Metadata {
            name: "test_instance".to_string(),
            description: "tests/maintenance".to_string(),
            labels: Vec::new(),
        }),
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
    let machines = env
        .api
        .find_machines(tonic::Request::new(rpcf::MachineSearchQuery {
            id: None,
            fqdn: None,
            search_config: Some(rpcf::MachineSearchConfig {
                include_dpus: true,
                include_predicted_host: true,
                only_maintenance: true,
                ..Default::default()
            }),
        }))
        .await?;
    let machines = machines.into_inner().machines;
    assert_eq!(machines.len(), 2); // Host and DPU
    let has_host = *machines[0].id.as_ref().unwrap() == rpc_host_id
        || *machines[1].id.as_ref().unwrap() == rpc_host_id;
    let has_dpu = *machines[0].id.as_ref().unwrap() == rpc_dpu_machine_id
        || *machines[1].id.as_ref().unwrap() == rpc_dpu_machine_id;
    if !has_host || !has_dpu {
        panic!("Listing maintenance machines return incorrectly machines. {machines:?}");
    }

    // disable maintenance
    let req = tonic::Request::new(rpcf::MaintenanceRequest {
        operation: rpcf::MaintenanceOperation::Disable.into(),
        host_id: Some(rpc_host_id.clone()),
        reference: None,
    });
    env.api.set_maintenance(req).await.unwrap();

    // There are now no machines in maintenance mode
    let machines = env
        .api
        .find_machines(tonic::Request::new(rpcf::MachineSearchQuery {
            id: None,
            fqdn: None,
            search_config: Some(rpcf::MachineSearchConfig {
                include_dpus: true,
                include_predicted_host: true,
                only_maintenance: true,
                ..Default::default()
            }),
        }))
        .await?;
    let machines = machines.into_inner().machines;
    assert!(machines.is_empty());

    // allocate: should succeed
    let req = rpcf::InstanceAllocationRequest {
        instance_id: None,
        machine_id: Some(rpc_host_id.clone()),
        config: Some(instance_config),
        metadata: Some(rpc::Metadata {
            name: "test_instance".to_string(),
            description: "tests/maintenance".to_string(),
            labels: Vec::new(),
        }),
    };
    env.api.allocate_instance(tonic::Request::new(req)).await?;

    Ok(())
}
#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_maintenance_multi_dpu(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;

    // Create a machine
    let host_id = create_managed_host_multi_dpu(&env, 2).await;
    let rpc_host_id: rpc::MachineId = host_id.to_string().into();

    let host = env
        .api
        .get_machine(tonic::Request::new(rpc_host_id.clone()))
        .await
        .unwrap()
        .into_inner();
    let rpc_dpu_ids = host.associated_dpu_machine_ids;

    // enable maintenance mode
    let req = rpcf::MaintenanceRequest {
        operation: rpcf::MaintenanceOperation::Enable.into(),
        host_id: Some(rpc_host_id.clone()),
        reference: Some("https://jira.example.com/ABC-123".to_string()),
    };
    env.api
        .set_maintenance(tonic::Request::new(req))
        .await
        .unwrap();

    let instance_config = rpcf::InstanceConfig {
        tenant: Some(default_tenant_config()),
        network: Some(single_interface_network_config(FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    // allocate: should fail
    let req = rpcf::InstanceAllocationRequest {
        instance_id: None,
        machine_id: Some(rpc_host_id.clone()),
        config: Some(instance_config.clone()),
        metadata: Some(rpcf::Metadata {
            name: "test_instance".to_string(),
            description: "tests/maintenance".to_string(),
            labels: Vec::new(),
        }),
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
    let machines = env
        .api
        .find_machines(tonic::Request::new(rpcf::MachineSearchQuery {
            id: None,
            fqdn: None,
            search_config: Some(rpcf::MachineSearchConfig {
                include_dpus: true,
                include_predicted_host: true,
                only_maintenance: true,
                ..Default::default()
            }),
        }))
        .await?;
    let machines = machines.into_inner().machines;
    assert_eq!(machines.len(), 3); // Host and 2 DPUs

    let found_id_set = machines
        .iter()
        .map(|m| m.id.as_ref().unwrap().to_string())
        .collect::<HashSet<_>>();
    assert!(
        found_id_set.contains(&rpc_host_id.id),
        "Did not find host machine when searching for maintenance machines"
    );

    let dpu_id_set = rpc_dpu_ids
        .iter()
        .map(|i| i.id.clone())
        .collect::<HashSet<_>>();
    assert!(
        found_id_set.is_superset(&dpu_id_set),
        "Did not find expected DPU machines when searching for maintenance machines"
    );

    // disable maintenance
    let req = tonic::Request::new(rpcf::MaintenanceRequest {
        operation: rpcf::MaintenanceOperation::Disable.into(),
        host_id: Some(rpc_host_id.clone()),
        reference: None,
    });
    env.api.set_maintenance(req).await.unwrap();

    // There are now no machines in maintenance mode
    let machines = env
        .api
        .find_machines(tonic::Request::new(rpcf::MachineSearchQuery {
            id: None,
            fqdn: None,
            search_config: Some(rpcf::MachineSearchConfig {
                include_dpus: true,
                include_predicted_host: true,
                only_maintenance: true,
                ..Default::default()
            }),
        }))
        .await?;
    let machines = machines.into_inner().machines;
    assert!(machines.is_empty());

    // allocate: should succeed
    let req = rpcf::InstanceAllocationRequest {
        instance_id: None,
        machine_id: Some(rpc_host_id.clone()),
        config: Some(instance_config),
        metadata: Some(rpc::Metadata {
            name: "test_instance".to_string(),
            description: "tests/maintenance".to_string(),
            labels: Vec::new(),
        }),
    };
    env.api.allocate_instance(tonic::Request::new(req)).await?;

    Ok(())
}
