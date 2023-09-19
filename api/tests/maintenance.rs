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

mod common;
use common::api_fixtures::{create_test_env, network_segment::FIXTURE_NETWORK_SEGMENT_ID};

use crate::common::api_fixtures::create_managed_host;

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

    // allocate: should fail

    let tenant = rpcf::TenantConfig {
        user_data: Some("SomeRandomData".to_string()),
        custom_ipxe: "SomeRandomiPxe".to_string(),
        tenant_organization_id: "Tenant1".to_string(),
        tenant_keyset_ids: vec![],
    };
    let network = rpcf::InstanceNetworkConfig {
        interfaces: vec![rpcf::InstanceInterfaceConfig {
            function_type: rpcf::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    };
    let req = rpcf::InstanceAllocationRequest {
        machine_id: Some(rpc_host_id.clone()),
        config: Some(rpcf::InstanceConfig {
            tenant: Some(tenant.clone()),
            network: Some(network.clone()),
            infiniband: None,
        }),
        ssh_keys: vec![],
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
        machine_id: Some(rpc_host_id.clone()),
        config: Some(rpcf::InstanceConfig {
            tenant: Some(tenant.clone()),
            network: Some(network.clone()),
            infiniband: None,
        }),
        ssh_keys: vec![],
    };
    env.api.allocate_instance(tonic::Request::new(req)).await?;

    Ok(())
}
