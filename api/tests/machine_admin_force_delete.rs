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

use ::rpc::forge::{forge_server::Forge, AdminForceDeleteMachineRequest};
use carbide::{
    db::{
        machine::{Machine, MachineSearchConfig},
        machine_state_history::MachineStateHistory,
        machine_topology::MachineTopology,
    },
    ib::DEFAULT_IB_FABRIC_NAME,
    model::machine::{
        machine_id::{try_parse_machine_id, MachineId, MachineType},
        InstanceState, ManagedHostState,
    },
};

pub mod common;
use common::api_fixtures::{
    create_managed_host, create_test_env,
    dpu::create_dpu_machine,
    host::host_discover_dhcp,
    ib_partition::{create_ib_partition, DEFAULT_TENANT},
    instance::create_instance_with_ib_config,
    TestEnv,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_only(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert!(
        !MachineStateHistory::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !MachineTopology::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()])
            .await
            .unwrap()
            .is_empty()
    );

    let host = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();

    txn.rollback().await.unwrap();

    let response = force_delete(&env, &dpu_machine_id).await;
    validate_delete_response(&response, Some(host.id()), &dpu_machine_id);
    assert_eq!(
        response.dpu_machine_interface_id,
        dpu_machine.interfaces()[0].id().to_string()
    );

    assert!(response.all_done, "DPU must be deleted");

    // Validate that the DPU is gone
    validate_machine_deletion(&env, &dpu_machine_id).await;
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_and_host_by_dpu_machine_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let response = force_delete(&env, &dpu_machine_id).await;
    validate_delete_response(&response, Some(&host_machine_id), &dpu_machine_id);
    assert!(response.all_done, "Host must be deleted");

    for id in [host_machine_id, dpu_machine_id] {
        validate_machine_deletion(&env, &id).await;
    }
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_and_host_by_host_machine_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let response = force_delete(&env, &host_machine_id).await;
    validate_delete_response(&response, Some(&host_machine_id), &dpu_machine_id);

    assert!(env
        .find_machines(Some(host_machine_id.to_string().into()), None, true)
        .await
        .machines
        .is_empty());
    assert!(env
        .find_machines(Some(dpu_machine_id.to_string().into()), None, true)
        .await
        .machines
        .is_empty());

    assert!(response.all_done, "Host and DPU must be deleted");

    // Everything should be gone now
    for id in [host_machine_id, dpu_machine_id] {
        validate_machine_deletion(&env, &id).await;
    }
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_and_partially_discovered_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_interface_id =
        host_discover_dhcp(&env, &host_sim.config, &dpu_machine_id.clone()).await;

    // The MachineInterface for the host should now exist and be linked to the DPU
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(host_machine_interface_id.clone()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    assert_eq!(
        iface.attached_dpu_machine_id,
        Some(dpu_machine_id.to_string().into())
    );

    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();
    txn.commit().await.unwrap();

    let response = force_delete(&env, &dpu_machine_id).await;
    validate_delete_response(&response, Some(host.id()), &dpu_machine_id);
    assert!(response.all_done, "DPU must be deleted");

    validate_machine_deletion(&env, &dpu_machine_id).await;

    // The MachineInterface for the host should still exist
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(host_machine_interface_id),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    assert_eq!(iface.attached_dpu_machine_id, None);
}

async fn force_delete(
    env: &TestEnv,
    machine_id: &MachineId,
) -> rpc::forge::AdminForceDeleteMachineResponse {
    env.api
        .admin_force_delete_machine(tonic::Request::new(AdminForceDeleteMachineRequest {
            host_query: machine_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
}

fn validate_delete_response(
    response: &rpc::forge::AdminForceDeleteMachineResponse,
    host_machine_id: Option<&MachineId>,
    dpu_machine_id: &MachineId,
) {
    assert_eq!(response.dpu_machine_id, dpu_machine_id.to_string());
    assert_eq!(
        response.managed_host_machine_id,
        host_machine_id.map(|id| id.to_string()).unwrap_or_default()
    );
    assert!(!response.dpu_bmc_ip.is_empty());
    if let Some(host_machine_id) = host_machine_id {
        if host_machine_id.machine_type() == MachineType::Host {
            assert!(!response.managed_host_bmc_ip.is_empty());
        }
    } else {
        assert!(response.managed_host_bmc_ip.is_empty());
    }
}

/// Validates that the Machine has been fully deleted
async fn validate_machine_deletion(env: &TestEnv, machine_id: &MachineId) {
    // The machine should be now be gone in the API
    let response = env
        .find_machines(Some(machine_id.to_string().into()), None, true)
        .await;
    assert!(response.machines.is_empty());

    // And it should also be gone on the DB layer
    let mut txn = env.pool.begin().await.unwrap();
    assert!(
        Machine::find_one(&mut txn, machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        MachineTopology::find_by_machine_ids(&mut txn, &[machine_id.clone()])
            .await
            .unwrap()
            .is_empty()
    );

    // The history should remain in table.
    assert!(
        !MachineStateHistory::find_by_machine_ids(&mut txn, &[machine_id.clone()])
            .await
            .unwrap()
            .is_empty()
    );
    txn.rollback().await.unwrap();
}

// TODO: Test deletion for machines with active instances on them

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_host_with_ib_instance(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let ib_config = rpc::forge::InstanceInfinibandConfig {
        ib_interfaces: vec![rpc::forge::InstanceIbInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
            virtual_function_id: None,
            ib_partition_id: Some(ib_partition_id.into()),
            device: "MT2910 Family [ConnectX-7]".to_string(),
            vendor: None,
            device_instance: 1,
        }],
    };

    let (instance_id, _instance) =
        create_instance_with_ib_config(&env, &dpu_machine_id, &host_machine_id, ib_config).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    assert_eq!(
        instance.machine_id.clone().unwrap().id,
        host_machine_id.to_string()
    );
    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .tenant
            .as_ref()
            .unwrap()
            .state(),
        rpc::TenantState::Ready
    );

    let ib_config = instance
        .config
        .as_ref()
        .unwrap()
        .infiniband
        .as_ref()
        .unwrap();

    assert_eq!(ib_config.ib_interfaces.len(), 1);

    let ib_fabric = env
        .ib_fabric_manager
        .connect(DEFAULT_IB_FABRIC_NAME.to_string())
        .await
        .unwrap();

    // one ib port in UFM
    assert_eq!(ib_fabric.find_ib_port(None).await.unwrap().len(), 1);

    let response = force_delete(&env, &host_machine_id).await;
    validate_delete_response(&response, Some(&host_machine_id), &dpu_machine_id);

    // after host deleted, ib port should be removed from UFM
    assert_eq!(ib_fabric.find_ib_port(None).await.unwrap().len(), 0);

    assert!(env
        .find_machines(Some(host_machine_id.to_string().into()), None, true)
        .await
        .machines
        .is_empty());
    assert!(env
        .find_machines(Some(dpu_machine_id.to_string().into()), None, true)
        .await
        .machines
        .is_empty());

    assert_eq!(response.ufm_unregistrations, 1);
    assert!(response.all_done, "Host and DPU must be deleted");

    // Everything should be gone now
    for id in [host_machine_id, dpu_machine_id] {
        validate_machine_deletion(&env, &id).await;
    }
}
