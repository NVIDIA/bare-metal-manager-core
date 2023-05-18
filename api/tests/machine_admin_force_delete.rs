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

use carbide::{
    db::{
        machine::{Machine, MachineSearchConfig},
        machine_state_history::MachineStateHistory,
        machine_topology::MachineTopology,
        vpc_resource_leaf::VpcResourceLeaf,
    },
    model::machine::machine_id::{try_parse_machine_id, MachineId, MachineType},
};

use ::rpc::forge::{forge_server::Forge, AdminForceDeleteMachineRequest};

pub mod common;
use common::api_fixtures::{
    create_managed_host, create_test_env,
    dpu::{create_dpu_machine, FIXTURE_DPU_BMC_IP_ADDRESS},
    host::{host_discover_dhcp, FIXTURE_HOST_BMC_IP_ADDRESS, FIXTURE_HOST_MAC_ADDRESS},
    TestEnv,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_only(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default()).await;

    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();

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
    assert!(VpcResourceLeaf::find(&mut txn, &dpu_machine_id)
        .await
        .is_ok());

    let host = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap();

    txn.rollback().await.unwrap();

    let mut response = force_delete(&env, &dpu_machine_id).await;
    validate_initial_delete_response(&response, Some(host.id()), &dpu_machine_id);
    assert_eq!(
        response.dpu_machine_interface_id,
        dpu_machine.interfaces()[0].id().to_string()
    );

    let mut delete_attempts = 0;
    while !response.all_done && delete_attempts < 10 {
        response = force_delete(&env, &dpu_machine_id).await;
        delete_attempts += 10;
    }
    assert!(
        response.all_done,
        "DPU must be deleted after at most 10 attempts"
    );

    // Validate that the DPU is gone
    validate_machine_deletion(&env, &dpu_machine_id).await;
    // Check that the leaf is released
    assert_eq!(env.vpc_api.num_leafs(), 0);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_and_host_by_dpu_machine_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut response = force_delete(&env, &dpu_machine_id).await;
    validate_initial_delete_response(&response, Some(&host_machine_id), &dpu_machine_id);

    let mut delete_attempts = 0;
    while !response.all_done && delete_attempts < 10 {
        response = force_delete(&env, &dpu_machine_id).await;
        delete_attempts += 10;
    }
    assert!(
        response.all_done,
        "Host must be deleted after at most 10 attempts"
    );

    for id in [host_machine_id, dpu_machine_id] {
        validate_machine_deletion(&env, &id).await;
    }
    // Check that the leaf is released
    assert_eq!(env.vpc_api.num_leafs(), 0);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_and_host_by_host_machine_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut response = force_delete(&env, &host_machine_id).await;
    validate_initial_delete_response(&response, Some(&host_machine_id), &dpu_machine_id);

    let mut delete_attempts = 0;
    while !response.all_done && delete_attempts < 10 {
        response = force_delete(&env, &host_machine_id).await;
        delete_attempts += 10;
    }
    assert!(
        response.all_done,
        "Host must be deleted after at most 10 attempts"
    );

    // The host machine should be now be gone in the API
    assert!(env
        .find_machines(Some(host_machine_id.to_string().into()), None, true)
        .await
        .machines
        .is_empty());
    // The dpu machine should still exist - we just can't look it up anymore based on
    // a non-existing DPU machine. Therefore `all_done` was set
    assert!(!env
        .find_machines(Some(dpu_machine_id.to_string().into()), None, true)
        .await
        .machines
        .is_empty());

    // Continue deleting based on the DPU machine ID
    delete_attempts = 0;
    response.all_done = false;
    while !response.all_done && delete_attempts < 10 {
        response = force_delete(&env, &dpu_machine_id).await;
        delete_attempts += 10;
    }
    assert!(
        response.all_done,
        "DPU must be deleted after at most 10 attempts"
    );

    // Everything should be gone now
    for id in [host_machine_id, dpu_machine_id] {
        validate_machine_deletion(&env, &id).await;
    }
    // Check that the leaf is released
    assert_eq!(env.vpc_api.num_leafs(), 0);
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_force_delete_dpu_and_partially_discovered_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default()).await;
    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();
    let host_machine_interface_id =
        host_discover_dhcp(&env, FIXTURE_HOST_MAC_ADDRESS, &dpu_machine_id.clone()).await;

    // The MachineInterface for the host should now exist and be linked to the DPU
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(host_machine_interface_id.clone()),
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

    let mut response = force_delete(&env, &dpu_machine_id).await;
    validate_initial_delete_response(&response, Some(host.id()), &dpu_machine_id);

    let mut delete_attempts = 0;
    while !response.all_done && delete_attempts < 10 {
        response = force_delete(&env, &dpu_machine_id).await;
        delete_attempts += 10;
    }
    assert!(
        response.all_done,
        "DPU must be deleted after at most 10 attempts"
    );

    validate_machine_deletion(&env, &dpu_machine_id).await;
    // Check that the leaf is released
    assert_eq!(env.vpc_api.num_leafs(), 0);

    // The MachineInterface for the host should still exist
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(host_machine_interface_id),
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

fn validate_initial_delete_response(
    response: &rpc::forge::AdminForceDeleteMachineResponse,
    host_machine_id: Option<&MachineId>,
    dpu_machine_id: &MachineId,
) {
    assert!(!response.all_done);
    assert_eq!(response.dpu_machine_id, dpu_machine_id.to_string());
    assert_eq!(
        response.managed_host_machine_id,
        host_machine_id.map(|id| id.to_string()).unwrap_or_default()
    );
    assert_eq!(response.dpu_bmc_ip, FIXTURE_DPU_BMC_IP_ADDRESS);
    if let Some(host_machine_id) = host_machine_id {
        if host_machine_id.machine_type() == MachineType::Host {
            assert_eq!(response.managed_host_bmc_ip, FIXTURE_HOST_BMC_IP_ADDRESS);
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
