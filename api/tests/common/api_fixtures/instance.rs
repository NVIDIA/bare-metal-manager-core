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

use carbide::model::machine::machine_id::MachineId;
use carbide::model::machine::CleanupState;
use carbide::model::machine::MachineState;
use carbide::state_controller::machine::handler::MachineStateHandler;
use carbide::{db::machine::Machine, model::machine::ManagedHostState};
use rpc::{forge::forge_server::Forge, InstanceReleaseRequest};

use super::TestEnv;

pub const FIXTURE_CIRCUIT_ID: &str = "vlan_100";
pub const FIXTURE_CIRCUIT_ID_1: &str = "vlan_101";

pub async fn create_instance(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    network: Option<rpc::InstanceNetworkConfig>,
    infiniband: Option<rpc::InstanceInfinibandConfig>,
    keyset_ids: Vec<String>,
) -> (uuid::Uuid, rpc::Instance) {
    let config = rpc::InstanceConfig {
        tenant: Some(rpc::TenantConfig {
            user_data: Some("SomeRandomData".to_string()),
            custom_ipxe: "SomeRandomiPxe".to_string(),
            tenant_organization_id: "Tenant1".to_string(),
            tenant_keyset_ids: keyset_ids,
            always_boot_with_custom_ipxe: false,
        }),
        network,
        infiniband,
    };

    create_instance_with_config(env, dpu_machine_id, host_machine_id, config).await
}

pub async fn create_instance_with_config(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    config: rpc::InstanceConfig,
) -> (uuid::Uuid, rpc::Instance) {
    let mut info = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config),
            ssh_keys: vec![],
        }))
        .await
        .expect("Create instance failed.")
        .into_inner();

    let handler = MachineStateHandler::default();

    // - first run: state controller moves state to WaitingForNetworkConfig
    env.run_machine_state_controller_iteration(host_machine_id.clone(), &handler)
        .await;
    // - second run: state controller sets use_admin_network to false
    env.run_machine_state_controller_iteration(host_machine_id.clone(), &handler)
        .await;
    // - forge-dpu-agent gets an instance network to configure, reports it configured
    let (_, instance_config_version) = super::network_configured(env, dpu_machine_id).await;
    if let Some(icv) = instance_config_version {
        info.network_config_version = icv;
    }

    // - third run: state controller runs again, advances state to Ready
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        &handler,
        2,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: carbide::model::machine::InstanceState::Ready,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let instance_id = uuid::Uuid::try_from(info.id.clone().expect("Missing instance ID")).unwrap();
    (instance_id, info)
}

pub async fn delete_instance(
    env: &TestEnv,
    instance_id: uuid::Uuid,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
) {
    env.api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
        }))
        .await
        .expect("Delete instance failed.");

    let handler = MachineStateHandler::default();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        &handler,
        1,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: carbide::model::machine::InstanceState::BootingWithDiscoveryImage,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        host_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    machine.update_reboot_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    // Run state machine twice.
    // First DeletingManagedResource updates use_admin_network, transitions to WaitingForNetworkReconfig
    // Second to discover we are now in WaitingForNetworkReconfig
    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        &handler,
        2,
        &mut txn,
        ManagedHostState::Assigned {
            instance_state: carbide::model::machine::InstanceState::WaitingForNetworkReconfig,
        },
    )
    .await;
    txn.commit().await.unwrap();

    // Apply switching back to admin network
    super::network_configured(env, dpu_machine_id).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        &handler,
        1,
        &mut txn,
        ManagedHostState::WaitingForCleanup {
            cleanup_state: CleanupState::HostCleanup,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        host_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    machine.update_reboot_time(&mut txn).await.unwrap();
    machine.update_cleanup_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        &handler,
        3,
        &mut txn,
        ManagedHostState::HostNotReady {
            machine_state: MachineState::Discovered,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        host_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    machine.update_reboot_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        host_machine_id,
        &handler,
        3,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();
}
