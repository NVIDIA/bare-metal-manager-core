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

use super::TestEnv;
use carbide::model::machine::machine_id::MachineId;
use carbide::model::machine::CleanupState;
use carbide::model::machine::MachineState;
use carbide::state_controller::machine::handler::MachineStateHandler;
use carbide::{db::machine::Machine, model::machine::ManagedHostState};
use rpc::{forge::forge_server::Forge, InstanceReleaseRequest};

pub const FIXTURE_CIRCUIT_ID: &str = "vlan_100";
pub const FIXTURE_CIRCUIT_ID_1: &str = "vlan_101";

pub async fn create_instance(
    env: &TestEnv,
    host_machine_id: &MachineId,
    dpu_machine_id: &MachineId,
    network: Option<rpc::InstanceNetworkConfig>,
) -> (uuid::Uuid, rpc::Instance) {
    let info = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(rpc::TenantConfig {
                    user_data: Some("SomeRandomData".to_string()),
                    custom_ipxe: "SomeRandomiPxe".to_string(),
                    tenant_organization_id: "Tenant1".to_string(),
                    tenant_keyset_ids: vec![],
                }),
                network,
            }),
            ssh_keys: vec!["mykey1".to_owned()],
        }))
        .await
        .expect("Create instance failed.")
        .into_inner();

    let handler = MachineStateHandler::default();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        dpu_machine_id,
        &handler,
        2,
        &mut txn,
        ManagedHostState::Assigned(carbide::model::machine::InstanceState::Ready),
    )
    .await;
    txn.commit().await.unwrap();
    let instance_id = uuid::Uuid::try_from(info.id.clone().expect("Missing instance ID")).unwrap();
    (instance_id, info)
}

pub async fn delete_instance(
    env: &TestEnv,
    instance_id: uuid::Uuid,
    host_machine_id: &MachineId,
    dpu_machine_id: &MachineId,
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
        dpu_machine_id,
        &handler,
        3,
        &mut txn,
        ManagedHostState::WaitingForCleanup(CleanupState::HostCleanup),
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        host_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
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
        dpu_machine_id,
        &handler,
        3,
        &mut txn,
        ManagedHostState::HostNotReady(MachineState::Discovered),
    )
    .await;
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        host_machine_id,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
        },
    )
    .await
    .unwrap()
    .unwrap();
    machine.update_reboot_time(&mut txn).await.unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        dpu_machine_id,
        &handler,
        3,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();
}
