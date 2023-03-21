/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
pub use crate::common::api_fixtures::FIXTURE_DPU_MACHINE_ID;
pub use crate::common::api_fixtures::FIXTURE_X86_MACHINE_ID;

use super::TestEnv;
use carbide::model::machine::CleanupState;
use carbide::model::machine::MachineState;
use carbide::state_controller::machine::handler::MachineStateHandler;
use carbide::{db::machine::Machine, model::machine::ManagedHostState};
use rpc::{forge::forge_server::Forge, InstanceReleaseRequest};

pub const FIXTURE_CIRCUIT_ID: &str = "vlan_100";
pub const FIXTURE_CIRCUIT_ID_1: &str = "vlan_101";

pub async fn prepare_machine(pool: &sqlx::PgPool) {
    let mut txn = pool.begin().await.unwrap();
    let machine = Machine::find_one(
        &mut txn,
        FIXTURE_X86_MACHINE_ID,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(machine.current_state(), ManagedHostState::Created));
    machine
        .advance(&mut txn, ManagedHostState::Ready, None)
        .await
        .unwrap();
    let machine = Machine::find_one(
        &mut txn,
        FIXTURE_DPU_MACHINE_ID,
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(machine.current_state(), ManagedHostState::Created));
    machine
        .advance(&mut txn, ManagedHostState::Ready, None)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

pub async fn create_instance(
    env: &TestEnv,
    network: Option<rpc::InstanceNetworkConfig>,
) -> (uuid::Uuid, rpc::Instance) {
    // Note: This also requests a background task in the DB for creating managed
    // resources. That's however ok - we will just ignore it and not execute
    // that task. Later we might also verify that the creation of those resources
    // is requested
    let info = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            machine_id: Some(FIXTURE_X86_MACHINE_ID.to_string().into()),
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
        FIXTURE_DPU_MACHINE_ID,
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

pub async fn delete_instance(env: &TestEnv, instance_id: uuid::Uuid) {
    env.api
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id.into()),
        }))
        .await
        .expect("Delete instance failed.");

    let handler = MachineStateHandler::default();

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        FIXTURE_DPU_MACHINE_ID,
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
        FIXTURE_X86_MACHINE_ID,
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
        FIXTURE_DPU_MACHINE_ID,
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
        FIXTURE_X86_MACHINE_ID,
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
        FIXTURE_DPU_MACHINE_ID,
        &handler,
        3,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();
}
