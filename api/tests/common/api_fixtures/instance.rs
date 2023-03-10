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
use super::TestApi;
use carbide::{db::machine::Machine, model::machine::MachineState};
use rpc::{forge::forge_server::Forge, InstanceReleaseRequest};

pub const FIXTURE_X86_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd99");
pub const FIXTURE_CIRCUIT_ID: &str = "vlan_100";
pub const FIXTURE_CIRCUIT_ID_1: &str = "vlan_101";

pub async fn prepare_machine(pool: &sqlx::PgPool) {
    let mut txn = pool.begin().await.unwrap();
    let machine = Machine::find_one(&mut txn, FIXTURE_X86_MACHINE_ID)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(machine.current_state(), MachineState::Init));
    machine
        .advance(&mut txn, MachineState::Adopted)
        .await
        .unwrap();
    machine
        .advance(&mut txn, MachineState::Ready)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

pub async fn create_instance(
    api: &TestApi,
    network: Option<rpc::InstanceNetworkConfig>,
) -> (uuid::Uuid, rpc::Instance) {
    // Note: This also requests a background task in the DB for creating managed
    // resources. That's however ok - we will just ignore it and not execute
    // that task. Later we might also verify that the creation of those resources
    // is requested
    let info = api
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

    let instance_id = uuid::Uuid::try_from(info.id.clone().expect("Missing instance ID")).unwrap();
    (instance_id, info)
}

pub async fn delete_instance(api: &TestApi, instance_id: uuid::Uuid) {
    api.release_instance(tonic::Request::new(InstanceReleaseRequest {
        id: Some(instance_id.into()),
    }))
    .await
    .expect("Delete instance failed.");
}
