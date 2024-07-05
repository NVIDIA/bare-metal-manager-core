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

use carbide::{
    db::instance::InstanceId, db::machine_interface::MachineInterface,
    model::machine::machine_id::MachineId,
};
use common::api_fixtures::{create_test_env, TestEnv};
use rpc::forge::{forge_server::Forge, PxeInstructions};

use crate::common::api_fixtures::{
    create_managed_host,
    instance::{
        create_instance_with_config, default_os_config, default_tenant_config,
        single_interface_network_config,
    },
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_uses_custom_ipxe_only_once(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let host_interface_id =
        MachineInterface::find_by_machine_ids(&mut txn, &[host_machine_id.clone()])
            .await
            .unwrap()
            .get(&host_machine_id)
            .unwrap()[0]
            .id
            .to_string();
    txn.rollback().await.unwrap();

    let (instance_id, _instance) =
        create_instance(&env, &dpu_machine_id, &host_machine_id, false).await;
    assert!(
        !env.find_instances(Some(instance_id.into()))
            .await
            .instances
            .remove(0)
            .config
            .unwrap()
            .tenant
            .unwrap()
            .always_boot_with_custom_ipxe
    );

    // First boot should return custom iPXE instructions
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");

    // Second boot should return "exit"
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "exit");

    // A regular reboot attempt should still lead to returning "exit"
    invoke_instance_power(&env, host_machine_id.clone(), false).await;
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "exit");

    // A reboot with flag `boot_with_custom_ipxe` should provide the custom iPXE
    invoke_instance_power(&env, host_machine_id.clone(), true).await;
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");

    // The next reboot should again lead to returning "exit"
    invoke_instance_power(&env, host_machine_id.clone(), false).await;
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "exit");
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_always_boot_with_custom_ipxe(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let host_interface_id =
        MachineInterface::find_by_machine_ids(&mut txn, &[host_machine_id.clone()])
            .await
            .unwrap()
            .get(&host_machine_id)
            .unwrap()[0]
            .id
            .to_string();
    txn.rollback().await.unwrap();

    let (instance_id, _instance) =
        create_instance(&env, &dpu_machine_id, &host_machine_id, true).await;
    assert!(
        env.find_instances(Some(instance_id.into()))
            .await
            .instances
            .remove(0)
            .config
            .unwrap()
            .tenant
            .unwrap()
            .always_boot_with_custom_ipxe
    );

    // First boot should return custom iPXE instructions
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");

    // Second boot should also return custom iPXE instructions
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");

    // A regular reboot attempt should also return custom iPXE instructions
    invoke_instance_power(&env, host_machine_id.clone(), false).await;
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");

    // A reboot with flag `boot_with_custom_ipxe` should also return custom iPXE instructions
    invoke_instance_power(&env, host_machine_id.clone(), true).await;
    let pxe = fetch_ipxe_instructions(&env, host_interface_id.clone()).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");
}

async fn fetch_ipxe_instructions(env: &TestEnv, interface_id: String) -> PxeInstructions {
    env.api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: rpc::forge::MachineArchitecture::X86 as i32,
            interface_id: Some(rpc::Uuid {
                value: interface_id,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
}

async fn invoke_instance_power(
    env: &TestEnv,
    host_machine_id: MachineId,
    boot_with_custom_ipxe: bool,
) {
    env.api
        .invoke_instance_power(tonic::Request::new(rpc::forge::InstancePowerRequest {
            machine_id: Some(rpc::common::MachineId {
                id: host_machine_id.to_string(),
            }),
            operation: rpc::forge::instance_power_request::Operation::PowerReset as _,
            boot_with_custom_ipxe,
            apply_updates_on_reboot: false,
        }))
        .await
        .unwrap();
}

pub async fn create_instance(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    run_provisioning_instructions_on_every_boot: bool,
) -> (InstanceId, rpc::Instance) {
    let mut os = default_os_config();
    os.run_provisioning_instructions_on_every_boot = run_provisioning_instructions_on_every_boot;

    let config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(os),
        network: Some(single_interface_network_config(*FIXTURE_NETWORK_SEGMENT_ID)),
        infiniband: None,
    };

    create_instance_with_config(env, dpu_machine_id, host_machine_id, config, None).await
}
