/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::HashMap;

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use common::api_fixtures::{TestEnv, create_test_env};
use db::{self};
use futures_util::FutureExt;
use mac_address::MacAddress;
use model::machine::{DpuInitState, MachineState, ManagedHostState};
use rpc::forge::CloudInitInstructionsRequest;
use rpc::forge::forge_server::Forge;

use crate::tests::common;
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::site_explorer::MockExploredHost;
use crate::tests::common::mac_address_pool::DPU_OOB_MAC_ADDRESS_POOL;
use crate::tests::common::rpc_builder::DhcpDiscovery;

async fn move_machine_to_needed_state(
    machine_id: MachineId,
    state: &ManagedHostState,
    pool: &sqlx::PgPool,
) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let machine = db::machine::find_one(
        &mut txn,
        &machine_id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    db::machine::advance(&machine, &mut txn, state, None)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

async fn get_pxe_instructions(
    env: &TestEnv,
    interface_id: MachineInterfaceId,
    arch: rpc::forge::MachineArchitecture,
    product: Option<String>,
) -> rpc::forge::PxeInstructions {
    env.api
        .get_pxe_instructions(tonic::Request::new(rpc::forge::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: Some(interface_id),
            product,
        }))
        .await
        .unwrap()
        .into_inner()
}

#[crate::sqlx_test]
async fn test_pxe_dpu_ready(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_id, dpu_id) = common::api_fixtures::create_managed_host(&env).await.into();
    move_machine_to_needed_state(dpu_id, &ManagedHostState::Ready, &env.pool).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let dpu_interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_id])
        .await
        .unwrap()[&dpu_id][0]
        .id;
    txn.commit().await.unwrap();

    let instructions = get_pxe_instructions(
        &env,
        dpu_interface_id,
        rpc::forge::MachineArchitecture::Arm,
        Some("Fake Bluefield".to_string()),
    )
    .await;
    assert!(
        instructions.pxe_script.contains("Current state: Ready"),
        "Actual script: {}",
        instructions.pxe_script
    );
    assert!(instructions.pxe_script.contains(
        "This state assumes an OS is provisioned and will exit into the OS in 5 seconds."
    ));
}

#[crate::sqlx_test]
async fn test_pxe_dpu_waiting_for_network_install(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let mh = common::api_fixtures::dpu::create_dpu_machine_in_waiting_for_network_install(
        &env,
        &host_config,
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();

    let machine = mh.dpu().db_machine(&mut txn).await;

    assert_eq!(
        machine.current_state(),
        &ManagedHostState::DPUInit {
            dpu_states: model::machine::DpuInitStates {
                states: HashMap::from([(mh.dpu().id, DpuInitState::WaitingForNetworkConfig,)]),
            },
        }
    );

    let instructions = get_pxe_instructions(
        &env,
        machine.interfaces.first().unwrap().id,
        rpc::forge::MachineArchitecture::Arm,
        Some("Fake Bluefield".to_string()),
    )
    .await;

    assert!(
        instructions
            .pxe_script
            .contains("Current state: DPUInitializing/WaitingForNetworkConfig"),
        "Actual script: {}",
        instructions.pxe_script
    );
    assert!(instructions.pxe_script.contains(
        "This state assumes an OS is provisioned and will exit into the OS in 5 seconds."
    ));

    assert!(!instructions.pxe_script.contains("aarch64/carbide.root"));
}

#[crate::sqlx_test]
async fn test_dpu_pxe_gets_correct_os_when_machine_is_not_created(
    pool: sqlx::PgPool,
) -> eyre::Result<()> {
    // This test ensures that when a DPU PXE boots after site-explorer ingestion, but before the
    // managed host is fully configured, we don't confuse it for an ARM host, and we give it
    // carbide.efi (the DPU OS) and *not* scout.efi.
    let env = create_test_env(pool).await;
    let mock_explored_host = MockExploredHost::new(&env, ManagedHostConfig::default());
    let dpu_oob_mac = mock_explored_host.managed_host.dpus[0].oob_mac_address;

    // Ingest the DPU BMC into site explorer
    mock_explored_host
        .discover_dhcp_dpu_bmc(0, |_, _| Ok(()))
        .boxed()
        .await?
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .boxed()
        .await;

    // Discover DHCP from the DPU's OOB
    let dpu_interface_id =
        common::api_fixtures::dpu::dpu_discover_dhcp(&env, &dpu_oob_mac.to_string()).await;

    let instructions = get_pxe_instructions(
        &env,
        dpu_interface_id,
        rpc::forge::MachineArchitecture::Arm,
        Some("Fake Bluefield".to_string()),
    )
    .await;

    assert!(
        !instructions.pxe_script.contains("exit"),
        "should PXE boot, got an exit instruction"
    );
    assert!(
        instructions.pxe_script.contains("aarch64/carbide.efi"),
        "should PXE boot to carbide.efi for DPU agent OS"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_pxe_when_machine_is_not_ingested(pool: sqlx::PgPool) -> eyre::Result<()> {
    let env = create_test_env(pool).await;
    let dpu_interface_id = common::api_fixtures::dpu::dpu_discover_dhcp(
        &env,
        &DPU_OOB_MAC_ADDRESS_POOL.allocate().to_string(),
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        dpu_interface_id,
        rpc::forge::MachineArchitecture::Arm,
        Some("Fake Host".to_string()),
    )
    .await;

    assert!(
        instructions.pxe_script.contains("exit"),
        "should exit, since we don't know about this machine"
    );
    assert!(
        !instructions.pxe_script.contains("aarch64"),
        "should not PXE boot, since we don't know about this machine"
    );

    let instructions = get_pxe_instructions(
        &env,
        dpu_interface_id,
        rpc::forge::MachineArchitecture::X86,
        None,
    )
    .await;
    assert!(
        instructions.pxe_script.contains("exit"),
        "should exit, since we don't know about this machine"
    );
    assert!(
        !instructions.pxe_script.contains("x86_64/scout.efi"),
        "should not PXE boot, since we don't know about this machine"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_pxe_when_dpu_is_not_ingested(pool: sqlx::PgPool) -> eyre::Result<()> {
    let env = create_test_env(pool).await;
    let dpu_interface_id = common::api_fixtures::dpu::dpu_discover_dhcp(
        &env,
        &DPU_OOB_MAC_ADDRESS_POOL.allocate().to_string(),
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        dpu_interface_id,
        rpc::forge::MachineArchitecture::Arm,
        Some("Fake Bluefield".to_string()),
    )
    .await;

    assert!(
        !instructions.pxe_script.contains("exit"),
        "should not exit, since DPUs are allowed to boot"
    );
    assert!(
        instructions.pxe_script.contains("aarch64"),
        "should PXE boot, since DPUs are allowed to boot"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_pxe_host(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_id, _dpu_id) = common::api_fixtures::create_managed_host(&env).await.into();
    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let host_interface_id = db::machine_interface::find_by_machine_ids(&mut txn, &[host_id])
        .await
        .unwrap()[&host_id][0]
        .id;
    txn.commit().await.unwrap();
    move_machine_to_needed_state(
        host_id,
        &ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForDiscovery,
        },
        &env.pool,
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        host_interface_id,
        rpc::forge::MachineArchitecture::X86,
        None,
    )
    .await;
    assert!(instructions.pxe_script.contains("x86_64/scout.efi"));

    move_machine_to_needed_state(
        host_id,
        &ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
        &env.pool,
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        host_interface_id,
        rpc::forge::MachineArchitecture::X86,
        None,
    )
    .await;
    assert!(instructions.pxe_script.contains("x86_64/scout.efi"));

    move_machine_to_needed_state(
        host_id,
        &ManagedHostState::WaitingForCleanup {
            cleanup_state: model::machine::CleanupState::Init,
        },
        &env.pool,
    )
    .await;

    let instructions = get_pxe_instructions(
        &env,
        host_interface_id,
        rpc::forge::MachineArchitecture::X86,
        Some("Fake X86 Host".to_string()),
    )
    .await;
    assert!(instructions.pxe_script.contains("x86_64/scout.efi"));
}

#[crate::sqlx_test]
async fn test_pxe_instance(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env
        .pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let host_interface = mh.host().first_interface(&mut txn).await;
    txn.commit().await.unwrap();

    mh.instance_builer(&env)
        .single_interface_network_config(segment_id)
        .build()
        .await;

    let instructions = host_interface
        .get_pxe_instructions(rpc::forge::MachineArchitecture::X86)
        .await;

    assert_eq!(instructions.pxe_script, "SomeRandomiPxe".to_string());
}

#[crate::sqlx_test]
async fn test_cloud_init_when_machine_is_not_created(pool: sqlx::PgPool) {
    let env = common::api_fixtures::create_test_env(pool).await;

    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let _ = env
        .api
        .discover_dhcp(DhcpDiscovery::builder(&mac_address, "192.0.2.1").tonic_request())
        .await
        .unwrap()
        .into_inner();

    // Interface is created. Let's fetch interface id.
    let mut txn = env.pool.begin().await.unwrap();
    let interfaces = db::machine_interface::find_by_mac_address(
        &mut txn,
        mac_address.parse::<MacAddress>().unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(interfaces.len(), 1);

    let cloud_init_cfg = env
        .api
        .get_cloud_init_instructions(tonic::Request::new(CloudInitInstructionsRequest {
            ip: interfaces[0].addresses[0].to_string(),
        }))
        .await
        .expect("get_cloud_init_instructions returned an error")
        .into_inner();

    assert!(cloud_init_cfg.discovery_instructions.is_some());
}

#[crate::sqlx_test]
async fn test_cloud_init_after_dpu_update(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let (_host_id, dpu_id) = common::api_fixtures::create_managed_host(&env).await.into();
    move_machine_to_needed_state(
        dpu_id,
        &ManagedHostState::DPUInit {
            dpu_states: model::machine::DpuInitStates {
                states: HashMap::from([(dpu_id, DpuInitState::Init)]),
            },
        },
        &env.pool,
    )
    .await;

    // Interface is created. Let's fetch interface id.
    let machine = env.find_machine(dpu_id).await.remove(0);
    assert_eq!(machine.interfaces.len(), 1);

    let cloud_init_cfg = env
        .api
        .get_cloud_init_instructions(tonic::Request::new(CloudInitInstructionsRequest {
            ip: machine.interfaces[0].address[0].clone(),
        }))
        .await
        .expect("get_cloud_init_instructions returned an error")
        .into_inner();

    assert!(cloud_init_cfg.discovery_instructions.is_some());
}
