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
    db::{bmc_machine::BmcMachine, machine_topology::MachineTopology},
    model::bmc_machine::{BmcMachineState, RpcBmcMachineTypeWrapper},
    state_controller::{
        bmc_machine::{handler::BmcMachineStateHandler, io::BmcMachineStateControllerIO},
        io::StateControllerIO,
    },
};
pub mod common;
use common::api_fixtures::{create_test_env, dpu::dpu_bmc_discover_dhcp};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn dpu_bmc_machine_discovery_creates_bmc_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_bmc_machine_interface =
        dpu_bmc_discover_dhcp(&env, &host_sim.config.dpu_bmc_mac_address.to_string()).await;
    let dpu_bmc_machine_interface = uuid::Uuid::try_from(dpu_bmc_machine_interface).unwrap();

    let mut txn = pool.begin().await?;

    let io = BmcMachineStateControllerIO::default();
    let mut bmc_machine_ids = io.list_objects(&mut txn).await?;
    assert_eq!(bmc_machine_ids.len(), 1);
    let bmc_machine_id = bmc_machine_ids.remove(0);

    let bmc_machine = io.load_object_state(&mut txn, &bmc_machine_id).await?;
    assert_eq!(bmc_machine.machine_interface_id, dpu_bmc_machine_interface);
    assert_eq!(
        bmc_machine.controller_state.value,
        BmcMachineState::Initializing
    );
    txn.rollback().await?;

    // Running the controller will not yet advance the state
    env.run_bmc_machine_controller_iteration(bmc_machine_id, &BmcMachineStateHandler::default())
        .await;

    // Initializing -> Configuring
    let mut txn = pool.begin().await?;
    let bmc_machine = io.load_object_state(&mut txn, &bmc_machine_id).await?;
    assert_eq!(bmc_machine.machine_interface_id, dpu_bmc_machine_interface);
    assert_eq!(
        bmc_machine.controller_state.value,
        BmcMachineState::Configuring
    );
    txn.rollback().await?;

    env.run_bmc_machine_controller_iteration(bmc_machine_id, &BmcMachineStateHandler::default())
        .await;

    // Configuring -> DpuReboot
    let mut txn = pool.begin().await?;
    let bmc_machine = io.load_object_state(&mut txn, &bmc_machine_id).await?;
    assert_eq!(bmc_machine.machine_interface_id, dpu_bmc_machine_interface);
    assert_eq!(
        bmc_machine.controller_state.value,
        BmcMachineState::DpuReboot
    );
    txn.rollback().await?;

    env.run_bmc_machine_controller_iteration(bmc_machine_id, &BmcMachineStateHandler::default())
        .await;

    // DpuReboot -> Initialized
    let mut txn = pool.begin().await?;
    let bmc_machine = io.load_object_state(&mut txn, &bmc_machine_id).await?;
    assert_eq!(bmc_machine.machine_interface_id, dpu_bmc_machine_interface);
    assert_eq!(
        bmc_machine.controller_state.value,
        BmcMachineState::Initialized
    );
    txn.rollback().await?;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn dpu_bmc_machine_links_with_dpu_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;

    let mut txn = pool.begin().await?;
    let dpu_topology =
        MachineTopology::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()]).await?;

    assert!(
        dpu_topology.contains_key(&dpu_machine_id) && !dpu_topology[&dpu_machine_id].is_empty()
    );

    let bmc_machine_id = dpu_topology[&dpu_machine_id]
        .first()
        .unwrap()
        .topology()
        .bmc_machine_id;

    // Test there's new Bmc Machine id link
    assert!(bmc_machine_id.is_some());

    let bmc_machine = BmcMachine::get_by_id(&mut txn, bmc_machine_id.unwrap()).await?;
    let bmc_ip = bmc_machine.ip_address.to_string();

    assert!(dpu_topology[&dpu_machine_id]
        .first()
        .unwrap()
        .topology()
        .bmc_info
        .ip
        .as_ref()
        .is_some_and(|ip| *ip == bmc_ip));

    let machine_id = MachineTopology::find_machine_id_by_bmc_ip(&mut txn, bmc_ip.as_str()).await?;
    assert!(machine_id.is_some_and(|id| id == dpu_machine_id));

    // Test list machines
    let response = env
        .find_bmc_machines(Some(bmc_machine.id.into()), true)
        .await;
    assert_eq!(response.bmc_machines.len(), 1);
    let rpc_bmc = &response.bmc_machines[0];
    assert_eq!(rpc_bmc.id, bmc_machine.id.to_string());
    assert_eq!(
        rpc_bmc.bmc_type,
        *RpcBmcMachineTypeWrapper::from(bmc_machine.bmc_type) as i32
    );
    assert_eq!(
        rpc_bmc.hostname,
        bmc_machine.hostname.unwrap_or("".to_string())
    );
    assert_eq!(rpc_bmc.mac_address, bmc_machine.mac_address.to_string());
    assert_eq!(
        rpc_bmc.machine_id,
        bmc_machine.machine_id.unwrap().to_string()
    );
    assert_eq!(
        rpc_bmc.state,
        bmc_machine.controller_state.value.to_string()
    );
    assert_eq!(
        rpc_bmc.fw_version,
        bmc_machine.bmc_firmware_version.unwrap_or("".to_string())
    );

    let host_topology =
        MachineTopology::find_by_machine_ids(&mut txn, &[host_machine_id.clone()]).await?;
    assert!(
        host_topology.contains_key(&host_machine_id) && !host_topology[&host_machine_id].is_empty()
    );

    // For host there's no BMC machine yet.
    assert!(host_topology[&host_machine_id]
        .first()
        .unwrap()
        .topology()
        .bmc_machine_id
        .is_none());

    let host_bmc_ip = &host_topology[&host_machine_id]
        .first()
        .unwrap()
        .topology()
        .bmc_info
        .ip
        .as_ref();

    assert!(host_bmc_ip.is_some());

    let host_machine =
        MachineTopology::find_machine_id_by_bmc_ip(&mut txn, host_bmc_ip.unwrap().as_str()).await?;
    assert!(host_machine.is_some_and(|id| id == host_machine_id));

    Ok(())
}
