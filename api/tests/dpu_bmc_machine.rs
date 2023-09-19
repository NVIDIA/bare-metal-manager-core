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
    model::bmc_machine::BmcMachineState,
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
    assert_eq!(bmc_machine.controller_state.value, BmcMachineState::Init);
    txn.rollback().await?;

    // Running the controller will not yet advance the state
    env.run_bmc_machine_controller_iteration(bmc_machine_id, &BmcMachineStateHandler::default())
        .await;

    let mut txn = pool.begin().await?;
    let bmc_machine = io.load_object_state(&mut txn, &bmc_machine_id).await?;
    assert_eq!(bmc_machine.machine_interface_id, dpu_bmc_machine_interface);
    assert_eq!(bmc_machine.controller_state.value, BmcMachineState::Init);
    txn.rollback().await?;

    Ok(())
}
