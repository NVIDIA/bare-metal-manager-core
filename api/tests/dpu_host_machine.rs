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
    db::{dpu_machine::DpuMachine, host_machine::HostMachine, vpc_resource_leaf::VpcResourceLeaf},
    kubernetes::VpcApiSimConfig,
    model::machine::machine_id::try_parse_machine_id,
    state_controller::snapshot_loader::{DbSnapshotLoader, MachineStateSnapshotLoader},
};

pub mod common;
use common::api_fixtures::{create_test_env, dpu::create_dpu_machine};

use crate::common::api_fixtures::create_managed_host;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

/// This is just a random MachineId to simulate fetching a Machine that doesn't exist
const UNKNOWN_MACHINE_ID: &str = "fm100htaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00";

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_loopback(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // We explictly specify the loopback API that the DPU will get
    let vpc_sim_config = VpcApiSimConfig {
        leaf_loopback_ip_start_address: [172, 20, 0, 2],
        ..Default::default()
    };

    let env = create_test_env(
        pool.clone(),
        common::api_fixtures::TestEnvConfig { vpc_sim_config },
    )
    .await;
    let dpu_rpc_machine_id = create_dpu_machine(&env).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    let mut txn = pool.begin().await?;
    let dpu_machine = DpuMachine::find_by_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap();

    let machine_interface = VpcResourceLeaf::find_associated_dpu_machine_interface(
        &mut txn,
        "172.20.0.2".parse().unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(machine_interface.machine_id.unwrap(), dpu_machine_id);
    assert_eq!(machine_interface.id, *dpu_machine._machine_interface_id());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_find_dpu_machine(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone(), Default::default()).await;
    let dpu_rpc_machine_id = create_dpu_machine(&env).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    let mut txn = pool.begin().await?;

    let mut machines = env
        .find_machines(Some(dpu_rpc_machine_id), None, true)
        .await;
    assert_eq!(machines.machines.len(), 1);
    let machine = machines.machines.remove(0);

    let dpu_machine = DpuMachine::find_by_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap();

    assert_eq!(
        dpu_machine._machine_interface_id().to_string(),
        machine.interfaces[0].id.as_ref().unwrap().to_string(),
    );

    let machine =
        DpuMachine::find_by_machine_id(&mut txn, &UNKNOWN_MACHINE_ID.parse().unwrap()).await;
    assert!(machine.is_err());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_find_host_machine(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone(), Default::default()).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = pool.begin().await?;

    let mut machines = env
        .find_machines(Some(host_machine_id.to_string().into()), None, true)
        .await;
    assert_eq!(machines.machines.len(), 1);
    let machine = machines.machines.remove(0);

    let host_machine = HostMachine::find_by_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    assert_eq!(
        host_machine._machine_interface_id().to_string(),
        machine.interfaces[0].id.as_ref().unwrap().to_string(),
    );

    let machine =
        HostMachine::find_by_machine_id(&mut txn, &UNKNOWN_MACHINE_ID.parse().unwrap()).await;
    assert!(machine.is_err());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_find_temp_host_machine(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone(), Default::default()).await;
    let dpu_rpc_machine_id = create_dpu_machine(&env).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    let mut txn = pool.begin().await?;

    let host_machine_id = DbSnapshotLoader::default()
        .load_machine_snapshot(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .host_snapshot
        .machine_id;

    let host_machine = HostMachine::find_by_machine_id(&mut txn, &host_machine_id)
        .await
        .unwrap();

    assert!(host_machine.machine_id().machine_type().is_predicted_host());
    Ok(())
}
