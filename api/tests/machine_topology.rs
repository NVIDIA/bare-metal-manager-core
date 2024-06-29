use std::str::FromStr;

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
        machine_interface::MachineInterface,
        machine_topology::MachineTopology,
        network_segment::{NetworkSegment, NetworkSegmentIdKeyedObjectFilter},
    },
    model::{hardware_info::HardwareInfo, machine::machine_id::MachineId},
};

pub mod common;
use common::api_fixtures::{
    create_test_env, dpu::create_dpu_machine, host::create_host_hardware_info,
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};
use sqlx::PgPool;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

const FIXTURE_CREATED_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_crud_machine_topology(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // We can't use the fixture created Machine here, since it already has a topology attached
    // therefore we create a new one
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();

    let mut txn = env.pool.begin().await?;

    let segment = NetworkSegment::find(
        &mut txn,
        NetworkSegmentIdKeyedObjectFilter::One(*FIXTURE_NETWORK_SEGMENT_ID),
        carbide::db::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()
    .remove(0);

    let iface = MachineInterface::create(
        &mut txn,
        &segment,
        &host_sim.config.host_mac_address,
        Some(FIXTURE_CREATED_DOMAIN_ID),
        true,
        carbide::db::address_selection_strategy::AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();
    let hardware_info = create_host_hardware_info(&host_sim.config);
    let machine_id = MachineId::from_hardware_info(&hardware_info).unwrap();
    let (machine, _is_new) = Machine::get_or_create(&mut txn, &machine_id, &iface)
        .await
        .unwrap();

    txn.commit().await?;

    let mut txn = env.pool.begin().await?;

    MachineTopology::create_or_update(&mut txn, machine.id(), &hardware_info).await?;

    txn.commit().await?;

    let mut txn = env.pool.begin().await?;

    let topos = MachineTopology::find_by_machine_ids(&mut txn, &[machine.id().clone()])
        .await
        .unwrap();
    assert_eq!(topos.len(), 1);
    let topo = topos.get(machine.id()).unwrap();
    assert_eq!(topo.len(), 1);

    let returned_hw_info = topo[0].topology().discovery_data.info.clone();
    assert_eq!(returned_hw_info, hardware_info);

    // Hardware info is available on the machine
    let machine2 = Machine::find_one(
        &mut txn,
        machine.id(),
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let rpc_machine: rpc::Machine = machine2.into();
    let discovery_info = rpc_machine.discovery_info.unwrap();
    let retrieved_hw_info = HardwareInfo::try_from(discovery_info).unwrap();

    assert_eq!(retrieved_hw_info, hardware_info);

    txn.commit().await?;

    // Updating a machine topology will update the data.
    let mut txn = env.pool.begin().await?;

    let mut new_info = hardware_info.clone();
    new_info.cpus[0].model = "SnailSpeedCpu".to_string();

    let topology = MachineTopology::create_or_update(&mut txn, machine.id(), &new_info)
        .await
        .unwrap();
    //
    // Value should NOT be updated.
    assert_ne!(
        "SnailSpeedCpu".to_string(),
        topology.topology().discovery_data.info.cpus[0].model
    );

    MachineTopology::set_topology_update_needed(&mut txn, machine.id(), true)
        .await
        .unwrap();
    let topology = MachineTopology::create_or_update(&mut txn, machine.id(), &new_info)
        .await
        .unwrap();

    // Value should be updated.
    assert_eq!(
        "SnailSpeedCpu".to_string(),
        topology.topology().discovery_data.info.cpus[0].model
    );

    assert!(!topology.topology_update_needed());

    let machine2 = Machine::find_one(
        &mut txn,
        machine.id(),
        carbide::db::machine::MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    let rpc_machine: rpc::Machine = machine2.into();
    let discovery_info = rpc_machine.discovery_info.unwrap();
    let retrieved_hw_info = HardwareInfo::try_from(discovery_info).unwrap();

    assert_eq!(retrieved_hw_info, new_info);

    txn.commit().await?;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_topology_missing_mac_field(pool: PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let rpc_machine_id = create_dpu_machine(&env, &host_sim.config).await;

    let mut txn = env.pool.begin().await.unwrap();

    let query = r#"UPDATE machine_topologies SET topology = (SELECT topology::jsonb #- '{bmc_info,mac}' FROM machine_topologies WHERE machine_id=$1) where machine_id=$1;"#;

    sqlx::query(query)
        .bind(rpc_machine_id.to_string())
        .execute(&mut *txn)
        .await
        .expect("update failed");

    txn.commit().await.expect("commit failed");

    let machines = env.find_machines(Some(rpc_machine_id), None, true).await;

    let machine = machines.machines.first().unwrap();
    let bmc_info = machine.bmc_info.as_ref().unwrap();
    assert!(bmc_info.mac.is_none());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_topology_update_on_machineid_update(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) = common::api_fixtures::create_managed_host(&env).await;
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(host.hardware_info().is_some());

    let mut txn = env.pool.begin().await.unwrap();

    let query = r#"UPDATE machines SET id = $2 WHERE id=$1;"#;

    sqlx::query(query)
        .bind(host.id().to_string())
        .bind("fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg")
        .execute(&mut *txn)
        .await
        .expect("update failed");
    txn.commit().await.unwrap();

    let m_id =
        MachineId::from_str("fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg").unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    let host = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap();
    assert!(host.is_none());

    let host = Machine::find_one(&mut txn, &m_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(host.hardware_info().is_some());
}
