/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use crate::{
    db::{
        self,
        machine::{Machine, MachineSearchConfig},
        machine_interface::associate_interface_with_dpu_machine,
        machine_topology::MachineTopology,
        network_segment::NetworkSegment,
    },
    model::hardware_info::HardwareInfo,
    model::machine::machine_id::{from_hardware_info, try_parse_machine_id},
};
use forge_uuid::{domain::DomainId, machine::MachineId};

use crate::db::{network_segment, ObjectColumnFilter};
use crate::tests::common;
use common::api_fixtures::{
    create_managed_host, create_test_env, dpu::create_dpu_machine,
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};
use lazy_static::lazy_static;
use rpc::forge::forge_server::Forge;
use std::str::FromStr;

lazy_static! {
    pub static ref FIXTURE_CREATED_DOMAIN_ID: DomainId =
        uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e").into();
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_crud_machine_topology(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // We can't use the fixture created Machine here, since it already has a topology attached
    // therefore we create a new one
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu = host_sim.config.get_and_assert_single_dpu();

    let mut txn = env.pool.begin().await?;

    let dpu_machine_id = create_dpu_machine(&env, &host_sim.config).await;
    let host_machine_id = ::rpc::MachineId {
        id: dpu_machine_id.id.replace("fm100d", "fm100p"),
    };
    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();
    let host_machine_id = try_parse_machine_id(&host_machine_id).unwrap();

    let iface = db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id.clone()])
        .await
        .unwrap();

    let iface = iface.get(&host_machine_id);
    let iface = iface.unwrap().clone().remove(0);
    db::machine_interface::delete(&iface.id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let segment = NetworkSegment::find_by(
        &mut txn,
        ObjectColumnFilter::One(network_segment::IdColumn, &FIXTURE_NETWORK_SEGMENT_ID),
        crate::db::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()
    .remove(0);

    let iface = db::machine_interface::create(
        &mut txn,
        &segment,
        &dpu.host_mac_address,
        Some(*FIXTURE_CREATED_DOMAIN_ID),
        true,
        crate::db::address_selection_strategy::AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();

    let hardware_info = HardwareInfo::from(&host_sim.config);
    let machine_id = from_hardware_info(&hardware_info).unwrap();
    let machine = Machine::get_or_create(&mut txn, None, &machine_id, &iface)
        .await
        .unwrap();

    associate_interface_with_dpu_machine(&iface.id, &dpu_machine_id, &mut txn)
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
    txn.commit().await?;

    // Hardware info is available on the machine
    let rpc_machine = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine.id().to_string().into()],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);

    let discovery_info = rpc_machine.discovery_info.unwrap();
    let retrieved_hw_info = HardwareInfo::try_from(discovery_info).unwrap();

    assert_eq!(retrieved_hw_info, hardware_info);

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
    txn.commit().await?;

    let rpc_machine = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine.id().to_string().into()],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0);
    let discovery_info = rpc_machine.discovery_info.unwrap();
    let retrieved_hw_info = HardwareInfo::try_from(discovery_info).unwrap();

    assert_eq!(retrieved_hw_info, new_info);

    Ok(())
}

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
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

#[crate::sqlx_test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_ids_by_bmc_ips(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Setup
    let env = create_test_env(db_pool.clone()).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;
    let host_machine = env
        .find_machines(Some(host_machine_id.to_string().into()), None, true)
        .await
        .machines
        .remove(0);

    let bmc_ip = host_machine.bmc_info.as_ref().unwrap().ip();
    let req = tonic::Request::new(rpc::forge::BmcIpList {
        bmc_ips: vec![bmc_ip.to_string()],
    });
    let res = env.api.find_machine_ids_by_bmc_ips(req).await?.into_inner();
    assert_eq!(res.pairs.len(), 1);
    let m = res.pairs.first().unwrap();
    assert_eq!(
        m.machine_id.as_ref().unwrap().to_string(),
        host_machine_id.to_string()
    );
    assert_eq!(m.bmc_ip, bmc_ip);

    Ok(())
}
