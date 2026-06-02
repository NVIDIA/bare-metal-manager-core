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
use std::str::FromStr;

use carbide_uuid::machine::{MachineId, MachineType};
use common::api_fixtures::dpu::create_dpu_machine;
use common::api_fixtures::{create_managed_host, create_test_env};
use db::machine_interface::associate_interface_with_dpu_machine;
use db::{self, ObjectColumnFilter, network_segment};
use model::hardware_info::HardwareInfo;
use model::machine::machine_id::from_hardware_info;
use model::machine::machine_search_config::MachineSearchConfig;
use rpc::forge::forge_server::Forge;

use crate::tests::common;

#[crate::sqlx_test]
async fn test_crud_machine_topology(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // We can't use the fixture created Machine here, since it already has a topology attached
    // therefore we create a new one
    let env = create_test_env(pool).await;
    let host_config = env.managed_host_config();
    let dpu = host_config.get_and_assert_single_dpu();

    let mut txn = env.pool.begin().await?;

    let dpu_machine_id = create_dpu_machine(&env, &host_config).await;
    let host_machine_id = dpu_machine_id
        .to_string()
        .replace(
            MachineType::Dpu.id_prefix(),
            MachineType::PredictedHost.id_prefix(),
        )
        .parse::<MachineId>()
        .unwrap();

    let iface = db::machine_interface::find_by_machine_ids(&mut txn, &[host_machine_id])
        .await
        .unwrap();

    let iface = iface.get(&host_machine_id);
    let iface = iface.unwrap().clone().remove(0);
    db::machine_interface::delete(&iface.id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let segment = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(network_segment::IdColumn, env.admin_segment_ref()),
        model::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()
    .remove(0);

    let iface = db::machine_interface::create(
        &mut txn,
        std::slice::from_ref(&segment),
        &dpu.host_mac_address,
        true,
        model::address_selection_strategy::AddressSelectionStrategy::NextAvailableIp,
    )
    .await
    .unwrap();

    let hardware_info = HardwareInfo::from(&host_config);
    let machine_id = from_hardware_info(&hardware_info).unwrap();
    let machine = db::machine::get_or_create(&mut txn, None, &machine_id, &iface)
        .await
        .unwrap();

    associate_interface_with_dpu_machine(&iface.id, &dpu_machine_id, &mut txn)
        .await
        .unwrap();
    txn.commit().await?;

    let mut txn = env.pool.begin().await?;

    db::machine_topology::create_or_update(&mut txn, &machine.id, &hardware_info).await?;

    txn.commit().await?;

    let mut txn = env.pool.begin().await?;

    let topos = db::machine_topology::find_by_machine_ids(&mut txn, &[machine.id])
        .await
        .unwrap();
    assert_eq!(topos.len(), 1);
    let topo = topos.get(&machine.id).unwrap();
    assert_eq!(topo.len(), 1);

    let returned_hw_info = topo[0].topology().discovery_data.info.clone();
    assert_eq!(returned_hw_info, hardware_info);
    txn.commit().await?;

    // Hardware info is available on the machine
    let rpc_machine = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine.id],
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
    new_info.cpu_info[0].model = "SnailSpeedCpu".to_string();

    let topology = db::machine_topology::create_or_update(&mut txn, &machine.id, &new_info)
        .await
        .unwrap();
    //
    // Value should NOT be updated.
    assert_ne!(
        "SnailSpeedCpu".to_string(),
        topology.topology().discovery_data.info.cpu_info[0].model
    );

    db::machine_topology::set_topology_update_needed(&mut txn, &machine.id, true)
        .await
        .unwrap();
    let topology = db::machine_topology::create_or_update(&mut txn, &machine.id, &new_info)
        .await
        .unwrap();

    // Value should be updated.
    assert_eq!(
        "SnailSpeedCpu".to_string(),
        topology.topology().discovery_data.info.cpu_info[0].model
    );

    assert!(!topology.topology_update_needed());
    txn.commit().await?;

    let rpc_machine = env
        .api
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine.id],
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

#[crate::sqlx_test]
async fn test_topology_update_on_machineid_update(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) =
        common::api_fixtures::create_managed_host(&env).await.into();
    let mut txn = env.pool.begin().await.unwrap();
    let host = db::machine::find_one(
        txn.as_mut(),
        &host_machine_id,
        MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    assert!(host.hardware_info.as_ref().is_some());

    let mut txn = env.pool.begin().await.unwrap();

    let query = r#"UPDATE machines SET id = $2 WHERE id=$1;"#;

    sqlx::query(query)
        .bind(host.id.to_string())
        .bind("fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg")
        .execute(&mut *txn)
        .await
        .expect("update failed");
    txn.commit().await.unwrap();

    let m_id =
        MachineId::from_str("fm100hsag07peffp850l14kvmhrqjf9h6jslilfahaknhvb6sq786c0g3jg").unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    let host = db::machine::find_one(
        txn.as_mut(),
        &host_machine_id,
        MachineSearchConfig::default(),
    )
    .await
    .unwrap();
    assert!(host.is_none());

    let host = db::machine::find_one(txn.as_mut(), &m_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(host.hardware_info.as_ref().is_some());
}

#[crate::sqlx_test]
async fn test_find_machine_ids_by_bmc_ips(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Setup
    let env = create_test_env(db_pool.clone()).await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();
    let host_machine = env.find_machine(host_machine_id).await.remove(0);

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
