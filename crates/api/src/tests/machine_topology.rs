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
use common::api_fixtures::host::X86_V1_CPU_INFO_JSON;
use common::api_fixtures::{create_managed_host, create_test_env};
use db::machine_interface::associate_interface_with_dpu_machine;
use db::machine_topology::test_helpers::{HardwareInfoV1, TopologyDataV1};
use db::{self, ObjectColumnFilter, network_segment};
use model::hardware_info::{Cpu, CpuInfo, HardwareInfo};
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
        ObjectColumnFilter::One(network_segment::IdColumn, &env.admin_segment.unwrap()),
        model::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()
    .remove(0);

    let iface = db::machine_interface::create(
        &mut txn,
        &segment,
        &dpu.host_mac_address,
        Some(env.domain.into()),
        true,
        model::address_selection_strategy::AddressSelectionStrategy::Automatic,
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

// TODO: Remove when there's no longer a need to handle the old topology format
#[crate::sqlx_test]
async fn test_v1_cpu_topology(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
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
        ObjectColumnFilter::One(network_segment::IdColumn, &env.admin_segment.unwrap()),
        model::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()
    .remove(0);

    let iface = db::machine_interface::create(
        &mut txn,
        &segment,
        &dpu.host_mac_address,
        Some(env.domain.into()),
        true,
        model::address_selection_strategy::AddressSelectionStrategy::Automatic,
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

    let cpus = serde_json::from_slice::<Vec<Cpu>>(X86_V1_CPU_INFO_JSON).unwrap();
    let hardware_info_v1 = HardwareInfoV1 {
        network_interfaces: hardware_info.network_interfaces,
        infiniband_interfaces: hardware_info.infiniband_interfaces,
        cpus,
        block_devices: hardware_info.block_devices,
        machine_type: hardware_info.machine_type,
        nvme_devices: hardware_info.nvme_devices,
        dmi_data: hardware_info.dmi_data,
        tpm_ek_certificate: hardware_info.tpm_ek_certificate,
        dpu_info: hardware_info.dpu_info,
        gpus: hardware_info.gpus,
        memory_devices: hardware_info.memory_devices,
    };

    db::machine_topology::test_helpers::create_or_update_v1(
        &mut txn,
        &machine.id,
        &hardware_info_v1,
    )
    .await?;

    txn.commit().await?;

    // Confirm that the raw JSON of the inserted v1 topology still matches the pre-inserted v1
    // value after reading it back from the database.
    let inserted_topology_json: (serde_json::Value,) =
        sqlx::query_as("SELECT topology FROM machine_topologies WHERE machine_id = $1")
            .bind(machine.id)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    let inserted_topology: TopologyDataV1 =
        serde_json::from_value(inserted_topology_json.0).unwrap();
    assert_eq!(
        inserted_topology.discovery_data.info.cpus,
        hardware_info_v1.cpus,
    );

    let mut txn = env.pool.begin().await?;

    let topos = db::machine_topology::find_by_machine_ids(&mut txn, &[machine.id])
        .await
        .unwrap();
    assert_eq!(topos.len(), 1);
    let topo = topos.get(&machine.id).unwrap();
    assert_eq!(topo.len(), 1);

    // Verify that v1 topology is deserialized into v2 topology when the inserted row is read back
    // from the database.
    let returned_hw_info = topo[0].topology().discovery_data.info.clone();
    let expected_cpu_info = CpuInfo {
        model: "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz".to_string(),
        vendor: "GenuineIntel".to_string(),
        sockets: 1,
        cores: 18,
        threads: 72,
    };
    assert_eq!(returned_hw_info.cpu_info, vec![expected_cpu_info]);
    txn.commit().await?;

    // V1 format parses successfully even if "cpus" is missing, by defaulting to empty array.
    // Verify that behavior is unchanged and that reading the topology back from the database
    // automatically converts the V1 format into the expected V2 format.
    // Start with raw JSON having no cpu data.
    let mut txn = env.pool.begin().await?;
    let mut raw_json_topology: serde_json::Value =
        serde_json::to_value(topo[0].topology()).unwrap();

    if let Some(discovery_data) = raw_json_topology
        .get_mut("discovery_data")
        .and_then(|v| v.as_object_mut())
        && let Some(info) = discovery_data
            .get_mut("Info")
            .and_then(|v| v.as_object_mut())
    {
        info.remove("cpus");
        info.remove("cpu_info");
    }

    // Insert the topology with missing cpu data into the machine_topologies table.
    let sql = r#"
    INSERT INTO machine_topologies (machine_id, topology)
    VALUES ($1, $2::json)
    ON CONFLICT (machine_id)
    DO UPDATE SET topology = EXCLUDED.topology
    "#;

    sqlx::query(sql)
        .bind(machine.id.to_string())
        .bind(sqlx::types::Json(&raw_json_topology))
        .execute(&mut *txn)
        .await?;

    txn.commit().await?;

    // Confirm that the raw JSON read back from the table still matches the pre-inserted v1
    // topology by not including any cpu data.
    let inserted_topology_json: (serde_json::Value,) =
        sqlx::query_as("SELECT topology FROM machine_topologies WHERE machine_id = $1")
            .bind(machine.id)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert!(inserted_topology_json.0["discovery_data"]["Info"]["cpu_info"].is_null());
    assert!(inserted_topology_json.0["discovery_data"]["Info"]["cpus"].is_null());

    // Read the topology back from the database as the expected type.
    let mut txn = env.pool.begin().await?;
    let topos = db::machine_topology::find_by_machine_ids(&mut txn, &[machine.id])
        .await
        .unwrap();
    assert_eq!(topos.len(), 1);
    let topo = topos.get(&machine.id).unwrap();
    assert_eq!(topo.len(), 1);

    // Verify that v1 topology is deserialized into v2 topology when read back from the database,
    // despite empty cpu data.
    let returned_hw_info = topo[0].topology().discovery_data.info.clone();
    assert_eq!(returned_hw_info.cpu_info, vec![]);
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_topology_update_on_machineid_update(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (host_machine_id, _dpu_machine_id) =
        common::api_fixtures::create_managed_host(&env).await.into();
    let mut txn = env.pool.begin().await.unwrap();
    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
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
    let host = db::machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap();
    assert!(host.is_none());

    let host = db::machine::find_one(&mut txn, &m_id, MachineSearchConfig::default())
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
