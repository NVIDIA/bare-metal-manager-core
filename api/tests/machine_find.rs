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
use data_encoding::BASE32_DNSSEC;
use std::net::IpAddr;

use carbide::{
    db::{
        machine::{Machine, MachineSearchConfig},
        ObjectFilter,
    },
    model::machine::machine_id::{try_parse_machine_id, MachineId, MACHINE_ID_PREFIX_LENGTH},
};
use itertools::Itertools;
use mac_address::MacAddress;
use sha2::{Digest, Sha256};
use tonic::Request;

pub mod common;
use common::{
    api_fixtures::{create_managed_host, create_test_env, dpu::create_dpu_machine},
    mac_address_pool::DPU_OOB_MAC_ADDRESS_POOL,
};
use rpc::forge::forge_server::Forge;

use crate::common::api_fixtures::{
    dpu::create_dpu_hardware_info, host::create_host_machine,
    managed_host::create_managed_host_multi_dpu,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine = Machine::find_by_query(&mut txn, &dpu_machine_id.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(*machine.id(), dpu_machine_id);
    assert!(machine.is_dpu());

    // We shouldn't find a machine that doesn't exist
    let mut new_id = dpu_machine_id.to_string();
    match unsafe { new_id.as_bytes_mut().get_mut(MACHINE_ID_PREFIX_LENGTH + 1) } {
        Some(c) if *c == b'a' => *c = b'b',
        Some(c) => *c = b'a',
        None => panic!("Not expected"),
    }
    let id2: MachineId = new_id.parse().unwrap();
    assert!(Machine::find_by_query(&mut txn, &id2.to_string())
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ip = dpu_machine.interfaces()[0].addresses()[0].address;

    let machine = Machine::find_by_query(&mut txn, &ip.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(*machine.id(), dpu_machine_id);
    assert_eq!(machine.interfaces()[0].addresses()[0].address, ip);

    // We shouldn't find a machine that doesn't exist
    let ip2: IpAddr = "254.254.254.254".parse().unwrap();
    assert!(Machine::find_by_query(&mut txn, &ip2.to_string())
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_mac(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    let mac = dpu_machine.interfaces()[0].mac_address;

    let machine = Machine::find_by_query(&mut txn, &mac.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(*machine.id(), dpu_machine_id);
    assert_eq!(machine.interfaces()[0].mac_address, mac);
    assert!(DPU_OOB_MAC_ADDRESS_POOL.contains(machine.interfaces()[0].mac_address));

    // We shouldn't find a machine that doesn't exist
    let mut mac2 = mac.bytes();
    mac2[5] = 0xFF;
    let mac2 = MacAddress::from(mac2);
    assert!(Machine::find_by_query(&mut txn, &mac2.to_string())
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_hostname(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    let hostname = dpu_machine.interfaces()[0].hostname();

    let machine = Machine::find_by_query(&mut txn, hostname)
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(*machine.id(), dpu_machine_id);
    assert_eq!(machine.interfaces()[0].hostname(), hostname);

    // We shouldn't find a machine that doesn't exist
    let hostname2 = format!("a{}", hostname);
    assert!(Machine::find_by_query(&mut txn, &hostname2)
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_fqdn(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let fqdn = format!("{}.dwrt1.com", dpu_machine.interfaces()[0].hostname());

    let mut machines = Machine::find_by_fqdn(&mut txn, &fqdn, MachineSearchConfig::default())
        .await
        .unwrap();
    let machine = machines.remove(0);
    assert!(machines.is_empty());
    assert_eq!(*machine.id(), dpu_machine_id);

    // We shouldn't find a machine that doesn't exist
    let fqdn2 = format!("a{}", fqdn);
    let machines = Machine::find_by_fqdn(&mut txn, &fqdn2, MachineSearchConfig::default())
        .await
        .unwrap();
    assert!(machines.is_empty());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_dpu_included(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let machines = env.find_machines(None, None, true).await;
    assert_eq!(machines.machines.len(), 2); // 1 host and 1 DPU

    let machine_types = machines
        .machines
        .into_iter()
        .map(|x| x.machine_type)
        .collect_vec();

    assert!(machine_types.contains(&(rpc::forge::MachineType::Host as i32)));
    assert!(machine_types.contains(&(rpc::forge::MachineType::Dpu as i32)));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_find_machine_dpu_excluded(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (_host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let machines = env.find_machines(None, None, false).await;
    assert_eq!(machines.machines.len(), 1); // 1 host
    assert_eq!(
        machines.machines[0].machine_type,
        rpc::forge::MachineType::Host as i32
    );
}

#[sqlx::test]
async fn test_find_all_machines_when_there_arent_any(pool: sqlx::PgPool) {
    let mut txn = pool
        .begin()
        .await
        .expect("Could create a transaction on database pool");

    let machines = Machine::find(
        &mut txn,
        ObjectFilter::All,
        carbide::db::machine::MachineSearchConfig {
            include_history: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(machines.is_empty());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_ids(pool: sqlx::PgPool) {
    let config = carbide::db::machine::MachineSearchConfig {
        include_dpus: true,
        include_history: false,
        include_associated_machine_id: false,
        only_maintenance: false,
        include_predicted_host: true,
        exclude_hosts: false,
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id =
        MachineId::host_id_from_dpu_hardware_info(&create_dpu_hardware_info(&host_sim.config))
            .unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine_ids = Machine::find_machine_ids(&mut txn, config).await.unwrap();

    assert_eq!(machine_ids.len(), 2);
    assert!(machine_ids.contains(&dpu_machine_id));
    assert!(machine_ids.contains(&host_machine_id));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_dpu_machine_ids(pool: sqlx::PgPool) {
    let config = carbide::db::machine::MachineSearchConfig {
        include_dpus: true,
        include_history: false,
        include_associated_machine_id: false,
        only_maintenance: false,
        include_predicted_host: false,
        exclude_hosts: true,
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id =
        MachineId::host_id_from_dpu_hardware_info(&create_dpu_hardware_info(&host_sim.config))
            .unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine_ids = Machine::find_machine_ids(&mut txn, config).await.unwrap();

    assert_eq!(machine_ids.len(), 1);
    assert!(machine_ids.contains(&dpu_machine_id));
    assert!(!machine_ids.contains(&host_machine_id));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_predicted_host_machine_ids(pool: sqlx::PgPool) {
    let config = carbide::db::machine::MachineSearchConfig {
        include_dpus: false,
        include_history: false,
        include_associated_machine_id: false,
        only_maintenance: false,
        include_predicted_host: true,
        exclude_hosts: true,
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let host_machine_id =
        MachineId::host_id_from_dpu_hardware_info(&create_dpu_hardware_info(&host_sim.config))
            .unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine_ids = Machine::find_machine_ids(&mut txn, config).await.unwrap();

    assert_eq!(machine_ids.len(), 1);
    assert!(!machine_ids.contains(&dpu_machine_id));
    assert!(machine_ids.contains(&host_machine_id));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_host_machine_ids_when_predicted(pool: sqlx::PgPool) {
    let config = carbide::db::machine::MachineSearchConfig {
        include_dpus: false,
        include_history: false,
        include_associated_machine_id: false,
        only_maintenance: false,
        include_predicted_host: false,
        exclude_hosts: false,
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let _dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();
    let mut txn = env.pool.begin().await.unwrap();

    let machine_ids = Machine::find_machine_ids(&mut txn, config).await.unwrap();

    assert!(machine_ids.is_empty());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_host_machine_ids(pool: sqlx::PgPool) {
    let config = carbide::db::machine::MachineSearchConfig {
        include_dpus: false,
        include_history: false,
        include_associated_machine_id: false,
        only_maintenance: false,
        include_predicted_host: false,
        exclude_hosts: false,
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let tmp_machine_id = create_host_machine(&env, &host_sim.config, &dpu_machine_id).await;
    let host_machine_id = try_parse_machine_id(&tmp_machine_id).unwrap();

    let mut txn = env.pool.begin().await.unwrap();

    tracing::info!("finding machine ids");
    let machine_ids = Machine::find_machine_ids(&mut txn, config).await.unwrap();
    assert_eq!(machine_ids.len(), 1);
    assert!(machine_ids.contains(&host_machine_id));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_mixed_host_machine_ids(pool: sqlx::PgPool) {
    let config = carbide::db::machine::MachineSearchConfig {
        include_dpus: false,
        include_history: false,
        include_associated_machine_id: false,
        only_maintenance: false,
        include_predicted_host: true,
        exclude_hosts: false,
    };

    let env = create_test_env(pool).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(&env, &host_sim.config).await).unwrap();

    let tmp_machine_id = create_host_machine(&env, &host_sim.config, &dpu_machine_id).await;
    let host_machine_id = try_parse_machine_id(&tmp_machine_id).unwrap();

    let host_sim2 = env.start_managed_host_sim();
    create_dpu_machine(&env, &host_sim2.config).await;
    let predicted_host_machine_id =
        MachineId::host_id_from_dpu_hardware_info(&create_dpu_hardware_info(&host_sim2.config))
            .unwrap();

    let mut txn = env.pool.begin().await.unwrap();

    tracing::info!("finding machine ids");
    let machine_ids = Machine::find_machine_ids(&mut txn, config).await.unwrap();
    assert_eq!(machine_ids.len(), 2);
    assert!(machine_ids.contains(&host_machine_id));
    assert!(machine_ids.contains(&predicted_host_machine_id));
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_attached_dpu_machine_ids_multi_dpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let machine_id = create_managed_host_multi_dpu(&env, 2).await;

    // Now host1 should have two DPUs.
    let host_machine = env
        .api
        .get_machine(tonic::Request::new(rpc::MachineId {
            id: machine_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();
    let dpu_ids = host_machine.associated_dpu_machine_ids;
    assert_eq!(
        dpu_ids.len(),
        2,
        "host machine should have had 2 DPU IDs, got {}",
        dpu_ids.len()
    );

    for ref dpu_id in dpu_ids.iter() {
        assert!(
            dpu_ids.contains(dpu_id),
            "host machine has an unexpected associated_dpu_machine_id {}",
            dpu_id
        );
    }

    let deprecated_dpu_id = host_machine.associated_dpu_machine_id
        .expect("host machine should fill in an associated_dpu_machine_id field for backwards compatibility");

    let first_dpu_id = dpu_ids.into_iter().next().unwrap();
    assert_eq!(
        deprecated_dpu_id, first_dpu_id,
        "deprecated DPU field should equal the first DPU ID"
    );
}

#[sqlx::test()]
async fn test_find_machines_by_ids_over_max(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // create vector of machine IDs with more than max allowed
    // it does not matter if these are real or not, since we are testing an error back for passing more than max
    let end_index: u32 = env.config.max_find_by_ids + 1;
    let machine_ids = (1..=end_index)
        .map(|index| {
            let serial = format!("machine_{index}");
            let hash: [u8; 32] = Sha256::new_with_prefix(serial.as_bytes()).finalize().into();
            let encoded = BASE32_DNSSEC.encode(&hash);
            ::rpc::common::MachineId {
                id: format!("fm100ds{encoded}"),
            }
        })
        .collect();
    //build request
    let request: Request<::rpc::common::MachineIdList> =
        Request::new(::rpc::common::MachineIdList { machine_ids });
    // execute
    let response = env.api.find_machines_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing more than allowed number of machine IDs"
    );
    assert_eq!(
        response.err().unwrap().message(),
        format!(
            "no more than {} IDs can be accepted",
            env.config.max_find_by_ids
        )
    );
}

#[sqlx::test()]
async fn test_find_machines_by_ids_none(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let request = tonic::Request::new(::rpc::common::MachineIdList::default());

    let response = env.api.find_machines_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing no machine IDs"
    );
    assert_eq!(
        response.err().unwrap().message(),
        "at least one ID must be provided",
    );
}
