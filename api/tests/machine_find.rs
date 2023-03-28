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
use std::net::IpAddr;

use itertools::Itertools;
use log::LevelFilter;
use mac_address::MacAddress;

use carbide::{
    db::{
        machine::{Machine, MachineSearchConfig},
        ObjectFilter,
    },
    model::machine::machine_id::{try_parse_machine_id, MachineId, MACHINE_ID_PREFIX_LENGTH},
};

pub mod common;
use common::api_fixtures::{
    create_test_env,
    dpu::{create_dpu_machine, FIXTURE_DPU_MAC_ADDRESS},
};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default());

    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();
    let mut txn = pool.begin().await.unwrap();

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
    let env = create_test_env(pool.clone(), Default::default());

    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();
    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, &dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let ip = dpu_machine.interfaces()[0].addresses()[0].address.ip();

    let machine = Machine::find_by_query(&mut txn, &ip.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(*machine.id(), dpu_machine_id);
    assert_eq!(machine.interfaces()[0].addresses()[0].address.ip(), ip);

    // We shouldn't find a machine that doesn't exist
    let ip2: IpAddr = "254.254.254.254".parse().unwrap();
    assert!(Machine::find_by_query(&mut txn, &ip2.to_string())
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_mac(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default());

    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();
    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_history: true,
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
    assert_eq!(
        machine.interfaces()[0].mac_address.to_string(),
        FIXTURE_DPU_MAC_ADDRESS
    );

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
    let env = create_test_env(pool.clone(), Default::default());

    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();
    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_history: true,
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
    let env = create_test_env(pool.clone(), Default::default());

    let dpu_machine_id = try_parse_machine_id(&create_dpu_machine(&env).await).unwrap();
    let mut txn = pool.begin().await.unwrap();
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

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_find_machine_dpu_included(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default());

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

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_find_machine_dpu_excluded(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default());

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
        },
    )
    .await
    .unwrap();

    assert!(machines.is_empty());
}
