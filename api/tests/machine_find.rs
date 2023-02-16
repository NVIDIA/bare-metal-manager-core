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

use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::machine::Machine;

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
async fn test_find_machine_by_uuid(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default());

    let dpu_machine_id: uuid::Uuid = create_dpu_machine(&env).await.try_into().unwrap();
    let mut txn = pool.begin().await.unwrap();

    let machine = Machine::find_by_query(&mut txn, &dpu_machine_id.to_string())
        .await
        .unwrap()
        .expect("expect DPU to be found");
    assert_eq!(*machine.id(), dpu_machine_id);
    assert!(machine.is_dpu());

    // We shouldn't find a machine that doesn't exist
    let id2 = uuid::Uuid::from_u128(dpu_machine_id.as_u128() + 1);
    assert!(Machine::find_by_query(&mut txn, &id2.to_string())
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_find_machine_by_ip(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone(), Default::default());

    let dpu_machine_id: uuid::Uuid = create_dpu_machine(&env).await.try_into().unwrap();
    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, dpu_machine_id)
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

    let dpu_machine_id: uuid::Uuid = create_dpu_machine(&env).await.try_into().unwrap();
    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, dpu_machine_id)
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

    let dpu_machine_id: uuid::Uuid = create_dpu_machine(&env).await.try_into().unwrap();
    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, dpu_machine_id)
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

    let dpu_machine_id: uuid::Uuid = create_dpu_machine(&env).await.try_into().unwrap();
    let mut txn = pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(&mut txn, dpu_machine_id)
        .await
        .unwrap()
        .unwrap();

    let fqdn = format!("{}.dwrt1.com", dpu_machine.interfaces()[0].hostname());

    let mut machines = Machine::find_by_fqdn(&mut txn, &fqdn).await.unwrap();
    let machine = machines.remove(0);
    assert!(machines.is_empty());
    assert_eq!(*machine.id(), dpu_machine_id);

    // We shouldn't find a machine that doesn't exist
    let fqdn2 = format!("a{}", fqdn);
    let machines = Machine::find_by_fqdn(&mut txn, &fqdn2).await.unwrap();
    assert!(machines.is_empty());
}
