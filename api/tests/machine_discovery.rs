/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::str::FromStr;

use ipnetwork::IpNetwork;
use itertools::Itertools;
use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::machine_interface::MachineInterface;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_discovery_no_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine_interface = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        "192.0.2.1".parse().unwrap(),
    )
    .await
    .expect("Unable to create machine");

    let wanted_ips: Vec<IpNetwork> = vec![
        "192.0.2.3".parse().unwrap(),
        "2001:db8:f::64".parse().unwrap(),
    ]
    .into_iter()
    .sorted()
    .collect::<Vec<IpNetwork>>();

    let actual_ips = machine_interface
        .addresses()
        .iter()
        .map(|address| address.address)
        .sorted()
        .collect::<Vec<IpNetwork>>();

    assert_eq!(actual_ips, wanted_ips);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_discovery_with_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let machine_interface = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        "192.0.2.1".parse().unwrap(),
    )
    .await
    .expect("Unable to create machine");

    let wanted_ips: Vec<IpNetwork> = vec![
        "192.0.2.3".parse().unwrap(),
        "2001:db8:f::64".parse().unwrap(),
    ];

    assert_eq!(
        machine_interface
            .addresses()
            .iter()
            .map(|address| address.address)
            .sorted()
            .collect::<Vec<IpNetwork>>(),
        wanted_ips.into_iter().sorted().collect::<Vec<IpNetwork>>()
    );

    assert!(machine_interface
        .addresses()
        .iter()
        .any(|item| item.address == "192.0.2.3".parse().unwrap()));

    Ok(())
}
