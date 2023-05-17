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
use std::str::FromStr;

use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;

use carbide::{
    db::machine_interface::MachineInterface, model::machine::machine_id::try_parse_machine_id,
};

mod common;
use common::api_fixtures::{
    create_test_env,
    dpu::create_dpu_machine,
    host::{create_host_hardware_info, host_discover_dhcp, FIXTURE_HOST_MAC_ADDRESS},
    FIXTURE_DHCP_RELAY_ADDRESS,
};
use rpc::forge::forge_server::Forge;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_discovery_no_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine_interface = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
    )
    .await
    .expect("Unable to create machine");

    let wanted_ips: Vec<IpNetwork> = vec!["192.0.2.3".parse().unwrap()]
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
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
    )
    .await
    .expect("Unable to create machine");

    let wanted_ips: Vec<IpNetwork> = vec!["192.0.2.3".parse().unwrap()];

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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_reject_host_machine_with_disabled_tpm(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone(), Default::default());
    let dpu_machine_id = create_dpu_machine(&env).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();

    let host_machine_interface_id =
        host_discover_dhcp(&env, FIXTURE_HOST_MAC_ADDRESS, &dpu_machine_id).await;

    let mut hardware_info = create_host_hardware_info();
    hardware_info.tpm_ek_certificate = None;

    let response = env
        .api
        .discover_machine(tonic::Request::new(rpc::MachineDiscoveryInfo {
            machine_interface_id: Some(host_machine_interface_id.clone()),
            discovery_data: Some(rpc::DiscoveryData::Info(
                rpc::DiscoveryInfo::try_from(hardware_info).unwrap(),
            )),
        }))
        .await;
    let err = response.expect_err("Expected DiscoverMachine request to fail");
    assert!(err.to_string().contains(&format!(
        "Ignoring DiscoverMachine request for non-tpm enabled host with InterfaceId {}",
        host_machine_interface_id
    )));

    // We shouldn't have created any machine
    let machines = env.find_machines(None, None, false).await;
    assert!(machines.machines.is_empty());

    Ok(())
}
