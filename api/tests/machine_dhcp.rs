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
use log::LevelFilter;

use mac_address::MacAddress;
use rpc::forge::{forge_server::Forge, DhcpDiscovery};
use std::str::FromStr;

use carbide::db::machine_interface::MachineInterface;
#[allow(dead_code)]
mod common;

use common::api_fixtures::{
    instance::{create_instance, prepare_machine, FIXTURE_CIRCUIT_ID, FIXTURE_CIRCUIT_ID_1},
    network_segment::{FIXTURE_NETWORK_SEGMENT_ID, FIXTURE_NETWORK_SEGMENT_ID_1},
};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_dhcp(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let test_mac_address = MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap();
    let test_gateway_address = "192.0.2.1".parse().unwrap();

    MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        test_gateway_address,
    )
    .await?;

    txn.commit().await.unwrap();

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_dhcp_with_api(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let api = common::api_fixtures::create_test_api(pool.clone());

    // Inititially 0 addresses are allocated on the segment
    let mut txn = pool.begin().await?;
    assert_eq!(
        MachineInterface::count_by_segment_id(&mut txn, &FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();

    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let response = api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        response.segment_id.unwrap(),
        FIXTURE_NETWORK_SEGMENT_ID.into()
    );

    assert_eq!(response.mac_address, mac_address);
    assert_eq!(
        response.subdomain_id.unwrap(),
        common::api_fixtures::FIXTURE_DOMAIN_ID.into()
    );
    assert_eq!(response.address, "192.0.2.3/32".to_owned());
    assert_eq!(response.prefix, "192.0.2.0/24".to_owned());
    assert_eq!(response.gateway.unwrap(), "192.0.2.1/32".to_owned());

    // After DHCP, 1 address is allocated on the segment
    let mut txn = pool.begin().await?;
    assert_eq!(
        MachineInterface::count_by_segment_id(&mut txn, &FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_multiple_machines_dhcp_with_api(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let api = common::api_fixtures::create_test_api(pool.clone());

    // Inititially 0 addresses are allocated on the segment
    let mut txn = pool.begin().await?;
    assert_eq!(
        MachineInterface::count_by_segment_id(&mut txn, &FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();

    let mac_address = "FF:FF:FF:FF:FF:0".to_string();
    const NUM_MACHINES: usize = 6;
    for i in 0..NUM_MACHINES {
        let mac = format!("{}{}", mac_address, i);
        let expected_ip = format!("192.0.2.{}/32", i + 3); // IP starts with 3.
        let response = api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: mac.clone(),
                relay_address: "192.0.2.1".to_string(),
                link_address: None,
                vendor_string: None,
                circuit_id: None,
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            response.segment_id.unwrap(),
            common::api_fixtures::network_segment::FIXTURE_NETWORK_SEGMENT_ID.into()
        );

        assert_eq!(response.mac_address, mac);
        assert_eq!(
            response.subdomain_id.unwrap(),
            common::api_fixtures::FIXTURE_DOMAIN_ID.into()
        );
        assert_eq!(response.address, expected_ip);
        assert_eq!(response.prefix, "192.0.2.0/24".to_owned());
        assert_eq!(response.gateway.unwrap(), "192.0.2.1/32".to_owned());
    }

    let mut txn = pool.begin().await?;
    assert_eq!(
        MachineInterface::count_by_segment_id(&mut txn, &FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        NUM_MACHINES
    );
    txn.commit().await.unwrap();
    Ok(())
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine",
))]
async fn test_machine_dhcp_with_api_for_instance_physical_virtual(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let api = common::api_fixtures::create_test_api(pool.clone());
    prepare_machine(&pool).await;
    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::PhysicalFunction as i32,
                network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::VirtualFunction as i32,
                network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID_1.into()),
            },
        ],
    });
    let (_instance_id, _instance) = create_instance(&api, network).await;
    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let response = api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: "192.168.0.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: Some(FIXTURE_CIRCUIT_ID.to_string()),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        response.segment_id.unwrap(),
        FIXTURE_NETWORK_SEGMENT_ID.into()
    );

    assert_eq!(response.mac_address, mac_address);
    assert_eq!(
        response.subdomain_id.unwrap(),
        common::api_fixtures::FIXTURE_DOMAIN_ID.into()
    );
    assert_eq!(response.address, "192.0.2.3/32".to_owned());
    assert_eq!(response.prefix, "192.0.2.0/24".to_owned());
    assert_eq!(response.gateway.unwrap(), "192.0.2.1/32".to_owned());

    let response = api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: "192.168.0.1".to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: Some(FIXTURE_CIRCUIT_ID_1.to_string()),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        response.segment_id.unwrap(),
        FIXTURE_NETWORK_SEGMENT_ID_1.into()
    );

    assert!(response.machine_interface_id.is_none());

    assert_eq!(response.mac_address, mac_address);
    assert!(response.subdomain_id.is_none(),);
    assert_eq!(response.address, "192.0.3.3/32".to_owned());
    assert_eq!(response.prefix, "192.0.3.0/24".to_owned());
    assert_eq!(response.gateway.unwrap(), "192.0.3.1/32".to_owned());
    Ok(())
}
