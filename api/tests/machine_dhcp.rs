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

use mac_address::MacAddress;
use rpc::forge::{forge_server::Forge, DhcpDiscovery};
use std::str::FromStr;

use carbide::db::{
    dhcp_entry::DhcpEntry, machine_interface::MachineInterface, vpc_resource_leaf::VpcResourceLeaf,
};

mod common;
use common::api_fixtures::{
    create_managed_host, create_test_env,
    dpu::create_dpu_machine,
    instance::{create_instance, FIXTURE_CIRCUIT_ID, FIXTURE_CIRCUIT_ID_1},
    network_segment::{FIXTURE_NETWORK_SEGMENT_ID, FIXTURE_NETWORK_SEGMENT_ID_1},
    TestEnv, FIXTURE_DHCP_RELAY_ADDRESS,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_dhcp(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let test_mac_address = MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap();
    let test_gateway_address = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

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
    let api = common::api_fixtures::create_test_env(pool.clone(), Default::default())
        .await
        .api;

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
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
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
    let api = common::api_fixtures::create_test_env(pool.clone(), Default::default())
        .await
        .api;

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
                relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_dhcp_with_api_for_instance_physical_virtual(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone(), Default::default()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let leaf = VpcResourceLeaf::find(&mut txn, &dpu_machine_id)
        .await
        .unwrap();
    let dpu_loopback_ip = leaf.loopback_ip_address().unwrap();

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID_1.into()),
            },
        ],
        // TODO(k82cn): add IB interface configuration.
        ib_interfaces: Vec::new(),
    });
    let (_instance_id, _instance) = create_instance(&env, &host_machine_id, network).await;
    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: dpu_loopback_ip.to_string(),
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

    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: dpu_loopback_ip.to_string(),
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn machine_interface_discovery_persists_vendor_strings(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    async fn assert_vendor_strings_equal(
        pool: &sqlx::PgPool,
        interface_id: &uuid::Uuid,
        expected: &[&str],
    ) {
        let mut txn = pool.clone().begin().await.unwrap();
        let entry = DhcpEntry::find_by_interface_id(&mut txn, interface_id)
            .await
            .unwrap();
        assert_eq!(
            entry
                .iter()
                .map(|e| e.vendor_string.as_str())
                .collect::<Vec<&str>>(),
            expected
        );
        txn.rollback().await.unwrap();
    }

    async fn dhcp_with_vendor(
        env: &TestEnv,
        mac_address: MacAddress,
        vendor_string: Option<String>,
    ) -> rpc::protos::forge::DhcpRecord {
        env.api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: mac_address.to_string(),
                relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
                vendor_string,
                link_address: None,
                circuit_id: None,
            }))
            .await
            .unwrap()
            .into_inner()
    }

    let env = create_test_env(pool.clone(), Default::default()).await;
    let mac_address = MacAddress::from_str("ab:cd:ff:ff:ff:ff").unwrap();

    let response = dhcp_with_vendor(&env, mac_address, Some("vendor1".to_string())).await;
    let interface_id: uuid::Uuid = response
        .machine_interface_id
        .expect("machine_interface_id must be set")
        .try_into()
        .unwrap();
    assert_vendor_strings_equal(&pool, &interface_id, &["vendor1"]).await;

    let _ = dhcp_with_vendor(&env, mac_address, Some("vendor2".to_string())).await;
    assert_vendor_strings_equal(&pool, &interface_id, &["vendor1", "vendor2"]).await;

    let _ = dhcp_with_vendor(&env, mac_address, None).await;
    assert_vendor_strings_equal(&pool, &interface_id, &["vendor1", "vendor2"]).await;

    // DHCP with a previously known vendor string
    // This should not fail
    let _ = dhcp_with_vendor(&env, mac_address, Some("vendor2".to_string())).await;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_dpu_machine_dhcp_for_existing_dpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone(), Default::default()).await;

    let dpu_machine_id = create_dpu_machine(&env).await;

    let mut machines = env.find_machines(Some(dpu_machine_id), None, true).await;
    let machine = machines.machines.remove(0);
    let mac = machine.interfaces[0].mac_address.clone();

    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac.clone(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        response.address.as_str(),
        machine.interfaces[0].address[0].as_str()
    );

    Ok(())
}
