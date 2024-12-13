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

use crate::db::{self, dhcp_entry, dhcp_entry::DhcpEntry, ObjectColumnFilter};
use crate::CarbideError;
use forge_uuid::machine::MachineInterfaceId;
use mac_address::MacAddress;
use rpc::forge::{forge_server::Forge, DhcpDiscovery};

use crate::db::network_segment::NetworkSegment;
use crate::tests::common;
use common::api_fixtures::{
    create_managed_host, create_test_env, dpu, instance::create_instance, TestEnv,
    FIXTURE_DHCP_RELAY_ADDRESS,
};

#[crate::sqlx_test]
async fn test_machine_dhcp(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let test_mac_address = MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap();
    let test_gateway_address = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        test_gateway_address,
    )
    .await?;

    txn.commit().await.unwrap();

    Ok(())
}

#[crate::sqlx_test]
async fn test_machine_dhcp_from_wrong_vlan_fails(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let test_mac_address = MacAddress::from_str("ff:ff:ff:ff:ff:ff").unwrap();
    let test_gateway_address = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        test_gateway_address,
    )
    .await?;

    // Test a second time after initial creation on the same segment should not cause issues
    db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        test_gateway_address,
    )
    .await?;

    // expect this to error out
    let output = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        "192.0.1.1".parse().unwrap(),
    )
    .await;

    assert!(
        matches!(output, Err(CarbideError::Internal { message, ..}) if message.starts_with("Network segment mismatch for existing mac address"))
    );

    txn.commit().await.unwrap();

    Ok(())
}

#[crate::sqlx_test]
async fn test_machine_dhcp_with_api(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Inititially 0 addresses are allocated on the segment
    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.admin_segment.unwrap())
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();

    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        response.segment_id.unwrap(),
        (env.admin_segment.unwrap()).into()
    );

    assert_eq!(response.mac_address, mac_address);
    assert_eq!(response.subdomain_id.unwrap(), env.domain.into());
    assert_eq!(response.address, "192.0.2.3".to_owned());
    assert_eq!(response.prefix, "192.0.2.0/24".to_owned());
    assert_eq!(response.gateway.unwrap(), "192.0.2.1".to_owned());

    // After DHCP, 1 address is allocated on the segment
    let mut txn = pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.admin_segment.unwrap())
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();
    Ok(())
}

#[crate::sqlx_test]
async fn test_multiple_machines_dhcp_with_api(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Inititially 0 addresses are allocated on the segment
    let mut txn = pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.admin_segment.unwrap())
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();

    let mac_address = "FF:FF:FF:FF:FF:0".to_string();
    const NUM_MACHINES: usize = 6;
    for i in 0..NUM_MACHINES {
        let mac = format!("{}{}", mac_address, i);
        let expected_ip = format!("192.0.2.{}", i + 3); // IP starts with 3.
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: mac.clone(),
                relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
                link_address: None,
                vendor_string: None,
                circuit_id: None,
                remote_id: None,
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            response.segment_id.unwrap(),
            (env.admin_segment.unwrap()).into()
        );

        assert_eq!(response.mac_address, mac);
        assert_eq!(response.subdomain_id.unwrap(), env.domain.into());
        assert_eq!(response.address, expected_ip);
        assert_eq!(response.prefix, "192.0.2.0/24".to_owned());
        assert_eq!(response.gateway.unwrap(), "192.0.2.1".to_owned());
    }

    let mut txn = pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.admin_segment.unwrap())
            .await
            .unwrap(),
        NUM_MACHINES
    );
    txn.commit().await.unwrap();
    Ok(())
}

#[crate::sqlx_test]
async fn test_machine_dhcp_with_api_for_instance_physical_virtual(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let (segment_id_1, segment_id_2) = env.create_vpc_and_dual_tenant_segment().await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let dpu_loopback_ip = dpu::loopback_ip(&mut txn, &dpu_machine_id).await;

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some((segment_id_1).into()),
                network_details: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some((segment_id_2).into()),
                network_details: None,
            },
        ],
    });
    let segment_1 = NetworkSegment::find_by_name(&mut txn, "TENANT")
        .await
        .unwrap();
    let segment_2 = NetworkSegment::find_by_name(&mut txn, "TENANT2")
        .await
        .unwrap();
    let (_instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        None,
        vec![],
    )
    .await;
    let mac_address = "FF:FF:FF:FF:FF:FF".to_string();
    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: dpu_loopback_ip.to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: Some(format!("vlan{}", segment_1.vlan_id.unwrap())),
            remote_id: Some(dpu_machine_id.remote_id()),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.segment_id.unwrap(), (segment_id_1).into());

    assert_eq!(response.mac_address, mac_address);
    assert_eq!(response.subdomain_id.unwrap(), env.domain.into());
    assert_eq!(response.address, "192.0.4.3".to_owned());
    assert_eq!(response.prefix, "192.0.4.0/24".to_owned());
    assert_eq!(response.gateway.unwrap(), "192.0.4.1".to_owned());

    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mac_address.clone(),
            relay_address: dpu_loopback_ip.to_string(),
            link_address: None,
            vendor_string: None,
            circuit_id: Some(format!("vlan{}", segment_2.vlan_id.unwrap())),
            remote_id: Some(dpu_machine_id.remote_id()),
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.segment_id.unwrap(), (segment_id_2).into());

    assert!(response.machine_interface_id.is_none());

    assert_eq!(response.mac_address, mac_address);
    assert!(response.subdomain_id.is_none(),);
    assert_eq!(response.address, "192.0.5.3".to_owned());
    assert_eq!(response.prefix, "192.0.5.0/24".to_owned());
    assert_eq!(response.gateway.unwrap(), "192.0.5.1".to_owned());
    Ok(())
}

#[crate::sqlx_test]
async fn machine_interface_discovery_persists_vendor_strings(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    async fn assert_vendor_strings_equal(
        pool: &sqlx::PgPool,
        interface_id: &MachineInterfaceId,
        expected: &[&str],
    ) {
        let mut txn = pool.clone().begin().await.unwrap();
        let entry = DhcpEntry::find_by(
            &mut txn,
            ObjectColumnFilter::One(dhcp_entry::MachineInterfaceIdColumn, interface_id),
        )
        .await
        .unwrap();
        assert_eq!(
            entry
                .iter()
                .map(|e| e.vendor_string.as_str())
                .collect::<Vec<&str>>(),
            expected
        );

        // Also check via the MachineInterface API
        let iface = db::machine_interface::find_one(&mut txn, *interface_id)
            .await
            .unwrap();
        assert_eq!(iface.vendors, expected);

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
                remote_id: None,
            }))
            .await
            .unwrap()
            .into_inner()
    }

    let env = create_test_env(pool.clone()).await;
    let mac_address = MacAddress::from_str("ab:cd:ff:ff:ff:ff").unwrap();

    let response = dhcp_with_vendor(&env, mac_address, Some("vendor1".to_string())).await;
    let interface_id: MachineInterfaceId = response
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

#[crate::sqlx_test]
async fn test_dpu_machine_dhcp_for_existing_dpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id = dpu::create_dpu_machine(&env, &host_sim.config).await;

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
            remote_id: None,
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
