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

use carbide_uuid::machine::MachineInterfaceId;
use common::api_fixtures::{
    FIXTURE_DHCP_RELAY_ADDRESS, TestEnv, create_managed_host, create_test_env, dpu,
};
use db::{self, ObjectColumnFilter, dhcp_entry};
use itertools::Itertools;
use mac_address::MacAddress;
use rpc::forge::ManagedHostNetworkConfigRequest;
use rpc::forge::forge_server::Forge;

use crate::DatabaseError;
use crate::tests::common;
use crate::tests::common::rpc_builder::DhcpDiscovery;

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
        None,
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
        None,
    )
    .await?;

    // Test a second time after initial creation on the same segment should not cause issues
    db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        test_gateway_address,
        None,
    )
    .await?;

    // expect this to error out
    let output = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        "192.0.1.1".parse().unwrap(),
        None,
    )
    .await;

    assert!(
        matches!(output, Err(DatabaseError::Internal { message, ..}) if message.starts_with("Network segment mismatch for existing mac address"))
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

    let mac_address = "FF:FF:FF:FF:FF:FF";
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mac_address, FIXTURE_DHCP_RELAY_ADDRESS).tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    assert_eq!(response.segment_id.unwrap(), (env.admin_segment.unwrap()));

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
        let mac = format!("{mac_address}{i}");
        let expected_ip = format!("192.0.2.{}", i + 3); // IP starts with 3.
        let response = env
            .api
            .discover_dhcp(DhcpDiscovery::builder(&mac, FIXTURE_DHCP_RELAY_ADDRESS).tonic_request())
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.segment_id.unwrap(), (env.admin_segment.unwrap()));

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
    let mh = create_managed_host(&env).await;

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some(segment_id_1),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some(segment_id_2),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
            },
        ],
    };

    mh.instance_builer(&env).network(network).build().await;
    // Instance dhcp is not handled by carbide. Best way to find out allocated IP info is to read
    // data from managedhostnetworkconfig.
    let response = env
        .api
        .get_managed_host_network_config(tonic::Request::new(ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(mh.dpu().id),
        }))
        .await
        .unwrap()
        .into_inner();

    let tenant_data = response.tenant_interfaces;
    assert!(
        tenant_data
            .iter()
            .map(|x| x.ip.clone())
            .contains("192.0.4.3")
    );
    assert!(
        tenant_data
            .iter()
            .map(|x| x.ip.clone())
            .contains("192.1.4.3")
    );

    assert!(
        tenant_data
            .iter()
            .map(|x| x.prefix.clone())
            .contains("192.0.4.0/24")
    );
    assert!(
        tenant_data
            .iter()
            .map(|x| x.prefix.clone())
            .contains("192.1.4.0/24")
    );

    assert!(
        tenant_data
            .iter()
            .map(|x| x.gateway.clone())
            .contains("192.0.4.1/24")
    );
    assert!(
        tenant_data
            .iter()
            .map(|x| x.gateway.clone())
            .contains("192.1.4.1/24")
    );

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
        let entry = db::dhcp_entry::find_by(
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
        vendor_string: Option<&str>,
    ) -> rpc::protos::forge::DhcpRecord {
        let builder = DhcpDiscovery::builder(mac_address, FIXTURE_DHCP_RELAY_ADDRESS);
        let builder = if let Some(vendor_string) = vendor_string {
            builder.vendor_string(vendor_string)
        } else {
            builder
        };
        env.api
            .discover_dhcp(builder.tonic_request())
            .await
            .unwrap()
            .into_inner()
    }

    let env = create_test_env(pool.clone()).await;
    let mac_address = MacAddress::from_str("ab:cd:ff:ff:ff:ff").unwrap();

    let response = dhcp_with_vendor(&env, mac_address, Some("vendor1")).await;
    let interface_id = response
        .machine_interface_id
        .expect("machine_interface_id must be set");
    assert_vendor_strings_equal(&pool, &interface_id, &["vendor1"]).await;

    let _ = dhcp_with_vendor(&env, mac_address, Some("vendor2")).await;
    assert_vendor_strings_equal(&pool, &interface_id, &["vendor1", "vendor2"]).await;

    let _ = dhcp_with_vendor(&env, mac_address, None).await;
    assert_vendor_strings_equal(&pool, &interface_id, &["vendor1", "vendor2"]).await;

    // DHCP with a previously known vendor string
    // This should not fail
    let _ = dhcp_with_vendor(&env, mac_address, Some("vendor2")).await;

    Ok(())
}

#[crate::sqlx_test]
async fn test_dpu_machine_dhcp_for_existing_dpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let host_config = env.managed_host_config();
    let dpu_machine_id = dpu::create_dpu_machine(&env, &host_config).await;

    let machine = env.find_machine(dpu_machine_id).await.remove(0);
    let mac = machine.interfaces[0].mac_address.clone();

    let response = env
        .api
        .discover_dhcp(DhcpDiscovery::builder(&mac, FIXTURE_DHCP_RELAY_ADDRESS).tonic_request())
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        response.address.as_str(),
        machine.interfaces[0].address[0].as_str()
    );

    Ok(())
}
