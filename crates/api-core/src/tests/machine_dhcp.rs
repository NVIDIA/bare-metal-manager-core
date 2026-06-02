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

use std::net::IpAddr;
use std::str::FromStr;

use carbide_network::ip::IpAddressFamily;
use carbide_uuid::machine::MachineInterfaceId;
use common::api_fixtures::managed_host::ManagedHostConfig;
use common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    create_host_inband_network_segment, create_network_segment,
};
use common::api_fixtures::{
    FIXTURE_DHCP_RELAY_ADDRESS, TestEnv, TestEnvOverrides, create_managed_host,
    create_managed_host_multi_dpu, create_managed_host_with_config, create_test_env,
    create_test_env_with_overrides, dpu, get_config,
};
use db::{self, ObjectColumnFilter, dhcp_entry};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use model::machine_interface::InterfaceType;
use model::network_segment::NetworkSegmentType;
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
        std::slice::from_ref(&test_gateway_address),
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
        std::slice::from_ref(&test_gateway_address),
        None,
    )
    .await?;

    // Test a second time after initial creation on the same segment should not cause issues
    db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        std::slice::from_ref(&test_gateway_address),
        None,
    )
    .await?;

    // expect this to error out
    let output = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        test_mac_address,
        &["192.0.1.1".parse().unwrap()],
        None,
    )
    .await;

    assert!(
        matches!(output, Err(DatabaseError::Internal { message, ..}) if message.starts_with("Network segment mismatch for existing MAC address"))
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
        db::machine_interface::count_by_segment_id(&mut txn, env.admin_segment_ref())
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

    assert_eq!(response.segment_id.unwrap(), (env.admin_segment()));

    assert_eq!(response.mac_address, mac_address);
    assert_eq!(response.subdomain_id.unwrap(), env.domain.into());
    assert_eq!(response.address, "192.0.2.3".to_owned());
    assert_eq!(response.prefix, "192.0.2.0/24".to_owned());
    assert_eq!(response.gateway.unwrap(), "192.0.2.1".to_owned());

    // After DHCP, 1 address is allocated on the segment
    let mut txn = pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, env.admin_segment_ref())
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();
    Ok(())
}

#[crate::sqlx_test]
async fn test_non_primary_admin_interface_dhcp_is_rejected(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Create a multi-DPU host and find its dormant DPU-backed admin interface.
    let mh = create_managed_host_multi_dpu(&env, 2).await;
    let mut txn = pool.begin().await?;
    let mut interface_map = db::machine_interface::find_by_machine_ids(&mut txn, &[mh.id]).await?;
    let dormant_interface = interface_map
        .remove(&mh.id)
        .unwrap()
        .into_iter()
        .find(|interface| {
            interface.network_segment_type == Some(NetworkSegmentType::Admin)
                && interface.attached_dpu_machine_id.is_some()
                && !interface.primary_interface
        })
        .unwrap();
    assert!(dormant_interface.addresses.is_empty());
    txn.commit().await?;

    // DHCP on the dormant admin link must be rejected before a new lease
    // is allocated or any stale record can be returned.
    let result = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(dormant_interface.mac_address, FIXTURE_DHCP_RELAY_ADDRESS)
                .tonic_request(),
        )
        .await;
    let status = result.expect_err("dormant admin DHCP should be rejected");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert!(
        status
            .message()
            .contains("dormant non-primary admin interface")
    );

    // Verify the rejected request did not allocate a replacement address.
    let mut txn = pool.begin().await?;
    let persisted_interface =
        db::machine_interface::find_one(&mut *txn, dormant_interface.id).await?;
    assert!(persisted_interface.addresses.is_empty());
    txn.commit().await?;

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
        db::machine_interface::count_by_segment_id(&mut txn, env.admin_segment_ref())
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

        assert_eq!(response.segment_id.unwrap(), (env.admin_segment()));

        assert_eq!(response.mac_address, mac);
        assert_eq!(response.subdomain_id.unwrap(), env.domain.into());
        assert_eq!(response.address, expected_ip);
        assert_eq!(response.prefix, "192.0.2.0/24".to_owned());
        assert_eq!(response.gateway.unwrap(), "192.0.2.1".to_owned());
    }

    let mut txn = pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, env.admin_segment_ref())
            .await
            .unwrap(),
        NUM_MACHINES
    );
    txn.commit().await.unwrap();
    Ok(())
}

#[crate::sqlx_test]
async fn test_machine_dhcp_declared_admin_nic_allocates_from_relay_admin_segment(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = get_config();
    config.rack_management_enabled = true;
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::with_config(config)).await;

    // Create a second admin segment so the relay determines which admin segment is used.
    let second_admin_segment = create_network_segment(
        &env.api,
        "ADMIN_2",
        "192.0.12.0/24",
        "192.0.12.1",
        rpc::forge::NetworkSegmentType::Admin,
        None,
        true,
    )
    .await;

    // Register an expected host NIC declared as an admin-network NIC.
    let bmc_mac: MacAddress = "7a:7b:7c:7d:7e:10".parse().unwrap();
    let admin_nic_mac: MacAddress = "7a:7b:7c:7d:7e:11".parse().unwrap();
    env.api
        .add_expected_machine(tonic::Request::new(rpc::forge::ExpectedMachine {
            id: None,
            bmc_mac_address: bmc_mac.to_string(),
            bmc_username: "ADMIN".into(),
            bmc_password: "PASS".into(),
            chassis_serial_number: "EM-ADMIN-RELAY-001".into(),
            host_nics: vec![rpc::forge::ExpectedHostNic {
                mac_address: admin_nic_mac.to_string(),
                nic_type: Some("onboard".into()),
                fixed_ip: None,
                fixed_mask: None,
                fixed_gateway: None,
                primary: Some(true),
            }],
            ..Default::default()
        }))
        .await?;

    // DHCP through the second admin relay should allocate from that segment.
    let response = env
        .api
        .discover_dhcp(DhcpDiscovery::builder(admin_nic_mac, "192.0.12.1").tonic_request())
        .await?
        .into_inner();

    let expected_address: IpAddr = "192.0.12.3".parse().unwrap();
    assert_eq!(response.segment_id.unwrap(), second_admin_segment);
    assert_eq!(response.mac_address, admin_nic_mac.to_string());
    assert_eq!(response.subdomain_id.unwrap(), env.domain.into());
    assert_eq!(response.address, expected_address.to_string());
    assert_eq!(response.prefix, "192.0.12.0/24");
    assert_eq!(response.gateway.unwrap(), "192.0.12.1");

    // Verify the persisted interface matches the DHCP response.
    let interface_id = response
        .machine_interface_id
        .expect("DHCP response should include machine_interface_id");
    let mut txn = env.pool.begin().await?;
    let persisted_interface = db::machine_interface::find_one(txn.as_mut(), interface_id).await?;
    assert_eq!(persisted_interface.segment_id, second_admin_segment);
    assert_eq!(persisted_interface.mac_address, admin_nic_mac);
    assert_eq!(persisted_interface.domain_id, Some(env.domain.into()));
    assert!(persisted_interface.primary_interface);
    assert_eq!(persisted_interface.addresses, vec![expected_address]);

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
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some(segment_id_2),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            },
        ],
        auto: false,
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
        let iface = db::machine_interface::find_one(txn.as_mut(), *interface_id)
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

// test_dhcp_record_address_family verifies that find_by_mac_address correctly
// filters by address family. In a dual-stack environment, a machine interface
// has both IPv4 and IPv6 addresses. The DHCPv4 server must receive only the
// IPv4 record, and a future DHCPv6 server must receive only the IPv6 record.
#[crate::sqlx_test]
async fn test_dhcp_record_address_family(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a machine via DHCPv4 discovery — gives us an interface with an IPv4 address.
    let mac_address = "AB:CD:EF:01:23:45";
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mac_address, FIXTURE_DHCP_RELAY_ADDRESS).tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    let segment_id = response.segment_id.unwrap();
    let ipv4_address = response.address.clone();

    // Verify the IPv4 address is correct.
    let parsed_v4: IpAddr = ipv4_address.parse().unwrap();
    assert!(
        parsed_v4.is_ipv4(),
        "DHCPv4 discovery should return an IPv4 address"
    );

    // Insert an IPv6 address for the same interface, simulating dual-stack.
    let mut txn = pool.begin().await?;
    let parsed_mac: MacAddress = mac_address.parse().unwrap();
    let interfaces = db::machine_interface::find_by_mac_address(txn.as_mut(), parsed_mac).await?;
    let interface = &interfaces[0];

    let ipv6_addr: IpAddr = "fd00::42".parse().unwrap();
    sqlx::query("INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1, $2)")
        .bind(interface.id)
        .bind(ipv6_addr)
        .execute(&mut *txn)
        .await?;

    // The machine_dhcp_records view requires the address is contained within
    // the prefix, so we also need an IPv6 prefix on the same segment for the
    // IPv6 address to appear.
    sqlx::query(
        "INSERT INTO network_prefixes (segment_id, prefix, num_reserved) VALUES ($1, $2::cidr, 0)",
    )
    .bind(segment_id)
    .bind("fd00::/64")
    .execute(&mut *txn)
    .await?;

    txn.commit().await?;

    // Now test find_by_mac_address with IPv4 — should return only the IPv4 record.
    let mut txn = pool.begin().await?;
    let ipv4_record = db::dhcp_record::find_by_mac_address(
        &mut txn,
        &parsed_mac,
        &segment_id,
        IpAddressFamily::Ipv4,
    )
    .await?;
    assert!(
        ipv4_record.address.is_ipv4(),
        "IPv4 query should return an IPv4 address, got: {}",
        ipv4_record.address
    );
    assert_eq!(ipv4_record.address.to_string(), ipv4_address);
    txn.rollback().await?;

    // And with IPv6 — should return only the IPv6 record.
    let mut txn = pool.begin().await?;
    let ipv6_record = db::dhcp_record::find_by_mac_address(
        &mut txn,
        &parsed_mac,
        &segment_id,
        IpAddressFamily::Ipv6,
    )
    .await?;
    assert!(
        ipv6_record.address.is_ipv6(),
        "IPv6 query should return an IPv6 address, got: {}",
        ipv6_record.address
    );
    assert_eq!(ipv6_record.address, ipv6_addr);
    txn.rollback().await?;

    Ok(())
}

/// Resolve a machine_interface + its segment gateway for the given host, so
/// the test can drive a DHCP request with the same relay the real host would
/// see in production.
async fn host_interface_and_gateway(
    env: &TestEnv,
    host_machine_id: carbide_uuid::machine::MachineId,
) -> Result<(MacAddress, IpAddr), Box<dyn std::error::Error>> {
    let mut txn = env.pool.begin().await?;
    let interfaces_by_machine =
        db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_machine_id]).await?;
    let interface = interfaces_by_machine
        .get(&host_machine_id)
        .and_then(|ifaces| ifaces.first())
        .ok_or("host has no machine_interfaces")?;
    let prefix = db::network_prefix::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(db::network_prefix::SegmentIdColumn, &interface.segment_id),
    )
    .await?
    .into_iter()
    .next()
    .ok_or("no network_prefix for segment")?;
    let gateway = prefix.gateway.ok_or("segment prefix has no gateway")?;
    let mac = interface.mac_address;
    txn.rollback().await?;
    Ok((mac, gateway))
}

/// Insert an `instances` row directly, bypassing the allocator (which today
/// requires DPUs + VPCs). All the DHCP branch under test reads is
/// `instances.machine_id`, so a minimal INSERT is enough.
async fn attach_bare_instance(
    env: &TestEnv,
    machine_id: carbide_uuid::machine::MachineId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = env.pool.begin().await?;
    sqlx::query("INSERT INTO instances (machine_id) VALUES ($1)")
        .bind(machine_id)
        .execute(txn.as_mut())
        .await?;
    txn.commit().await?;
    Ok(())
}

// A host with DPUs must have its DHCP rejected once an instance is attached:
// the DPUs are expected to proxy the DHCP on the host's behalf. This preserves
// the long-standing behavior that predates zero-DPU support.
#[crate::sqlx_test]
#[ignore = "temporarily ignored while the DPU-ful host DHCP behavior is reconciled on this branch"]
async fn test_dhcp_rejects_dpu_host_with_instance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;
    attach_bare_instance(&env, mh.host().id).await?;

    let (host_mac, gateway) = host_interface_and_gateway(&env, mh.host().id).await?;

    let result = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(host_mac, FIXTURE_DHCP_RELAY_ADDRESS)
                .link_address(gateway.to_string())
                .tonic_request(),
        )
        .await;

    let status = result.expect_err("DHCP for DPU-ful host with instance should be rejected");
    assert!(
        status
            .message()
            .contains("DHCP request received for instance"),
        "unexpected error: {}",
        status.message()
    );

    Ok(())
}

// Host BMC DHCP must continue to work after an instance is allocated on a
// DPU-backed host. The instance DHCP rejection only applies to host data/admin
// DHCP that the DPU proxies, not to out-of-band BMC management.
#[crate::sqlx_test]
async fn test_dhcp_allows_host_bmc_with_instance_on_dpu_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mh = create_managed_host(&env).await;

    // Find the already-linked host BMC interface.
    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_all(txn.as_mut()).await?;
    let bmc_interface = interfaces
        .iter()
        .find(|interface| {
            interface.machine_id == Some(mh.host().id)
                && interface.interface_type == InterfaceType::Bmc
        })
        .ok_or("host has no BMC machine_interface")?;
    let bmc_mac = bmc_interface.mac_address;
    let bmc_segment_id = bmc_interface.segment_id;

    // Resolve the BMC segment gateway for the follow-up DHCP request.
    let prefix = db::network_prefix::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(db::network_prefix::SegmentIdColumn, &bmc_segment_id),
    )
    .await?
    .into_iter()
    .next()
    .ok_or("no network_prefix for BMC segment")?;
    let gateway = prefix.gateway.ok_or("BMC segment prefix has no gateway")?;
    txn.rollback().await?;

    // Allocate an instance after the BMC interface is linked.
    attach_bare_instance(&env, mh.host().id).await?;

    // A later BMC DHCP request should still return the BMC lease.
    let response = env
        .api
        .discover_dhcp(DhcpDiscovery::builder(bmc_mac, gateway.to_string()).tonic_request())
        .await
        .expect("host BMC DHCP should not be rejected because the host has an instance")
        .into_inner();

    assert_eq!(response.mac_address, bmc_mac.to_string());

    Ok(())
}

// A zero-DPU host with an instance attached has no DPU intermediary, so its
// own DHCP request must be allowed through instead of being rejected on the
// assumption that a DPU will handle it.
#[crate::sqlx_test]
async fn test_dhcp_allows_zero_dpu_host_with_instance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            ..Default::default()
        },
    )
    .await;
    create_host_inband_network_segment(&env.api, None).await;

    let mh = create_managed_host_with_config(&env, ManagedHostConfig::with_dpus(Vec::new())).await;
    assert!(
        mh.dpu_ids.is_empty(),
        "zero-DPU fixture should produce no DPU machines"
    );

    attach_bare_instance(&env, mh.host().id).await?;

    let (host_mac, gateway) = host_interface_and_gateway(&env, mh.host().id).await?;

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(host_mac, FIXTURE_DHCP_RELAY_ADDRESS)
                .link_address(gateway.to_string())
                .tonic_request(),
        )
        .await
        .expect("DHCP for zero-DPU host with instance should succeed")
        .into_inner();

    assert_eq!(response.mac_address, host_mac.to_string());

    Ok(())
}
