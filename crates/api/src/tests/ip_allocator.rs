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
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::network_prefix::NewNetworkPrefix;
use model::network_segment::{
    NetworkSegmentControllerState, NetworkSegmentType, NewNetworkSegment,
};

use crate::tests::common::api_fixtures::create_test_env;

/// Test that machine_interface::create allocates the correct IPv4 address
/// from the admin segment (192.0.2.0/24 with num_reserved=3, gateway=.1).
#[crate::sqlx_test]
async fn test_machine_interface_create_with_ipv4_prefix(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let network_segment = db::network_segment::admin(&mut txn).await?;
    let network_prefix = network_segment
        .prefixes
        .first()
        .expect("network_segment should have had at least one prefix");

    // The next IP should be .3, since num_reserved = 3.
    let expected_ip = match network_prefix.prefix.ip() {
        IpAddr::V4(ip) => {
            let [o1, o2, o3, _] = ip.octets();
            Ipv4Addr::new(
                o1,
                o2,
                o3,
                network_prefix
                    .num_reserved
                    .try_into()
                    .expect("too many reserved IPs in admin segment"),
            )
        }
        _ => panic!("admin segment should have an IPv4 prefix"),
    };

    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        Some(env.domain.into()),
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await
    .unwrap();

    assert_eq!(
        interface.addresses.len(),
        1,
        "interface should have 1 address allocated"
    );
    assert_eq!(
        interface.addresses[0], expected_ip,
        "interface address should be the first available IP after reserved"
    );

    // Allocate a second interface and verify it gets a different address
    let interface2 = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &MacAddress::from_str("ff:ff:ff:ff:ff:fe").unwrap(),
        Some(env.domain.into()),
        false,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await
    .unwrap();

    assert_ne!(
        interface.addresses[0], interface2.addresses[0],
        "two allocations should produce different addresses"
    );

    Ok(())
}

/// Verify that machine_interface::create allocates from an IPv6-only segment.
#[crate::sqlx_test]
async fn test_machine_interface_create_with_ipv6_prefix(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let domain = db::dns::domain::find_by_name(&mut txn, "dwrt1.com")
        .await?
        .into_iter()
        .next()
        .unwrap();

    // Create an underlay segment with only an IPv6 prefix
    let new_ns = NewNetworkSegment {
        name: "IPV6-UNDERLAY-TEST".to_string(),
        subdomain_id: Some(domain.id),
        vpc_id: None,
        mtu: 1500,
        prefixes: vec![NewNetworkPrefix {
            prefix: "2001:db8:abcd::0/112".parse().unwrap(),
            gateway: None,
            num_reserved: 2,
        }],
        vlan_id: None,
        vni: None,
        segment_type: NetworkSegmentType::Underlay,
        id: uuid::Uuid::new_v4().into(),
        can_stretch: None,
    };
    let network_segment =
        db::network_segment::persist(new_ns, &mut txn, NetworkSegmentControllerState::Ready)
            .await?;

    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &MacAddress::from_str("aa:bb:cc:dd:ee:01").unwrap(),
        Some(domain.id),
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    assert_eq!(
        interface.addresses.len(),
        1,
        "interface should have 1 address allocated"
    );
    let addr = interface.addresses[0];
    assert!(
        addr.is_ipv6(),
        "allocated address should be IPv6, got {addr}"
    );

    // Allocate a second interface to verify sequential allocation works
    let interface2 = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &MacAddress::from_str("aa:bb:cc:dd:ee:02").unwrap(),
        Some(domain.id),
        false,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    let addr2 = interface2.addresses[0];
    assert!(
        addr2.is_ipv6(),
        "second address should be IPv6, got {addr2}"
    );
    assert_ne!(
        addr, addr2,
        "two allocations should produce different addresses"
    );

    Ok(())
}

/// Verify that a dual-stack segment (IPv4 + IPv6 prefixes) allocates one
/// address from each family, and that the hostname is derived from the IPv4
/// address (more human-readable).
#[crate::sqlx_test]
async fn test_machine_interface_create_dual_stack(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let domain = db::dns::domain::find_by_name(&mut txn, "dwrt1.com")
        .await?
        .into_iter()
        .next()
        .unwrap();

    let new_ns = NewNetworkSegment {
        name: "DUAL-STACK-TEST".to_string(),
        subdomain_id: Some(domain.id),
        vpc_id: None,
        mtu: 1500,
        prefixes: vec![
            NewNetworkPrefix {
                prefix: "10.99.1.0/24".parse().unwrap(),
                gateway: Some("10.99.1.1".parse().unwrap()),
                num_reserved: 1,
            },
            NewNetworkPrefix {
                prefix: "2001:db8:99::0/112".parse().unwrap(),
                gateway: None,
                num_reserved: 1,
            },
        ],
        vlan_id: None,
        vni: None,
        segment_type: NetworkSegmentType::Underlay,
        id: uuid::Uuid::new_v4().into(),
        can_stretch: None,
    };
    let network_segment =
        db::network_segment::persist(new_ns, &mut txn, NetworkSegmentControllerState::Ready)
            .await?;

    let interface = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &MacAddress::from_str("aa:bb:cc:00:00:01").unwrap(),
        Some(domain.id),
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    // Dual-stack: should have one IPv4 and one IPv6 address
    assert_eq!(
        interface.addresses.len(),
        2,
        "dual-stack interface should have 2 addresses, got {:?}",
        interface.addresses
    );

    let has_v4 = interface.addresses.iter().any(|a| a.is_ipv4());
    let has_v6 = interface.addresses.iter().any(|a| a.is_ipv6());
    assert!(has_v4, "should have an IPv4 address");
    assert!(has_v6, "should have an IPv6 address");

    // Hostname should be derived from the IPv4 address (preferred for readability)
    assert!(
        !interface.hostname.contains(':'),
        "hostname should be derived from IPv4 (no colons), got: {}",
        interface.hostname
    );
    assert!(
        interface.hostname.contains('-'),
        "hostname should have dashes from IPv4 dot replacement, got: {}",
        interface.hostname
    );

    // Allocate a second interface and verify both families get new addresses
    let interface2 = db::machine_interface::create(
        &mut txn,
        &network_segment,
        &MacAddress::from_str("aa:bb:cc:00:00:02").unwrap(),
        Some(domain.id),
        false,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    assert_eq!(
        interface2.addresses.len(),
        2,
        "second dual-stack interface should also have 2 addresses"
    );

    // No addresses should overlap between the two interfaces
    for addr in &interface.addresses {
        assert!(
            !interface2.addresses.contains(addr),
            "address {addr} was allocated to both interfaces"
        );
    }

    Ok(())
}
