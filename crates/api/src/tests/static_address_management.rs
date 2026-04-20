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

use common::api_fixtures::{FIXTURE_DHCP_RELAY_ADDRESS, create_test_env};
use mac_address::MacAddress;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    AssignStaticAddressRequest, AssignStaticAddressStatus, FindInterfaceAddressesRequest,
    RemoveStaticAddressRequest, RemoveStaticAddressStatus,
};
use tonic::Request;

use crate::tests::common;

#[crate::sqlx_test]
async fn test_assign_static_address(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    // Create an interface (via DHCP discovery to get an interface_id).
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:10").unwrap(),
        relay,
        None,
    )
    .await?;
    // Delete the DHCP address so we can assign a static one for this family.
    db::machine_interface_address::delete(&mut txn, &interface.id).await?;
    txn.commit().await?;

    // Assign a static address.
    let resp = env
        .api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "192.0.2.210".to_string(),
        }))
        .await?
        .into_inner();

    assert_eq!(resp.status(), AssignStaticAddressStatus::Assigned);
    assert_eq!(resp.ip_address, "192.0.2.210");

    Ok(())
}

#[crate::sqlx_test]
async fn test_assign_replaces_existing_static(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:11").unwrap(),
        relay,
        None,
    )
    .await?;
    db::machine_interface_address::delete(&mut txn, &interface.id).await?;
    txn.commit().await?;

    // Assign first static address.
    env.api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "192.0.2.211".to_string(),
        }))
        .await?;

    // Assign a different static address for the same family,
    // which should replace.
    let resp = env
        .api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "192.0.2.212".to_string(),
        }))
        .await?
        .into_inner();

    assert_eq!(resp.status(), AssignStaticAddressStatus::ReplacedStatic);
    assert_eq!(resp.ip_address, "192.0.2.212");

    // Verify only the new address exists.
    let addrs = env
        .api
        .find_interface_addresses(Request::new(FindInterfaceAddressesRequest {
            interface_id: Some(interface.id),
        }))
        .await?
        .into_inner();

    assert_eq!(addrs.addresses.len(), 1);
    assert_eq!(addrs.addresses[0].address, "192.0.2.212");
    assert_eq!(addrs.addresses[0].allocation_type, "static");

    Ok(())
}

#[crate::sqlx_test]
async fn test_assign_takes_over_dhcp_allocation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    // Create interface with DHCP-allocated IPv4.
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:12").unwrap(),
        relay,
        None,
    )
    .await?;
    let dhcp_ip = interface.addresses[0];
    txn.commit().await?;

    // And now assign a static IPv4 over the DHCP allocation,
    // which should take over.
    let resp = env
        .api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "192.0.2.213".to_string(),
        }))
        .await?
        .into_inner();

    assert_eq!(resp.status(), AssignStaticAddressStatus::ReplacedDhcp);
    assert_eq!(resp.ip_address, "192.0.2.213");

    // Verify the old DHCP address is gone and the static one is there.
    let addrs = env
        .api
        .find_interface_addresses(Request::new(FindInterfaceAddressesRequest {
            interface_id: Some(interface.id),
        }))
        .await?
        .into_inner();

    assert_eq!(addrs.addresses.len(), 1);
    assert_eq!(addrs.addresses[0].address, "192.0.2.213");
    assert_eq!(addrs.addresses[0].allocation_type, "static");
    assert_ne!(
        addrs.addresses[0].address,
        dhcp_ip.to_string(),
        "old DHCP address should be gone"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_remove_static_address(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:13").unwrap(),
        relay,
        None,
    )
    .await?;
    db::machine_interface_address::delete(&mut txn, &interface.id).await?;
    txn.commit().await?;

    // Assign then remove.
    env.api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "192.0.2.214".to_string(),
        }))
        .await?;

    let resp = env
        .api
        .remove_static_address(Request::new(RemoveStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "192.0.2.214".to_string(),
        }))
        .await?
        .into_inner();

    assert_eq!(resp.status(), RemoveStaticAddressStatus::Removed);

    // Verify no addresses remain.
    let addrs = env
        .api
        .find_interface_addresses(Request::new(FindInterfaceAddressesRequest {
            interface_id: Some(interface.id),
        }))
        .await?
        .into_inner();

    assert!(addrs.addresses.is_empty());

    Ok(())
}

#[crate::sqlx_test]
async fn test_remove_nonexistent_returns_not_found(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:14").unwrap(),
        relay,
        None,
    )
    .await?;
    txn.commit().await?;

    let resp = env
        .api
        .remove_static_address(Request::new(RemoveStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "10.99.99.99".to_string(),
        }))
        .await?
        .into_inner();

    assert_eq!(resp.status(), RemoveStaticAddressStatus::NotFound);

    Ok(())
}

/// Trying to remove a DHCP-allocated address via remove-address should
/// return NotFound -- remove-address only operates on static allocations.
/// DHCP allocations are managed by the lease expiration flow.
#[crate::sqlx_test]
async fn test_remove_dhcp_address_returns_not_found(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    // Create an interface with a DHCP-allocated IP.
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:25").unwrap(),
        relay,
        None,
    )
    .await?;
    let dhcp_ip = interface.addresses[0];
    txn.commit().await?;

    // Try to remove it via remove-address -- should return NotFound
    // because the address is DHCP, not static.
    let resp = env
        .api
        .remove_static_address(Request::new(RemoveStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: dhcp_ip.to_string(),
        }))
        .await?
        .into_inner();

    assert_eq!(
        resp.status(),
        RemoveStaticAddressStatus::NotFound,
        "remove-address should not delete DHCP allocations"
    );

    // Verify the DHCP address is still there.
    let mut txn = env.pool.begin().await?;
    let addr =
        db::machine_interface_address::find_ipv4_for_interface(&mut txn, interface.id).await?;
    assert_eq!(addr.address, dhcp_ip, "DHCP address should still exist");

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_interface_addresses_shows_types(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    // Create interface with DHCP address.
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:15").unwrap(),
        relay,
        None,
    )
    .await?;
    txn.commit().await?;

    let addrs = env
        .api
        .find_interface_addresses(Request::new(FindInterfaceAddressesRequest {
            interface_id: Some(interface.id),
        }))
        .await?
        .into_inner();

    assert_eq!(addrs.addresses.len(), 1);
    assert_eq!(addrs.addresses[0].allocation_type, "dhcp");

    Ok(())
}

#[crate::sqlx_test]
async fn test_assign_remove_then_dhcp_reallocates(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();
    let mac = MacAddress::from_str("aa:bb:cc:dd:ee:16").unwrap();
    let static_ip = "192.0.2.216";

    // First, create the interface, clear its DHCP address, and
    // a assign static one.
    let mut txn = env.pool.begin().await?;
    let interface =
        db::machine_interface::validate_existing_mac_and_create(&mut txn, mac, relay, None).await?;
    db::machine_interface_address::delete(&mut txn, &interface.id).await?;
    txn.commit().await?;

    env.api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: static_ip.to_string(),
        }))
        .await?;

    // Now, remove the static address.
    let remove_resp = env
        .api
        .remove_static_address(Request::new(RemoveStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: static_ip.to_string(),
        }))
        .await?
        .into_inner();
    assert_eq!(remove_resp.status(), RemoveStaticAddressStatus::Removed);

    // And then fire off a DHCPDISCOVER -- the interface has no addresses,
    // should it should re-allocate a new one that is DHCP-managed.
    let mac_str = mac.to_string();
    let discover_resp = env
        .api
        .discover_dhcp(
            crate::tests::common::rpc_builder::DhcpDiscovery::builder(
                &mac_str,
                FIXTURE_DHCP_RELAY_ADDRESS,
            )
            .tonic_request(),
        )
        .await?
        .into_inner();

    assert!(
        !discover_resp.address.is_empty(),
        "should get a DHCP address after static was removed"
    );
    assert_eq!(
        discover_resp.machine_interface_id.unwrap(),
        interface.id,
        "should reuse the same interface"
    );

    // Moment of truth.. verify it's a DHCP allocation.
    let addrs = env
        .api
        .find_interface_addresses(Request::new(FindInterfaceAddressesRequest {
            interface_id: Some(interface.id),
        }))
        .await?
        .into_inner();
    assert_eq!(addrs.addresses.len(), 1);
    assert_eq!(addrs.addresses[0].allocation_type, "dhcp");

    Ok(())
}

/// When assigning a static IP that's within a managed segment's prefix,
/// the interface's segment_id should be updated to that segment.
#[crate::sqlx_test]
async fn test_assign_moves_interface_to_correct_segment(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    // Create interface on the admin segment via DHCP.
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:20").unwrap(),
        relay,
        None,
    )
    .await?;
    db::machine_interface_address::delete(&mut txn, &interface.id).await?;
    txn.commit().await?;

    // Interface is on the admin segment (192.0.2.0/24).
    assert_eq!(interface.segment_id, env.admin_segment.unwrap());

    // Assign a static IP in the underlay segment's range (192.0.1.0/24).
    env.api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "192.0.1.180".to_string(),
        }))
        .await?;

    // Verify the interface moved to the underlay segment.
    let mut txn = env.pool.begin().await?;
    let updated = db::machine_interface::find_one(&mut *txn, interface.id).await?;
    assert_eq!(
        updated.segment_id,
        env.underlay_segment.unwrap(),
        "interface should have moved to the underlay segment"
    );

    Ok(())
}

/// When assigning an external static IP (not in any managed prefix),
/// the interface's segment_id should be updated to static-assignments.
#[crate::sqlx_test]
async fn test_assign_external_ip_moves_to_static_assignments(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    // Create interface on the admin segment via DHCP.
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:21").unwrap(),
        relay,
        None,
    )
    .await?;
    db::machine_interface_address::delete(&mut txn, &interface.id).await?;
    txn.commit().await?;

    assert_eq!(interface.segment_id, env.admin_segment.unwrap());

    // Assign an external IP (not in any managed segment).
    env.api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "10.50.1.100".to_string(),
        }))
        .await?;

    // Verify the interface moved to static-assignments with the segment's domain.
    let mut txn = env.pool.begin().await?;
    let updated = db::machine_interface::find_one(&mut *txn, interface.id).await?;
    let static_seg = db::network_segment::static_assignments(&mut txn).await?;
    assert_eq!(
        updated.segment_id, static_seg.id,
        "interface should have moved to the static-assignments segment"
    );
    assert_eq!(
        updated.domain_id, static_seg.subdomain_id,
        "domain_id should match the static-assignments segment's subdomain"
    );

    Ok(())
}

/// When assigning a static IP within the interface's current segment,
/// the segment_id should not change.
#[crate::sqlx_test]
async fn test_assign_within_same_segment_no_move(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    // Create interface on the admin segment via DHCP.
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:22").unwrap(),
        relay,
        None,
    )
    .await?;
    db::machine_interface_address::delete(&mut txn, &interface.id).await?;
    txn.commit().await?;

    let original_segment = interface.segment_id;

    // Assign a static IP within the same admin segment (192.0.2.0/24).
    env.api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface.id),
            ip_address: "192.0.2.220".to_string(),
        }))
        .await?;

    // Verify the segment didn't change.
    let mut txn = env.pool.begin().await?;
    let updated = db::machine_interface::find_one(&mut *txn, interface.id).await?;
    assert_eq!(
        updated.segment_id, original_segment,
        "interface should stay on the same segment"
    );

    Ok(())
}

/// When an interface is on static-assignments (external IP was assigned
/// then removed), DHCP discover should move it back to the correct
/// segment based on the relay address and allocate a new IP.
#[crate::sqlx_test]
async fn test_dhcp_moves_interface_back_from_static_assignments(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mac = MacAddress::from_str("aa:bb:cc:dd:ee:23").unwrap();

    // First, the initial DHCP discover, which creates an
    // interface on the admin segment.
    let mac_str = mac.to_string();
    let response1 = env
        .api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(&mac_str, FIXTURE_DHCP_RELAY_ADDRESS)
                .tonic_request(),
        )
        .await?
        .into_inner();
    let interface_id = response1.machine_interface_id.unwrap();

    // Next, assign an external static IP, which moves the interface
    // to static-assignments.
    env.api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface_id),
            ip_address: "10.50.1.200".to_string(),
        }))
        .await?;

    // Verify it's on static-assignments.
    let mut txn = env.pool.begin().await?;
    let iface = db::machine_interface::find_one(&mut *txn, interface_id).await?;
    let static_seg = db::network_segment::static_assignments(&mut txn).await?;
    assert_eq!(iface.segment_id, static_seg.id);
    txn.commit().await?;

    // And then remove the static address.
    env.api
        .remove_static_address(Request::new(RemoveStaticAddressRequest {
            interface_id: Some(interface_id),
            ip_address: "10.50.1.200".to_string(),
        }))
        .await?;

    // And now re-walk the DHCP discover path again, which should move
    // the interace back to admin segment and allocate an IP.
    let response2 = env
        .api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(&mac_str, FIXTURE_DHCP_RELAY_ADDRESS)
                .tonic_request(),
        )
        .await?
        .into_inner();

    assert!(
        !response2.address.is_empty(),
        "should get a new IP after DHCP re-discover"
    );
    assert_eq!(
        response2.machine_interface_id.unwrap(),
        interface_id,
        "should reuse the same interface"
    );

    // Verify the interface moved back to the admin segment
    // with the correct domain_id.
    let mut txn = env.pool.begin().await?;
    let updated = db::machine_interface::find_one(&mut *txn, interface_id).await?;
    assert_eq!(
        updated.segment_id,
        env.admin_segment.unwrap(),
        "interface should have moved back to admin segment from static-assignments"
    );
    assert!(
        updated.domain_id.is_some(),
        "domain_id should be restored when moving back from static-assignments"
    );

    Ok(())
}

/// When an interface is on static-assignments and still has a static
/// address, DHCP discover should NOT move it back -- the operator's
/// static assignment takes priority over DHCP.
#[crate::sqlx_test]
async fn test_dhcp_does_not_move_interface_with_static_address(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mac = MacAddress::from_str("aa:bb:cc:dd:ee:24").unwrap();

    // First, the DHCP discover flow -- create an interface on
    // the admin segment.
    let mac_str = mac.to_string();
    let response1 = env
        .api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(&mac_str, FIXTURE_DHCP_RELAY_ADDRESS)
                .tonic_request(),
        )
        .await?
        .into_inner();
    let interface_id = response1.machine_interface_id.unwrap();

    // And now assign external static IP -- this will move the
    // interface to static-assignments.
    env.api
        .assign_static_address(Request::new(AssignStaticAddressRequest {
            interface_id: Some(interface_id),
            ip_address: "10.50.1.201".to_string(),
        }))
        .await?;

    // Verify it's on static-assignments with the static IP.
    let mut txn = env.pool.begin().await?;
    let static_seg = db::network_segment::static_assignments(&mut txn).await?;
    let iface = db::machine_interface::find_one(&mut *txn, interface_id).await?;
    assert_eq!(iface.segment_id, static_seg.id);
    assert!(
        !iface.addresses.is_empty(),
        "should have the static address"
    );
    txn.commit().await?;

    // Hit the DHCP discover again -- the interface has an external static
    // IP on static-assignments. The discover flow finds the interface but
    // doesn't move it (static takes priority). The DHCP record view will
    // fail because the external IP isn't within any managed prefix, which
    // is correct -- we don't serve DHCP for external networks.
    let result = env
        .api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(&mac_str, FIXTURE_DHCP_RELAY_ADDRESS)
                .tonic_request(),
        )
        .await;

    // The discover fails (external IP can't be in the DHCP records view),
    // but the important thing is the interface was NOT moved.
    assert!(
        result.is_err(),
        "DHCP discover should fail for external static IP"
    );

    // Verify the interface is still on static-assignments, untouched.
    let mut txn = env.pool.begin().await?;
    let updated = db::machine_interface::find_one(&mut *txn, interface_id).await?;
    assert_eq!(
        updated.segment_id, static_seg.id,
        "interface should stay on static-assignments when it has a static address"
    );
    assert!(
        updated.addresses.contains(&"10.50.1.201".parse().unwrap()),
        "static address should still be intact"
    );

    Ok(())
}

/// On a reserved segment, a device with a static reservation gets
/// its reserved IP via DHCP.
#[crate::sqlx_test]
async fn test_reserved_segment_serves_static_reservation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let bmc_mac = MacAddress::from_str("aa:bb:cc:dd:ee:30").unwrap();
    let reserved_ip: IpAddr = "192.0.2.230".parse().unwrap();

    // Set the admin segment to reserved allocation strategy.
    let mut txn = env.pool.begin().await?;
    sqlx::query("UPDATE network_segments SET allocation_strategy = 'reserved' WHERE id = $1")
        .bind(env.admin_segment.unwrap())
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    // Create a static reservation for this MAC on the admin segment.
    let mut txn = env.pool.begin().await?;
    let admin_seg = db::network_segment::admin(&mut txn).await?;
    db::machine_interface::create(
        &mut txn,
        &admin_seg,
        &bmc_mac,
        admin_seg.subdomain_id,
        true,
        model::address_selection_strategy::AddressSelectionStrategy::StaticAddress(reserved_ip),
    )
    .await?;
    txn.commit().await?;

    // DHCP discover -- should get the reserved IP.
    let mac_str = bmc_mac.to_string();
    let response = env
        .api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(&mac_str, FIXTURE_DHCP_RELAY_ADDRESS)
                .tonic_request(),
        )
        .await?
        .into_inner();

    assert_eq!(
        response.address,
        reserved_ip.to_string(),
        "should get the reserved IP"
    );

    Ok(())
}

/// On a reserved segment, a device without a static reservation
/// gets no DHCP response (the discover fails).
#[crate::sqlx_test]
async fn test_reserved_segment_rejects_unknown_mac(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Set the admin segment to reserved allocation strategy.
    let mut txn = env.pool.begin().await?;
    sqlx::query("UPDATE network_segments SET allocation_strategy = 'reserved' WHERE id = $1")
        .bind(env.admin_segment.unwrap())
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    // DHCP discover with an unknown MAC -- should fail.
    let result = env
        .api
        .discover_dhcp(
            common::rpc_builder::DhcpDiscovery::builder(
                "aa:bb:cc:dd:ee:31",
                FIXTURE_DHCP_RELAY_ADDRESS,
            )
            .tonic_request(),
        )
        .await;

    assert!(
        result.is_err(),
        "reserved segment should reject unknown MAC"
    );

    Ok(())
}
