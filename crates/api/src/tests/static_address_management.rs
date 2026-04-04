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

    // Create an interface (via DHCP discovery to get an interface_id)
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:10").unwrap(),
        relay,
        None,
    )
    .await?;
    // Delete the DHCP address so we can assign a static one for this family
    db::machine_interface_address::delete(&mut txn, &interface.id).await?;
    txn.commit().await?;

    // Assign a static address
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
