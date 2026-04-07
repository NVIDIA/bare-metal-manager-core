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
use model::address_selection_strategy::AddressSelectionStrategy;
use rpc::forge::forge_server::Forge;
use rpc::forge::{ExpireDhcpLeaseRequest, ExpireDhcpLeaseStatus};
use tonic::Request;

use crate::tests::common;
use crate::tests::common::rpc_builder::DhcpDiscovery;

#[crate::sqlx_test]
async fn test_expire_releases_allocation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let relay: std::net::IpAddr = FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap();

    // Create an interface with an allocated IP
    let mut txn = env.pool.begin().await?;
    let interface = db::machine_interface::validate_existing_mac_and_create(
        &mut txn,
        MacAddress::from_str("aa:bb:cc:dd:ee:01").unwrap(),
        relay,
        None,
    )
    .await?;
    let ip = interface.addresses[0];
    txn.commit().await?;

    // Expire the lease via the RPC endpoint
    let response = env
        .api
        .expire_dhcp_lease(Request::new(ExpireDhcpLeaseRequest {
            ip_address: ip.to_string(),
        }))
        .await?;

    let resp = response.into_inner();
    assert_eq!(resp.ip_address, ip.to_string());
    assert_eq!(resp.status(), ExpireDhcpLeaseStatus::Released);

    // Verify the address was deleted but the interface preserved
    let mut txn = env.pool.begin().await?;
    let result =
        db::machine_interface_address::find_ipv4_for_interface(&mut txn, interface.id).await;
    assert!(result.is_err(), "address should have been deleted");

    let iface = db::machine_interface::find_one(&mut *txn, interface.id).await?;
    assert_eq!(
        iface.id, interface.id,
        "interface should still exist (only the address is removed)"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_expire_nonexistent_address_returns_not_found(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let response = env
        .api
        .expire_dhcp_lease(Request::new(ExpireDhcpLeaseRequest {
            ip_address: "10.99.99.99".to_string(),
        }))
        .await?;

    let resp = response.into_inner();
    assert_eq!(resp.ip_address, "10.99.99.99");
    assert_eq!(resp.status(), ExpireDhcpLeaseStatus::NotFound);

    Ok(())
}

#[crate::sqlx_test]
async fn test_expire_invalid_address_fails(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let result = env
        .api
        .expire_dhcp_lease(Request::new(ExpireDhcpLeaseRequest {
            ip_address: "not-an-ip".to_string(),
        }))
        .await;

    assert!(result.is_err(), "invalid IP address should fail");

    Ok(())
}

#[crate::sqlx_test]
async fn test_expire_ipv6_address(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let response = env
        .api
        .expire_dhcp_lease(Request::new(ExpireDhcpLeaseRequest {
            ip_address: "fd00::42".to_string(),
        }))
        .await?;

    let resp = response.into_inner();
    assert_eq!(resp.ip_address, "fd00::42");
    assert_eq!(resp.status(), ExpireDhcpLeaseStatus::NotFound);

    Ok(())
}

#[crate::sqlx_test]
async fn test_discover_reallocates_after_expiration(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mac_address = "aa:bb:cc:dd:ee:07";

    // First, we do the initial DHCP discover, which
    // creates an interface and allocates an IP.
    let response1 = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mac_address, FIXTURE_DHCP_RELAY_ADDRESS).tonic_request(),
        )
        .await?
        .into_inner();
    let original_ip = response1.address.clone();
    assert!(
        !original_ip.is_empty(),
        "should get an IP on first discover"
    );

    // Now, expire the lease by actually sending an `expire_dhcp_lease()`
    // API call. This deletes the address, BUT keeps the interface (which
    // now doesn't have an address).
    let expire_response = env
        .api
        .expire_dhcp_lease(Request::new(ExpireDhcpLeaseRequest {
            ip_address: original_ip.clone(),
        }))
        .await?
        .into_inner();
    assert_eq!(expire_response.status(), ExpireDhcpLeaseStatus::Released);

    // And finally, DHCP discover again! This should see the interface
    // exists, but doesn't have an IP, so it will [re]allocate an IP to
    // that pre-existing interface
    let response2 = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mac_address, FIXTURE_DHCP_RELAY_ADDRESS).tonic_request(),
        )
        .await?
        .into_inner();
    assert!(
        !response2.address.is_empty(),
        "should get an IP after re-allocation"
    );

    // Verify the interface is be the same one (preserved across expiration).
    assert_eq!(
        response1.machine_interface_id, response2.machine_interface_id,
        "should reuse the same interface"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_expire_does_not_delete_static_allocation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let static_ip: IpAddr = "192.0.2.200".parse().unwrap();

    // Create an interface with a static IP via the proper create path.
    let mut txn = env.pool.begin().await?;
    let segment = db::network_segment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &segment,
        &MacAddress::from_str("aa:bb:cc:dd:ee:08").unwrap(),
        segment.subdomain_id,
        true,
        AddressSelectionStrategy::StaticAddress(static_ip),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(interface.addresses[0], static_ip);

    // Try to expire it -- should NOT delete because it's static.
    let response = env
        .api
        .expire_dhcp_lease(Request::new(ExpireDhcpLeaseRequest {
            ip_address: static_ip.to_string(),
        }))
        .await?
        .into_inner();
    assert_eq!(
        response.status(),
        ExpireDhcpLeaseStatus::NotFound,
        "static allocation should not be expired"
    );

    // Verify the address still exists.
    let mut txn = env.pool.begin().await?;
    let addr =
        db::machine_interface_address::find_ipv4_for_interface(&mut txn, interface.id).await?;
    assert_eq!(addr.address, static_ip, "static address should still exist");

    Ok(())
}

#[crate::sqlx_test]
async fn test_static_address_survives_expiration_and_rediscover(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let mac = MacAddress::from_str("aa:bb:cc:dd:ee:09").unwrap();
    let static_ip: IpAddr = "192.0.2.201".parse().unwrap();

    // Create an interface with a static IP via the proper create path.
    let mut txn = env.pool.begin().await?;
    let segment = db::network_segment::admin(&mut txn).await?;
    let interface = db::machine_interface::create(
        &mut txn,
        &segment,
        &mac,
        segment.subdomain_id,
        true,
        AddressSelectionStrategy::StaticAddress(static_ip),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(interface.addresses[0], static_ip);

    // Device goes offline, Kea expires the lease.
    let expire_response = env
        .api
        .expire_dhcp_lease(Request::new(ExpireDhcpLeaseRequest {
            ip_address: static_ip.to_string(),
        }))
        .await?
        .into_inner();
    assert_eq!(
        expire_response.status(),
        ExpireDhcpLeaseStatus::NotFound,
        "static address should not be expired"
    );

    // Device comes back online, sends DHCP discover.
    let mac_str = mac.to_string();
    let discover_response = env
        .api
        .discover_dhcp(DhcpDiscovery::builder(&mac_str, FIXTURE_DHCP_RELAY_ADDRESS).tonic_request())
        .await?
        .into_inner();

    // Should get the same static IP back, on the same interface.
    assert_eq!(
        discover_response.address,
        static_ip.to_string(),
        "should get the same static IP back"
    );
    assert_eq!(
        discover_response.machine_interface_id.unwrap(),
        interface.id,
        "should reuse the same interface"
    );

    Ok(())
}
