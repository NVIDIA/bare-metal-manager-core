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

use common::api_fixtures::{FIXTURE_DHCP_RELAY_ADDRESS, create_test_env};
use mac_address::MacAddress;
use rpc::forge::forge_server::Forge;
use rpc::forge::{ExpireDhcpLeaseRequest, ExpireDhcpLeaseStatus};
use tonic::Request;

use crate::tests::common;

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

    // Verify the address was deleted
    let mut txn = env.pool.begin().await?;
    let result =
        db::machine_interface_address::find_ipv4_for_interface(&mut txn, interface.id).await;
    assert!(result.is_err(), "address should have been deleted");

    // Verify the interface itself still exists
    let iface = db::machine_interface::find_one(&mut *txn, interface.id).await?;
    assert_eq!(iface.id, interface.id, "interface should still exist");

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
