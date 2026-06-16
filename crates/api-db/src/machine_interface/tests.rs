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

use model::machine_interface::InterfaceType;
use model::network_prefix::NewNetworkPrefix;
use model::network_segment::{
    AllocationStrategy, NetworkSegmentControllerState, NetworkSegmentType, NewNetworkSegment,
};

use super::*;
use crate as db;

async fn create_static_assignments_segment(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = db::Transaction::begin(pool).await?;
    db::network_segment::persist(
        NewNetworkSegment {
            id: uuid::Uuid::new_v4().into(),
            name: db::network_segment::STATIC_ASSIGNMENTS_SEGMENT_NAME.to_string(),
            subdomain_id: None,
            vpc_id: None,
            mtu: 1500,
            prefixes: vec![NewNetworkPrefix {
                prefix: "169.254.254.254/32".parse().unwrap(),
                gateway: None,
                num_reserved: 1,
            }],
            vlan_id: None,
            vni: None,
            segment_type: NetworkSegmentType::Underlay,
            can_stretch: Some(false),
            allocation_strategy: AllocationStrategy::Reserved,
        },
        txn.as_pgconn(),
        NetworkSegmentControllerState::Ready,
    )
    .await?;
    txn.commit().await?;

    Ok(())
}

/// Verify `preallocate_machine_interface` is idempotent.
/// AddExpectedMachine, expected_machines.json, and the DHCP discover() flow can
/// all fire against the same (ip, mac) pair, including after state has already
/// converged, which is both on purpose and to help flexibly adjust where we
/// find these calls fit best.
///
/// A repeat call must be Ok without changing rows.
#[crate::sqlx_test]
async fn test_preallocate_machine_interface_is_idempotent(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    let mac: MacAddress = "7A:7B:7C:7D:7E:31".parse().unwrap();
    let ip: std::net::IpAddr = "192.0.2.241".parse().unwrap();

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac, ip, None).await?;
    txn.commit().await?;

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac, ip, None).await?;
    let interfaces = find_by_mac_address(&mut txn, mac).await?;
    txn.commit().await?;

    assert_eq!(
        interfaces.len(),
        1,
        "second preallocate should be a no-op, not create a duplicate row"
    );
    assert!(
        interfaces[0].addresses.contains(&ip),
        "interface should still carry the static IP"
    );

    Ok(())
}

/// Pre-allocating a different IP for an existing MAC must error, rather than
/// silently reassigning. If an `expected_machine.bmc_ip_address` (or a host_nic
/// fixed_ip) drifts from its `machine_interface` row, operators should see the
/// conflict instead of an automatic rewrite.
#[crate::sqlx_test]
async fn test_preallocate_machine_interface_rejects_conflicting_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    let mac: MacAddress = "7A:7B:7C:7D:7E:32".parse().unwrap();
    let ip1: std::net::IpAddr = "192.0.2.242".parse().unwrap();
    let ip2: std::net::IpAddr = "192.0.2.243".parse().unwrap();

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac, ip1, None).await?;
    txn.commit().await?;

    let mut txn = db::Transaction::begin(&pool).await?;
    let result = preallocate_machine_interface(txn.as_pgconn(), mac, ip2, None).await;
    assert!(
        matches!(result, Err(DatabaseError::InvalidArgument(_))),
        "preallocating a different IP for the same MAC should be rejected, got {result:?}"
    );

    Ok(())
}

/// Symmetric to `test_preallocate_machine_interface_rejects_conflicting_ip`: pre-allocating
/// an IP that another MAC already owns must error rather than silently reassigning. Covers
/// the `find_by_address`-branch in `preallocate_machine_interface_with_type`.
#[crate::sqlx_test]
async fn test_preallocate_machine_interface_rejects_ip_owned_by_different_mac(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    let mac_a: MacAddress = "7A:7B:7C:7D:7E:35".parse().unwrap();
    let mac_b: MacAddress = "7A:7B:7C:7D:7E:36".parse().unwrap();
    let ip: std::net::IpAddr = "192.0.2.248".parse().unwrap();

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac_a, ip, None).await?;
    txn.commit().await?;

    let mut txn = db::Transaction::begin(&pool).await?;
    let result = preallocate_machine_interface(txn.as_pgconn(), mac_b, ip, None).await;
    assert!(
        matches!(result, Err(DatabaseError::InvalidArgument(_))),
        "preallocating an IP owned by a different MAC should be rejected, got {result:?}"
    );

    Ok(())
}

/// After a `machine_interface` row gets deleted (e.g. force-delete
/// --delete-interfaces), a subsequent `preallocate_machine_interface` call
/// must successfully recreate it with the same static IP. This is the
/// deferred-allocation flow that we rely on with DHCP discover(...).
#[crate::sqlx_test]
async fn test_preallocate_machine_interface_recreates_after_deletion(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    let mac: MacAddress = "7A:7B:7C:7D:7E:33".parse().unwrap();
    let ip: std::net::IpAddr = "192.0.2.244".parse().unwrap();

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac, ip, None).await?;
    let interfaces_before = find_by_mac_address(&mut txn, mac).await?;
    let interface_id = interfaces_before[0].id;
    delete(&interface_id, txn.as_pgconn()).await?;
    txn.commit().await?;

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac, ip, None).await?;
    let interfaces_after = find_by_mac_address(&mut txn, mac).await?;
    txn.commit().await?;

    assert_eq!(
        interfaces_after.len(),
        1,
        "interface should be re-created after deletion"
    );
    assert!(
        interfaces_after[0].addresses.contains(&ip),
        "re-created interface should carry the same static IP"
    );

    Ok(())
}

/// When an interface row already exists for the right (MAC, IP) but with the wrong
/// `interface_type`, a subsequent preallocate call should promote the type rather than
/// erroring or creating a duplicate. Covers the case where a host NIC initially DHCPs in as
/// `InterfaceType::Data`, then the operator's expected_machine config later marks the same
/// MAC as the BMC (or vice versa), and the next reconciliation pass (or discover hook)
/// reconciles.
#[crate::sqlx_test]
async fn test_preallocate_machine_interface_promotes_interface_type(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    let mac: MacAddress = "7A:7B:7C:7D:7E:34".parse().unwrap();
    let ip: std::net::IpAddr = "192.0.2.247".parse().unwrap();

    // Initial preallocation lands as InterfaceType::Data.
    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac, ip, None).await?;
    let before = find_by_mac_address(&mut txn, mac).await?;
    assert_eq!(
        before[0].interface_type,
        InterfaceType::Data,
        "Data-variant preallocate should start as InterfaceType::Data"
    );
    txn.commit().await?;

    // Re-preallocate the same (MAC, IP) but as the BMC variant. Helper should promote
    // the existing row's interface_type rather than erroring or creating a duplicate.
    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_bmc_machine_interface(txn.as_pgconn(), mac, ip, None).await?;
    let after = find_by_mac_address(&mut txn, mac).await?;
    txn.commit().await?;

    assert_eq!(after.len(), 1, "no duplicate row should have been created");
    assert_eq!(
        after[0].interface_type,
        InterfaceType::Bmc,
        "Bmc-variant preallocate should promote the existing row to InterfaceType::Bmc"
    );
    assert!(
        after[0].addresses.contains(&ip),
        "promoted row should still carry the same IP"
    );

    Ok(())
}
