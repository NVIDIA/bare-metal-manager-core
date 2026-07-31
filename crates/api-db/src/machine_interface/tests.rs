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

use carbide_uuid::domain::DomainId;
use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use carbide_uuid::network::NetworkSegmentId;
use model::allocation_type::AllocationType;
use model::expected_machine::{
    ExpectedInterface, ExpectedInterfaceIpAllocation, ExpectedInterfaceRole,
};
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
                dhcpv6_link_address: None,
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

async fn create_test_segment(
    pool: &sqlx::PgPool,
    name: &str,
) -> Result<NetworkSegmentId, Box<dyn std::error::Error>> {
    let segment_id = NetworkSegmentId::new();
    let mut txn = db::Transaction::begin(pool).await?;
    db::network_segment::persist(
        NewNetworkSegment {
            id: segment_id,
            name: name.to_string(),
            subdomain_id: None,
            vpc_id: None,
            mtu: 1500,
            prefixes: Vec::new(),
            vlan_id: None,
            vni: None,
            segment_type: NetworkSegmentType::HostInband,
            can_stretch: Some(false),
            allocation_strategy: AllocationStrategy::Reserved,
        },
        txn.as_pgconn(),
        NetworkSegmentControllerState::Ready,
    )
    .await?;
    txn.commit().await?;

    Ok(segment_id)
}

async fn create_managed_segment(
    pool: &sqlx::PgPool,
    name: &str,
    prefix: &str,
    segment_type: NetworkSegmentType,
    allocation_strategy: AllocationStrategy,
) -> Result<NetworkSegmentId, Box<dyn std::error::Error>> {
    create_managed_segment_with_prefixes(pool, name, &[prefix], segment_type, allocation_strategy)
        .await
}

/// Create a managed segment with one or more address-family prefixes.
async fn create_managed_segment_with_prefixes(
    pool: &sqlx::PgPool,
    name: &str,
    prefixes: &[&str],
    segment_type: NetworkSegmentType,
    allocation_strategy: AllocationStrategy,
) -> Result<NetworkSegmentId, Box<dyn std::error::Error>> {
    let segment_id = NetworkSegmentId::new();
    let mut txn = db::Transaction::begin(pool).await?;
    let prefixes = prefixes
        .iter()
        .map(|prefix| {
            Ok(NewNetworkPrefix {
                prefix: prefix.parse()?,
                gateway: None,
                dhcpv6_link_address: None,
                num_reserved: 0,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    db::network_segment::persist(
        NewNetworkSegment {
            id: segment_id,
            name: name.to_string(),
            subdomain_id: None,
            vpc_id: None,
            mtu: 1500,
            prefixes,
            vlan_id: None,
            vni: None,
            segment_type,
            can_stretch: Some(false),
            allocation_strategy,
        },
        txn.as_pgconn(),
        NetworkSegmentControllerState::Ready,
    )
    .await?;
    txn.commit().await?;

    Ok(segment_id)
}

/// Load a test segment after its setup transaction commits.
async fn load_test_segment(
    pool: &sqlx::PgPool,
    name: &str,
) -> Result<NetworkSegment, Box<dyn std::error::Error>> {
    let mut txn = db::Transaction::begin(pool).await?;
    let segment = db::network_segment::find_by_name(txn.as_pgconn(), name).await?;
    txn.rollback().await?;
    Ok(segment)
}

/// Create an addressless interface whose hostname cannot collide with the
/// IP-derived name used by a competing allocation.
async fn create_addressless_race_interface(
    pool: &sqlx::PgPool,
    segment_id: NetworkSegmentId,
    mac_address: MacAddress,
    hostname: &str,
) -> Result<MachineInterfaceId, Box<dyn std::error::Error>> {
    let mut txn = db::Transaction::begin(pool).await?;
    let interface_id = sqlx::query_scalar(
        "INSERT INTO machine_interfaces
            (segment_id, mac_address, primary_interface, hostname)
         VALUES ($1, $2, false, $3)
         RETURNING id",
    )
    .bind(segment_id)
    .bind(mac_address)
    .bind(hostname)
    .fetch_one(txn.as_pgconn())
    .await?;
    txn.commit().await?;
    Ok(interface_id)
}

/// Wait until `blocked_pid` is actually waiting on `blocker_pid`.
///
/// This proves the competing write reached the PostgreSQL uniqueness boundary
/// under test before the winner commits.
async fn wait_for_transaction_conflict(
    pool: &sqlx::PgPool,
    blocker_pid: i32,
    blocked_pid: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                .bind(blocker_pid)
                .bind(blocked_pid)
                .fetch_one(pool)
                .await?;
            if blocked {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| std::io::Error::other("transaction did not reach the expected database wait"))??;
    Ok(())
}

/// Run one fixed/fixed race and verify the committed owner wins cleanly.
///
/// The losing create commits its outer transaction after handling the typed
/// conflict. That proves the create path's savepoint removed its partial
/// interface row without making the caller discard unrelated work.
#[allow(txn_held_across_await)] // The uncommitted winner is the concurrency boundary under test.
async fn run_fixed_address_race(
    pool: &sqlx::PgPool,
    segment: NetworkSegment,
    address: IpAddr,
    owner_mac: MacAddress,
    contender_mac: MacAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_id = segment.id;
    let owner_id = create_addressless_race_interface(
        pool,
        segment_id,
        owner_mac,
        &format!("fixed-owner-{}", owner_mac.to_string().replace(':', "-")),
    )
    .await?;

    let mut owner_txn = db::Transaction::begin(pool).await?;
    let owner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(owner_txn.as_pgconn())
        .await?;
    crate::machine_interface_address::assign_static(owner_txn.as_pgconn(), owner_id, address)
        .await?;

    let (contender_pid_tx, contender_pid_rx) = tokio::sync::oneshot::channel();
    let contender_pool = pool.clone();
    let mut contender_task = tokio::spawn(async move {
        let mut txn = db::Transaction::begin(&contender_pool)
            .await
            .map_err(|error| error.to_string())?;
        let contender_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(txn.as_pgconn())
            .await
            .map_err(|error| error.to_string())?;
        contender_pid_tx
            .send(contender_pid)
            .map_err(|_| "could not report contender backend PID".to_string())?;

        let result = create(
            txn.as_pgconn(),
            std::slice::from_ref(&segment),
            &contender_mac,
            false,
            AddressSelectionStrategy::StaticAddress(address),
            None,
        )
        .await;
        match result {
            Ok(snapshot) => {
                txn.commit().await.map_err(|error| error.to_string())?;
                Ok::<_, String>(Ok(snapshot))
            }
            Err(error @ DatabaseError::AddressAlreadyInUse(_)) => {
                txn.commit().await.map_err(|error| error.to_string())?;
                Ok(Err(error))
            }
            Err(error) => {
                txn.rollback().await.map_err(|error| error.to_string())?;
                Ok(Err(error))
            }
        }
    });

    let contender_pid = contender_pid_rx.await?;
    if let Err(error) = wait_for_transaction_conflict(pool, owner_pid, contender_pid).await {
        contender_task.abort();
        let _ = contender_task.await;
        owner_txn.rollback().await?;
        return Err(error);
    }
    owner_txn.commit().await?;

    let contender_result =
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut contender_task).await {
            Ok(result) => result
                .map_err(|error| std::io::Error::other(error.to_string()))?
                .map_err(std::io::Error::other)?,
            Err(_) => {
                contender_task.abort();
                let _ = contender_task.await;
                return Err(std::io::Error::other("fixed-address contender did not finish").into());
            }
        };

    match contender_result {
        Err(DatabaseError::AddressAlreadyInUse(AddressAlreadyInUseError(
            conflict_address,
            conflict_mac,
            conflict_segment_id,
            conflict_interface_id,
        ))) => {
            assert_eq!(conflict_address, address);
            assert_eq!(conflict_mac, owner_mac);
            assert_eq!(conflict_segment_id, segment_id);
            assert_eq!(conflict_interface_id, owner_id);
        }
        other => panic!("expected the fixed owner to win, got {other:?}"),
    }

    let owner_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM machine_interface_addresses WHERE address = $1::inet",
    )
    .bind(address)
    .fetch_one(pool)
    .await?;
    assert_eq!(owner_count, 1);
    let contender_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM machine_interfaces WHERE mac_address = $1")
            .bind(contender_mac)
            .fetch_one(pool)
            .await?;
    assert_eq!(
        contender_count, 0,
        "the failed fixed-address create must roll back its interface row"
    );
    Ok(())
}

/// Run one fixed/first-DHCP race and verify DHCP retries another address.
#[allow(txn_held_across_await)] // The uncommitted winner is the concurrency boundary under test.
async fn run_fixed_dynamic_create_race(
    pool: &sqlx::PgPool,
    segment: NetworkSegment,
    owner_segment: NetworkSegment,
    fixed_address: IpAddr,
    address_strategy: AddressSelectionStrategy,
    owner_mac: MacAddress,
    dhcp_mac: MacAddress,
) -> Result<MachineInterfaceSnapshot, Box<dyn std::error::Error>> {
    let mut owner_txn = db::Transaction::begin(pool).await?;
    let owner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(owner_txn.as_pgconn())
        .await?;
    create(
        owner_txn.as_pgconn(),
        std::slice::from_ref(&owner_segment),
        &owner_mac,
        false,
        AddressSelectionStrategy::StaticAddress(fixed_address),
        None,
    )
    .await?;

    let (dhcp_pid_tx, dhcp_pid_rx) = tokio::sync::oneshot::channel();
    let dhcp_pool = pool.clone();
    let mut dhcp_task = tokio::spawn(async move {
        let mut txn = db::Transaction::begin(&dhcp_pool)
            .await
            .map_err(|error| error.to_string())?;
        let dhcp_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(txn.as_pgconn())
            .await
            .map_err(|error| error.to_string())?;
        dhcp_pid_tx
            .send(dhcp_pid)
            .map_err(|_| "could not report DHCP backend PID".to_string())?;

        let result = create(
            txn.as_pgconn(),
            std::slice::from_ref(&segment),
            &dhcp_mac,
            false,
            address_strategy,
            None,
        )
        .await;
        match result {
            Ok(snapshot) => {
                txn.commit().await.map_err(|error| error.to_string())?;
                Ok::<_, String>(snapshot)
            }
            Err(error) => {
                txn.rollback()
                    .await
                    .map_err(|rollback| rollback.to_string())?;
                Err(error.to_string())
            }
        }
    });

    let dhcp_pid = dhcp_pid_rx.await?;
    if let Err(error) = wait_for_transaction_conflict(pool, owner_pid, dhcp_pid).await {
        dhcp_task.abort();
        let _ = dhcp_task.await;
        owner_txn.rollback().await?;
        return Err(error);
    }
    owner_txn.commit().await?;

    let dhcp_interface =
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut dhcp_task).await {
            Ok(result) => result
                .map_err(|error| std::io::Error::other(error.to_string()))?
                .map_err(std::io::Error::other)?,
            Err(_) => {
                dhcp_task.abort();
                let _ = dhcp_task.await;
                return Err(std::io::Error::other("DHCP allocation did not retry").into());
            }
        };
    assert!(
        !dhcp_interface.addresses.contains(&fixed_address),
        "DHCP must retry instead of sharing {fixed_address}",
    );
    assert!(
        dhcp_interface
            .addresses
            .iter()
            .all(|address| address.is_address_family(fixed_address.address_family())),
    );
    Ok(dhcp_interface)
}

/// Run one fixed/DHCP-recovery race and verify family reallocation retries.
#[allow(txn_held_across_await)] // The uncommitted winner is the concurrency boundary under test.
async fn run_fixed_dynamic_reallocation_race(
    pool: &sqlx::PgPool,
    segment: NetworkSegment,
    owner_segment_id: NetworkSegmentId,
    fixed_address: IpAddr,
    family: IpAddressFamily,
    owner_mac: MacAddress,
    dhcp_mac: MacAddress,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner_id = create_addressless_race_interface(
        pool,
        owner_segment_id,
        owner_mac,
        &format!(
            "reallocation-owner-{}",
            owner_mac.to_string().replace(':', "-")
        ),
    )
    .await?;
    let dhcp_interface_id = create_addressless_race_interface(
        pool,
        segment.id,
        dhcp_mac,
        &format!(
            "reallocation-contender-{}",
            dhcp_mac.to_string().replace(':', "-")
        ),
    )
    .await?;

    let mut owner_txn = db::Transaction::begin(pool).await?;
    let owner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(owner_txn.as_pgconn())
        .await?;
    crate::machine_interface_address::assign_static(owner_txn.as_pgconn(), owner_id, fixed_address)
        .await?;

    let (dhcp_pid_tx, dhcp_pid_rx) = tokio::sync::oneshot::channel();
    let dhcp_pool = pool.clone();
    let mut dhcp_task = tokio::spawn(async move {
        let mut txn = db::Transaction::begin(&dhcp_pool)
            .await
            .map_err(|error| error.to_string())?;
        let dhcp_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(txn.as_pgconn())
            .await
            .map_err(|error| error.to_string())?;
        dhcp_pid_tx
            .send(dhcp_pid)
            .map_err(|_| "could not report DHCP backend PID".to_string())?;

        let result =
            allocate_address_for_family(txn.as_pgconn(), dhcp_interface_id, &segment, family).await;
        match result {
            Ok(addresses) => {
                txn.commit().await.map_err(|error| error.to_string())?;
                Ok::<_, String>(addresses)
            }
            Err(error) => {
                txn.rollback()
                    .await
                    .map_err(|rollback| rollback.to_string())?;
                Err(error.to_string())
            }
        }
    });

    let dhcp_pid = dhcp_pid_rx.await?;
    if let Err(error) = wait_for_transaction_conflict(pool, owner_pid, dhcp_pid).await {
        dhcp_task.abort();
        let _ = dhcp_task.await;
        owner_txn.rollback().await?;
        return Err(error);
    }
    owner_txn.commit().await?;

    let addresses =
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut dhcp_task).await {
            Ok(result) => result
                .map_err(|error| std::io::Error::other(error.to_string()))?
                .map_err(std::io::Error::other)?,
            Err(_) => {
                dhcp_task.abort();
                let _ = dhcp_task.await;
                return Err(std::io::Error::other("DHCP reallocation did not retry").into());
            }
        };
    assert!(
        !addresses.is_empty(),
        "DHCP reallocation must return a {family:?} address",
    );
    assert!(!addresses.contains(&fixed_address));
    assert!(
        addresses
            .iter()
            .all(|address| address.is_address_family(family)),
    );
    Ok(())
}

/// Fixed requests use the same database ownership boundary for managed and
/// external addresses, in both families.
#[crate::sqlx_test]
async fn concurrent_fixed_requests_keep_one_owner(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    create_managed_segment(
        &pool,
        "fixed-race-managed-ipv4",
        "192.0.2.0/29",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;
    create_managed_segment(
        &pool,
        "fixed-race-managed-ipv6",
        "2001:db8:100::/125",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;

    let managed_ipv4 = load_test_segment(&pool, "fixed-race-managed-ipv4").await?;
    let managed_ipv6 = load_test_segment(&pool, "fixed-race-managed-ipv6").await?;
    let static_assignments =
        load_test_segment(&pool, db::network_segment::STATIC_ASSIGNMENTS_SEGMENT_NAME).await?;
    let cases = [
        (
            managed_ipv4,
            "192.0.2.3".parse::<IpAddr>()?,
            "02:00:00:10:01:01".parse::<MacAddress>()?,
            "02:00:00:10:01:02".parse::<MacAddress>()?,
        ),
        (
            managed_ipv6,
            "2001:db8:100::3".parse::<IpAddr>()?,
            "02:00:00:10:02:01".parse::<MacAddress>()?,
            "02:00:00:10:02:02".parse::<MacAddress>()?,
        ),
        (
            static_assignments.clone(),
            "203.0.113.30".parse::<IpAddr>()?,
            "02:00:00:10:03:01".parse::<MacAddress>()?,
            "02:00:00:10:03:02".parse::<MacAddress>()?,
        ),
        (
            static_assignments,
            "2001:db8:ffff::30".parse::<IpAddr>()?,
            "02:00:00:10:04:01".parse::<MacAddress>()?,
            "02:00:00:10:04:02".parse::<MacAddress>()?,
        ),
    ];

    for (segment, address, owner_mac, contender_mac) in cases {
        run_fixed_address_race(&pool, segment, address, owner_mac, contender_mac).await?;
    }

    Ok(())
}

/// A first DHCP allocation retries when a fixed writer on another segment
/// commits the candidate it selected, for IPv4 and IPv6.
#[crate::sqlx_test]
async fn initial_dhcp_retries_a_concurrent_fixed_address(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    create_managed_segment(
        &pool,
        "dynamic-race-ipv4",
        "198.51.100.0/29",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let fixed_owner_segment =
        load_test_segment(&pool, db::network_segment::STATIC_ASSIGNMENTS_SEGMENT_NAME).await?;
    create_managed_segment(
        &pool,
        "dynamic-race-ipv6",
        "2001:db8:200::/125",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;

    let cases = [
        (
            load_test_segment(&pool, "dynamic-race-ipv4").await?,
            "198.51.100.2".parse::<IpAddr>()?,
            "02:00:00:20:01:01".parse::<MacAddress>()?,
            "02:00:00:20:01:02".parse::<MacAddress>()?,
        ),
        (
            load_test_segment(&pool, "dynamic-race-ipv6").await?,
            "2001:db8:200::1".parse::<IpAddr>()?,
            "02:00:00:20:02:01".parse::<MacAddress>()?,
            "02:00:00:20:02:02".parse::<MacAddress>()?,
        ),
    ];

    for (segment, fixed_address, owner_mac, dhcp_mac) in cases {
        run_fixed_dynamic_create_race(
            &pool,
            segment,
            fixed_owner_segment.clone(),
            fixed_address,
            AddressSelectionStrategy::NextAvailableIp,
            owner_mac,
            dhcp_mac,
        )
        .await?;
    }

    Ok(())
}

/// Whole-prefix allocation rolls its failed interface row back before trying
/// the next prefix after a fixed writer wins the first candidate.
#[crate::sqlx_test]
async fn prefix_allocation_retries_a_concurrent_fixed_address(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    create_managed_segment(
        &pool,
        "prefix-allocation-race",
        "192.0.2.0/28",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;

    let fixed_owner_segment =
        load_test_segment(&pool, db::network_segment::STATIC_ASSIGNMENTS_SEGMENT_NAME).await?;
    let segment = load_test_segment(&pool, "prefix-allocation-race").await?;
    let interface = run_fixed_dynamic_create_race(
        &pool,
        segment,
        fixed_owner_segment,
        "192.0.2.4".parse()?,
        AddressSelectionStrategy::NextAvailablePrefix(30),
        "02:00:00:20:03:01".parse()?,
        "02:00:00:20:03:02".parse()?,
    )
    .await?;

    assert_eq!(interface.addresses, vec!["192.0.2.8".parse::<IpAddr>()?]);
    Ok(())
}

/// New interface creation claims its address before entering the configured
/// DNS domain. Pause that address insert so an existing interface can claim
/// both values without the two transactions waiting on each other.
#[crate::sqlx_test]
#[allow(txn_held_across_await)] // The gate transaction creates the exact ordering under test.
async fn new_interface_defers_fqdn_until_its_address_is_owned(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_id = create_managed_segment(
        &pool,
        "address-fqdn-order",
        "192.0.2.0/29",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let contender_mac: MacAddress = "02:00:00:20:03:11".parse()?;
    let owner_mac: MacAddress = "02:00:00:20:03:12".parse()?;
    let contender_id = create_addressless_race_interface(
        &pool,
        segment_id,
        contender_mac,
        "address-fqdn-contender",
    )
    .await?;

    let mut setup_txn = db::Transaction::begin(&pool).await?;
    let domain = db::dns::domain::persist(
        model::dns::NewDomain::new("address-order.example"),
        setup_txn.as_pgconn(),
    )
    .await?;
    sqlx::query("UPDATE network_segments SET subdomain_id = $1 WHERE id = $2")
        .bind(domain.id)
        .bind(segment_id)
        .execute(setup_txn.as_pgconn())
        .await?;
    sqlx::query("UPDATE machine_interfaces SET domain_id = $1 WHERE id = $2")
        .bind(domain.id)
        .bind(contender_id)
        .execute(setup_txn.as_pgconn())
        .await?;
    // MacAddress formatting is constrained to a normalized MAC literal, so it
    // is safe to reuse owner_mac in this test-only trigger definition.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE FUNCTION test_block_fixed_address_insert()
         RETURNS trigger
         LANGUAGE plpgsql
         AS $$
         BEGIN
             IF EXISTS (
                 SELECT 1
                 FROM machine_interfaces
                 WHERE id = NEW.interface_id
                   AND mac_address = '{owner_mac}'::macaddr
             ) THEN
                 PERFORM pg_advisory_xact_lock(
                     hashtextextended(current_database() || ':address-fqdn-order', 0)
                 );
             END IF;
             RETURN NEW;
         END
         $$;
         CREATE TRIGGER test_block_fixed_address_insert
         BEFORE INSERT ON machine_interface_addresses
         FOR EACH ROW
         EXECUTE FUNCTION test_block_fixed_address_insert();"
    )))
    .execute(setup_txn.as_pgconn())
    .await?;
    setup_txn.commit().await?;
    let segment = load_test_segment(&pool, "address-fqdn-order").await?;
    let fixed_address: IpAddr = "192.0.2.2".parse()?;

    let mut gate_txn = db::Transaction::begin(&pool).await?;
    let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(gate_txn.as_pgconn())
        .await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(
             hashtextextended(current_database() || ':address-fqdn-order', 0)
         )",
    )
    .execute(gate_txn.as_pgconn())
    .await?;

    let (owner_pid_tx, owner_pid_rx) = tokio::sync::oneshot::channel();
    let owner_pool = pool.clone();
    let owner_segment = segment.clone();
    let mut owner_task = tokio::spawn(async move {
        let mut txn = db::Transaction::begin(&owner_pool)
            .await
            .map_err(|error| error.to_string())?;
        let owner_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(txn.as_pgconn())
            .await
            .map_err(|error| error.to_string())?;
        owner_pid_tx
            .send(owner_pid)
            .map_err(|_| "could not report fixed-owner backend PID".to_string())?;

        let result = create(
            txn.as_pgconn(),
            std::slice::from_ref(&owner_segment),
            &owner_mac,
            false,
            AddressSelectionStrategy::StaticAddress(fixed_address),
            None,
        )
        .await;
        match result {
            Ok(snapshot) => {
                txn.commit().await.map_err(|error| error.to_string())?;
                Ok::<_, String>(Ok(snapshot))
            }
            Err(error) => {
                txn.rollback().await.map_err(|error| error.to_string())?;
                Ok(Err(error))
            }
        }
    });

    let owner_pid = owner_pid_rx.await?;
    if let Err(error) = wait_for_transaction_conflict(&pool, gate_pid, owner_pid).await {
        gate_txn.rollback().await?;
        owner_task.abort();
        let _ = owner_task.await;
        return Err(error);
    }

    let mut contender_txn = db::Transaction::begin(&pool).await?;
    let allocated = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        allocate_address_for_family(
            contender_txn.as_pgconn(),
            contender_id,
            &segment,
            IpAddressFamily::Ipv4,
        ),
    )
    .await
    {
        Ok(Ok(allocated)) => allocated,
        Ok(Err(error)) => {
            contender_txn.rollback().await?;
            gate_txn.commit().await?;
            owner_task.abort();
            let _ = owner_task.await;
            return Err(error.into());
        }
        Err(_) => {
            contender_txn.rollback().await?;
            gate_txn.commit().await?;
            owner_task.abort();
            let _ = owner_task.await;
            return Err(std::io::Error::other(
                "address recovery blocked on the fixed owner's uncommitted FQDN",
            )
            .into());
        }
    };
    contender_txn.commit().await?;
    assert_eq!(allocated, vec![fixed_address]);

    let (contender_hostname, contender_domain): (String, Option<DomainId>) =
        sqlx::query_as("SELECT hostname, domain_id FROM machine_interfaces WHERE id = $1")
            .bind(contender_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(contender_hostname, "192-0-2-2");
    assert_eq!(contender_domain, Some(domain.id));

    gate_txn.commit().await?;
    let owner_result =
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut owner_task).await {
            Ok(result) => result
                .map_err(|error| std::io::Error::other(error.to_string()))?
                .map_err(std::io::Error::other)?,
            Err(_) => {
                owner_task.abort();
                let _ = owner_task.await;
                return Err(std::io::Error::other("fixed owner did not finish").into());
            }
        };
    assert!(matches!(
        owner_result,
        Err(DatabaseError::AddressAlreadyInUse(AddressAlreadyInUseError(
            address,
            mac_address,
            conflict_segment_id,
            conflict_interface_id,
        ))) if address == fixed_address
            && mac_address == contender_mac
            && conflict_segment_id == segment_id
            && conflict_interface_id == contender_id
    ));

    let owner_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM machine_interfaces WHERE mac_address = $1")
            .bind(owner_mac)
            .fetch_one(&pool)
            .await?;
    assert_eq!(owner_rows, 0);
    Ok(())
}

/// Reapplying an admin range can permute existing addresses. The stored
/// procedure stages the complete mapping so the global constraint never sees
/// a temporary duplicate, updates IP-derived hostnames, and leaves names from
/// the other host naming strategies alone.
#[crate::sqlx_test]
async fn update_admin_network_replaces_overlapping_addresses(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_id = create_managed_segment(
        &pool,
        "overlapping-admin-update",
        "198.18.0.0/29",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let mut interface_ids = [
        create_addressless_race_interface(
            &pool,
            segment_id,
            "02:00:00:20:04:01".parse()?,
            "overlapping-admin-one",
        )
        .await?,
        create_addressless_race_interface(
            &pool,
            segment_id,
            "02:00:00:20:04:02".parse()?,
            "overlapping-admin-two",
        )
        .await?,
    ];
    interface_ids.sort_unstable();

    let mut txn = db::Transaction::begin(&pool).await?;
    let domain = db::dns::domain::persist(
        model::dns::NewDomain::new("overlapping-admin.example"),
        txn.as_pgconn(),
    )
    .await?;
    sqlx::query("UPDATE network_segments SET subdomain_id = $1 WHERE id = $2")
        .bind(domain.id)
        .bind(segment_id)
        .execute(txn.as_pgconn())
        .await?;
    for (interface_id, hostname) in [
        (interface_ids[0], "198-18-0-3"),
        (interface_ids[1], "wholesale-walrus"),
    ] {
        sqlx::query(
            "UPDATE machine_interfaces
             SET domain_id = $1, hostname = $2
             WHERE id = $3",
        )
        .bind(domain.id)
        .bind(hostname)
        .bind(interface_id)
        .execute(txn.as_pgconn())
        .await?;
    }
    crate::machine_interface_address::insert(
        txn.as_pgconn(),
        interface_ids[0],
        "198.18.0.3".parse()?,
        AllocationType::Static,
    )
    .await?;
    crate::machine_interface_address::insert(
        txn.as_pgconn(),
        interface_ids[1],
        "198.18.0.2".parse()?,
        AllocationType::Static,
    )
    .await?;
    let address_ids: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT mia.id
         FROM machine_interfaces mi
         JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
         WHERE mi.segment_id = $1
         ORDER BY mi.id",
    )
    .bind(segment_id)
    .fetch_all(txn.as_pgconn())
    .await?;

    sqlx::query(
        "CALL update_admin_network(
            $1,
            '198.18.0.0/29'::inet,
            '198.18.0.1'::inet
         )",
    )
    .bind(segment_id)
    .execute(txn.as_pgconn())
    .await?;

    let rows: Vec<(
        uuid::Uuid,
        MachineInterfaceId,
        IpAddr,
        AllocationType,
        String,
    )> = sqlx::query_as(
        "SELECT mia.id, mi.id, mia.address, mia.allocation_type, mi.hostname
         FROM machine_interfaces mi
         JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
         WHERE mi.segment_id = $1
         ORDER BY mi.id",
    )
    .bind(segment_id)
    .fetch_all(txn.as_pgconn())
    .await?;

    assert_eq!(
        rows,
        vec![
            (
                address_ids[0],
                interface_ids[0],
                "198.18.0.2".parse()?,
                AllocationType::Static,
                "198-18-0-2".to_string(),
            ),
            (
                address_ids[1],
                interface_ids[1],
                "198.18.0.3".parse()?,
                AllocationType::Static,
                "wholesale-walrus".to_string(),
            ),
        ]
    );
    let preserved_domains: i64 = sqlx::query_scalar(
        "SELECT count(*)
         FROM machine_interfaces
         WHERE segment_id = $1 AND domain_id = $2",
    )
    .bind(segment_id)
    .bind(domain.id)
    .fetch_one(txn.as_pgconn())
    .await?;
    assert_eq!(preserved_domains, 2);
    Ok(())
}

/// A single-prefix admin segment keeps the legacy ability to change address
/// families while the procedure replaces its stored addresses. The first
/// remap also recognizes and normalizes the older compressed IPv6 hostname.
#[crate::sqlx_test]
async fn update_admin_network_replaces_a_single_prefix_with_another_family(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_id = create_managed_segment(
        &pool,
        "cross-family-admin-update",
        "2001:db8:400::/125",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let interface_id = create_addressless_race_interface(
        &pool,
        segment_id,
        "02:00:00:20:05:01".parse()?,
        "2001:db8:400::2",
    )
    .await?;

    let mut txn = db::Transaction::begin(&pool).await?;
    crate::machine_interface_address::insert(
        txn.as_pgconn(),
        interface_id,
        "2001:db8:400::2".parse()?,
        AllocationType::Static,
    )
    .await?;
    sqlx::query(
        "CALL update_admin_network(
            $1,
            '2001:db8:401::/125'::inet,
            NULL::inet
         )",
    )
    .bind(segment_id)
    .execute(txn.as_pgconn())
    .await?;
    let (ipv6_address, ipv6_hostname): (IpAddr, String) = sqlx::query_as(
        "SELECT mia.address, mi.hostname
         FROM machine_interfaces mi
         JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
         WHERE mi.id = $1",
    )
    .bind(interface_id)
    .fetch_one(txn.as_pgconn())
    .await?;
    assert_eq!(ipv6_address, "2001:db8:401::2".parse::<IpAddr>()?);
    assert_eq!(ipv6_hostname, "2001-0db8-0401-0000-0000-0000-0000-0002");

    sqlx::query(
        "CALL update_admin_network(
            $1,
            '198.19.0.0/29'::inet,
            '198.19.0.1'::inet
         )",
    )
    .bind(segment_id)
    .execute(txn.as_pgconn())
    .await?;

    let rows: Vec<(IpNetwork, Option<IpAddr>, IpAddr, String)> = sqlx::query_as(
        "SELECT np.prefix, np.gateway, mia.address, mi.hostname
         FROM network_prefixes np
         JOIN machine_interfaces mi ON mi.segment_id = np.segment_id
         JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
         WHERE np.segment_id = $1",
    )
    .bind(segment_id)
    .fetch_all(txn.as_pgconn())
    .await?;

    assert_eq!(
        rows,
        vec![(
            "198.19.0.0/29".parse()?,
            Some("198.19.0.1".parse()?),
            "198.19.0.2".parse::<IpAddr>()?,
            "198-19-0-2".to_string(),
        )],
    );
    Ok(())
}

/// A dual-stack admin update selects the matching prefix and leaves the other
/// address family untouched.
#[crate::sqlx_test]
async fn update_admin_network_changes_only_the_matching_family(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_id = create_managed_segment_with_prefixes(
        &pool,
        "dual-stack-admin-update",
        &["198.20.0.0/29", "2001:db8:500::/125"],
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let interface_id = create_addressless_race_interface(
        &pool,
        segment_id,
        "02:00:00:20:06:01".parse()?,
        "198-20-0-2",
    )
    .await?;

    let mut txn = db::Transaction::begin(&pool).await?;
    for address in [
        "198.20.0.2".parse::<IpAddr>()?,
        "2001:db8:500::2".parse::<IpAddr>()?,
    ] {
        crate::machine_interface_address::insert(
            txn.as_pgconn(),
            interface_id,
            address,
            AllocationType::Static,
        )
        .await?;
    }
    sqlx::query(
        "CALL update_admin_network(
            $1,
            '198.20.1.0/29'::inet,
            '198.20.1.1'::inet
         )",
    )
    .bind(segment_id)
    .execute(txn.as_pgconn())
    .await?;

    let prefixes: Vec<IpNetwork> = sqlx::query_scalar(
        "SELECT prefix
         FROM network_prefixes
         WHERE segment_id = $1
         ORDER BY family(prefix)",
    )
    .bind(segment_id)
    .fetch_all(txn.as_pgconn())
    .await?;
    let addresses: Vec<IpAddr> = sqlx::query_scalar(
        "SELECT address
         FROM machine_interface_addresses
         WHERE interface_id = $1
         ORDER BY family(address)",
    )
    .bind(interface_id)
    .fetch_all(txn.as_pgconn())
    .await?;

    assert_eq!(
        prefixes,
        vec!["198.20.1.0/29".parse()?, "2001:db8:500::/125".parse()?,]
    );
    assert_eq!(
        addresses,
        vec![
            "198.20.1.2".parse::<IpAddr>()?,
            "2001:db8:500::2".parse::<IpAddr>()?,
        ]
    );

    sqlx::query(
        "CALL update_admin_network(
            $1,
            '2001:db8:501::/125'::inet,
            NULL::inet
         )",
    )
    .bind(segment_id)
    .execute(txn.as_pgconn())
    .await?;
    let addresses: Vec<IpAddr> = sqlx::query_scalar(
        "SELECT address
         FROM machine_interface_addresses
         WHERE interface_id = $1
         ORDER BY family(address)",
    )
    .bind(interface_id)
    .fetch_all(txn.as_pgconn())
    .await?;
    let hostname: String =
        sqlx::query_scalar("SELECT hostname FROM machine_interfaces WHERE id = $1")
            .bind(interface_id)
            .fetch_one(txn.as_pgconn())
            .await?;
    assert_eq!(
        addresses,
        vec![
            "198.20.1.2".parse::<IpAddr>()?,
            "2001:db8:501::2".parse::<IpAddr>()?,
        ]
    );
    assert_eq!(hostname, "198-20-1-2");
    Ok(())
}

/// DHCP family recovery also sees fixed owners on another segment.
#[crate::sqlx_test]
async fn dhcp_family_reallocation_retries_a_concurrent_fixed_address(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    create_managed_segment(
        &pool,
        "reallocation-race-ipv4",
        "203.0.113.0/29",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let fixed_owner_segment =
        load_test_segment(&pool, db::network_segment::STATIC_ASSIGNMENTS_SEGMENT_NAME).await?;
    create_managed_segment(
        &pool,
        "reallocation-race-ipv6",
        "2001:db8:300::/125",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;

    let cases = [
        (
            load_test_segment(&pool, "reallocation-race-ipv4").await?,
            "203.0.113.2".parse::<IpAddr>()?,
            IpAddressFamily::Ipv4,
            "02:00:00:30:01:01".parse::<MacAddress>()?,
            "02:00:00:30:01:02".parse::<MacAddress>()?,
        ),
        (
            load_test_segment(&pool, "reallocation-race-ipv6").await?,
            "2001:db8:300::1".parse::<IpAddr>()?,
            IpAddressFamily::Ipv6,
            "02:00:00:30:02:01".parse::<MacAddress>()?,
            "02:00:00:30:02:02".parse::<MacAddress>()?,
        ),
    ];

    for (segment, fixed_address, family, owner_mac, dhcp_mac) in cases {
        run_fixed_dynamic_reallocation_race(
            &pool,
            segment,
            fixed_owner_segment.id,
            fixed_address,
            family,
            owner_mac,
            dhcp_mac,
        )
        .await?;
    }

    Ok(())
}

/// A MAC identifies one physical interface even when stale or transitional
/// rows represent it on more than one segment. Site Explorer learns one
/// vendor-native Redfish id for that interface, so `set_boot_interface_id`
/// updates every row for the MAC rather than whichever segment happened to
/// report first.
#[crate::sqlx_test]
async fn set_boot_interface_id_updates_every_segment_row_for_mac(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_a = create_test_segment(&pool, "boot-id-segment-a").await?;
    let segment_b = create_test_segment(&pool, "boot-id-segment-b").await?;
    let boot_mac: MacAddress = "7A:7B:7C:7D:7E:41".parse()?;
    let other_mac: MacAddress = "7A:7B:7C:7D:7E:42".parse()?;

    let mut txn = db::Transaction::begin(&pool).await?;
    let query = "
INSERT INTO machine_interfaces
    (segment_id, mac_address, primary_interface, hostname)
VALUES
    ($1, $2, false, 'boot-a'),
    ($3, $2, false, 'boot-b'),
    ($1, $4, false, 'other')";
    sqlx::query(query)
        .bind(segment_a)
        .bind(boot_mac)
        .bind(segment_b)
        .bind(other_mac)
        .execute(txn.as_pgconn())
        .await?;

    set_boot_interface_id(boot_mac, "NIC.Slot.7-1-1", txn.as_pgconn()).await?;

    let boot_ids: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT boot_interface_id FROM machine_interfaces WHERE mac_address=$1 ORDER BY hostname",
    )
    .bind(boot_mac)
    .fetch_all(txn.as_pgconn())
    .await?;
    let other_id: Option<String> =
        sqlx::query_scalar("SELECT boot_interface_id FROM machine_interfaces WHERE mac_address=$1")
            .bind(other_mac)
            .fetch_one(txn.as_pgconn())
            .await?;

    assert_eq!(
        boot_ids,
        vec![
            Some("NIC.Slot.7-1-1".to_string()),
            Some("NIC.Slot.7-1-1".to_string())
        ]
    );
    assert_eq!(other_id, None, "a different MAC must remain unchanged");

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

/// Legacy installations can have an external static reservation on an
/// ordinary segment without the newer static-assignments anchor. Reapplying
/// that exact reservation remains an idempotent no-op.
#[crate::sqlx_test]
async fn test_preallocate_machine_interface_is_idempotent_without_static_assignments(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_id = create_test_segment(&pool, "legacy-external-static").await?;
    let mac: MacAddress = "7A:7B:7C:7D:7E:30".parse()?;
    let ip: IpAddr = "203.0.113.230".parse()?;

    let mut txn = db::Transaction::begin(&pool).await?;
    let interface_id: MachineInterfaceId = sqlx::query_scalar(
        "INSERT INTO machine_interfaces
            (segment_id, mac_address, primary_interface, hostname)
         VALUES ($1, $2, true, 'legacy-external-static')
         RETURNING id",
    )
    .bind(segment_id)
    .bind(mac)
    .fetch_one(txn.as_pgconn())
    .await?;
    crate::machine_interface_address::insert(
        txn.as_pgconn(),
        interface_id,
        ip,
        AllocationType::Static,
    )
    .await?;

    preallocate_machine_interface(txn.as_pgconn(), mac, ip, None).await?;
    let legacy_expected_interface = ExpectedInterface {
        mac_address: mac,
        fixed_ip: Some(ip),
        ..Default::default()
    };
    preallocate_expected_machine_interface(txn.as_pgconn(), &legacy_expected_interface, None)
        .await?;

    // An explicit policy requires a managed prefix even when the exact
    // external reservation already exists. Resolve it before the idempotent
    // `(MAC, IP)` path can return success.
    let explicit_expected_interface = ExpectedInterface {
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
        ..legacy_expected_interface
    };
    let error =
        preallocate_expected_machine_interface(txn.as_pgconn(), &explicit_expected_interface, None)
            .await
            .expect_err("an explicit fixed policy should require a managed prefix");
    assert!(matches!(error, DatabaseError::InvalidArgument(_)));

    let interfaces = find_by_mac_address(txn.as_pgconn(), mac).await?;
    txn.commit().await?;

    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].segment_id, segment_id);
    assert_eq!(interfaces[0].addresses, vec![ip]);

    Ok(())
}

#[crate::sqlx_test]
async fn test_expected_declaration_does_not_reclassify_attached_dpu_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_name = "attached-dpu-interface";
    create_managed_segment(
        &pool,
        segment_name,
        "192.0.2.0/24",
        NetworkSegmentType::Underlay,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let dpu_id = MachineId::new(
        MachineIdSource::ProductBoardChassisSerial,
        [0x43; 32],
        MachineType::Dpu,
    );
    let mac: MacAddress = "7A:7B:7C:7D:7E:2F".parse()?;
    let relay: IpAddr = "192.0.2.1".parse()?;

    let mut txn = db::Transaction::begin(&pool).await?;
    sqlx::query("INSERT INTO machines (id, dpf) VALUES ($1, '{}'::jsonb)")
        .bind(dpu_id)
        .execute(txn.as_pgconn())
        .await?;
    let segment = db::network_segment::find_by_name(txn.as_pgconn(), segment_name).await?;
    let interface = create_without_addresses(
        txn.as_pgconn(),
        &segment,
        &mac,
        true,
        InterfaceType::Data,
        None,
    )
    .await?;
    associate_interface_with_dpu_machine(&interface.id, &dpu_id, txn.as_pgconn()).await?;

    let expected_interface = ExpectedInterface {
        mac_address: mac,
        role: ExpectedInterfaceRole::DpuBmc,
        ..Default::default()
    };
    let reconciled = find_or_create_machine_interface(
        txn.as_pgconn(),
        None,
        mac,
        &[relay],
        Some(expected_interface),
        Some(false),
        None,
    )
    .await?;
    txn.commit().await?;

    assert_eq!(reconciled.attached_dpu_machine_id, Some(dpu_id));
    assert_eq!(reconciled.interface_type, InterfaceType::Data);
    assert!(reconciled.primary_interface);

    Ok(())
}

/// An association that commits after DHCP reads an interface must still win
/// over ExpectedMachine settings derived from that stale snapshot.
#[crate::sqlx_test]
async fn test_expected_interface_settings_do_not_overwrite_concurrent_dpu_association(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_name = "concurrently-attached-dpu-interface";
    create_managed_segment(
        &pool,
        segment_name,
        "198.51.100.0/24",
        NetworkSegmentType::Underlay,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let dpu_id = MachineId::new(
        MachineIdSource::ProductBoardChassisSerial,
        [0x44; 32],
        MachineType::Dpu,
    );
    let mac: MacAddress = "7A:7B:7C:7D:7E:2E".parse()?;

    let mut setup_txn = db::Transaction::begin(&pool).await?;
    sqlx::query("INSERT INTO machines (id, dpf) VALUES ($1, '{}'::jsonb)")
        .bind(dpu_id)
        .execute(setup_txn.as_pgconn())
        .await?;
    let segment = db::network_segment::find_by_name(setup_txn.as_pgconn(), segment_name).await?;
    let interface = create_without_addresses(
        setup_txn.as_pgconn(),
        &segment,
        &mac,
        true,
        InterfaceType::Data,
        None,
    )
    .await?;
    setup_txn.commit().await?;

    let mut snapshot_txn = db::Transaction::begin(&pool).await?;
    let mut stale_interface = find_one(snapshot_txn.as_pgconn(), interface.id).await?;
    let updated = update_unassociated_expected_interface_settings(
        snapshot_txn.as_pgconn(),
        interface.id,
        Some(InterfaceType::Data),
        Some(true),
    )
    .await?;
    assert!(
        !updated,
        "steady-state ExpectedInterface settings should not write a new row version",
    );
    snapshot_txn.commit().await?;

    let mut association_txn = db::Transaction::begin(&pool).await?;
    associate_interface_with_dpu_machine(&interface.id, &dpu_id, association_txn.as_pgconn())
        .await?;
    association_txn.commit().await?;

    let mut expected_txn = db::Transaction::begin(&pool).await?;
    reconcile_unassociated_expected_interface_settings(
        expected_txn.as_pgconn(),
        &mut stale_interface,
        Some(InterfaceType::Bmc),
        Some(false),
    )
    .await?;
    assert_eq!(stale_interface.attached_dpu_machine_id, Some(dpu_id));
    assert_eq!(stale_interface.interface_type, InterfaceType::Data);
    assert!(stale_interface.primary_interface);
    expected_txn.commit().await?;

    let mut verify_txn = db::Transaction::begin(&pool).await?;
    let reconciled = find_one(verify_txn.as_pgconn(), interface.id).await?;
    verify_txn.commit().await?;

    assert_eq!(reconciled.attached_dpu_machine_id, Some(dpu_id));
    assert_eq!(reconciled.interface_type, InterfaceType::Data);
    assert!(reconciled.primary_interface);

    Ok(())
}

/// Pre-allocating a different IP for an existing MAC must error, rather than
/// silently reassigning. If an `expected_machine.bmc_ip_address` (or an
/// `ExpectedInterface.fixed_ip`) drifts from its `machine_interface` row,
/// operators should see the conflict instead of an automatic rewrite.
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

/// A retained Host BMC promotes its DHCP address to `Static`, remains
/// idempotent, and then survives the DHCP-scoped expiry delete path.
#[crate::sqlx_test]
async fn test_retained_host_bmc_address_pins_dhcp_and_survives_expiry(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use model::allocation_type::AllocationType;

    create_static_assignments_segment(&pool).await?;
    let mac: MacAddress = "7A:7B:7C:7D:7E:37".parse().unwrap();
    let ip: std::net::IpAddr = "192.0.2.250".parse().unwrap();

    // Create a BMC interface (preallocate lands a Static address), then swap that
    // address for a Dhcp one so we have a BMC interface holding a DHCP lease --
    // the state a BMC reaches when it auto-allocates over DHCP.
    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_bmc_machine_interface(txn.as_pgconn(), mac, ip, None).await?;
    let interfaces = find_by_mac_address(&mut txn, mac).await?;
    let interface_id = interfaces[0].id;
    assert_eq!(
        interfaces[0].interface_type,
        InterfaceType::Bmc,
        "preallocated interface should be the BMC type"
    );
    crate::machine_interface_address::delete(txn.as_pgconn(), &interface_id).await?;
    crate::machine_interface_address::insert(
        txn.as_pgconn(),
        interface_id,
        ip,
        AllocationType::Dhcp,
    )
    .await?;
    txn.commit().await?;

    let expected_interface = ExpectedInterface {
        mac_address: mac,
        role: ExpectedInterfaceRole::HostBmc,
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Retained),
        ..Default::default()
    };

    // Retain: the DHCP address is promoted to Static.
    let mut txn = db::Transaction::begin(&pool).await?;
    retain_expected_machine_interface_address(txn.as_pgconn(), &expected_interface).await?;
    let addrs =
        crate::machine_interface_address::find_for_interface(txn.as_pgconn(), interface_id).await?;
    txn.commit().await?;
    assert_eq!(addrs.len(), 1, "retain must not duplicate the address row");
    assert_eq!(
        addrs[0].allocation_type,
        AllocationType::Static,
        "retain should promote the DHCP address to Static"
    );

    // Idempotent: a second retain is a no-op (the row is already Static).
    let mut txn = db::Transaction::begin(&pool).await?;
    retain_expected_machine_interface_address(txn.as_pgconn(), &expected_interface).await?;
    let addrs =
        crate::machine_interface_address::find_for_interface(txn.as_pgconn(), interface_id).await?;
    txn.commit().await?;
    assert_eq!(addrs.len(), 1, "second retain must remain a single row");
    assert_eq!(
        addrs[0].allocation_type,
        AllocationType::Static,
        "second retain should leave the address Static"
    );

    // The promoted Static address survives the DHCP-scoped expiry delete path:
    // delete_by_address(.., Dhcp) finds nothing to delete and the row remains.
    let mut txn = db::Transaction::begin(&pool).await?;
    let deleted = crate::machine_interface_address::delete_by_address(
        txn.as_pgconn(),
        ip,
        AllocationType::Dhcp,
    )
    .await?;
    let addrs =
        crate::machine_interface_address::find_for_interface(txn.as_pgconn(), interface_id).await?;
    txn.commit().await?;
    assert!(
        deleted.is_empty(),
        "DHCP-scoped expiry delete should not match a Static address"
    );
    assert_eq!(
        addrs.len(),
        1,
        "the retained Static address should survive DHCP lease expiry"
    );
    assert_eq!(addrs[0].allocation_type, AllocationType::Static);

    Ok(())
}

#[crate::sqlx_test]
async fn test_expected_interface_role_controls_fixed_preallocation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    let segment_id = create_managed_segment(
        &pool,
        "expected-interface-underlay",
        "192.0.2.0/24",
        NetworkSegmentType::Underlay,
        AllocationStrategy::Reserved,
    )
    .await?;

    struct Case {
        name: &'static str,
        suffix: u8,
        role: ExpectedInterfaceRole,
        primary: Option<bool>,
        expected_type: InterfaceType,
        expected_primary: bool,
    }

    for Case {
        name,
        suffix,
        role,
        primary,
        expected_type,
        expected_primary,
    } in [
        Case {
            name: "host default",
            suffix: 0x51,
            role: ExpectedInterfaceRole::Host,
            primary: None,
            expected_type: InterfaceType::Data,
            expected_primary: true,
        },
        Case {
            name: "Host false retains legacy creation default",
            suffix: 0x52,
            role: ExpectedInterfaceRole::Host,
            primary: Some(false),
            expected_type: InterfaceType::Data,
            expected_primary: true,
        },
        Case {
            name: "DPU OS",
            suffix: 0x53,
            role: ExpectedInterfaceRole::DpuOs,
            primary: None,
            expected_type: InterfaceType::Data,
            expected_primary: true,
        },
        Case {
            name: "DPU BMC",
            suffix: 0x54,
            role: ExpectedInterfaceRole::DpuBmc,
            primary: None,
            expected_type: InterfaceType::Bmc,
            expected_primary: false,
        },
    ] {
        let expected_interface = ExpectedInterface {
            mac_address: MacAddress::new([0x7a, 0x7b, 0x7c, 0x7d, 0x7e, suffix]),
            role,
            ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
            network_segment_type: Some(NetworkSegmentType::Underlay),
            fixed_ip: Some(format!("192.0.2.{suffix}").parse()?),
            primary,
            ..Default::default()
        };

        let mut txn = db::Transaction::begin(&pool).await?;
        preallocate_expected_machine_interface(txn.as_pgconn(), &expected_interface, None).await?;
        let interfaces =
            find_by_mac_address(txn.as_pgconn(), expected_interface.mac_address).await?;
        txn.commit().await?;

        assert_eq!(interfaces.len(), 1, "case: {name}");
        assert_eq!(interfaces[0].interface_type, expected_type, "case: {name}");
        assert_eq!(
            interfaces[0].primary_interface, expected_primary,
            "case: {name}",
        );
        assert_eq!(interfaces[0].segment_id, segment_id, "case: {name}");
        assert_eq!(
            interfaces[0].addresses,
            vec![expected_interface.fixed_ip.unwrap()],
            "case: {name}",
        );
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_fixed_host_preallocation_does_not_override_machine_wide_primary_selection(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    create_managed_segment(
        &pool,
        "fixed-host-primary",
        "192.0.2.0/24",
        NetworkSegmentType::Underlay,
        AllocationStrategy::Reserved,
    )
    .await?;
    let expected_interface = ExpectedInterface {
        mac_address: "7A:7B:7C:7D:7E:59".parse()?,
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
        fixed_ip: Some("192.0.2.59".parse()?),
        ..Default::default()
    };

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_expected_machine_interface(txn.as_pgconn(), &expected_interface, None).await?;
    let interface_id = find_by_mac_address(txn.as_pgconn(), expected_interface.mac_address)
        .await?
        .pop()
        .expect("fixed Host preallocation should create an interface")
        .id;

    // DHCP applies the ExpectedMachine-wide primary declaration. A later Site
    // Explorer pass must not replace it with the Host creation default.
    set_primary_interface(&interface_id, false, txn.as_pgconn()).await?;
    preallocate_expected_machine_interface(txn.as_pgconn(), &expected_interface, None).await?;
    let interface = find_one(txn.as_pgconn(), interface_id).await?;
    txn.commit().await?;

    assert!(!interface.primary_interface);

    Ok(())
}

#[crate::sqlx_test]
async fn test_fixed_preallocation_resolves_managed_prefix_and_segment_type(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    let underlay_segment = create_managed_segment(
        &pool,
        "fixed-address-underlay",
        "198.51.100.0/24",
        NetworkSegmentType::Underlay,
        AllocationStrategy::Reserved,
    )
    .await?;
    let non_target_segment = create_test_segment(&pool, "fixed-address-non-target").await?;

    let mut txn = db::Transaction::begin(&pool).await?;
    let legacy_hint = ExpectedInterface {
        mac_address: "7A:7B:7C:7D:7E:61".parse()?,
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
        nic_type: Some("onboard".to_string()),
        fixed_ip: Some("198.51.100.61".parse()?),
        ..Default::default()
    };
    preallocate_expected_machine_interface(txn.as_pgconn(), &legacy_hint, None).await?;
    let interface = find_by_mac_address(txn.as_pgconn(), legacy_hint.mac_address)
        .await?
        .pop()
        .expect("legacy fixed interface should be preallocated");
    assert_eq!(interface.segment_id, underlay_segment);
    let reconciled = validate_existing_mac_and_create(
        txn.as_pgconn(),
        legacy_hint.mac_address,
        &["198.51.100.1".parse()?],
        Some(legacy_hint.clone()),
        None,
    )
    .await?;
    assert_eq!(
        reconciled.segment_id, underlay_segment,
        "legacy nic_type must not reject an existing row whose fixed IP selected the segment",
    );

    let legacy_typed_segment = ExpectedInterface {
        mac_address: "7A:7B:7C:7D:7E:64".parse()?,
        network_segment_type: Some(NetworkSegmentType::Underlay),
        fixed_ip: Some("203.0.113.64".parse()?),
        ..Default::default()
    };
    preallocate_expected_machine_interface(txn.as_pgconn(), &legacy_typed_segment, None).await?;
    let legacy_interface = find_by_mac_address(txn.as_pgconn(), legacy_typed_segment.mac_address)
        .await?
        .pop()
        .expect("legacy fixed interface should be preallocated");
    let static_assignments = db::network_segment::static_assignments(txn.as_pgconn()).await?;
    assert_eq!(
        legacy_interface.segment_id, static_assignments.id,
        "a legacy Host declaration must not turn its DHCP selector into a fixed-address guard",
    );

    let legacy_host_bmc = ExpectedInterface {
        mac_address: "7A:7B:7C:7D:7E:69".parse()?,
        role: ExpectedInterfaceRole::HostBmc,
        fixed_ip: Some("203.0.113.69".parse()?),
        ..Default::default()
    };
    preallocate_expected_machine_interface(txn.as_pgconn(), &legacy_host_bmc, None).await?;
    let legacy_host_bmc_interface =
        find_by_mac_address(txn.as_pgconn(), legacy_host_bmc.mac_address)
            .await?
            .pop()
            .expect("legacy Host BMC fixed interface should be preallocated");
    assert_eq!(legacy_host_bmc_interface.segment_id, static_assignments.id);
    assert_eq!(legacy_host_bmc_interface.interface_type, InterfaceType::Bmc);
    assert!(!legacy_host_bmc_interface.primary_interface);

    // The address alone cannot make an exact row idempotent when an explicit
    // policy resolves it to a different managed segment.
    let misplaced_mac: MacAddress = "7A:7B:7C:7D:7E:68".parse()?;
    let misplaced_ip: IpAddr = "198.51.100.68".parse()?;
    let misplaced_interface_id: MachineInterfaceId = sqlx::query_scalar(
        "INSERT INTO machine_interfaces
            (segment_id, mac_address, primary_interface, hostname)
         VALUES ($1, $2, true, 'fixed-address-non-target')
         RETURNING id",
    )
    .bind(non_target_segment)
    .bind(misplaced_mac)
    .fetch_one(txn.as_pgconn())
    .await?;
    crate::machine_interface_address::insert(
        txn.as_pgconn(),
        misplaced_interface_id,
        misplaced_ip,
        AllocationType::Static,
    )
    .await?;
    let misplaced_reservation = ExpectedInterface {
        mac_address: misplaced_mac,
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
        fixed_ip: Some(misplaced_ip),
        ..Default::default()
    };
    let error =
        preallocate_expected_machine_interface(txn.as_pgconn(), &misplaced_reservation, None)
            .await
            .expect_err("an exact reservation on another segment should be rejected");
    assert!(matches!(error, DatabaseError::InvalidArgument(_)));
    let misplaced_interface = find_one(txn.as_pgconn(), misplaced_interface_id).await?;
    assert_eq!(misplaced_interface.segment_id, non_target_segment);

    /// One generalized fixed-address declaration that must reject the
    /// out-of-prefix address used by this test.
    struct OutsidePrefixCase {
        name: &'static str,
        suffix: u8,
        role: ExpectedInterfaceRole,
        ip_allocation: Option<ExpectedInterfaceIpAllocation>,
        network_segment_type: Option<NetworkSegmentType>,
    }

    for case in [
        OutsidePrefixCase {
            name: "explicit Host Fixed policy",
            suffix: 0x65,
            role: ExpectedInterfaceRole::Host,
            ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
            network_segment_type: None,
        },
        OutsidePrefixCase {
            name: "DPU OS inferred Fixed policy",
            suffix: 0x66,
            role: ExpectedInterfaceRole::DpuOs,
            ip_allocation: None,
            network_segment_type: None,
        },
        OutsidePrefixCase {
            name: "DPU BMC inferred Fixed policy",
            suffix: 0x67,
            role: ExpectedInterfaceRole::DpuBmc,
            ip_allocation: None,
            network_segment_type: None,
        },
        OutsidePrefixCase {
            name: "explicit Host BMC Fixed policy",
            suffix: 0x6a,
            role: ExpectedInterfaceRole::HostBmc,
            ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
            network_segment_type: None,
        },
        OutsidePrefixCase {
            name: "inferred Host BMC Fixed policy with a segment guard",
            suffix: 0x6b,
            role: ExpectedInterfaceRole::HostBmc,
            ip_allocation: None,
            network_segment_type: Some(NetworkSegmentType::Underlay),
        },
    ] {
        let expected_interface = ExpectedInterface {
            mac_address: MacAddress::new([0x7a, 0x7b, 0x7c, 0x7d, 0x7e, case.suffix]),
            role: case.role,
            ip_allocation: case.ip_allocation,
            fixed_ip: Some(format!("203.0.113.{}", case.suffix).parse()?),
            network_segment_type: case.network_segment_type,
            ..Default::default()
        };

        let error =
            preallocate_expected_machine_interface(txn.as_pgconn(), &expected_interface, None)
                .await
                .expect_err(case.name);
        assert!(
            matches!(error, DatabaseError::InvalidArgument(_)),
            "case: {}",
            case.name,
        );
        assert!(
            find_by_mac_address(txn.as_pgconn(), expected_interface.mac_address)
                .await?
                .is_empty(),
            "case: {}",
            case.name,
        );
    }

    let wrong_guard = ExpectedInterface {
        mac_address: "7A:7B:7C:7D:7E:62".parse()?,
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
        network_segment_type: Some(NetworkSegmentType::Admin),
        fixed_ip: Some("198.51.100.62".parse()?),
        ..Default::default()
    };
    let error = preallocate_expected_machine_interface(txn.as_pgconn(), &wrong_guard, None)
        .await
        .expect_err("the typed segment guard should reject a different segment type");
    assert!(matches!(error, DatabaseError::InvalidArgument(_)));

    let outside_guard = ExpectedInterface {
        mac_address: "7A:7B:7C:7D:7E:63".parse()?,
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Fixed),
        network_segment_type: Some(NetworkSegmentType::Underlay),
        fixed_ip: Some("203.0.113.63".parse()?),
        ..Default::default()
    };
    let error = preallocate_expected_machine_interface(txn.as_pgconn(), &outside_guard, None)
        .await
        .expect_err("a guarded fixed IP should belong to a configured segment");
    assert!(matches!(error, DatabaseError::InvalidArgument(_)));
    txn.rollback().await?;

    Ok(())
}

/// Existing Host declarations used `network_segment_type` only to narrow the
/// first DHCP segment choice. An explicit allocation policy turns that same
/// field into a guard for later DHCP reconciliation.
#[crate::sqlx_test]
async fn test_explicit_policy_opts_existing_host_interface_into_segment_guard(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    let segment_id = create_managed_segment(
        &pool,
        "legacy-host-segment-selector",
        "198.51.100.0/24",
        NetworkSegmentType::Underlay,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let mac_address: MacAddress = "7A:7B:7C:7D:7E:65".parse()?;
    let fixed_ip = "198.51.100.65".parse()?;
    let relay = "198.51.100.1".parse()?;

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac_address, fixed_ip, None).await?;

    let legacy_interface = ExpectedInterface {
        mac_address,
        network_segment_type: Some(NetworkSegmentType::Admin),
        ..Default::default()
    };
    let reconciled = validate_existing_mac_and_create(
        txn.as_pgconn(),
        mac_address,
        &[relay],
        Some(legacy_interface.clone()),
        None,
    )
    .await?;
    assert_eq!(reconciled.segment_id, segment_id);

    let explicit_policy = ExpectedInterface {
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Dynamic),
        ..legacy_interface
    };
    let error = validate_existing_mac_and_create(
        txn.as_pgconn(),
        mac_address,
        &[relay],
        Some(explicit_policy),
        None,
    )
    .await
    .expect_err("an explicit policy should enforce the typed segment guard");
    assert!(matches!(error, DatabaseError::FailedPrecondition(_)));
    assert!(
        error
            .to_string()
            .contains("do not identify the expected admin network segment type"),
        "{error}",
    );
    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_expected_interface_retained_policy_pins_all_dhcp_address_families(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    create_static_assignments_segment(&pool).await?;
    create_managed_segment(
        &pool,
        "retained-wrong-interface-type",
        "203.0.113.0/24",
        NetworkSegmentType::Underlay,
        AllocationStrategy::Dynamic,
    )
    .await?;
    create_managed_segment(
        &pool,
        "retained-wrong-segment-type",
        "198.51.100.0/24",
        NetworkSegmentType::Admin,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let mac_address: MacAddress = "7A:7B:7C:7D:7E:71".parse()?;
    let wrong_segment_mac: MacAddress = "7A:7B:7C:7D:7E:72".parse()?;
    let addresses = ["192.0.2.71".parse()?, "2001:db8::71".parse()?];
    let bmc_address = "203.0.113.71".parse()?;
    let wrong_segment_address = "198.51.100.72".parse()?;

    let mut txn = db::Transaction::begin(&pool).await?;
    preallocate_machine_interface(txn.as_pgconn(), mac_address, addresses[0], None).await?;
    let interface_id = find_by_mac_address(txn.as_pgconn(), mac_address)
        .await?
        .pop()
        .expect("preallocation should create an interface")
        .id;
    crate::machine_interface_address::delete(txn.as_pgconn(), &interface_id).await?;
    for address in addresses {
        crate::machine_interface_address::insert(
            txn.as_pgconn(),
            interface_id,
            address,
            AllocationType::Dhcp,
        )
        .await?;
    }

    let bmc_segment =
        crate::network_segment::for_prefix_containing_address(txn.as_pgconn(), bmc_address)
            .await?
            .expect("BMC test address should belong to the managed segment");
    let bmc_interface = create_with_type(
        txn.as_pgconn(),
        &[bmc_segment],
        &mac_address,
        false,
        AddressSelectionStrategy::StaticAddress(bmc_address),
        InterfaceType::Bmc,
        None,
    )
    .await?;
    crate::machine_interface_address::delete(txn.as_pgconn(), &bmc_interface.id).await?;
    crate::machine_interface_address::insert(
        txn.as_pgconn(),
        bmc_interface.id,
        bmc_address,
        AllocationType::Dhcp,
    )
    .await?;

    preallocate_machine_interface(
        txn.as_pgconn(),
        wrong_segment_mac,
        wrong_segment_address,
        None,
    )
    .await?;
    let wrong_segment_interface_id = find_by_mac_address(txn.as_pgconn(), wrong_segment_mac)
        .await?
        .pop()
        .expect("wrong-segment preallocation should create an interface")
        .id;
    crate::machine_interface_address::delete(txn.as_pgconn(), &wrong_segment_interface_id).await?;
    crate::machine_interface_address::insert(
        txn.as_pgconn(),
        wrong_segment_interface_id,
        wrong_segment_address,
        AllocationType::Dhcp,
    )
    .await?;

    let expected_interface = ExpectedInterface {
        mac_address,
        role: ExpectedInterfaceRole::DpuOs,
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Retained),
        ..Default::default()
    };
    retain_expected_machine_interface_address(txn.as_pgconn(), &expected_interface).await?;
    retain_expected_machine_interface_address(txn.as_pgconn(), &expected_interface).await?;
    let retained =
        crate::machine_interface_address::find_for_interface(txn.as_pgconn(), interface_id).await?;
    let bmc_addresses =
        crate::machine_interface_address::find_for_interface(txn.as_pgconn(), bmc_interface.id)
            .await?;

    let wrong_segment_expected_interface = ExpectedInterface {
        mac_address: wrong_segment_mac,
        role: ExpectedInterfaceRole::DpuOs,
        ip_allocation: Some(ExpectedInterfaceIpAllocation::Retained),
        network_segment_type: Some(NetworkSegmentType::Underlay),
        ..Default::default()
    };
    let error = retain_expected_machine_interface_address(
        txn.as_pgconn(),
        &wrong_segment_expected_interface,
    )
    .await
    .expect_err("the typed segment guard should reject a DHCP address on another segment type");
    assert!(matches!(error, DatabaseError::FailedPrecondition(_)));
    let wrong_segment_addresses = crate::machine_interface_address::find_for_interface(
        txn.as_pgconn(),
        wrong_segment_interface_id,
    )
    .await?;
    txn.commit().await?;

    assert_eq!(retained.len(), 2);
    assert!(
        retained
            .iter()
            .all(|address| address.allocation_type == AllocationType::Static),
    );
    assert_eq!(bmc_addresses.len(), 1);
    assert_eq!(bmc_addresses[0].allocation_type, AllocationType::Dhcp);
    assert_eq!(wrong_segment_addresses.len(), 1);
    assert_eq!(
        wrong_segment_addresses[0].allocation_type,
        AllocationType::Dhcp,
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_expected_interface_role_controls_observed_interface_creation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let segment_id = create_managed_segment(
        &pool,
        "observed-interface-underlay",
        "203.0.113.0/24",
        NetworkSegmentType::Underlay,
        AllocationStrategy::Dynamic,
    )
    .await?;
    let relay = "203.0.113.1".parse()?;

    struct Case {
        name: &'static str,
        suffix: u8,
        role: ExpectedInterfaceRole,
        primary: Option<bool>,
        expected_type: InterfaceType,
        expected_primary: bool,
    }

    for Case {
        name,
        suffix,
        role,
        primary,
        expected_type,
        expected_primary,
    } in [
        Case {
            name: "Host false retains legacy creation default",
            suffix: 0x81,
            role: ExpectedInterfaceRole::Host,
            primary: Some(false),
            expected_type: InterfaceType::Data,
            expected_primary: true,
        },
        Case {
            name: "DPU OS",
            suffix: 0x82,
            role: ExpectedInterfaceRole::DpuOs,
            primary: None,
            expected_type: InterfaceType::Data,
            expected_primary: true,
        },
        Case {
            name: "DPU BMC",
            suffix: 0x83,
            role: ExpectedInterfaceRole::DpuBmc,
            primary: None,
            expected_type: InterfaceType::Bmc,
            expected_primary: false,
        },
    ] {
        let expected_interface = ExpectedInterface {
            mac_address: MacAddress::new([0x7a, 0x7b, 0x7c, 0x7d, 0x7e, suffix]),
            role,
            ip_allocation: Some(ExpectedInterfaceIpAllocation::Dynamic),
            network_segment_type: Some(NetworkSegmentType::Underlay),
            primary,
            ..Default::default()
        };
        let mut txn = db::Transaction::begin(&pool).await?;
        let interface = find_or_create_observed_machine_interface(
            txn.as_pgconn(),
            None,
            expected_interface.mac_address,
            &[relay],
            Some(expected_interface),
            None,
            None,
        )
        .await?;
        txn.commit().await?;

        assert_eq!(interface.segment_id, segment_id, "case: {name}");
        assert_eq!(interface.interface_type, expected_type, "case: {name}");
        assert_eq!(
            interface.primary_interface, expected_primary,
            "case: {name}",
        );
        assert!(interface.addresses.is_empty(), "case: {name}");
    }

    Ok(())
}
