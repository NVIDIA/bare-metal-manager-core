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

use carbide_network::ip::{IdentifyAddressFamily, IpAddressFamily};
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::switch::SwitchId;
use mac_address::MacAddress;
use model::allocation_type::{AllocationType, AssignStaticResult};
use model::machine_interface::InterfaceType;
use model::network_segment::NetworkSegmentType;
use sqlx::{FromRow, PgConnection};

use super::{DatabaseError, Transaction};
use crate::db_read::DbReader;

#[cfg(test)]
mod test_find_by_address;

const ADDRESS_INSERT_MAX_RETRIES: usize = 3;

/// Returned when a writer tries to give an address to a second interface.
///
/// Fixed and manual assignment paths return this conflict to the caller.
/// Dynamic allocation paths use it to select another candidate.
#[derive(thiserror::Error, Debug)]
#[error("address already in use: {0} by {1} in network segment {2} (interface: {3})")]
pub struct AddressAlreadyInUseError(
    pub IpAddr,
    pub MacAddress,
    pub NetworkSegmentId,
    pub MachineInterfaceId,
);

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddress {
    pub address: IpAddr,
}

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddressWithType {
    pub address: IpAddr,
    pub allocation_type: AllocationType,
}

pub async fn find_ipv4_for_interface(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
) -> Result<MachineInterfaceAddress, DatabaseError> {
    let query =
        "SELECT * FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = 4";
    sqlx::query_as(query)
        .bind(interface_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Looks up which machine interface owns an IP, with association, segment, role, and allocation
/// metadata.
///
/// The IP finder uses `interface_type` together with `allocation_type` and segment metadata to
/// distinguish static BMC addresses from static Data addresses.
pub async fn find_by_address(
    txn: impl DbReader<'_>,
    address: IpAddr,
) -> Result<Option<MachineInterfaceSearchResult>, DatabaseError> {
    let query = "SELECT mi.id, mi.machine_id, mi.switch_id, mi.interface_type,
                ns.name, ns.network_segment_type, mia.allocation_type
            FROM machine_interface_addresses mia
            INNER JOIN machine_interfaces mi ON mi.id = mia.interface_id
            INNER JOIN network_segments ns ON ns.id = mi.segment_id
            WHERE mia.address = $1::inet
        ";
    sqlx::query_as(query)
        .bind(address)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn delete(
    txn: &mut PgConnection,
    interface_id: &MachineInterfaceId,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1";
    sqlx::query(query)
        .bind(interface_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Find all addresses for an interface, including their allocation type.
pub async fn find_for_interface(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
) -> Result<Vec<MachineInterfaceAddressWithType>, DatabaseError> {
    let query =
        "SELECT address, allocation_type FROM machine_interface_addresses WHERE interface_id = $1";
    sqlx::query_as(query)
        .bind(interface_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Find the allocation type of the existing address for a given
/// interface and address family, if one exists.
pub async fn find_allocation_type_for_family(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    family: IpAddressFamily,
) -> Result<Option<AllocationType>, DatabaseError> {
    let query = "SELECT allocation_type FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = $2";
    let result: Option<(AllocationType,)> = sqlx::query_as(query)
        .bind(interface_id)
        .bind(family.pg_family())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(result.map(|(t,)| t))
}

/// Delete the address for a given interface, address family, and
/// allocation type. Returns true if a row was deleted.
pub async fn delete_by_interface_family(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    family: IpAddressFamily,
    allocation_type: AllocationType,
) -> Result<bool, DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = $2 AND allocation_type = $3";
    sqlx::query(query)
        .bind(interface_id)
        .bind(family.pg_family())
        .bind(allocation_type)
        .execute(txn)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(query, e))
}

/// Delete a specific address from a specific interface. Returns true if a
/// matching row was deleted. Scoping by `interface_id` ensures an operator
/// remove-address call only removes the caller's own address, never another
/// interface's row that happens to hold the same IP.
pub async fn delete_by_interface_and_address(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    address: IpAddr,
    allocation_type: AllocationType,
) -> Result<bool, DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1 AND address = $2::inet AND allocation_type = $3";
    sqlx::query(query)
        .bind(interface_id)
        .bind(address)
        .bind(allocation_type)
        .execute(txn)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(query, e))
}

/// Insert a new address for an interface with the given allocation type.
///
/// `machine_interface_addresses_address_key` is the final ownership boundary:
/// at most one machine interface may own a given IP across the site.
/// `ON CONFLICT` keeps the caller's transaction usable when that address
/// constraint wins, so a replay by the current owner stays idempotent without
/// changing its stored allocation type. A different owner returns
/// [`AddressAlreadyInUseError`] instead of a generic database error.
///
/// This conflict handling applies only to exact-address ownership. The
/// existing one-address-per-family constraint on each interface remains a
/// separate write boundary.
pub async fn insert(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    address: IpAddr,
    allocation_type: AllocationType,
) -> Result<(), DatabaseError> {
    let insert_query = "INSERT INTO machine_interface_addresses
            (interface_id, address, allocation_type)
        VALUES ($1::uuid, $2::inet, $3)
        ON CONFLICT ON CONSTRAINT machine_interface_addresses_address_key
        DO NOTHING";
    let owner_query = "SELECT mi.mac_address, mi.segment_id, mi.id
        FROM machine_interface_addresses mia
        JOIN machine_interfaces mi ON mi.id = mia.interface_id
        WHERE mia.address = $1::inet";

    for _ in 0..ADDRESS_INSERT_MAX_RETRIES {
        let inserted = sqlx::query(insert_query)
            .bind(interface_id)
            .bind(address)
            .bind(allocation_type)
            .execute(&mut *txn)
            .await
            .map_err(|error| DatabaseError::query(insert_query, error))?;
        if inserted.rows_affected() == 1 {
            return Ok(());
        }

        // Under `READ COMMITTED`, the conflicting row may have committed after
        // the INSERT statement took its snapshot. A second statement can see
        // that winner and gives callers the same typed error as the sequential
        // fixed-address check.
        let owner: Option<(MacAddress, NetworkSegmentId, MachineInterfaceId)> =
            sqlx::query_as(owner_query)
                .bind(address)
                .fetch_optional(&mut *txn)
                .await
                .map_err(|error| DatabaseError::query(owner_query, error))?;
        if let Some((mac_address, segment_id, owner_interface_id)) = owner {
            if owner_interface_id == interface_id {
                // The existing allocation type remains authoritative. In
                // particular, a DHCP replay must not downgrade a static row.
                return Ok(());
            }
            return Err(AddressAlreadyInUseError(
                address,
                mac_address,
                segment_id,
                owner_interface_id,
            )
            .into());
        }

        // The winner disappeared between conflict detection and lookup. Try
        // the insert again rather than returning an ownerless conflict.
    }

    Err(DatabaseError::internal(format!(
        "address {address} repeatedly changed owners while assigning it to interface {interface_id}",
    )))
}

/// Assign a static address to an interface. If the interface already
/// has an address for the same family, the behavior depends on its
/// allocation type:
///
/// - `Static`: the old static address is replaced.
/// - `Dhcp` or `Slaac`: the managed allocation is removed and
///   replaced with the static assignment.
///
/// The replacement runs in a savepoint so a conflicting owner cannot leave the
/// interface addressless when the caller handles the typed error and continues
/// its outer transaction.
pub async fn assign_static(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    address: IpAddr,
) -> Result<AssignStaticResult, DatabaseError> {
    let mut assign_txn = Transaction::begin_inner(txn).await?;
    let result = assign_static_inner(assign_txn.as_pgconn(), interface_id, address).await;
    match result {
        Ok(result) => {
            assign_txn.commit().await?;
            Ok(result)
        }
        Err(error) => {
            assign_txn.rollback().await?;
            Err(error)
        }
    }
}

/// Perform the delete-and-insert portion of [`assign_static`] inside its
/// savepoint.
async fn assign_static_inner(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    address: IpAddr,
) -> Result<AssignStaticResult, DatabaseError> {
    let family = address.address_family();

    let existing = find_allocation_type_for_family(&mut *txn, interface_id, family).await?;

    let result = match existing {
        Some(allocation_type @ (AllocationType::Dhcp | AllocationType::Slaac)) => {
            delete_by_interface_family(&mut *txn, interface_id, family, allocation_type).await?;
            AssignStaticResult::ReplacedDhcp
        }
        Some(AllocationType::Static) => {
            delete_by_interface_family(&mut *txn, interface_id, family, AllocationType::Static)
                .await?;
            AssignStaticResult::ReplacedStatic
        }
        None => AssignStaticResult::Assigned,
    };

    insert(txn, interface_id, address, AllocationType::Static).await?;

    Ok(result)
}

/// Delete an address allocation of the given type. Returns the interface that
/// owned the deleted address (or an empty vector if nothing matched) so callers
/// can resync its hostname without a separate ownership lookup.
///
/// The vector return stays in place for existing callers, although the global
/// address constraint now limits it to one interface.
pub async fn delete_by_address(
    txn: &mut PgConnection,
    address: IpAddr,
    allocation_type: AllocationType,
) -> Result<Vec<MachineInterfaceId>, DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses WHERE address = $1::inet AND allocation_type = $2 RETURNING interface_id";
    sqlx::query_scalar(query)
        .bind(address)
        .bind(allocation_type)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Delete an address allocation for a given (ip, mac) pair, which
/// of course only actually deletes when the pair matches.
///
/// Returns the interface that owned the deleted allocation (or an empty vector
/// if the pair matched nothing) so callers can resync its hostname against the
/// authoritative deleted row rather than a separate lookup. The vector return
/// stays in place for existing callers.
pub async fn delete_by_address_and_mac(
    txn: &mut PgConnection,
    address: IpAddr,
    mac_address: mac_address::MacAddress,
    allocation_type: AllocationType,
) -> Result<Vec<MachineInterfaceId>, DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses mia
        USING machine_interfaces mi
        WHERE mia.interface_id = mi.id
          AND mia.address = $1::inet
          AND mia.allocation_type = $2
          AND mi.mac_address = $3::macaddr
        RETURNING mia.interface_id";
    sqlx::query_scalar(query)
        .bind(address)
        .bind(allocation_type)
        .bind(mac_address)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Check whether an interface has any address assigned for the
/// given address family.
///
/// This is used by the DHCPDISCOVER flow to decide whether to
/// re-allocate after a lease expiration. If the interface still
/// has an address for the family (static or DHCP), no re-allocation
// is needed.
pub async fn has_address_for_family(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    family: IpAddressFamily,
) -> Result<bool, DatabaseError> {
    let query = "SELECT EXISTS(SELECT 1 FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = $2)";
    sqlx::query_scalar(query)
        .bind(interface_id)
        .bind(family.pg_family())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Row shape for [`find_by_address`]: interface identity, association, role, owning segment, and
/// how the address was assigned (DHCP vs static / operator-configured).
#[derive(Debug, FromRow)]
pub struct MachineInterfaceSearchResult {
    pub id: MachineInterfaceId,
    pub machine_id: Option<MachineId>,
    pub switch_id: Option<SwitchId>,
    pub interface_type: InterfaceType,
    pub name: String,
    pub network_segment_type: NetworkSegmentType,
    pub allocation_type: AllocationType,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS_UNIQUENESS_MIGRATION: &str =
        include_str!("../migrations/20260730222152_machine_interface_addresses_unique.sql");

    /// Create the minimal segment used by address ownership tests.
    async fn create_test_segment(
        txn: &mut PgConnection,
        name: &str,
    ) -> Result<NetworkSegmentId, sqlx::Error> {
        sqlx::query_scalar(
            "INSERT INTO network_segments (name, version)
             VALUES ($1, 'V1-T0')
             RETURNING id",
        )
        .bind(name)
        .fetch_one(txn)
        .await
    }

    /// Create an addressless interface with a stable hostname.
    async fn create_test_interface(
        txn: &mut PgConnection,
        segment_id: NetworkSegmentId,
        mac_address: &str,
        hostname: &str,
    ) -> Result<MachineInterfaceId, sqlx::Error> {
        sqlx::query_scalar(
            "INSERT INTO machine_interfaces
                (segment_id, mac_address, primary_interface, hostname)
             VALUES ($1, $2::macaddr, false, $3)
             RETURNING id",
        )
        .bind(segment_id)
        .bind(mac_address)
        .bind(hostname)
        .fetch_one(txn)
        .await
    }

    /// Verifies the new SLAAC allocation type survives a database round trip.
    #[crate::sqlx_test]
    async fn slaac_allocation_type_round_trips(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        // Create the minimal segment and interface rows needed to own an address.
        let segment_id: NetworkSegmentId = sqlx::query_scalar(
            "INSERT INTO network_segments (name, version) VALUES ($1, 'V1-T0') RETURNING id",
        )
        .bind("slaac-roundtrip")
        .fetch_one(txn.as_mut())
        .await?;
        let interface_id: MachineInterfaceId = sqlx::query_scalar(
            "INSERT INTO machine_interfaces (segment_id, mac_address, primary_interface, hostname)
             VALUES ($1, $2::macaddr, true, 'slaac-roundtrip') RETURNING id",
        )
        .bind(segment_id)
        .bind("02:00:00:00:00:01")
        .fetch_one(txn.as_mut())
        .await?;

        // Insert a SLAAC allocation through the public helper and read it back.
        insert(
            txn.as_mut(),
            interface_id,
            "2001:db8::10".parse()?,
            AllocationType::Slaac,
        )
        .await?;
        let addresses = find_for_interface(txn.as_mut(), interface_id).await?;

        // Verify the persisted row preserved the new allocation type.
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].allocation_type, AllocationType::Slaac);

        txn.rollback().await?;
        Ok(())
    }

    /// The shared insert accepts an exact owner replay and returns a typed
    /// conflict for another owner without poisoning the caller's transaction.
    #[crate::sqlx_test]
    async fn insert_rejects_an_address_owned_by_another_interface(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let segment_id = create_test_segment(txn.as_mut(), "unique-address-owner").await?;
        let owner_mac: MacAddress = "02:00:00:00:01:01".parse()?;
        let owner_id = create_test_interface(
            txn.as_mut(),
            segment_id,
            &owner_mac.to_string(),
            "address-owner",
        )
        .await?;
        let contender_id = create_test_interface(
            txn.as_mut(),
            segment_id,
            "02:00:00:00:01:02",
            "address-contender",
        )
        .await?;

        for address in [
            "192.0.2.10".parse::<IpAddr>()?,
            "2001:db8::10".parse::<IpAddr>()?,
        ] {
            insert(txn.as_mut(), owner_id, address, AllocationType::Static).await?;
            insert(txn.as_mut(), owner_id, address, AllocationType::Static).await?;
            let owner_rows: i64 = sqlx::query_scalar(
                "SELECT count(*)
                 FROM machine_interface_addresses
                 WHERE interface_id = $1 AND address = $2",
            )
            .bind(owner_id)
            .bind(address)
            .fetch_one(txn.as_mut())
            .await?;
            assert_eq!(owner_rows, 1, "an exact owner replay stays idempotent");

            let error = insert(txn.as_mut(), contender_id, address, AllocationType::Static)
                .await
                .expect_err("a second interface must not own the same address");
            match error {
                DatabaseError::AddressAlreadyInUse(AddressAlreadyInUseError(
                    conflict_address,
                    conflict_mac,
                    conflict_segment_id,
                    conflict_interface_id,
                )) => {
                    assert_eq!(conflict_address, address);
                    assert_eq!(conflict_mac, owner_mac);
                    assert_eq!(conflict_segment_id, segment_id);
                    assert_eq!(conflict_interface_id, owner_id);
                }
                other => panic!("expected AddressAlreadyInUse, got {other:?}"),
            }

            // `ON CONFLICT` leaves the outer transaction usable.
            let one: i32 = sqlx::query_scalar("SELECT 1")
                .fetch_one(txn.as_mut())
                .await?;
            assert_eq!(one, 1);
        }

        Ok(())
    }

    /// A failed static replacement rolls its delete back before returning the
    /// conflicting owner.
    #[crate::sqlx_test]
    async fn assign_static_conflict_keeps_the_previous_address(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let segment_id = create_test_segment(txn.as_mut(), "static-replacement-conflict").await?;
        let owner_id = create_test_interface(
            txn.as_mut(),
            segment_id,
            "02:00:00:00:02:01",
            "replacement-owner",
        )
        .await?;
        let contender_id = create_test_interface(
            txn.as_mut(),
            segment_id,
            "02:00:00:00:02:02",
            "replacement-contender",
        )
        .await?;

        let cases = [
            (
                "192.0.2.20".parse::<IpAddr>()?,
                "192.0.2.21".parse::<IpAddr>()?,
            ),
            (
                "2001:db8::20".parse::<IpAddr>()?,
                "2001:db8::21".parse::<IpAddr>()?,
            ),
        ];
        for (owned_address, previous_address) in cases {
            insert(
                txn.as_mut(),
                owner_id,
                owned_address,
                AllocationType::Static,
            )
            .await?;
            insert(
                txn.as_mut(),
                contender_id,
                previous_address,
                AllocationType::Static,
            )
            .await?;

            let error = assign_static(txn.as_mut(), contender_id, owned_address)
                .await
                .expect_err("the replacement must reject another interface's address");
            assert!(matches!(error, DatabaseError::AddressAlreadyInUse(_)));

            let contender_addresses = find_for_interface(txn.as_mut(), contender_id).await?;
            assert!(
                contender_addresses
                    .iter()
                    .any(|address| address.address == previous_address),
                "the failed replacement must restore {previous_address}",
            );
        }

        Ok(())
    }

    /// The migration reports historical duplicate owners rather than choosing
    /// one and deleting the other.
    #[crate::sqlx_test]
    async fn migration_rejects_duplicate_hosts_with_different_masks(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::raw_sql(
            "ALTER TABLE machine_interface_addresses
                 DROP CONSTRAINT machine_interface_addresses_address_key;
             ALTER TABLE machine_interface_addresses
                 DROP CONSTRAINT machine_interface_addresses_host_address_check;",
        )
        .execute(&pool)
        .await?;

        let mut txn = pool.begin().await?;
        let segment_id = create_test_segment(txn.as_mut(), "migration-duplicate-address").await?;
        let first_id = create_test_interface(
            txn.as_mut(),
            segment_id,
            "02:00:00:00:03:01",
            "migration-owner-one",
        )
        .await?;
        let second_id = create_test_interface(
            txn.as_mut(),
            segment_id,
            "02:00:00:00:03:02",
            "migration-owner-two",
        )
        .await?;
        sqlx::query(
            "INSERT INTO machine_interface_addresses (interface_id, address)
             VALUES
                 ($1, '192.0.2.30/24'::inet),
                 ($2, '192.0.2.30/32'::inet)",
        )
        .bind(first_id)
        .bind(second_id)
        .execute(txn.as_mut())
        .await?;
        txn.commit().await?;

        let error = sqlx::raw_sql(ADDRESS_UNIQUENESS_MIGRATION)
            .execute(&pool)
            .await
            .expect_err("the migration must stop on ambiguous ownership");
        let message = error.to_string();
        assert!(message.contains("duplicate host addresses"), "{message}");
        assert!(message.contains("1 total"), "{message}");
        assert!(message.contains(&first_id.to_string()), "{message}");
        assert!(message.contains(&second_id.to_string()), "{message}");

        let row_count: i64 = sqlx::query_scalar("SELECT count(*) FROM machine_interface_addresses")
            .fetch_one(&pool)
            .await?;
        assert_eq!(
            row_count, 2,
            "the failed audit must not delete either owner"
        );

        Ok(())
    }

    /// The migration converts lone legacy masks to host addresses before
    /// requiring `/32` and `/128` from future writers.
    #[crate::sqlx_test]
    async fn migration_normalizes_non_host_masks(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::raw_sql(
            "ALTER TABLE machine_interface_addresses
                 DROP CONSTRAINT machine_interface_addresses_address_key;
             ALTER TABLE machine_interface_addresses
                 DROP CONSTRAINT machine_interface_addresses_host_address_check;",
        )
        .execute(&pool)
        .await?;

        let mut txn = pool.begin().await?;
        let segment_id = create_test_segment(txn.as_mut(), "migration-normalize-address").await?;
        let ipv4_id = create_test_interface(
            txn.as_mut(),
            segment_id,
            "02:00:00:00:04:01",
            "normalize-ipv4",
        )
        .await?;
        let ipv6_id = create_test_interface(
            txn.as_mut(),
            segment_id,
            "02:00:00:00:04:02",
            "normalize-ipv6",
        )
        .await?;
        sqlx::query(
            "INSERT INTO machine_interface_addresses (interface_id, address)
             VALUES
                 ($1, '192.0.2.40/24'::inet),
                 ($2, '2001:db8::40/64'::inet)",
        )
        .bind(ipv4_id)
        .bind(ipv6_id)
        .execute(txn.as_mut())
        .await?;
        txn.commit().await?;

        sqlx::raw_sql(ADDRESS_UNIQUENESS_MIGRATION)
            .execute(&pool)
            .await?;

        let masks: Vec<i32> = sqlx::query_scalar(
            "SELECT masklen(address)
             FROM machine_interface_addresses
             ORDER BY family(address)",
        )
        .fetch_all(&pool)
        .await?;
        assert_eq!(masks, vec![32, 128]);

        let duplicate = sqlx::query(
            "INSERT INTO machine_interface_addresses (interface_id, address)
             VALUES ($1, '192.0.2.40'::inet)",
        )
        .bind(ipv6_id)
        .execute(&pool)
        .await
        .expect_err("the replayed migration must enforce global ownership");
        let constraint = duplicate
            .as_database_error()
            .and_then(|error| error.constraint());
        assert_eq!(constraint, Some("machine_interface_addresses_address_key"));

        Ok(())
    }
}
