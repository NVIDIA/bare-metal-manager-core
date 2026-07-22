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

//! BMC MAC addresses that must be hidden from discovery, DHCP, or both.

use mac_address::MacAddress;
use model::ignored_bmc_mac::{IgnoredBmcMac, NewIgnoredBmcMac};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

/// Inserts or replaces the desired suppression state for a BMC MAC.
///
/// A DHCP-discovery observation remains valid across idempotent writes that
/// leave DHCP suppression enabled. Changing DHCP suppression in either
/// direction clears the observation so a later enable must be observed again.
pub async fn upsert(
    txn: &mut PgConnection,
    input: &NewIgnoredBmcMac,
) -> DatabaseResult<IgnoredBmcMac> {
    const QUERY: &str = "INSERT INTO ignored_bmc_macs (
        bmc_mac_address,
        reason,
        suppress_site_explorer,
        suppress_dhcp
    ) VALUES ($1, $2, $3, $4)
    ON CONFLICT (bmc_mac_address) DO UPDATE SET
        reason = EXCLUDED.reason,
        suppress_site_explorer = EXCLUDED.suppress_site_explorer,
        suppress_dhcp = EXCLUDED.suppress_dhcp,
        dhcp_discover_suppressed_at = CASE
            WHEN EXCLUDED.suppress_dhcp AND ignored_bmc_macs.suppress_dhcp
                THEN ignored_bmc_macs.dhcp_discover_suppressed_at
            ELSE NULL
        END,
        updated_at = NOW()
    RETURNING
        bmc_mac_address,
        reason,
        suppress_site_explorer,
        suppress_dhcp,
        dhcp_discover_suppressed_at,
        created_at,
        updated_at";

    sqlx::query_as(QUERY)
        .bind(input.bmc_mac_address)
        .bind(&input.reason)
        .bind(input.suppress_site_explorer)
        .bind(input.suppress_dhcp)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns the suppression record for `bmc_mac_address`, if one exists.
pub async fn find(
    db: impl DbReader<'_>,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<Option<IgnoredBmcMac>> {
    const QUERY: &str = "SELECT
        bmc_mac_address,
        reason,
        suppress_site_explorer,
        suppress_dhcp,
        dhcp_discover_suppressed_at,
        created_at,
        updated_at
    FROM ignored_bmc_macs
    WHERE bmc_mac_address = $1";

    sqlx::query_as(QUERY)
        .bind(bmc_mac_address)
        .fetch_optional(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns every BMC MAC that Site Explorer must skip.
pub async fn find_site_explorer_suppressed(
    db: impl DbReader<'_>,
) -> DatabaseResult<Vec<MacAddress>> {
    const QUERY: &str = "SELECT bmc_mac_address
        FROM ignored_bmc_macs
        WHERE suppress_site_explorer
        ORDER BY bmc_mac_address";

    sqlx::query_scalar(QUERY)
        .fetch_all(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns whether DHCP service is suppressed for `bmc_mac_address`.
pub async fn is_dhcp_suppressed(
    db: impl DbReader<'_>,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<bool> {
    const QUERY: &str = "SELECT EXISTS(
        SELECT 1
        FROM ignored_bmc_macs
        WHERE bmc_mac_address = $1 AND suppress_dhcp
    )";

    sqlx::query_scalar(QUERY)
        .bind(bmc_mac_address)
        .fetch_one(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Records that a DHCPDISCOVER was ignored for a DHCP-suppressed BMC.
/// This is used to verify that the BMC has withdrawn its DHCP lease.
///
/// The lookup and timestamp write are atomic. The return value is `true` when
/// DHCP is suppressed and the caller must not offer a lease; it is `false`
/// when no matching suppression exists. Repeated observations preserve the
/// time of the first suppressed discovery.
pub async fn record_dhcp_discover_suppressed(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<bool> {
    const QUERY: &str = "UPDATE ignored_bmc_macs SET
        updated_at = CASE
            WHEN dhcp_discover_suppressed_at IS NULL THEN NOW()
            ELSE updated_at
        END,
        dhcp_discover_suppressed_at = COALESCE(dhcp_discover_suppressed_at, NOW())
    WHERE bmc_mac_address = $1 AND suppress_dhcp";

    sqlx::query(QUERY)
        .bind(bmc_mac_address)
        .execute(txn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Deletes the suppression record for one BMC MAC.
///
/// Returns `true` when a row was removed.
pub async fn delete(txn: &mut PgConnection, bmc_mac_address: MacAddress) -> DatabaseResult<bool> {
    const QUERY: &str = "DELETE FROM ignored_bmc_macs WHERE bmc_mac_address = $1";

    sqlx::query(QUERY)
        .bind(bmc_mac_address)
        .execute(txn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Deletes suppression records for a set of BMC MACs and returns their count.
pub async fn delete_many(
    txn: &mut PgConnection,
    bmc_mac_addresses: &[MacAddress],
) -> DatabaseResult<u64> {
    const QUERY: &str = "DELETE FROM ignored_bmc_macs WHERE bmc_mac_address = ANY($1)";

    sqlx::query(QUERY)
        .bind(bmc_mac_addresses)
        .execute(txn)
        .await
        .map(|result| result.rows_affected())
        .map_err(|e| DatabaseError::query(QUERY, e))
}

#[cfg(test)]
mod tests {
    use mac_address::MacAddress;
    use model::ignored_bmc_mac::NewIgnoredBmcMac;

    use super::{
        delete, delete_many, find, find_site_explorer_suppressed, is_dhcp_suppressed,
        record_dhcp_discover_suppressed, upsert,
    };

    fn mac(last: u8) -> MacAddress {
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, last])
    }

    fn upsert_input(
        last: u8,
        reason: &str,
        suppress_site_explorer: bool,
        suppress_dhcp: bool,
    ) -> NewIgnoredBmcMac {
        NewIgnoredBmcMac {
            bmc_mac_address: mac(last),
            reason: reason.to_string(),
            suppress_site_explorer,
            suppress_dhcp,
        }
    }

    #[crate::sqlx_test]
    async fn suppression_flags_are_independent(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        upsert(
            txn.as_mut(),
            &upsert_input(1, "decommissioning", true, false),
        )
        .await
        .unwrap();
        upsert(
            txn.as_mut(),
            &upsert_input(2, "decommissioning", false, true),
        )
        .await
        .unwrap();
        upsert(
            txn.as_mut(),
            &upsert_input(3, "decommissioning", true, true),
        )
        .await
        .unwrap();

        assert_eq!(
            find_site_explorer_suppressed(txn.as_mut()).await.unwrap(),
            vec![mac(1), mac(3)]
        );
        assert!(!is_dhcp_suppressed(txn.as_mut(), mac(1)).await.unwrap());
        assert!(is_dhcp_suppressed(txn.as_mut(), mac(2)).await.unwrap());
        assert!(is_dhcp_suppressed(txn.as_mut(), mac(3)).await.unwrap());
        assert!(!is_dhcp_suppressed(txn.as_mut(), mac(4)).await.unwrap());
    }

    #[crate::sqlx_test]
    async fn dhcp_discovery_is_recorded_only_while_suppressed(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        upsert(
            txn.as_mut(),
            &upsert_input(1, "site explorer only", true, false),
        )
        .await
        .unwrap();
        assert!(
            !record_dhcp_discover_suppressed(txn.as_mut(), mac(1))
                .await
                .unwrap()
        );
        assert!(
            find(txn.as_mut(), mac(1))
                .await
                .unwrap()
                .unwrap()
                .dhcp_discover_suppressed_at
                .is_none()
        );

        upsert(txn.as_mut(), &upsert_input(1, "dhcp handoff", true, true))
            .await
            .unwrap();
        assert!(
            record_dhcp_discover_suppressed(txn.as_mut(), mac(1))
                .await
                .unwrap()
        );
        assert!(
            find(txn.as_mut(), mac(1))
                .await
                .unwrap()
                .unwrap()
                .dhcp_discover_suppressed_at
                .is_some()
        );
    }

    #[crate::sqlx_test]
    async fn idempotent_upsert_preserves_dhcp_observation(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        upsert(txn.as_mut(), &upsert_input(1, "dhcp handoff", true, true))
            .await
            .unwrap();
        record_dhcp_discover_suppressed(txn.as_mut(), mac(1))
            .await
            .unwrap();
        let observed_at = find(txn.as_mut(), mac(1))
            .await
            .unwrap()
            .unwrap()
            .dhcp_discover_suppressed_at;

        let record = upsert(txn.as_mut(), &upsert_input(1, "retry", true, true))
            .await
            .unwrap();
        assert_eq!(record.dhcp_discover_suppressed_at, observed_at);

        let record = upsert(txn.as_mut(), &upsert_input(1, "release DHCP", true, false))
            .await
            .unwrap();
        assert!(record.dhcp_discover_suppressed_at.is_none());

        let record = upsert(
            txn.as_mut(),
            &upsert_input(1, "suppress DHCP again", true, true),
        )
        .await
        .unwrap();
        assert!(record.dhcp_discover_suppressed_at.is_none());
    }

    #[crate::sqlx_test]
    async fn delete_helpers_are_idempotent(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        for last in 1..=3 {
            upsert(
                txn.as_mut(),
                &upsert_input(last, "decommissioning", true, true),
            )
            .await
            .unwrap();
        }

        assert!(delete(txn.as_mut(), mac(1)).await.unwrap());
        assert!(!delete(txn.as_mut(), mac(1)).await.unwrap());
        assert_eq!(
            delete_many(txn.as_mut(), &[mac(2), mac(3), mac(4)])
                .await
                .unwrap(),
            2
        );
        assert!(find(txn.as_mut(), mac(2)).await.unwrap().is_none());
        assert!(find(txn.as_mut(), mac(3)).await.unwrap().is_none());
    }
}
