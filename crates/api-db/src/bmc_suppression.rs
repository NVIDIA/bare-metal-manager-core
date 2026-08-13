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

//! Per-subsystem suppression requests for BMC MAC addresses.
//!
//! Writers key rows by `(bmc_mac_address, subsystem, source)`. Consumers that
//! only care whether a subsystem should skip a MAC query by subsystem alone so
//! any active source keeps the MAC suppressed.

use mac_address::MacAddress;
use model::bmc_suppression::{
    BmcSuppression, BmcSuppressionSource, BmcSuppressionSubsystem, NewBmcSuppression,
};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

/// Inserts or updates a suppression request for one source.
///
/// Repeated requests preserve the original request and acknowledgement
/// timestamps so retries do not restart an acknowledged handoff.
pub async fn upsert(
    txn: &mut PgConnection,
    input: &NewBmcSuppression,
) -> DatabaseResult<BmcSuppression> {
    const QUERY: &str = "INSERT INTO bmc_suppressions (
        bmc_mac_address,
        subsystem,
        source,
        reason
    ) VALUES ($1, $2, $3, $4)
    ON CONFLICT (bmc_mac_address, subsystem, source) DO UPDATE SET
        reason = EXCLUDED.reason
    RETURNING
        bmc_mac_address,
        subsystem,
        source,
        reason,
        requested_at,
        acknowledged_at";

    sqlx::query_as(QUERY)
        .bind(input.bmc_mac_address)
        .bind(input.subsystem)
        .bind(input.source)
        .bind(&input.reason)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns an active suppression request for one source, if one exists.
pub async fn find(
    db: impl DbReader<'_>,
    bmc_mac_address: MacAddress,
    subsystem: BmcSuppressionSubsystem,
    source: BmcSuppressionSource,
) -> DatabaseResult<Option<BmcSuppression>> {
    const QUERY: &str = "SELECT
        bmc_mac_address,
        subsystem,
        source,
        reason,
        requested_at,
        acknowledged_at
    FROM bmc_suppressions
    WHERE bmc_mac_address = $1 AND subsystem = $2 AND source = $3";

    sqlx::query_as(QUERY)
        .bind(bmc_mac_address)
        .bind(subsystem)
        .bind(source)
        .fetch_optional(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns every BMC suppression for `subsystem`, across all sources.
pub async fn find_all_by_subsystem(
    db: impl DbReader<'_>,
    subsystem: BmcSuppressionSubsystem,
) -> DatabaseResult<Vec<BmcSuppression>> {
    const QUERY: &str = "SELECT
        bmc_mac_address,
        subsystem,
        source,
        reason,
        requested_at,
        acknowledged_at
    FROM bmc_suppressions
    WHERE subsystem = $1
    ORDER BY bmc_mac_address, source";

    sqlx::query_as(QUERY)
        .bind(subsystem)
        .fetch_all(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Acknowledges pending suppression requests for the selected BMC MAC addresses.
///
/// Acknowledgements are not source-scoped: every matching subsystem row is
/// marked so each requester observes the handoff. Returns the distinct BMC MAC
/// addresses that had at least one previously unacknowledged row.
pub async fn acknowledge_unacknowledged(
    txn: &mut PgConnection,
    bmc_mac_addresses: &[MacAddress],
    subsystem: BmcSuppressionSubsystem,
) -> DatabaseResult<Vec<MacAddress>> {
    const QUERY: &str = "WITH updated AS (
        UPDATE bmc_suppressions
        SET acknowledged_at = statement_timestamp()
        WHERE bmc_mac_address = ANY($1)
            AND subsystem = $2
            AND acknowledged_at IS NULL
        RETURNING bmc_mac_address
    )
    SELECT DISTINCT bmc_mac_address FROM updated";

    sqlx::query_scalar(QUERY)
        .bind(bmc_mac_addresses)
        .bind(subsystem)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns whether a BMC MAC is suppressed for `subsystem` by any source.
pub async fn is_suppressed(
    db: impl DbReader<'_>,
    bmc_mac_address: MacAddress,
    subsystem: BmcSuppressionSubsystem,
) -> DatabaseResult<bool> {
    const QUERY: &str = "SELECT EXISTS(
        SELECT 1
        FROM bmc_suppressions
        WHERE bmc_mac_address = $1 AND subsystem = $2
    )";

    sqlx::query_scalar(QUERY)
        .bind(bmc_mac_address)
        .bind(subsystem)
        .fetch_one(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Records that `subsystem` has observed and applied suppression requests.
///
/// Acknowledgements are not source-scoped: every matching subsystem row is
/// marked. The lookup and timestamp write are atomic. The return value is
/// `true` when at least one suppression is active and `false` when no matching
/// request exists. Repeated acknowledgements preserve the first timestamp.
pub async fn acknowledge(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
    subsystem: BmcSuppressionSubsystem,
) -> DatabaseResult<bool> {
    const QUERY: &str = "UPDATE bmc_suppressions SET
        acknowledged_at = COALESCE(acknowledged_at, statement_timestamp())
    WHERE bmc_mac_address = $1 AND subsystem = $2";

    sqlx::query(QUERY)
        .bind(bmc_mac_address)
        .bind(subsystem)
        .execute(txn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Deletes one source's suppression request for a BMC MAC and subsystem.
///
/// Returns `true` when a row was removed. Other sources' rows are left intact
/// so the subsystem stays suppressed until every requester clears.
pub async fn delete(
    txn: &mut PgConnection,
    bmc_mac_address: MacAddress,
    subsystem: BmcSuppressionSubsystem,
    source: BmcSuppressionSource,
) -> DatabaseResult<bool> {
    const QUERY: &str = "DELETE FROM bmc_suppressions
        WHERE bmc_mac_address = $1 AND subsystem = $2 AND source = $3";

    sqlx::query(QUERY)
        .bind(bmc_mac_address)
        .bind(subsystem)
        .bind(source)
        .execute(txn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Deletes one source's suppression requests for a set of BMC MACs.
///
/// Returns the number of rows removed.
pub async fn delete_many(
    txn: &mut PgConnection,
    bmc_mac_addresses: &[MacAddress],
    subsystem: BmcSuppressionSubsystem,
    source: BmcSuppressionSource,
) -> DatabaseResult<u64> {
    const QUERY: &str = "DELETE FROM bmc_suppressions
        WHERE bmc_mac_address = ANY($1) AND subsystem = $2 AND source = $3";

    sqlx::query(QUERY)
        .bind(bmc_mac_addresses)
        .bind(subsystem)
        .bind(source)
        .execute(txn)
        .await
        .map(|result| result.rows_affected())
        .map_err(|e| DatabaseError::query(QUERY, e))
}

#[cfg(test)]
mod tests {
    use mac_address::MacAddress;
    use model::bmc_suppression::{
        BmcSuppressionSource, BmcSuppressionSubsystem, NewBmcSuppression,
    };

    use super::{
        acknowledge, acknowledge_unacknowledged, delete, delete_many, find, find_all_by_subsystem,
        is_suppressed, upsert,
    };

    const SITE_EXPLORER: BmcSuppressionSubsystem = BmcSuppressionSubsystem::SiteExplorer;
    const DHCP: BmcSuppressionSubsystem = BmcSuppressionSubsystem::Dhcp;
    const DECOMMISSIONING: BmcSuppressionSource = BmcSuppressionSource::Decommissioning;

    fn mac(last: u8) -> MacAddress {
        MacAddress::new([0x02, 0x00, 0x00, 0x00, 0x00, last])
    }

    fn upsert_input(
        last: u8,
        subsystem: BmcSuppressionSubsystem,
        reason: &str,
    ) -> NewBmcSuppression {
        NewBmcSuppression {
            bmc_mac_address: mac(last),
            subsystem,
            source: DECOMMISSIONING,
            reason: reason.to_string(),
        }
    }

    #[crate::sqlx_test]
    async fn subsystems_are_independent(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        upsert(
            txn.as_mut(),
            &upsert_input(1, SITE_EXPLORER, "decommissioning"),
        )
        .await
        .unwrap();
        upsert(txn.as_mut(), &upsert_input(2, DHCP, "decommissioning"))
            .await
            .unwrap();
        for subsystem in [SITE_EXPLORER, DHCP] {
            upsert(txn.as_mut(), &upsert_input(3, subsystem, "decommissioning"))
                .await
                .unwrap();
        }

        assert_eq!(
            find_all_by_subsystem(txn.as_mut(), SITE_EXPLORER)
                .await
                .unwrap()
                .into_iter()
                .map(|suppression| suppression.bmc_mac_address)
                .collect::<Vec<_>>(),
            vec![mac(1), mac(3)],
        );
        assert_eq!(
            find_all_by_subsystem(txn.as_mut(), DHCP)
                .await
                .unwrap()
                .into_iter()
                .map(|suppression| suppression.bmc_mac_address)
                .collect::<Vec<_>>(),
            vec![mac(2), mac(3)],
        );
        assert!(!is_suppressed(txn.as_mut(), mac(1), DHCP).await.unwrap());
        assert!(
            is_suppressed(txn.as_mut(), mac(3), SITE_EXPLORER)
                .await
                .unwrap()
        );
        assert!(!is_suppressed(txn.as_mut(), mac(4), DHCP).await.unwrap());
    }

    #[crate::sqlx_test]
    async fn acknowledgements_are_scoped_to_subsystem(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        for (last, subsystem, other_subsystem) in
            [(1, SITE_EXPLORER, DHCP), (2, DHCP, SITE_EXPLORER)]
        {
            upsert(
                txn.as_mut(),
                &upsert_input(last, subsystem, "decommissioning"),
            )
            .await
            .unwrap();

            assert!(
                !acknowledge(txn.as_mut(), mac(last), other_subsystem)
                    .await
                    .unwrap()
            );
            assert!(
                find(txn.as_mut(), mac(last), other_subsystem, DECOMMISSIONING)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                acknowledge(txn.as_mut(), mac(last), subsystem)
                    .await
                    .unwrap()
            );
            assert!(
                find(txn.as_mut(), mac(last), subsystem, DECOMMISSIONING)
                    .await
                    .unwrap()
                    .unwrap()
                    .acknowledged_at
                    .is_some()
            );
        }
    }

    #[crate::sqlx_test]
    async fn acknowledge_unacknowledged_is_batched_and_idempotent(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        for (last, subsystem) in [(1, SITE_EXPLORER), (2, DHCP), (3, SITE_EXPLORER)] {
            upsert(
                txn.as_mut(),
                &upsert_input(last, subsystem, "decommissioning"),
            )
            .await
            .unwrap();
        }

        let acknowledged =
            acknowledge_unacknowledged(txn.as_mut(), &[mac(1), mac(3), mac(4)], SITE_EXPLORER)
                .await
                .unwrap();
        assert_eq!(acknowledged.len(), 2);
        assert!(acknowledged.contains(&mac(1)));
        assert!(acknowledged.contains(&mac(3)));
        assert!(
            find(txn.as_mut(), mac(1), SITE_EXPLORER, DECOMMISSIONING)
                .await
                .unwrap()
                .unwrap()
                .acknowledged_at
                .is_some()
        );
        assert!(
            find(txn.as_mut(), mac(2), DHCP, DECOMMISSIONING)
                .await
                .unwrap()
                .unwrap()
                .acknowledged_at
                .is_none()
        );
        assert!(
            acknowledge_unacknowledged(txn.as_mut(), &[mac(1), mac(3)], SITE_EXPLORER)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[crate::sqlx_test]
    async fn repeated_requests_and_acknowledgements_are_idempotent(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        upsert(
            txn.as_mut(),
            &upsert_input(1, SITE_EXPLORER, "decommissioning"),
        )
        .await
        .unwrap();
        assert!(
            acknowledge(txn.as_mut(), mac(1), SITE_EXPLORER)
                .await
                .unwrap()
        );
        let initial = find(txn.as_mut(), mac(1), SITE_EXPLORER, DECOMMISSIONING)
            .await
            .unwrap()
            .unwrap();

        assert!(
            acknowledge(txn.as_mut(), mac(1), SITE_EXPLORER)
                .await
                .unwrap()
        );
        let repeated = find(txn.as_mut(), mac(1), SITE_EXPLORER, DECOMMISSIONING)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(repeated, initial);

        let retried = upsert(
            txn.as_mut(),
            &upsert_input(1, SITE_EXPLORER, "decommissioning retry"),
        )
        .await
        .unwrap();
        assert_eq!(retried.requested_at, initial.requested_at);
        assert_eq!(retried.acknowledged_at, initial.acknowledged_at);

        assert!(
            delete(txn.as_mut(), mac(1), SITE_EXPLORER, DECOMMISSIONING)
                .await
                .unwrap()
        );
        let recreated = upsert(
            txn.as_mut(),
            &upsert_input(1, SITE_EXPLORER, "new decommissioning request"),
        )
        .await
        .unwrap();
        assert!(recreated.acknowledged_at.is_none());
    }

    #[crate::sqlx_test]
    async fn delete_helpers_are_scoped_to_subsystem_and_source(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        for last in 1..=3 {
            for subsystem in [SITE_EXPLORER, DHCP] {
                upsert(
                    txn.as_mut(),
                    &upsert_input(last, subsystem, "decommissioning"),
                )
                .await
                .unwrap();
            }
        }

        assert!(
            delete(txn.as_mut(), mac(1), SITE_EXPLORER, DECOMMISSIONING)
                .await
                .unwrap()
        );
        assert!(
            !delete(txn.as_mut(), mac(1), SITE_EXPLORER, DECOMMISSIONING)
                .await
                .unwrap()
        );
        assert!(
            find(txn.as_mut(), mac(1), DHCP, DECOMMISSIONING)
                .await
                .unwrap()
                .is_some()
        );

        assert_eq!(
            delete_many(
                txn.as_mut(),
                &[mac(2), mac(3), mac(4)],
                SITE_EXPLORER,
                DECOMMISSIONING
            )
            .await
            .unwrap(),
            2
        );
        assert!(
            find(txn.as_mut(), mac(2), SITE_EXPLORER, DECOMMISSIONING)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            find(txn.as_mut(), mac(2), DHCP, DECOMMISSIONING)
                .await
                .unwrap()
                .is_some()
        );
    }
}
