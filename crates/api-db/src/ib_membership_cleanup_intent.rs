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

//! Durable requests to remove exact GUID memberships from an IB fabric.

use model::ib_partition::PartitionKey;
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

#[derive(Clone, Debug, Eq, PartialEq)]
struct IbMembershipCleanupIntent {
    fabric: String,
    pkey: PartitionKey,
    guid: String,
}

const LIST_BATCH_SIZE: i64 = 100;

/// Ensures that an exact desired-absence membership is durable.
async fn create(txn: &mut PgConnection, intent: &IbMembershipCleanupIntent) -> DatabaseResult<()> {
    const QUERY: &str = "INSERT INTO ib_membership_cleanup_intents (fabric, pkey, guid)
        VALUES ($1, $2, $3)
        ON CONFLICT (fabric, pkey, guid) DO NOTHING";

    sqlx::query(QUERY)
        .bind(&intent.fabric)
        .bind(i32::from(u16::from(intent.pkey)))
        .bind(&intent.guid)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns the next bounded batch in deterministic tuple order.
async fn list_batch(
    db: impl DbReader<'_>,
    after: Option<&IbMembershipCleanupIntent>,
) -> DatabaseResult<Vec<IbMembershipCleanupIntent>> {
    const QUERY: &str = "SELECT fabric, pkey, guid
        FROM ib_membership_cleanup_intents
        WHERE $1::text IS NULL
           OR (fabric, pkey, guid) > ($1::text, $2::integer, $3::text)
        ORDER BY fabric, pkey, guid
        LIMIT $4";

    let after_fabric = after.map(|intent| intent.fabric.as_str());
    let after_pkey = after.map(|intent| i32::from(u16::from(intent.pkey)));
    let after_guid = after.map(|intent| intent.guid.as_str());

    let rows: Vec<(String, i32, String)> = sqlx::query_as(QUERY)
        .bind(after_fabric)
        .bind(after_pkey)
        .bind(after_guid)
        .bind(LIST_BATCH_SIZE)
        .fetch_all(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))?;

    rows.into_iter()
        .map(|(fabric, pkey, guid)| {
            let pkey = u16::try_from(pkey)
                .ok()
                .and_then(|pkey| PartitionKey::try_from(pkey).ok())
                .ok_or_else(|| {
                    DatabaseError::internal(format!(
                        "ib_membership_cleanup_intents contains invalid pkey {pkey}"
                    ))
                })?;
            Ok(IbMembershipCleanupIntent { fabric, pkey, guid })
        })
        .collect()
}

/// Supersedes exactly one intent when the same membership becomes desired live
/// state. Callers must establish that live presence in the same serialized
/// transition; a successful cleanup alone must never remove the intent.
async fn supersede_for_live_presence(
    txn: &mut PgConnection,
    intent: &IbMembershipCleanupIntent,
) -> DatabaseResult<bool> {
    const QUERY: &str = "DELETE FROM ib_membership_cleanup_intents
        WHERE fabric = $1 AND pkey = $2 AND guid = $3";

    sqlx::query(QUERY)
        .bind(&intent.fabric)
        .bind(i32::from(u16::from(intent.pkey)))
        .bind(&intent.guid)
        .execute(txn)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(|e| DatabaseError::query(QUERY, e))
}

#[cfg(test)]
mod tests {
    use model::ib_partition::PartitionKey;

    use super::{
        IbMembershipCleanupIntent, LIST_BATCH_SIZE, create, list_batch, supersede_for_live_presence,
    };

    fn intent(fabric: &str, pkey: u16, guid: &str) -> IbMembershipCleanupIntent {
        IbMembershipCleanupIntent {
            fabric: fabric.to_string(),
            pkey: PartitionKey::try_from(pkey).expect("test PKey must be valid"),
            guid: guid.to_string(),
        }
    }

    #[crate::sqlx_test]
    async fn migration_enforces_the_pkey_range(pool: sqlx::PgPool) {
        for (pkey, should_succeed) in [(0, true), (32767, true), (-1, false), (32768, false)] {
            let result = sqlx::query(
                "INSERT INTO ib_membership_cleanup_intents (fabric, pkey, guid) \
                 VALUES ('fabric-a', $1, $1::text)",
            )
            .bind(pkey)
            .execute(&pool)
            .await;
            assert_eq!(result.is_ok(), should_succeed, "PKey: {pkey}");
        }
    }

    #[crate::sqlx_test]
    async fn repeated_create_is_idempotent(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        let intent = intent("fabric-a", 0x101, "guid-a");

        create(txn.as_mut(), &intent).await.unwrap();
        create(txn.as_mut(), &intent).await.unwrap();

        assert_eq!(list_batch(txn.as_mut(), None).await.unwrap(), vec![intent]);
    }

    #[crate::sqlx_test]
    async fn intent_outlives_its_machine_and_instance(pool: sqlx::PgPool) {
        let intent = intent("fabric-a", 0x101, "guid-a");
        let mut txn = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO machines (id, dpf, infiniband_status_observation) \
             VALUES ( \
                 'cleanup-intent-machine', \
                 '{}'::jsonb, \
                 '{\"observed_at\":\"2026-08-19T00:00:00Z\",\"ib_interfaces\":[{\"guid\":\"guid-a\",\"lid\":1,\"fabric_id\":\"fabric-a\",\"associated_pkeys\":[\"0x101\"],\"associated_partition_ids\":[]}]}'::jsonb \
             )",
        )
        .execute(txn.as_mut())
        .await
        .unwrap();
        sqlx::query("INSERT INTO instances (machine_id) VALUES ('cleanup-intent-machine')")
            .execute(txn.as_mut())
            .await
            .unwrap();
        create(txn.as_mut(), &intent).await.unwrap();
        txn.commit().await.unwrap();

        let mut txn = pool.begin().await.unwrap();
        sqlx::query("DELETE FROM instances WHERE machine_id = 'cleanup-intent-machine'")
            .execute(txn.as_mut())
            .await
            .unwrap();
        sqlx::query("DELETE FROM machines WHERE id = 'cleanup-intent-machine'")
            .execute(txn.as_mut())
            .await
            .unwrap();
        txn.commit().await.unwrap();

        assert_eq!(list_batch(&pool, None).await.unwrap(), vec![intent]);
    }

    #[crate::sqlx_test]
    async fn live_presence_supersedes_only_the_exact_tuple(pool: sqlx::PgPool) {
        let exact = intent("fabric-a", 0x101, "guid-a");
        let retained = [
            intent("fabric-b", 0x101, "guid-a"),
            intent("fabric-a", 0x102, "guid-a"),
            intent("fabric-a", 0x101, "guid-b"),
        ];
        let mut txn = pool.begin().await.unwrap();
        for candidate in std::iter::once(&exact).chain(&retained) {
            create(txn.as_mut(), candidate).await.unwrap();
        }

        assert!(
            supersede_for_live_presence(txn.as_mut(), &exact)
                .await
                .unwrap()
        );
        assert!(
            !supersede_for_live_presence(txn.as_mut(), &exact)
                .await
                .unwrap()
        );

        assert_eq!(
            list_batch(txn.as_mut(), None).await.unwrap(),
            vec![
                retained[2].clone(),
                retained[1].clone(),
                retained[0].clone()
            ],
        );
    }

    #[crate::sqlx_test]
    async fn list_uses_bounded_keyset_batches(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        for index in 0..=LIST_BATCH_SIZE {
            create(
                txn.as_mut(),
                &intent("fabric-a", 0x101, &format!("guid-{index:03}")),
            )
            .await
            .unwrap();
        }

        let first = list_batch(txn.as_mut(), None).await.unwrap();
        assert_eq!(first.len(), LIST_BATCH_SIZE as usize);
        let second = list_batch(txn.as_mut(), first.last()).await.unwrap();
        assert_eq!(second, vec![intent("fabric-a", 0x101, "guid-100")]);
    }
}
