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

//! Durable markers for work carbide still owes an external system per machine,
//! and a bounded history of the work already done.

use carbide_uuid::machine::MachineId;
use model::machine_pending_action::{MachinePendingAction, MachinePendingActionKind};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

/// Records that `kind` is owed for `machine_id`, returning the outstanding row.
///
/// Re-requesting an action that is already outstanding is a no-op write that
/// preserves the original `requested_at`, so the returned timestamp is how long
/// the machine has been waiting. Requesting one that was previously completed
/// starts a new row, leaving the earlier completion in the history.
pub async fn request(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    kind: MachinePendingActionKind,
) -> DatabaseResult<MachinePendingAction> {
    // The conflict target is the partial unique index over outstanding rows, so
    // only an unfinished request collides. `kind` already equals `EXCLUDED.kind`
    // there; assigning it is the way to make this a `DO UPDATE` -- which returns
    // the existing row -- without changing any column.
    const QUERY: &str = "INSERT INTO machine_pending_actions (
        machine_id,
        kind
    ) VALUES ($1, $2)
    ON CONFLICT (machine_id, kind) WHERE completed_at IS NULL DO UPDATE SET
        kind = EXCLUDED.kind
    RETURNING machine_id, kind, requested_at, completed_at";

    sqlx::query_as(QUERY)
        .bind(machine_id)
        .bind(kind)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns whether `kind` is still owed for `machine_id`.
pub async fn is_outstanding(
    db: impl DbReader<'_>,
    machine_id: &MachineId,
    kind: MachinePendingActionKind,
) -> DatabaseResult<bool> {
    const QUERY: &str = "SELECT EXISTS(
        SELECT 1
        FROM machine_pending_actions
        WHERE machine_id = $1 AND kind = $2 AND completed_at IS NULL
    )";

    sqlx::query_scalar(QUERY)
        .bind(machine_id)
        .bind(kind)
        .fetch_one(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Marks an outstanding action as done, which callers must do only once the work
/// has actually succeeded.
///
/// Returns `true` when an outstanding row was completed. Completing work that
/// was skipped rather than finished drops the signal: nothing re-requests it
/// until the external system independently re-triggers, which it may never do.
pub async fn complete(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    kind: MachinePendingActionKind,
) -> DatabaseResult<bool> {
    const QUERY: &str = "UPDATE machine_pending_actions
        SET completed_at = statement_timestamp()
        WHERE machine_id = $1 AND kind = $2 AND completed_at IS NULL";

    sqlx::query(QUERY)
        .bind(machine_id)
        .bind(kind)
        .execute(txn)
        .await
        .map(|result| result.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(QUERY, e))
}

/// Returns a machine's actions, newest first.
///
/// Any outstanding action sorts first, followed by the retained completions.
/// History is capped per machine by the database, so this is bounded.
pub async fn find_all_for_machine(
    db: impl DbReader<'_>,
    machine_id: &MachineId,
) -> DatabaseResult<Vec<MachinePendingAction>> {
    const QUERY: &str = "SELECT
        machine_id,
        kind,
        requested_at,
        completed_at
    FROM machine_pending_actions
    WHERE machine_id = $1
    ORDER BY id DESC";

    sqlx::query_as(QUERY)
        .bind(machine_id)
        .fetch_all(db)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

#[cfg(test)]
mod tests {
    use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
    use model::machine_pending_action::MachinePendingActionKind;
    use sqlx::{PgConnection, PgPool};

    use super::{complete, find_all_for_machine, is_outstanding, request};

    const DPU_SERVICE_SYNC: MachinePendingActionKind = MachinePendingActionKind::DpuServiceSync;

    fn machine_id(marker: u8) -> MachineId {
        let mut hardware_id = [0u8; 32];
        hardware_id[0] = marker;
        MachineId::new(
            MachineIdSource::ProductBoardChassisSerial,
            hardware_id,
            MachineType::Host,
        )
    }

    async fn seed_machine(
        txn: &mut PgConnection,
        machine_id: &MachineId,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"INSERT INTO machines (id, dpf)
               VALUES ($1, '{"enabled": false, "used_for_ingestion": false}'::jsonb)"#,
        )
        .bind(machine_id)
        .execute(txn)
        .await?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn requests_are_scoped_to_one_machine(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let requested = machine_id(1);
        let untouched = machine_id(2);
        seed_machine(txn.as_mut(), &requested).await?;
        seed_machine(txn.as_mut(), &untouched).await?;

        assert!(!is_outstanding(txn.as_mut(), &requested, DPU_SERVICE_SYNC).await?);

        let action = request(txn.as_mut(), &requested, DPU_SERVICE_SYNC).await?;
        assert_eq!(action.machine_id, requested);
        assert_eq!(action.kind, DPU_SERVICE_SYNC);
        assert!(action.is_outstanding());

        assert!(is_outstanding(txn.as_mut(), &requested, DPU_SERVICE_SYNC).await?);
        assert!(!is_outstanding(txn.as_mut(), &untouched, DPU_SERVICE_SYNC).await?);
        assert!(
            find_all_for_machine(txn.as_mut(), &untouched)
                .await?
                .is_empty()
        );

        Ok(())
    }

    #[crate::sqlx_test]
    async fn re_requesting_outstanding_work_preserves_the_original_request_time(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(1);
        seed_machine(txn.as_mut(), &machine_id).await?;

        let first = request(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?;
        let repeated = request(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?;
        assert_eq!(
            repeated, first,
            "a re-request must not restart the pending clock or queue a duplicate"
        );
        assert_eq!(
            find_all_for_machine(txn.as_mut(), &machine_id).await?.len(),
            1
        );

        Ok(())
    }

    #[crate::sqlx_test]
    async fn completing_retains_the_record_and_reopens_the_slot(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(1);
        seed_machine(txn.as_mut(), &machine_id).await?;

        assert!(
            !complete(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?,
            "completing work that was never requested must not invent a record"
        );

        let requested = request(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?;
        assert!(complete(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?);
        assert!(!is_outstanding(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?);
        assert!(
            !complete(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?,
            "completion is not repeatable"
        );

        let history = find_all_for_machine(txn.as_mut(), &machine_id).await?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].requested_at, requested.requested_at);
        assert!(history[0].completed_at.is_some());

        // A later request is a new wait, and does not disturb the completed row.
        let second = request(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?;
        assert!(second.is_outstanding());
        let history = find_all_for_machine(txn.as_mut(), &machine_id).await?;
        assert_eq!(history.len(), 2);
        assert!(history[0].is_outstanding(), "newest first");
        assert!(history[1].completed_at.is_some());

        Ok(())
    }

    #[crate::sqlx_test]
    async fn history_is_capped_per_machine_without_evicting_outstanding_work(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let busy = machine_id(1);
        let quiet = machine_id(2);
        seed_machine(txn.as_mut(), &busy).await?;
        seed_machine(txn.as_mut(), &quiet).await?;

        let quiet_first = request(txn.as_mut(), &quiet, DPU_SERVICE_SYNC).await?;
        assert!(complete(txn.as_mut(), &quiet, DPU_SERVICE_SYNC).await?);

        for _ in 0..25 {
            request(txn.as_mut(), &busy, DPU_SERVICE_SYNC).await?;
            assert!(complete(txn.as_mut(), &busy, DPU_SERVICE_SYNC).await?);
        }
        // Outstanding again, on top of an already-full history.
        let outstanding = request(txn.as_mut(), &busy, DPU_SERVICE_SYNC).await?;

        let history = find_all_for_machine(txn.as_mut(), &busy).await?;
        assert_eq!(history.len(), 21, "20 completions plus the outstanding row");
        assert_eq!(
            history
                .iter()
                .filter(|action| action.is_outstanding())
                .count(),
            1
        );
        assert_eq!(history[0].requested_at, outstanding.requested_at);
        assert!(
            is_outstanding(txn.as_mut(), &busy, DPU_SERVICE_SYNC).await?,
            "retention must never evict the outstanding marker"
        );

        // Trimming one machine's history leaves another machine's alone.
        let quiet_history = find_all_for_machine(txn.as_mut(), &quiet).await?;
        assert_eq!(quiet_history.len(), 1);
        assert_eq!(quiet_history[0].requested_at, quiet_first.requested_at);

        Ok(())
    }

    #[crate::sqlx_test]
    async fn deleting_the_machine_clears_its_actions(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = machine_id(1);
        seed_machine(txn.as_mut(), &machine_id).await?;
        request(txn.as_mut(), &machine_id, DPU_SERVICE_SYNC).await?;

        // The FK cascades, which is why `cleanup_machine_by_id` needs no entry
        // for this table.
        sqlx::query("DELETE FROM machines WHERE id = $1")
            .bind(machine_id)
            .execute(txn.as_mut())
            .await?;
        assert!(
            find_all_for_machine(txn.as_mut(), &machine_id)
                .await?
                .is_empty()
        );

        Ok(())
    }
}
