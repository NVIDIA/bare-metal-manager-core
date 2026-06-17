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

use carbide_uuid::machine_validation::{
    MachineValidationAttemptId, MachineValidationId, MachineValidationRunItemId,
};
use model::machine_validation::{
    MachineValidationAttempt, MachineValidationAttemptState, MachineValidationResult,
    MachineValidationRunItem, MachineValidationRunItemState, MachineValidationTest,
};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult, machine_validation_suites};

const DEFAULT_TIMEOUT_SECONDS: i64 = 7200;
// M1 persists Scout's existing sequential result stream as a single attempt per test.
// Retry-aware events will need to carry attempt identity before this can vary.
const INITIAL_ATTEMPT_NUMBER: i32 = 1;
const SUMMARY_LIMIT: usize = 4096;

pub async fn materialize_run_plan(
    txn: &mut PgConnection,
    run_id: &MachineValidationId,
    context: &str,
    selected_tests: &[MachineValidationTest],
) -> DatabaseResult<()> {
    for (order_index, test) in selected_tests.iter().enumerate() {
        let order_index = i32::try_from(order_index).map_err(|_| {
            DatabaseError::InvalidArgument(
                "machine validation run has too many selected tests".to_string(),
            )
        })?;
        let run_item_id =
            upsert_run_item_from_test(txn, run_id, context, test, order_index).await?;
        upsert_pending_attempt(txn, &run_item_id, test).await?;
    }

    Ok(())
}

pub async fn find_run_items_by_run_id(
    txn: impl DbReader<'_>,
    run_id: &MachineValidationId,
) -> DatabaseResult<Vec<MachineValidationRunItem>> {
    const QUERY: &str = "
        SELECT
            run_item.*,
            current_attempt.id AS current_attempt_id
        FROM machine_validation_run_items run_item
        LEFT JOIN LATERAL (
            SELECT id
            FROM machine_validation_attempts attempt
            WHERE attempt.run_item_id=run_item.id
            ORDER BY attempt.attempt_number DESC
            LIMIT 1
        ) current_attempt ON true
        WHERE run_item.run_id=$1
        ORDER BY run_item.order_index, run_item.display_name";

    sqlx::query_as::<_, MachineValidationRunItem>(QUERY)
        .bind(run_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

pub async fn find_run_item_ids_by_run_id(
    txn: impl DbReader<'_>,
    run_id: &MachineValidationId,
) -> DatabaseResult<Vec<MachineValidationRunItemId>> {
    const QUERY: &str = "
        SELECT id
        FROM machine_validation_run_items
        WHERE run_id=$1
        ORDER BY order_index, display_name";

    sqlx::query_scalar::<_, MachineValidationRunItemId>(QUERY)
        .bind(run_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

pub async fn find_run_items_by_ids(
    txn: impl DbReader<'_>,
    ids: &[MachineValidationRunItemId],
) -> DatabaseResult<Vec<MachineValidationRunItem>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    const QUERY: &str = "
        SELECT
            run_item.*,
            current_attempt.id AS current_attempt_id
        FROM machine_validation_run_items run_item
        LEFT JOIN LATERAL (
            SELECT id
            FROM machine_validation_attempts attempt
            WHERE attempt.run_item_id=run_item.id
            ORDER BY attempt.attempt_number DESC
            LIMIT 1
        ) current_attempt ON true
        WHERE run_item.id=ANY($1)
        ORDER BY run_item.order_index, run_item.display_name";

    sqlx::query_as::<_, MachineValidationRunItem>(QUERY)
        .bind(ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

pub async fn find_attempt_by_id(
    txn: impl DbReader<'_>,
    id: &MachineValidationAttemptId,
) -> DatabaseResult<MachineValidationAttempt> {
    const QUERY: &str = "SELECT * FROM machine_validation_attempts WHERE id=$1";

    sqlx::query_as::<_, MachineValidationAttempt>(QUERY)
        .bind(id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "machine_validation_attempt",
            id: id.to_string(),
        })
}

pub async fn find_attempts_by_run_item_id(
    txn: impl DbReader<'_>,
    run_item_id: &MachineValidationRunItemId,
) -> DatabaseResult<Vec<MachineValidationAttempt>> {
    const QUERY: &str = "
        SELECT * FROM machine_validation_attempts
        WHERE run_item_id=$1
        ORDER BY attempt_number";

    sqlx::query_as::<_, MachineValidationAttempt>(QUERY)
        .bind(run_item_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

pub async fn record_result(
    txn: &mut PgConnection,
    result: &MachineValidationResult,
) -> DatabaseResult<bool> {
    let run_item_id = upsert_run_item_from_result(txn, result).await?;
    let state = state_from_result(result);
    let stdout_summary = truncate_summary(&result.stdout);
    let stderr_summary = truncate_summary(&result.stderr);
    let failure_classification =
        (state == MachineValidationAttemptState::Failed).then(|| "CommandFailed".to_string());

    let updated_first_terminal = update_pending_attempt_from_result(
        txn,
        &run_item_id,
        result,
        &state,
        stdout_summary.as_deref(),
        stderr_summary.as_deref(),
        failure_classification.as_deref(),
    )
    .await?;

    let first_terminal = if updated_first_terminal {
        true
    } else {
        insert_terminal_attempt_from_result(
            txn,
            &run_item_id,
            result,
            &state,
            stdout_summary.as_deref(),
            stderr_summary.as_deref(),
            failure_classification.as_deref(),
        )
        .await?
    };

    if first_terminal {
        update_run_item_from_result(
            txn,
            &run_item_id,
            result,
            &state,
            stdout_summary.as_deref(),
            stderr_summary.as_deref(),
        )
        .await?;
    }

    Ok(first_terminal)
}

async fn upsert_run_item_from_test(
    txn: &mut PgConnection,
    run_id: &MachineValidationId,
    context: &str,
    test: &MachineValidationTest,
    order_index: i32,
) -> DatabaseResult<MachineValidationRunItemId> {
    const QUERY: &str = "
        WITH upserted AS (
            INSERT INTO machine_validation_run_items (
                id,
                run_id,
                test_id,
                test_version,
                display_name,
                context,
                component,
                state,
                order_index,
                attempt,
                max_attempts,
                timeout_seconds
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, 1, $10)
            ON CONFLICT (run_id, test_id) DO UPDATE
            SET
                test_version=EXCLUDED.test_version,
                display_name=EXCLUDED.display_name,
                context=EXCLUDED.context,
                component=EXCLUDED.component,
                order_index=EXCLUDED.order_index,
                max_attempts=EXCLUDED.max_attempts,
                timeout_seconds=EXCLUDED.timeout_seconds
            WHERE machine_validation_run_items.state IN ('Pending', 'Running')
            RETURNING id
        )
        SELECT id FROM upserted
        UNION ALL
        SELECT id
        FROM machine_validation_run_items
        WHERE run_id=$2 AND test_id=$3
        LIMIT 1";

    let id = MachineValidationRunItemId::new();
    sqlx::query_scalar::<_, MachineValidationRunItemId>(QUERY)
        .bind(id)
        .bind(run_id)
        .bind(&test.test_id)
        .bind(test.version.version_string())
        .bind(&test.name)
        .bind(context)
        .bind(test.components.first())
        .bind(MachineValidationRunItemState::Pending.to_string())
        .bind(order_index)
        .bind(test.timeout.unwrap_or(DEFAULT_TIMEOUT_SECONDS))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

async fn upsert_pending_attempt(
    txn: &mut PgConnection,
    run_item_id: &MachineValidationRunItemId,
    test: &MachineValidationTest,
) -> DatabaseResult<()> {
    const QUERY: &str = "
        INSERT INTO machine_validation_attempts (
            id,
            run_item_id,
            attempt_number,
            state,
            command,
            args,
            container_image,
            execute_in_host
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (run_item_id, attempt_number) DO UPDATE
        SET
            command=EXCLUDED.command,
            args=EXCLUDED.args,
            container_image=EXCLUDED.container_image,
            execute_in_host=EXCLUDED.execute_in_host
        WHERE machine_validation_attempts.state IN ('Pending', 'Running')";

    sqlx::query(QUERY)
        .bind(MachineValidationAttemptId::new())
        .bind(run_item_id)
        .bind(INITIAL_ATTEMPT_NUMBER)
        .bind(MachineValidationAttemptState::Pending.to_string())
        .bind(&test.command)
        .bind(&test.args)
        .bind(test.img_name.as_ref())
        .bind(test.execute_in_host)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))?;
    Ok(())
}

async fn upsert_run_item_from_result(
    txn: &mut PgConnection,
    result: &MachineValidationResult,
) -> DatabaseResult<MachineValidationRunItemId> {
    const QUERY: &str = "
        WITH upserted AS (
            INSERT INTO machine_validation_run_items (
                id,
                run_id,
                test_id,
                display_name,
                context,
                state,
                order_index,
                attempt,
                max_attempts,
                timeout_seconds
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6,
                COALESCE((SELECT MAX(order_index) + 1 FROM machine_validation_run_items WHERE run_id=$2), 0),
                0,
                1,
                $7
            )
            ON CONFLICT (run_id, test_id) DO UPDATE
            SET
                display_name=EXCLUDED.display_name,
                context=EXCLUDED.context
            WHERE machine_validation_run_items.state IN ('Pending', 'Running')
            RETURNING id
        )
        SELECT id FROM upserted
        UNION ALL
        SELECT id
        FROM machine_validation_run_items
        WHERE run_id=$2 AND test_id=$3
        LIMIT 1";

    sqlx::query_scalar::<_, MachineValidationRunItemId>(QUERY)
        .bind(MachineValidationRunItemId::new())
        .bind(result.validation_id)
        .bind(result_test_id(result))
        .bind(&result.name)
        .bind(&result.context)
        .bind(MachineValidationRunItemState::Pending.to_string())
        .bind(DEFAULT_TIMEOUT_SECONDS)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

async fn update_pending_attempt_from_result(
    txn: &mut PgConnection,
    run_item_id: &MachineValidationRunItemId,
    result: &MachineValidationResult,
    state: &MachineValidationAttemptState,
    stdout_summary: Option<&str>,
    stderr_summary: Option<&str>,
    failure_classification: Option<&str>,
) -> DatabaseResult<bool> {
    const QUERY: &str = "
        UPDATE machine_validation_attempts
        SET
            state=$3,
            command=$4,
            args=$5,
            exit_code=$6,
            failure_classification=$7,
            started_at=$8,
            ended_at=$9,
            last_heartbeat_at=$9,
            stdout_summary=$10,
            stderr_summary=$11
        WHERE run_item_id=$1
        AND attempt_number=$2
        AND state IN ('Pending', 'Running')
        RETURNING id";

    let updated = sqlx::query_scalar::<_, MachineValidationAttemptId>(QUERY)
        .bind(run_item_id)
        .bind(INITIAL_ATTEMPT_NUMBER)
        .bind(state.to_string())
        .bind(&result.command)
        .bind(&result.args)
        .bind(result.exit_code)
        .bind(failure_classification)
        .bind(result.start_time)
        .bind(result.end_time)
        .bind(stdout_summary)
        .bind(stderr_summary)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))?;
    Ok(updated.is_some())
}

async fn insert_terminal_attempt_from_result(
    txn: &mut PgConnection,
    run_item_id: &MachineValidationRunItemId,
    result: &MachineValidationResult,
    state: &MachineValidationAttemptState,
    stdout_summary: Option<&str>,
    stderr_summary: Option<&str>,
    failure_classification: Option<&str>,
) -> DatabaseResult<bool> {
    const QUERY: &str = "
        INSERT INTO machine_validation_attempts (
            id,
            run_item_id,
            attempt_number,
            state,
            command,
            args,
            exit_code,
            failure_classification,
            started_at,
            ended_at,
            last_heartbeat_at,
            stdout_summary,
            stderr_summary
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11, $12)
        ON CONFLICT (run_item_id, attempt_number) DO NOTHING
        RETURNING id";

    let inserted = sqlx::query_scalar::<_, MachineValidationAttemptId>(QUERY)
        .bind(MachineValidationAttemptId::new())
        .bind(run_item_id)
        .bind(INITIAL_ATTEMPT_NUMBER)
        .bind(state.to_string())
        .bind(&result.command)
        .bind(&result.args)
        .bind(result.exit_code)
        .bind(failure_classification)
        .bind(result.start_time)
        .bind(result.end_time)
        .bind(stdout_summary)
        .bind(stderr_summary)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))?;
    Ok(inserted.is_some())
}

async fn update_run_item_from_result(
    txn: &mut PgConnection,
    run_item_id: &MachineValidationRunItemId,
    result: &MachineValidationResult,
    state: &MachineValidationAttemptState,
    stdout_summary: Option<&str>,
    stderr_summary: Option<&str>,
) -> DatabaseResult<()> {
    const QUERY: &str = "
        UPDATE machine_validation_run_items
        SET
            state=$2,
            attempt=$3,
            started_at=$4,
            ended_at=$5,
            last_heartbeat_at=$5,
            skip_reason=$6,
            failure_reason=$7
        WHERE id=$1";

    let skip_reason = (*state == MachineValidationAttemptState::Skipped)
        .then(|| stdout_summary.or(stderr_summary).unwrap_or_default());
    let failure_reason = (*state == MachineValidationAttemptState::Failed)
        .then(|| stderr_summary.or(stdout_summary).unwrap_or_default());

    sqlx::query(QUERY)
        .bind(run_item_id)
        .bind(run_item_state(state).to_string())
        .bind(INITIAL_ATTEMPT_NUMBER)
        .bind(result.start_time)
        .bind(result.end_time)
        .bind(skip_reason)
        .bind(failure_reason)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))?;
    Ok(())
}

fn result_test_id(result: &MachineValidationResult) -> String {
    result
        .test_id
        .clone()
        .unwrap_or_else(|| machine_validation_suites::generate_test_id(&result.name))
}

fn state_from_result(result: &MachineValidationResult) -> MachineValidationAttemptState {
    if result.exit_code == 0 && result.stdout.trim_start().starts_with("Skipped") {
        MachineValidationAttemptState::Skipped
    } else if result.exit_code == 0 {
        MachineValidationAttemptState::Success
    } else {
        MachineValidationAttemptState::Failed
    }
}

fn run_item_state(state: &MachineValidationAttemptState) -> MachineValidationRunItemState {
    match state {
        MachineValidationAttemptState::Pending => MachineValidationRunItemState::Pending,
        MachineValidationAttemptState::Running => MachineValidationRunItemState::Running,
        MachineValidationAttemptState::Success => MachineValidationRunItemState::Success,
        MachineValidationAttemptState::Skipped => MachineValidationRunItemState::Skipped,
        MachineValidationAttemptState::Failed => MachineValidationRunItemState::Failed,
    }
}

fn truncate_summary(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.chars().take(SUMMARY_LIMIT).collect())
    }
}
