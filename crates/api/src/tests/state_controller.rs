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

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use config_version::{ConfigVersion, Versioned};
use db::DatabaseError;
use futures::StreamExt;
use model::StateSla;
use model::controller_outcome::PersistentStateHandlerOutcome;
use serde::{self, Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::{self, Enqueuer, QueuedObject, StateController};
use crate::state_controller::io::StateControllerIO;
use crate::state_controller::metrics::NoopMetricsEmitter;
use crate::state_controller::state_change_emitter::{
    StateChangeEmitterBuilder, StateChangeEvent, StateChangeHook,
};
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerContextObjects, StateHandlerError,
    StateHandlerOutcome, StateHandlerOutcomeWithTransaction,
};
use crate::tests::common::test_meter::TestMeter;

#[crate::sqlx_test]
async fn test_start_iteration(pool: sqlx::PgPool) -> eyre::Result<()> {
    create_test_state_controller_tables(&pool).await;
    let work_lock_manager_handle =
        db::work_lock_manager::start(pool.clone(), Default::default()).await?;

    // First iteration can acquire the lock
    let result = controller::db::lock_and_start_iteration(
        &pool,
        &work_lock_manager_handle,
        TestStateControllerIO::DB_ITERATION_ID_TABLE_NAME,
    )
    .await
    .unwrap();
    assert_eq!(result.iteration_data.id.0, 1);

    // Second lock will fail
    assert!(
        controller::db::lock_and_start_iteration(
            &pool,
            &work_lock_manager_handle,
            TestStateControllerIO::DB_ITERATION_ID_TABLE_NAME
        )
        .await
        .is_err()
    );

    // Release the lock
    std::mem::drop(result);

    let result = controller::db::lock_and_start_iteration(
        &pool,
        &work_lock_manager_handle,
        TestStateControllerIO::DB_ITERATION_ID_TABLE_NAME,
    )
    .await
    .unwrap();
    assert_eq!(result.iteration_data.id.0, 2);

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_outdated_iterations(pool: sqlx::PgPool) -> eyre::Result<()> {
    create_test_state_controller_tables(&pool).await;
    let work_lock_manager_handle =
        db::work_lock_manager::start(pool.clone(), Default::default()).await?;

    // If we insert up to 10 iterations, all of them shoudl be visible
    for i in 1..=10 {
        let result = controller::db::lock_and_start_iteration(
            &pool,
            &work_lock_manager_handle,
            TestStateControllerIO::DB_ITERATION_ID_TABLE_NAME,
        )
        .await
        .unwrap();
        assert_eq!(result.iteration_data.id.0, i);

        let mut txn = pool.begin().await?;
        let mut results = controller::db::fetch_iterations(
            &mut txn,
            TestStateControllerIO::DB_ITERATION_ID_TABLE_NAME,
            None,
        )
        .await
        .unwrap();
        assert_eq!(results.len(), i as usize);
        results.reverse();
        for j in 0..i {
            assert_eq!(results[j as usize].id.0, j + 1);
        }

        txn.commit().await.unwrap();
    }

    // Once we are above 10, we retain the latest 10 iterations
    for i in 11..=20 {
        let result = controller::db::lock_and_start_iteration(
            &pool,
            &work_lock_manager_handle,
            TestStateControllerIO::DB_ITERATION_ID_TABLE_NAME,
        )
        .await
        .unwrap();
        assert_eq!(result.iteration_data.id.0, i);

        let mut txn = pool.begin().await?;
        let mut results = controller::db::fetch_iterations(
            &mut txn,
            TestStateControllerIO::DB_ITERATION_ID_TABLE_NAME,
            None,
        )
        .await
        .unwrap();
        assert_eq!(results.len(), 10);
        results.reverse();
        for j in 0..10 {
            assert_eq!(results[j as usize].id.0, i - 9 + j);
        }

        txn.commit().await.unwrap();
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_queue_objects(pool: sqlx::PgPool) -> sqlx::Result<()> {
    create_test_state_controller_tables(&pool).await;

    let num_objects = 4;
    let mut object_ids = Vec::new();
    let mut txn = pool.begin().await.unwrap();
    for idx in 0..num_objects {
        let obj = create_test_object(idx.to_string(), &mut txn).await;
        object_ids.push(obj.id);
    }
    txn.commit().await.unwrap();

    // Test insert
    let mut txn = pool.begin().await.unwrap();
    let num_enqueued = controller::db::queue_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        &["0".to_string()],
    )
    .await
    .unwrap();
    assert_eq!(num_enqueued, 1);
    let num_enqueued = controller::db::queue_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        &["1".to_string(), "2".to_string()],
    )
    .await
    .unwrap();
    assert_eq!(num_enqueued, 2);

    let mut queued = controller::db::fetch_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
    )
    .await
    .unwrap();
    queued.sort_by(|a, b| a.object_id.cmp(&b.object_id));
    assert_eq!(
        queued,
        vec![
            QueuedObject {
                object_id: "0".to_string(),
                processed_by: None,
            },
            QueuedObject {
                object_id: "1".to_string(),
                processed_by: None,
            },
            QueuedObject {
                object_id: "2".to_string(),
                processed_by: None,
            },
        ]
    );
    txn.commit().await.unwrap();

    // Test queuing with different iteration IDs.
    // The old iteration ID should be maintained for objects which had
    // been queued before.
    let mut txn = pool.begin().await.unwrap();
    let num_enqueued = controller::db::queue_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        &["0".to_string()],
    )
    .await
    .unwrap();
    assert_eq!(num_enqueued, 0);
    let num_enqueued = controller::db::queue_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        &["3".to_string(), "2".to_string()],
    )
    .await
    .unwrap();
    assert_eq!(num_enqueued, 1);
    let mut queued = controller::db::fetch_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
    )
    .await
    .unwrap();
    queued.sort_by(|a, b| a.object_id.cmp(&b.object_id));
    assert_eq!(
        queued,
        vec![
            QueuedObject {
                object_id: "0".to_string(),
                processed_by: None,
            },
            QueuedObject {
                object_id: "1".to_string(),
                processed_by: None,
            },
            QueuedObject {
                object_id: "2".to_string(),
                processed_by: None,
            },
            QueuedObject {
                object_id: "3".to_string(),
                processed_by: None,
            },
        ]
    );
    txn.commit().await.unwrap();

    // Test acquire
    let processor_id1 = "000000000001".to_string();
    let processor_id2 = "000000000002".to_string();
    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await.unwrap();
    let mut txn2: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await.unwrap();
    let mut queued = controller::db::acquire_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        2,
        &processor_id1,
        std::time::Duration::from_secs(60),
    )
    .await
    .unwrap();
    queued.sort_by(|a, b| a.object_id.cmp(&b.object_id));
    assert_eq!(
        queued,
        vec![
            QueuedObject {
                object_id: "0".to_string(),
                processed_by: Some(processor_id1.clone()),
            },
            QueuedObject {
                object_id: "1".to_string(),
                processed_by: Some(processor_id1.clone()),
            },
        ]
    );
    let mut queued2 = controller::db::acquire_queued_objects(
        &mut txn2,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        1,
        &processor_id2,
        std::time::Duration::from_secs(60),
    )
    .await
    .unwrap();
    queued2.sort_by(|a, b| a.object_id.cmp(&b.object_id));
    assert_eq!(
        queued2,
        vec![QueuedObject {
            object_id: "2".to_string(),
            processed_by: Some(processor_id2.clone()),
        },]
    );

    txn.commit().await.unwrap();
    txn2.commit().await.unwrap();

    // Test delete invalid
    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await.unwrap();
    let num_deleted = controller::db::delete_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        &["0".to_string()],
        &processor_id2,
    )
    .await
    .unwrap();
    assert_eq!(num_deleted, 0);

    // Test valid delete
    let num_deleted = controller::db::delete_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        &["1".to_string()],
        &processor_id1,
    )
    .await
    .unwrap();
    assert_eq!(num_deleted, 1);

    let mut queued = controller::db::fetch_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
    )
    .await
    .unwrap();
    queued.sort_by(|a, b| a.object_id.cmp(&b.object_id));
    assert_eq!(
        queued,
        vec![
            QueuedObject {
                object_id: "0".to_string(),
                processed_by: Some(processor_id1.clone()),
            },
            QueuedObject {
                object_id: "2".to_string(),
                processed_by: Some(processor_id2.clone()),
            },
            QueuedObject {
                object_id: "3".to_string(),
                processed_by: None,
            },
        ]
    );
    txn.commit().await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // Test acquire with max_outdated
    let mut txn: sqlx::Transaction<'_, sqlx::Postgres> = pool.begin().await.unwrap();
    let queued = controller::db::acquire_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
        2,
        &processor_id1,
        std::time::Duration::from_millis(500),
    )
    .await
    .unwrap();
    // We might see 2-3 tasks not being acquired by the processor.
    // 2 if it re-acquires the tasks it already has, or 3 if it acquires other tasks
    let acquired = queued
        .iter()
        .filter(|queued| {
            queued
                .processed_by
                .as_ref()
                .is_some_and(|by| by == &processor_id1)
        })
        .count();
    assert!(
        acquired == 2 || acquired == 3,
        "Object is acquired {acquired} times: Full data: {queued:?}"
    );

    txn.commit().await.unwrap();

    Ok(())
}

#[derive(Debug, Default)]
struct TestStateControllerIO {}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TestObject {
    pub id: String,
    pub controller_state: Versioned<TestObjectControllerState>,
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
}

impl<'r> FromRow<'r, PgRow> for TestObject {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<TestObjectControllerState> =
            row.try_get("controller_state")?;
        let state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome")?;

        Ok(TestObject {
            id: row.try_get("id")?,
            controller_state: Versioned::new(
                controller_state.0,
                row.try_get("controller_state_version")?,
            ),
            controller_state_outcome: state_outcome.map(|x| x.0),
        })
    }
}

/// State of a IB subnet as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum TestObjectControllerState {
    A,
    B,
    C,
}

pub struct TestStateControllerContextObjects {}

impl StateHandlerContextObjects for TestStateControllerContextObjects {
    type Services = ();
    type ObjectMetrics = ();
}

async fn create_test_state_controller_tables(pool: &sqlx::PgPool) {
    let mut txn = pool.begin().await.unwrap();

    sqlx::query(
        "CREATE TABLE test_objects(
        id             varchar NOT NULL,
        controller_state         jsonb       NOT NULL,
        controller_state_version VARCHAR(64) NOT NULL,
        controller_state_outcome JSONB
    );",
    )
    .execute(&mut *txn)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE test_state_controller_lock(
        id uuid DEFAULT gen_random_uuid() NOT NULL
    );",
    )
    .execute(&mut *txn)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE test_state_controller_iteration_ids(
        id BIGSERIAL PRIMARY KEY,
        started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );",
    )
    .execute(&mut *txn)
    .await
    .unwrap();

    sqlx::query(
        "CREATE TABLE test_state_controller_queued_objects(
        object_id VARCHAR PRIMARY KEY,
        processed_by TEXT NULL,
        processing_started_at timestamptz NOT NULL DEFAULT NOW()
    );",
    )
    .execute(&mut *txn)
    .await
    .unwrap();

    txn.commit().await.unwrap();
}

async fn create_test_object(id: String, txn: &mut PgConnection) -> TestObject {
    let version: ConfigVersion = ConfigVersion::initial();
    let state = TestObjectControllerState::A;

    let query = "INSERT INTO test_objects(id, controller_state, controller_state_version)
        VALUES($1, $2::json, $3)
        RETURNING *";
    sqlx::query_as(query)
        .bind(id)
        .bind(sqlx::types::Json(state))
        .bind(version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
        .unwrap()
}

#[async_trait::async_trait]
impl StateControllerIO for TestStateControllerIO {
    type ObjectId = String;
    type State = TestObject;
    type ControllerState = TestObjectControllerState;
    type MetricsEmitter = NoopMetricsEmitter;
    type ContextObjects = TestStateControllerContextObjects;

    const DB_ITERATION_ID_TABLE_NAME: &'static str = "test_state_controller_iteration_ids";
    const DB_QUEUED_OBJECTS_TABLE_NAME: &'static str = "test_state_controller_queued_objects";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "test_state_controller";

    async fn list_objects(
        &self,
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        let query = "SELECT id FROM test_objects";
        let mut results = Vec::new();
        let mut segment_id_stream = sqlx::query_scalar(query).fetch(txn);
        while let Some(maybe_id) = segment_id_stream.next().await {
            let id = maybe_id.map_err(|e| DatabaseError::query(query, e))?;
            results.push(id);
        }

        Ok(results)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        let query = "SELECT * FROM test_objects where id = $1";
        let object = sqlx::query_as::<_, TestObject>(query)
            .bind(object_id)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::new("select", e))?;

        return Ok(object);
    }

    async fn load_controller_state(
        &self,
        _txn: &mut PgConnection,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, DatabaseError> {
        Ok(state.controller_state.clone())
    }

    async fn persist_controller_state(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        old_version: ConfigVersion,
        new_state: &Self::ControllerState,
    ) -> Result<(), DatabaseError> {
        let next_version = old_version.increment();

        let query = "UPDATE test_objects SET controller_state_version=$1, controller_state=$2::json
            where id=$3 AND controller_state_version=$4 returning id";
        let query_result = sqlx::query_scalar::<_, String>(query)
            .bind(next_version)
            .bind(sqlx::types::Json(new_state))
            .bind(object_id)
            .bind(old_version)
            .fetch_one(txn)
            .await;

        match query_result {
            Ok(_object_id) => {}
            Err(sqlx::Error::RowNotFound) => {}
            Err(e) => return Err(DatabaseError::query(query, e)),
        }

        Ok(())
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE test_objects SET controller_state_outcome=$1::json WHERE id=$2";
        sqlx::query(query)
            .bind(sqlx::types::Json(outcome))
            .bind(object_id)
            .execute(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
        Ok(())
    }

    fn metric_state_names(state: &TestObjectControllerState) -> (&'static str, &'static str) {
        match state {
            TestObjectControllerState::A => ("a", ""),
            TestObjectControllerState::B => ("b", ""),
            TestObjectControllerState::C => ("c", ""),
        }
    }

    fn state_sla(_state: &Versioned<Self::ControllerState>) -> StateSla {
        StateSla {
            sla: None,
            time_in_state_above_sla: false,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TestConcurrencyStateHandler {
    /// The total count for the handler
    pub count: Arc<AtomicUsize>,
    /// We count for every object ID how often the handler was called
    pub counts_per_id: Arc<Mutex<HashMap<String, usize>>>,
}

#[async_trait::async_trait]
impl StateHandler for TestConcurrencyStateHandler {
    type State = TestObject;
    type ControllerState = TestObjectControllerState;
    type ObjectId = String;
    type ContextObjects = TestStateControllerContextObjects;

    async fn handle_object_state(
        &self,
        object_id: &String,
        state: &mut TestObject,
        _controller_state: &Self::ControllerState,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<Self::ControllerState>, StateHandlerError> {
        assert_eq!(state.id, *object_id);
        self.count.fetch_add(1, Ordering::SeqCst);
        {
            let mut guard = self.counts_per_id.lock().unwrap();
            *guard.entry(object_id.to_string()).or_default() += 1;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok(StateHandlerOutcome::do_nothing().with_txn(None))
    }
}

#[crate::sqlx_test]
async fn test_multiple_state_controllers_schedule_object_only_once(
    pool: sqlx::PgPool,
) -> eyre::Result<()> {
    create_test_state_controller_tables(&pool).await;
    let work_lock_manager_handle =
        db::work_lock_manager::start(pool.clone(), Default::default()).await?;

    let num_objects = 4;
    let mut object_ids = Vec::new();
    let mut txn = pool.begin().await.unwrap();
    for idx in 0..num_objects {
        let obj = create_test_object(idx.to_string(), &mut txn).await;
        object_ids.push(obj.id);
    }
    txn.commit().await.unwrap();

    let state_handler = Arc::new(TestConcurrencyStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(10);
    let expected_iterations = (TEST_TIME.as_millis() / ITERATION_TIME.as_millis()) as f64;
    let expected_total_count = expected_iterations * object_ids.len() as f64;

    // We build multiple state controllers. But since only one should act at a time,
    // the count should still not increase
    let mut handles = Vec::new();
    for _ in 0..10 {
        handles.push(
            StateController::<TestStateControllerIO>::builder()
                .iteration_config(IterationConfig {
                    iteration_time: ITERATION_TIME,
                    processor_dispatch_interval: std::time::Duration::from_millis(10),
                    ..Default::default()
                })
                .database(pool.clone(), work_lock_manager_handle.clone())
                .processor_id(uuid::Uuid::new_v4().to_string())
                .services(Arc::new(()))
                .state_handler(state_handler.clone())
                .build_and_spawn()
                .unwrap(),
        );
    }

    tokio::time::sleep(TEST_TIME).await;
    drop(handles);
    // Wait some extra time until the controller background task shuts down
    tokio::time::sleep(Duration::from_secs(1)).await;

    let count = state_handler.count.load(Ordering::SeqCst) as f64;
    assert!(
        count >= 0.60 * expected_total_count && count <= 1.25 * expected_total_count,
        "Expected count of {expected_total_count}, but got {count}"
    );

    for object_id in object_ids {
        let guard = state_handler.counts_per_id.lock().unwrap();
        let count = guard
            .get(&object_id.to_string())
            .copied()
            .unwrap_or_default() as f64;

        assert!(
            count >= 0.60 * expected_iterations && count <= 1.25 * expected_iterations,
            "Expected individual count of {expected_iterations}, but got {count} for {object_id}"
        );
    }

    Ok(())
}

/// A state handler that transitions from A -> B -> C
#[derive(Debug, Default, Clone)]
pub struct TestTransitionStateHandler;

#[async_trait::async_trait]
impl StateHandler for TestTransitionStateHandler {
    type State = TestObject;
    type ControllerState = TestObjectControllerState;
    type ObjectId = String;
    type ContextObjects = TestStateControllerContextObjects;

    async fn handle_object_state(
        &self,
        _object_id: &String,
        _state: &mut TestObject,
        controller_state: &Self::ControllerState,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<Self::ControllerState>, StateHandlerError> {
        match controller_state {
            TestObjectControllerState::A => {
                Ok(StateHandlerOutcome::transition(TestObjectControllerState::B).with_txn(None))
            }
            TestObjectControllerState::B => {
                Ok(StateHandlerOutcome::transition(TestObjectControllerState::C).with_txn(None))
            }
            TestObjectControllerState::C => Ok(StateHandlerOutcome::do_nothing().with_txn(None)),
        }
    }
}

/// A state handler that transitions from A -> B -> A
#[derive(Debug, Default, Clone)]
pub struct CyclicTransitionStateHandler;

#[async_trait::async_trait]
impl StateHandler for CyclicTransitionStateHandler {
    type State = TestObject;
    type ControllerState = TestObjectControllerState;
    type ObjectId = String;
    type ContextObjects = TestStateControllerContextObjects;

    async fn handle_object_state(
        &self,
        _object_id: &String,
        _state: &mut TestObject,
        controller_state: &Self::ControllerState,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<Self::ControllerState>, StateHandlerError> {
        match controller_state {
            TestObjectControllerState::A => {
                Ok(StateHandlerOutcome::transition(TestObjectControllerState::B).with_txn(None))
            }
            TestObjectControllerState::B => {
                Ok(StateHandlerOutcome::transition(TestObjectControllerState::A).with_txn(None))
            }
            TestObjectControllerState::C => Err(StateHandlerError::InvalidState("C".to_string())),
        }
    }
}

/// Tests whether the amount of emitted metrics is stable
/// The test as checked in is mostly a smoke test
/// To get better test coverage, extend `TEST_TIME` to 3 or more minutes.
#[crate::sqlx_test]
async fn test_state_handler_metrics_are_stable(pool: sqlx::PgPool) -> eyre::Result<()> {
    let test_meter = TestMeter::default();

    create_test_state_controller_tables(&pool).await;
    let work_lock_manager_handle =
        db::work_lock_manager::start(pool.clone(), Default::default()).await?;

    let num_objects = 100;
    let mut object_ids = Vec::new();
    let mut txn = pool.begin().await.unwrap();
    for idx in 0..num_objects {
        let obj = create_test_object(idx.to_string(), &mut txn).await;
        object_ids.push(obj.id);
    }
    txn.commit().await.unwrap();

    let state_handler = Arc::new(CyclicTransitionStateHandler);
    const ITERATION_TIME: Duration = Duration::from_millis(100);
    const TEST_TIME: Duration = Duration::from_secs(10);
    let start_time = std::time::Instant::now();

    let _handle = StateController::<TestStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: std::time::Duration::from_millis(10),
            max_concurrency: num_objects,
            ..Default::default()
        })
        .meter("test_objects", test_meter.meter())
        .database(pool.clone(), work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(Arc::new(()))
        .state_handler(state_handler.clone())
        .build_and_spawn()
        .unwrap();

    // Check metrics periodically. We always expect to see 100 objects
    while start_time.elapsed() < TEST_TIME {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert_eq!(
            test_meter.formatted_metric("test_objects_total{fresh=\"true\"}"),
            Some(num_objects.to_string()),
            "Test failed after {}s",
            start_time.elapsed().as_secs_f32()
        );
    }

    Ok(())
}

/// Captured state change data for test verification.
#[derive(Debug, Clone)]
struct CapturedStateChange {
    object_id: String,
    previous_state: Option<TestObjectControllerState>,
    new_state: TestObjectControllerState,
}

/// A hook that sends events through a channel for deterministic test verification
pub struct ChannelHook {
    sender: tokio::sync::mpsc::UnboundedSender<CapturedStateChange>,
}

impl ChannelHook {
    fn new() -> (
        Self,
        tokio::sync::mpsc::UnboundedReceiver<CapturedStateChange>,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }
}

impl StateChangeHook<String, TestObjectControllerState> for ChannelHook {
    fn on_state_changed(&self, event: &StateChangeEvent<'_, String, TestObjectControllerState>) {
        let captured = CapturedStateChange {
            object_id: event.object_id.clone(),
            previous_state: event.previous_state.cloned(),
            new_state: event.new_state.clone(),
        };
        let _ = self.sender.send(captured);
    }
}

#[crate::sqlx_test]
async fn test_state_change_emitter_emits_events_on_transitions(
    pool: sqlx::PgPool,
) -> eyre::Result<()> {
    create_test_state_controller_tables(&pool).await;
    let work_lock_manager_handle =
        db::work_lock_manager::start(pool.clone(), Default::default()).await?;

    // Create a single test object in state A
    let mut txn = pool.begin().await?;
    let obj = create_test_object("test-obj-1".to_string(), &mut txn).await;
    txn.commit().await?;

    // Create a channel hook to receive events deterministically
    let (hook, mut receiver) = ChannelHook::new();

    // Build the emitter with our channel hook
    let emitter = StateChangeEmitterBuilder::default()
        .hook(Box::new(hook))
        .build();

    // Build the state controller with the emitter
    let mut controller = StateController::<TestStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: Duration::from_millis(50),
            ..Default::default()
        })
        .database(pool.clone(), work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(Arc::new(()))
        .state_handler(Arc::new(TestTransitionStateHandler))
        .state_change_emitter(emitter)
        .build_for_manual_iterations()?;

    // Run first iteration: A -> B
    controller.run_single_iteration().await;
    let event1 = receiver
        .recv()
        .await
        .expect("Expected first state change event");
    assert_eq!(event1.object_id, obj.id);
    assert_eq!(event1.previous_state, Some(TestObjectControllerState::A));
    assert_eq!(event1.new_state, TestObjectControllerState::B);

    // Run second iteration: B -> C
    controller.run_single_iteration().await;
    let event2 = receiver
        .recv()
        .await
        .expect("Expected second state change event");
    assert_eq!(event2.object_id, obj.id);
    assert_eq!(event2.previous_state, Some(TestObjectControllerState::B));
    assert_eq!(event2.new_state, TestObjectControllerState::C);

    // Run third iteration: C -> do_nothing (no transition, no event)
    controller.run_single_iteration().await;
    // Verify no more events in the channel
    assert!(
        receiver.try_recv().is_err(),
        "Expected no event for do_nothing outcome"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_state_controller_manual_enqueuing(pool: sqlx::PgPool) -> eyre::Result<()> {
    create_test_state_controller_tables(&pool).await;
    let work_lock_manager_handle =
        db::work_lock_manager::start(pool.clone(), Default::default()).await?;

    // Create a single test object in state A
    let mut txn = pool.begin().await?;
    let _obj = create_test_object("test-obj-1".to_string(), &mut txn).await;
    txn.commit().await?;

    // Build the state controller with the emitter
    let mut controller = StateController::<TestStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: Duration::from_millis(50),
            processor_dispatch_interval: Duration::from_millis(50),
            ..Default::default()
        })
        .database(pool.clone(), work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(Arc::new(()))
        .state_handler(Arc::new(TestTransitionStateHandler))
        .build_for_manual_iterations()?;

    // Transition A -> B, but no re-enqueuing
    controller.run_single_iteration_ext(false).await;

    let mut txn = pool.begin().await?;
    let queued = controller::db::fetch_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
    )
    .await
    .unwrap();
    assert!(queued.is_empty());
    txn.commit().await.unwrap();

    let enqueuer = Enqueuer::<TestStateControllerIO>::new(pool.clone());
    enqueuer.enqueue_object(&"test-obj-1".to_string()).await?;
    let mut txn = pool.begin().await?;
    let queued = controller::db::fetch_queued_objects(
        &mut txn,
        TestStateControllerIO::DB_QUEUED_OBJECTS_TABLE_NAME,
    )
    .await
    .unwrap();
    assert_eq!(
        queued,
        vec![QueuedObject {
            object_id: "test-obj-1".to_string(),
            processed_by: None,
        },]
    );
    txn.commit().await.unwrap();

    Ok(())
}
