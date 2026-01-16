/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::db::DatabaseError;
use ::db::work_lock_manager::{WorkLock, WorkLockManagerHandle};
use chrono::{DateTime, Utc};
use model::controller_outcome::PersistentStateHandlerOutcome;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::logging::sqlx_query_tracing;
use crate::state_controller::config::IterationConfig;
use crate::state_controller::io::StateControllerIO;
use crate::state_controller::metrics::{IterationMetrics, MetricHolder, ObjectHandlerMetrics};
use crate::state_controller::state_change_emitter::{StateChangeEmitter, StateChangeEvent};
use crate::state_controller::state_handler::{
    FromStateHandlerResult, StateHandler, StateHandlerContext, StateHandlerContextObjects,
    StateHandlerError, StateHandlerOutcome,
};

mod builder;
pub mod db;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ControllerIterationId(pub i64);

/// Metadata for a single state controller iteration
#[derive(Debug, Clone)]
pub struct ControllerIteration {
    /// The ID of the iteration
    pub id: ControllerIterationId,
    /// When the iteration started
    #[allow(dead_code)]
    pub started_at: DateTime<Utc>,
}

pub struct LockedControllerIteration {
    pub iteration_data: ControllerIteration,
    /// The lock for the work done in this iteration.
    pub _work_lock: WorkLock,
}

impl<'r> FromRow<'r, PgRow> for ControllerIteration {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let id: i64 = row.try_get("id")?;
        let started_at = row.try_get("started_at")?;
        Ok(ControllerIteration {
            id: ControllerIterationId(id),
            started_at,
        })
    }
}

/// Metadata for a single state controller iteration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedObject {
    /// The ID of the object which should get scheduled
    pub object_id: String,
    /// The ID of the run for which the object was scheduled
    pub iteration_id: ControllerIterationId,
}

impl<'r> FromRow<'r, PgRow> for QueuedObject {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let object_id = row.try_get("object_id")?;
        let iteration_id: i64 = row.try_get("iteration_id")?;
        Ok(QueuedObject {
            object_id,
            iteration_id: ControllerIterationId(iteration_id),
        })
    }
}

/// The object static controller evaluates the current state of all objects of a
/// certain type in a Forge site, and decides which actions the system should
/// undertake to bring the state inline with the state users requested.
///
/// Each Forge API server is running a StateController instance for each object type.
/// While all instances run in parallel, the StateController uses internal
/// synchronization to make sure that inside a single site - only a single controller
/// will decide the next step for a single object.
pub struct StateController<IO: StateControllerIO> {
    /// A database connection pool that can be used for additional queries
    pool: sqlx::PgPool,
    work_lock_manager_handle: WorkLockManagerHandle,
    handler_services: Arc<<IO::ContextObjects as StateHandlerContextObjects>::Services>,
    io: Arc<IO>,
    work_key: &'static str,
    state_handler: Arc<
        dyn StateHandler<
                State = IO::State,
                ControllerState = IO::ControllerState,
                ContextObjects = IO::ContextObjects,
                ObjectId = IO::ObjectId,
            >,
    >,
    metric_holder: Arc<MetricHolder<IO>>,
    stop_receiver: oneshot::Receiver<()>,
    iteration_config: IterationConfig,
    /// Emitter for broadcasting state change events to registered hooks.
    state_change_emitter: Arc<StateChangeEmitter<IO::ObjectId, IO::ControllerState>>,
}

pub struct SingleIterationResult {
    /// Whether the iteration was skipped due to not being able to obtain the lock.
    /// This will be `true` if the lock could not be obtained.
    skipped_iteration: bool,
}

impl<IO: StateControllerIO> StateController<IO> {
    /// Returns a [`Builder`] for configuring `StateController`
    pub fn builder() -> builder::Builder<IO> {
        builder::Builder::default()
    }

    /// Runs the state handler task repeadetly, while waiting for the configured
    /// amount of time between runs.
    ///
    /// The controller task will continue to run until `stop_receiver` was signaled
    pub async fn run(mut self) {
        let max_jitter = (self.iteration_config.iteration_time.as_millis() / 3) as u64;
        let err_jitter = (self.iteration_config.iteration_time.as_millis() / 5) as u64;

        loop {
            let start = Instant::now();
            let iteration_result = self.run_single_iteration().await;

            // We add some jitter before sleeping, to give other controller instances
            // a chance to pick up the lock.
            // If a controller got the lock, the maximum delay is higher than for controllers
            // which failed to get the lock, which aims to give another bias to
            // a different controller.
            use rand::Rng;
            let jitter = rand::rng().random::<u64>()
                % if iteration_result.skipped_iteration {
                    err_jitter
                } else {
                    max_jitter
                };
            let sleep_time = self
                .iteration_config
                .iteration_time
                .saturating_sub(start.elapsed())
                .saturating_add(Duration::from_millis(jitter));

            tokio::select! {
                _ = tokio::time::sleep(sleep_time) => {},
                _ = &mut self.stop_receiver => {
                    tracing::info!("StateController stop was requested");
                    return;
                }
            }
        }
    }

    /// Performs a single state controller iteration
    ///
    /// This includes
    /// - Generating a Span for the iteration
    /// - Loading all object states
    /// - Changing the state of all objects and storing results
    /// - Storing and emitting metrics for the run
    pub async fn run_single_iteration(&mut self) -> SingleIterationResult {
        let span_id = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));
        let mut metrics = IterationMetrics::default();
        let mut iteration_result = SingleIterationResult {
            skipped_iteration: false,
        };

        let controller_span = tracing::span!(
            parent: None,
            tracing::Level::INFO,
            "state_controller_iteration",
            span_id,
            controller = IO::LOG_SPAN_CONTROLLER_NAME,
            iteration_id = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
            otel.status_message = tracing::field::Empty,
            skipped_iteration = tracing::field::Empty,
            num_enqueued_objects = tracing::field::Empty,
            num_objects = tracing::field::Empty,
            num_errors = tracing::field::Empty,
            states = tracing::field::Empty,
            states_above_sla = tracing::field::Empty,
            error_types = tracing::field::Empty,
            app_timing_start_time = format!("{:?}", chrono::Utc::now()),
            app_timing_end_time = tracing::field::Empty,
            sql_queries = 0,
            sql_total_rows_affected = 0,
            sql_total_rows_returned = 0,
            sql_max_query_duration_us = 0,
            sql_max_query_duration_summary = tracing::field::Empty,
            sql_total_query_duration_us = 0,
        );

        let res = self
            .lock_and_handle_iteration(&mut metrics)
            .instrument(controller_span.clone())
            .await;
        metrics.common.recording_finished_at = std::time::Instant::now();

        controller_span.record("otel.status_code", if res.is_ok() { "ok" } else { "error" });

        let db_query_metrics = {
            let _e: tracing::span::Entered<'_> = controller_span.enter();
            sqlx_query_tracing::fetch_and_update_current_span_attributes()
        };

        match &res {
            Ok(()) => {
                controller_span.record("otel.status_code", "ok");
            }
            Err(IterationError::LockError) => {
                controller_span.record("otel.status_code", "ok");
                iteration_result.skipped_iteration = true;
            }
            Err(e) => {
                tracing::error!("StateController iteration failed due to: {:?}", e);
                controller_span.record("otel.status_code", "error");
                // Writing this field will set the span status to error
                // Therefore we only write it on errors
                controller_span.record("otel.status_message", format!("{e:?}"));
            }
        }

        // Immediately emit latency metrics
        // These will be emitted both in cases where we actually acted on objects
        // as well as for cases where we didn't get the lock. Since the
        // latter case doesn't handle any objects it will be a no-op apart
        // from emitting the latency for not getting the lock.
        if let Some(emitter) = self.metric_holder.emitter.as_ref() {
            emitter.emit_iteration_counters_and_histograms(
                IO::LOG_SPAN_CONTROLLER_NAME,
                &metrics,
                &db_query_metrics,
            );
            emitter.set_iteration_span_attributes(&controller_span, &metrics);
        }

        // If we actually performed an iteration (and not failed to obtain the lock),
        // cache all other metrics that have been captured in this iteration.
        // Those will be queried by OTEL on demand
        if res.is_ok() {
            let IterationMetrics { common, specific } = metrics;
            self.metric_holder
                .last_iteration_specific_metrics
                .update(specific);
            self.metric_holder
                .last_iteration_common_metrics
                .update(common);
        }

        controller_span.record("app_timing_end_time", format!("{:?}", chrono::Utc::now()));

        iteration_result
    }

    async fn lock_and_handle_iteration(
        &mut self,
        iteration_metrics: &mut IterationMetrics<IO>,
    ) -> Result<(), IterationError> {
        let _lock = match self
            .work_lock_manager_handle
            .try_acquire_lock(self.work_key.into())
            .await
        {
            Ok(lock) => {
                tracing::Span::current().record("skipped_iteration", false);
                tracing::trace!(lock = IO::DB_WORK_KEY, "State controller acquired the lock");
                lock
            }
            Err(e) => {
                tracing::Span::current().record("skipped_iteration", true);
                tracing::info!(
                    lock = IO::DB_WORK_KEY,
                    "State controller was not able to obtain the lock: {e}",
                );
                return Err(IterationError::LockError);
            }
        };

        let locked_controller_iteration = match db::lock_and_start_iteration(
            &self.pool,
            &self.work_lock_manager_handle,
            IO::DB_ITERATION_ID_TABLE_NAME,
        )
        .await
        {
            Ok(iteration_data) => iteration_data,
            Err(e) => {
                tracing::error!(
                    iteration_table_id = IO::DB_ITERATION_ID_TABLE_NAME,
                    error = %e,
                    "State controller was not able to start run"
                );
                return Err(IterationError::LockError);
            }
        };

        tracing::trace!(iteration_data = ?locked_controller_iteration.iteration_data, "Starting iteration with ID ");
        iteration_metrics.common.iteration_id = Some(locked_controller_iteration.iteration_data.id);

        self.enqueue_objects(
            iteration_metrics,
            locked_controller_iteration.iteration_data.id,
        )
        .await?;

        self.process_enqueued_objects(iteration_metrics).await?;

        Ok(())
    }

    /// Identifies all active objects that the state controller manages
    /// and enqueues them for state handler execution
    async fn enqueue_objects(
        &mut self,
        iteration_metrics: &mut IterationMetrics<IO>,
        iteration_id: ControllerIterationId,
    ) -> Result<(), IterationError> {
        // We start by grabbing a list of objects that should be active
        // The list might change until we fetch more data. However that should be ok:
        // The next iteration of the controller would also find objects that
        // have been added to the system. And no object should ever be removed
        // outside of the state controller
        let mut txn = self.pool.begin().await?;
        let object_ids = self.io.list_objects(&mut txn).await?;
        iteration_metrics.common.num_enqueued_objects = object_ids.len();

        let queued_objects: Vec<_> = object_ids
            .iter()
            .map(|object_id| (object_id.to_string(), iteration_id))
            .collect();
        db::queue_objects(&mut txn, IO::DB_QUEUED_OBJECTS_TABLE_NAME, &queued_objects).await?;

        txn.commit().await?;

        Ok(())
    }

    /// Executes the state handling function for all objects for which it has
    /// been enqueued
    #[allow(txn_held_across_await)]
    async fn process_enqueued_objects(
        &mut self,
        iteration_metrics: &mut IterationMetrics<IO>,
    ) -> Result<(), IterationError> {
        // Remove the current set of enqueued objects from the queue
        // Note that if the process crashes after dequeuing it won't be a big issue,
        // since the objects will be re-enqueued by the next controller iteration.
        let mut txn = self.pool.begin().await?;
        let object_ids =
            db::dequeue_queued_objects(&mut txn, IO::DB_QUEUED_OBJECTS_TABLE_NAME).await?;
        let object_ids: Vec<IO::ObjectId> = object_ids
            .into_iter()
            .filter_map(|object| match IO::ObjectId::from_str(&object.object_id) {
                Ok(id) => Some(id),
                Err(_) => {
                    tracing::error!(
                        controller = IO::LOG_SPAN_CONTROLLER_NAME,
                        "Can not convert queued object ID \"{}\" to IO::ObjectID format",
                        object.object_id
                    );
                    None
                }
            })
            .collect();

        txn.commit().await?;

        let mut task_set = JoinSet::new();

        let concurrency_limiter = Arc::new(tokio::sync::Semaphore::new(
            self.iteration_config.max_concurrency,
        ));

        for object_id in object_ids.iter() {
            let object_id = object_id.clone();
            let pool = self.pool.clone();
            let mut services = self.handler_services.as_ref().clone();
            let io = self.io.clone();
            let handler = self.state_handler.clone();
            let concurrency_limiter = concurrency_limiter.clone();
            let max_object_handling_time = self.iteration_config.max_object_handling_time;
            let metrics_emitter = self.metric_holder.emitter.clone();
            let state_change_emitter = self.state_change_emitter.clone();

            let _abort_handle = task_set
                .build_task()
                .name(&format!("state_controller {object_id}"))
                .spawn(
                    async move {
                        // Acquire a permit which will block more than `MAX_CONCURRENCY`
                        // tasks from running.
                        // Note that assigning the permit to a named variable is necessary
                        // to make it live until the end of the scope. Using `_` would
                        // immediately dispose the permit.
                        let _permit = concurrency_limiter
                            .acquire()
                            .await
                            .expect("Semaphore can't be closed");

                        let mut metrics = ObjectHandlerMetrics::<IO>::default();

                        let start = Instant::now();

                        // Note that this inner async block is required to be able to use
                        // the ? operator in the inner block, and then return a `Result`
                        // from the other outer block.
                        let result: Result<
                            Result<StateHandlerOutcome<_>, StateHandlerError>,
                            tokio::time::error::Elapsed,
                        > = tokio::time::timeout(max_object_handling_time, async {
                            let mut txn = pool.begin().await?;
                            let mut snapshot = io
                                .load_object_state(&mut txn, &object_id)
                                .await?
                                .ok_or_else(|| StateHandlerError::MissingData {
                                    object_id: object_id.to_string(),
                                    missing: "object_state",
                                })?;
                            let controller_state = io
                                .load_controller_state(&mut txn, &object_id, &snapshot)
                                .await?;

                            metrics.common.initial_state = Some(controller_state.value.clone());
                            // Unwrap uses a very large duration as default to show something is wrong
                            metrics.common.time_in_state = chrono::Utc::now()
                                .signed_duration_since(controller_state.version.timestamp())
                                .to_std()
                                .unwrap_or(Duration::from_secs(60 * 60 * 24));

                            let state_sla = IO::state_sla(&controller_state);
                            metrics.common.time_in_state_above_sla =
                                state_sla.time_in_state_above_sla;

                            let mut ctx = StateHandlerContext {
                                services: &mut services,
                                metrics: &mut metrics.specific,
                            };

                            let handler_outcome = handler
                                .handle_object_state(
                                    &object_id,
                                    &mut snapshot,
                                    &controller_state.value,
                                    &mut txn,
                                    &mut ctx,
                                )
                                .await;

                            let mut next_state = None;
                            if let Ok(StateHandlerOutcome::Transition { next_state: next, .. }) = &handler_outcome {
                                next_state = Some(next.clone());

                                if *next == controller_state.value {
                                    tracing::warn!(state=?next, %object_id, "Transition to current state");
                                }
                                io.persist_controller_state(
                                    &mut txn,
                                    &object_id,
                                    controller_state.version,
                                    next,
                                )
                                .await?;
                            }

                            let is_success = handler_outcome.is_ok();

                            // If the state handler neither transitioned nor returned no error,
                            // but the object is stuck in the state for longer than the defined SLA,
                            // then transform the outcome into an error
                            let handler_outcome = match handler_outcome {
                                Ok(StateHandlerOutcome::Wait { reason, .. })
                                    if state_sla.time_in_state_above_sla =>
                                {
                                    Err(StateHandlerError::TimeInStateAboveSla {
                                        handler_outcome: format!("Wait(\"{reason}\")"),
                                    })
                                }
                                Ok(StateHandlerOutcome::DoNothing {..})
                                    if state_sla.time_in_state_above_sla =>
                                {
                                    Err(StateHandlerError::TimeInStateAboveSla {
                                        handler_outcome: "DoNothing".to_string(),
                                    })
                                }
                                _ => handler_outcome,
                            };

                            if is_success {
                                // Commit transaction only when handler returned the Success.
                                if !matches!(handler_outcome, Ok(StateHandlerOutcome::Deleted { .. })) {
                                    let db_outcome = PersistentStateHandlerOutcome::from_result(handler_outcome.as_ref());
                                    io.persist_outcome(&mut txn, &object_id, db_outcome).await?;
                                }

                                txn.commit()
                                    .await
                                    .map_err(StateHandlerError::TransactionError)?;
                            } else if !matches!(handler_outcome, Ok(StateHandlerOutcome::Deleted { .. })) {
                                // Whatever is the reason, outcome must be stored in db.
                                let _ = txn.rollback().await;
                                let mut txn = pool.begin().await?;
                                let db_outcome = PersistentStateHandlerOutcome::from_result(handler_outcome.as_ref());
                                io.persist_outcome(&mut txn, &object_id, db_outcome).await?;
                                txn.commit()
                                    .await
                                    .map_err(StateHandlerError::TransactionError)?;
                            }

                            // Only emit the next state as metric if the transaction was actually
                            // committed and we are sure we reached the next state
                            metrics.common.next_state = next_state;

                            handler_outcome
                        })
                        .await;
                        metrics.common.handler_latency = start.elapsed();
                        // Emit the state changed event to registered hooks
                        if let Some(next_state) = &metrics.common.next_state {
                            state_change_emitter.emit(StateChangeEvent {
                                object_id: &object_id,
                                previous_state: metrics.common.initial_state.as_ref(),
                                new_state: next_state,
                                timestamp: chrono::Utc::now(),
                            });
                        }

                        // Emit the object handling metrics for this state handler invocation
                        if let Some(emitter) = metrics_emitter {
                            emitter.emit_object_counters_and_histograms(&metrics);
                        }

                        let result = match result {
                            Ok(Ok(result)) => Ok(result),
                            Ok(Err(err)) => Err(err),
                            Err(_timeout) => Err(StateHandlerError::Timeout {
                                object_id: object_id.to_string(),
                                state: metrics
                                    .common
                                    .initial_state
                                    .as_ref()
                                    .map(|state| format!("{state:?}"))
                                    .unwrap_or_default(),
                            }),
                        };
                        if let Err(e) = &result {
                            tracing::warn!(%object_id, error = ?e, "State handler error");
                        }

                        (metrics, result)
                    }
                    .in_current_span(),
                );
        }

        // We want for all tasks to run to completion here and therefore can't
        // return early until the `TaskSet` is fully consumed.
        // If we would return early then some tasks might still work on an object
        // even thought the next controller iteration already started.
        // Therefore we drain the `task_set` here completely and record all errors
        // before returning.
        let mut last_join_error: Option<tokio::task::JoinError> = None;
        while let Some(result) = task_set.join_next().await {
            match result {
                Err(join_error) => {
                    last_join_error = Some(join_error);
                }
                Ok((mut metrics, Err(handler_error))) => {
                    metrics.common.error = Some(handler_error);
                    iteration_metrics.merge_object_handling_metrics(&metrics);
                    // Since we log StateHandlerErrors including the objectId inside the
                    // handling task themselves, we don't have to forward these errors.
                    // This avoids double logging of the results of individual tasks.
                }
                Ok((metrics, Ok(_))) => {
                    iteration_metrics.merge_object_handling_metrics(&metrics);
                }
            }
        }

        if let Some(err) = last_join_error.take() {
            return Err(err.into());
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum IterationError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Unable to perform database transaction: {0}")]
    DatabaseError(#[from] DatabaseError),
    #[error("Unable to acquire lock and start iteration")]
    LockError,
    #[error("A task panicked: {0}")]
    Panic(#[from] tokio::task::JoinError),
    #[error("State handler error: {0}")]
    StateHandlerError(#[from] StateHandlerError),
}

/// A remote handle for the state controller
pub struct StateControllerHandle {
    /// Instructs the controller to stop.
    /// We rely on the handle being dropped to instruct the controller to stop performing actions
    _stop_sender: oneshot::Sender<()>,
}
