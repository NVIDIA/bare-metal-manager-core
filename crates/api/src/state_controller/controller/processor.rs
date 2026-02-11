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

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::db::DatabaseError;
use model::controller_outcome::PersistentStateHandlerOutcome;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use super::db;
use crate::logging::sqlx_query_tracing::{self, SqlxQueryDataAggregation};
use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::ControllerIterationId;
use crate::state_controller::io::StateControllerIO;
use crate::state_controller::metrics::{
    IterationMetrics, MetricHolder, ObjectHandlerMetrics, StateProcessorMetricEmitter,
};
use crate::state_controller::state_change_emitter::{StateChangeEmitter, StateChangeEvent};
use crate::state_controller::state_handler::{
    FromStateHandlerResult, StateHandler, StateHandlerContext, StateHandlerContextObjects,
    StateHandlerError, StateHandlerOutcome, StateHandlerOutcomeWithTransaction,
};

/// The `StateProcessor` is responsible for executing the state handler functions
/// for all objects where state handling is requested.
pub(super) struct StateProcessor<IO: StateControllerIO> {
    /// A database connection pool that can be used for additional queries
    pub(super) pool: sqlx::PgPool,
    pub(super) handler_services: Arc<<IO::ContextObjects as StateHandlerContextObjects>::Services>,
    pub(super) io: Arc<IO>,
    pub(super) state_handler: Arc<
        dyn StateHandler<
                State = IO::State,
                ControllerState = IO::ControllerState,
                ContextObjects = IO::ContextObjects,
                ObjectId = IO::ObjectId,
            >,
    >,
    pub(super) metric_emitter: Option<ProcessorMetricsEmitter>,
    pub(super) metric_holder: Arc<MetricHolder<IO>>,

    pub(super) object_metrics: HashMap<IO::ObjectId, CollectedMetrics<IO>>,
    /// The iteration ID for which metrics have been passed towards `metric_holder`
    pub(super) published_metrics_iteration_id: Option<ControllerIterationId>,
    pub(super) stop_token: CancellationToken,
    pub(super) iteration_config: IterationConfig,
    /// IDs of objects where the task handler is currently executed
    pub(super) in_flight: HashSet<IO::ObjectId>,
    /// Objects where the state handling task was finished but where the entry
    /// in the database has not yet been deleted.
    pub(super) completed_objects: HashSet<IO::ObjectId>,
    /// Objects for which another object handling task should be queued since
    /// the state handler returned `Transition`
    pub(super) requeue_objects: HashSet<IO::ObjectId>,
    pub(super) task_sender: tokio::sync::mpsc::UnboundedSender<ObjectHandlingTaskResult<IO>>,
    pub(super) task_receiver: tokio::sync::mpsc::UnboundedReceiver<ObjectHandlingTaskResult<IO>>,
    pub(super) data_since_iteration_start: DataSinceStartOfIteration,
    /// The last time a log message had been emitted
    pub(super) last_log_time: std::time::Instant,
    pub(super) stats_since_last_log: StatsSinceLastLog,
    pub(super) processor_span: tracing::Span,
    /// Globally unique ID that identifies the state controller (and processor) working on objects
    pub(super) processor_id: String,
    /// Emitter for broadcasting state change events to registered hooks.
    pub(super) state_change_emitter: Arc<StateChangeEmitter<IO::ObjectId, IO::ControllerState>>,
}
pub(super) struct ObjectHandlingTaskResult<IO: StateControllerIO> {
    object_id: IO::ObjectId,
    metrics: ObjectHandlerMetrics<IO>,
}

pub(super) struct CollectedMetrics<IO: StateControllerIO> {
    metrics: ObjectHandlerMetrics<IO>,
    refreshed_in_current_iteration: bool,
}

#[derive(Debug)]
pub(super) struct DataSinceStartOfIteration {
    /// The time when the first state state handling task for the iteration was dequeued
    iteration_started_at: std::time::Instant,
    iteration_started_at_utc: chrono::DateTime<chrono::Utc>,
}

impl std::default::Default for DataSinceStartOfIteration {
    fn default() -> Self {
        Self {
            iteration_started_at: std::time::Instant::now(),
            iteration_started_at_utc: chrono::Utc::now(),
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub(super) struct SingleIterationResult {
    /// The amount of object handling tasks that have been dequeued from the database
    /// and dispatched for handling
    pub(super) num_dispatched_tasks: usize,
    /// The amount of object handling tasks which completed
    pub(super) num_completed_tasks: usize,
}

#[derive(Debug, Default, Clone)]
pub(super) struct StatsSinceLastLog {
    /// The amount of object handling tasks that have been dequeued from the database
    /// and dispatched for handling
    num_dispatched_tasks: usize,
    /// The amount of object handling tasks which completed
    num_completed_tasks: usize,
    /// The amount of tasks which returned an error
    num_errored_tasks: usize,
    /// The amount of queued objects which have been deleted from the DB
    num_deleted_queued_objects: usize,
    /// The amount of objects which have been queued again for statehandling
    num_requeued_objects: usize,
    /// The aggregated sqlx metrics at the last time logs had been emitted
    db_query_metrics: SqlxQueryDataAggregation,
}

#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
struct QueueStats {
    /// The ID of the latest iteration that had been started
    latest_iteration: Option<ControllerIterationId>,
    /// The ID of the last iteration (before the most recent one)
    previous_iteration: Option<ControllerIterationId>,
}

impl<IO: StateControllerIO> StateProcessor<IO> {
    /// Runs the state handler task repeatedly, while waiting for the configured
    /// amount of time between runs.
    ///
    /// The controller task will continue to run until `stop_receiver` was signaled
    pub async fn run(mut self) {
        let dispatch_interval = self.iteration_config.processor_dispatch_interval;
        let max_jitter = (dispatch_interval.as_millis() / 3) as u64;

        loop {
            let span = self.processor_span.clone();
            let start = Instant::now();
            let jitter = if max_jitter > 0 {
                rand::rng().random::<u64>() % max_jitter
            } else {
                0
            };
            let iteration_time = dispatch_interval.saturating_add(Duration::from_millis(jitter));
            let mut next_dispatch_at = start.checked_add(iteration_time).unwrap_or(start);

            match self
                .run_single_iteration(iteration_time, true)
                .instrument(span)
                .await
            {
                Ok(result) => {
                    // If any task completed, then there's a chance we can dispatch more tasks
                    // Therefore run another iteration without backoff
                    if result.num_completed_tasks > 1 {
                        next_dispatch_at = start;
                    }
                }
                Err(err) => {
                    tracing::error!(controller=IO::LOG_SPAN_CONTROLLER_NAME, %err, "State processor iteration error")
                }
            }

            // The iteration might not have used up all of dispatch_interval in case
            // all dispatched tasks finished earlier. In this case we wait the configured
            // time before the next dispatch.
            use rand::Rng;
            let sleep_time = next_dispatch_at.saturating_duration_since(std::time::Instant::now());
            if !sleep_time.is_zero() {
                let cancelled_future = self.stop_token.cancelled();
                tokio::pin!(cancelled_future);
                tokio::select! {
                        biased;
                    _ = &mut cancelled_future => {
                        tracing::info!(controller=IO::LOG_SPAN_CONTROLLER_NAME, "State processor stop was requested");
                        return;
                    }
                    _ = tokio::time::sleep(sleep_time) => {},
                }
            } else if self.stop_token.is_cancelled() {
                tracing::info!(
                    controller = IO::LOG_SPAN_CONTROLLER_NAME,
                    "State processor stop was requested"
                );
                return;
            }
        }
    }

    /// Calculates how many additional object handling tasks can be spawned
    fn remaining_capacity(&self) -> usize {
        self.iteration_config
            .max_concurrency
            .saturating_sub(self.in_flight.len())
    }

    /// Performs a single state processor iteration.
    /// The iteration will dispatch as many object handling tasks as possible,
    /// and then wait for the specified time for as many completions as possible.
    pub(super) async fn run_single_iteration(
        &mut self,
        max_completion_wait_time: std::time::Duration,
        allow_requeue: bool,
    ) -> Result<SingleIterationResult, IterationError> {
        let num_dispatched_tasks = self.dequeue_and_dispatch_object_handling_tasks().await?;
        // We are assuming that we dispatch as many tasks that are available and fit into
        // the queue. Therefore its ok to wait until at least one task has been dequeued
        // before evaluating any next steps.
        let num_completed_tasks = self
            .wait_and_process_object_handling_task_completions(
                max_completion_wait_time,
                allow_requeue,
            )
            .await;

        // Delete the DB entries for tasks which finished in `wait_and_process_object_handling_task_completions`.
        self.cleanup_completed_objects().await?;

        // Schedule handler again for objects which transitioned.
        // We queue them using the latest iteration_id.
        // This needs to happen after `cleanup_completed_objects` to remove
        // the old entries from the DB first.
        self.requeue_transitioned_objects().await?;

        let queue_stats = self.gather_queue_stats().await?;
        self.emit_metric_if_iteration_changed(&queue_stats);

        self.emit_periodic_log_if_necessary();

        Ok(SingleIterationResult {
            num_dispatched_tasks,
            num_completed_tasks,
        })
    }

    async fn gather_queue_stats(&self) -> Result<QueueStats, IterationError> {
        // We don't need a transaction for a pulling stats
        let mut conn = self.pool.acquire().await?;
        let iterations =
            db::fetch_iterations(&mut conn, IO::DB_ITERATION_ID_TABLE_NAME, Some(2)).await?;
        let latest_iteration = iterations.first().cloned().map(|iteration| iteration.id);
        let previous_iteration = if iterations.len() >= 2 {
            Some(iterations[1].id)
        } else {
            None
        };

        Ok(QueueStats {
            latest_iteration,
            previous_iteration,
        })
    }

    /// Publishes metrics for the previous iteration ID.
    /// Since we want the metrics to be emitted on time (coordinated across multiple
    /// state controller instances), we won't wait until all tasks are finished.
    fn emit_metric_if_iteration_changed(&mut self, stats: &QueueStats) {
        self.emit_metrics_for_iteration(stats.previous_iteration);
    }

    /// Publishes metrics for a certain iteration ID, based on all data that is currently
    /// known within that iteration.
    /// If the target ID is `None`, an empty set of metrics will be emitted.
    pub(super) fn emit_metrics_for_iteration(
        &mut self,
        finished_iteration_id: Option<ControllerIterationId>,
    ) {
        if self.published_metrics_iteration_id == finished_iteration_id {
            // Metrics are already published
            return;
        }
        self.published_metrics_iteration_id = finished_iteration_id;

        let mut aggregate = IterationMetrics::<IO>::default();
        for object_metrics in self.object_metrics.values() {
            aggregate.merge_object_handling_metrics(&object_metrics.metrics);
        }

        // Remove metrics that have not been refreshed in the last iteration
        // Metrics that have gathered in this iteration will carry forward forward
        // for one more iteration.
        // This prevents the race condition where handlers for some objects already
        // finish processing for iteration N+1 before metrics for iteration N are emitted.
        // In that case the metrics for iteration N+1 would be lost.
        self.object_metrics
            .retain(|_object_id, metrics| metrics.refreshed_in_current_iteration);
        for object_metrics in self.object_metrics.values_mut() {
            object_metrics.refreshed_in_current_iteration = false;
        }

        emit_iteration_log(
            finished_iteration_id,
            self.data_since_iteration_start.iteration_started_at_utc,
            &aggregate,
        );

        if let Some(emitter) = self.metric_emitter.as_ref() {
            emitter.emit_iteration_counters_and_histograms(&self.data_since_iteration_start);
        }

        self.data_since_iteration_start = DataSinceStartOfIteration::default();

        self.metric_holder
            .last_iteration_specific_metrics
            .update(aggregate.specific);
        self.metric_holder
            .last_iteration_common_metrics
            .update(aggregate.common);
    }

    fn emit_periodic_log_if_necessary(&mut self) {
        let now = std::time::Instant::now();
        if now
            < self
                .last_log_time
                .checked_add(self.iteration_config.processor_log_interval)
                .unwrap_or(now)
        {
            return;
        }

        self.last_log_time = now;
        let db_query_metrics = {
            let _e: tracing::span::Entered<'_> = self.processor_span.enter();
            sqlx_query_tracing::fetch_and_update_current_span_attributes()
        };

        let stats = std::mem::take(&mut self.stats_since_last_log);
        let db_metrics_since_last_query = db_query_metrics.diff(&stats.db_query_metrics);
        self.stats_since_last_log.db_query_metrics = db_query_metrics;

        if let Some(emitter) = self.metric_emitter.as_ref() {
            emitter.emit_db_ops_metrics(&db_metrics_since_last_query, IO::LOG_SPAN_CONTROLLER_NAME);
        }

        tracing::info!(
            controller = IO::LOG_SPAN_CONTROLLER_NAME,
            tasks_in_flight = self.in_flight.len(),
            completed_tasks = stats.num_completed_tasks,
            dispatched_tasks = stats.num_dispatched_tasks,
            requeued_objects = stats.num_requeued_objects,
            errored_tasks = stats.num_errored_tasks,
            sql_queries = db_metrics_since_last_query.num_queries,
            sql_total_rows_affected = db_metrics_since_last_query.total_rows_affected,
            sql_total_rows_returned = db_metrics_since_last_query.total_rows_returned,
            sql_total_query_duration_us =
                db_metrics_since_last_query.total_query_duration.as_micros(),
            "state_processor",
        );
    }

    /// Waits for object handling tasks to finish
    ///
    /// The function will return if all in-flight tasks have been completed and additional waiting is unnecessary.
    /// In addition, `max_duration` can be used to specify how long to wait for completions.
    ///
    /// Returns the amount of task completions
    async fn wait_and_process_object_handling_task_completions(
        &mut self,
        max_duration: std::time::Duration,
        allow_requeue: bool,
    ) -> usize {
        // Don't wait if there's nothing to do.
        if self.in_flight.is_empty() {
            return 0;
        }

        let mut finished_tasks: Vec<_> = Vec::with_capacity(self.in_flight.len());
        let finished_tasks_capacity = finished_tasks.capacity();
        let mut total_completions = 0;

        tokio::select! {
            biased;
            num_received = self.task_receiver.recv_many(&mut finished_tasks, finished_tasks_capacity) => {
                for _ in 0 .. num_received {
                    let finished_task = finished_tasks.pop().expect("Object handling task finished");
                    self.process_object_handling_task_result(finished_task, allow_requeue);
                    total_completions += 1;
                }
            }
            _ = tokio::time::sleep(max_duration) => {
                // Timeout
            }
        };

        if total_completions > 0
            && let Some(emitter) = &self.metric_emitter
        {
            emitter
                .completed_tasks_counter
                .add(total_completions as u64, &[]);
        }

        total_completions
    }

    /// Determines how many additional state handling tasks can be processed,
    /// dequeues up to that amount from the global queue, and sends the task up to processing.
    async fn dequeue_and_dispatch_object_handling_tasks(
        &mut self,
    ) -> Result<usize, IterationError> {
        // Determine how many new objects can still be processed and dequeue that amount
        let capacity = self.remaining_capacity();
        let objects = if capacity > 0 {
            // Acquire new object handling tasks
            // If processing of an object was already start by another state controller
            // but not committed, it can be acquired after a certain amount of time.
            // The time is higher than the task handling timeout on each state controller.
            // This guarantees that the task is no longer processed by the original owner.
            let capacity = capacity.min(u32::MAX as usize) as u32;
            let mut txn = self.pool.begin().await?;
            let queued = db::acquire_queued_objects(
                &mut txn,
                IO::DB_QUEUED_OBJECTS_TABLE_NAME,
                capacity,
                &self.processor_id,
                self.iteration_config.max_object_handling_time * 3,
            )
            .await?;
            txn.commit().await?;
            queued
        } else {
            Vec::new()
        };

        let objects: Vec<IO::ObjectId> = objects
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

        let num_dispatched_tasks = objects.len();
        self.stats_since_last_log.num_dispatched_tasks += num_dispatched_tasks;

        // Send off the new objects for processing
        for object_id in objects {
            self.dispatch_object_handling_task(object_id.clone());
            self.in_flight.insert(object_id);
        }

        if let Some(emitter) = &self.metric_emitter
            && num_dispatched_tasks > 0
        {
            emitter
                .dispatched_tasks_counter
                .add(num_dispatched_tasks as u64, &[]);
        }

        Ok(num_dispatched_tasks)
    }

    // Executes the state handling function for all objects for a single queued object
    fn dispatch_object_handling_task(&mut self, object_id: IO::ObjectId) {
        let cloned_object_id = object_id.clone();
        let pool = self.pool.clone();
        let services = self.handler_services.as_ref().clone();
        let io = self.io.clone();
        let handler = self.state_handler.clone();
        let max_object_handling_time = self.iteration_config.max_object_handling_time;
        let metrics_emitter = self.metric_holder.emitter.clone();
        let state_change_emitter = self.state_change_emitter.clone();
        let result_sender = self.task_sender.clone();

        let _join_handle = tokio::task::Builder::new()
            .name(&format!("state_processor {object_id}"))
            .spawn(
                async move {
                    let metrics = process_object(
                        cloned_object_id.clone(),
                        pool,
                        services,
                        io,
                        handler,
                        max_object_handling_time,
                        metrics_emitter,
                        state_change_emitter,
                    )
                    .await;

                    if let Err(e) = result_sender.send(ObjectHandlingTaskResult {
                        object_id: cloned_object_id,
                        metrics,
                    }) {
                        tracing::error!(
                            object_id = %e.0.object_id,
                            "Can't send result back to StateProcessor"
                        );
                    }
                }
                .in_current_span(),
            )
            .expect("Expect task to spawn");
    }

    async fn cleanup_completed_objects(&mut self) -> Result<(), IterationError> {
        if self.completed_objects.is_empty() {
            return Ok(());
        }

        let object_ids: Vec<String> = self
            .completed_objects
            .iter()
            .map(|id| id.to_string())
            .collect();
        let mut txn = self.pool.begin().await?;
        let num_deleted = db::delete_queued_objects(
            &mut txn,
            IO::DB_QUEUED_OBJECTS_TABLE_NAME,
            &object_ids,
            &self.processor_id,
        )
        .await?;
        txn.commit().await?;

        debug_assert_eq!(
            object_ids.len(),
            num_deleted,
            "Not all objects have been deleted from the database"
        );

        self.stats_since_last_log.num_deleted_queued_objects += num_deleted;
        self.completed_objects.clear();
        Ok(())
    }

    async fn requeue_transitioned_objects(&mut self) -> Result<(), IterationError> {
        if self.requeue_objects.is_empty() {
            return Ok(());
        }

        let queue_objects: Vec<String> = self
            .requeue_objects
            .iter()
            .map(|id| id.to_string())
            .collect();
        let mut txn = self.pool.begin().await?;
        let num_requeued =
            db::queue_objects(&mut txn, IO::DB_QUEUED_OBJECTS_TABLE_NAME, &queue_objects).await?;
        txn.commit().await?;

        self.stats_since_last_log.num_requeued_objects += num_requeued;
        if let Some(emitter) = &self.metric_emitter {
            emitter.requeued_tasks_counter.add(num_requeued as u64, &[]);
        }
        self.requeue_objects.clear();
        Ok(())
    }

    fn process_object_handling_task_result(
        &mut self,
        task_result: ObjectHandlingTaskResult<IO>,
        allow_requeue: bool,
    ) {
        // We don't remove objects from the database here but store them first
        // and remove them later in order to not forget about these in case there
        // is a transient database error
        self.completed_objects.insert(task_result.object_id.clone());
        // If the state handler returned `Transition`, then run the handler again
        // as soon as possible.
        if allow_requeue && task_result.metrics.common.next_state.is_some() {
            self.requeue_objects.insert(task_result.object_id.clone());
        }

        self.stats_since_last_log.num_completed_tasks += 1;
        if task_result.metrics.common.error.is_some() {
            self.stats_since_last_log.num_errored_tasks += 1;
        }

        self.in_flight.remove(&task_result.object_id);
        self.object_metrics.insert(
            task_result.object_id.clone(),
            CollectedMetrics {
                metrics: task_result.metrics,
                refreshed_in_current_iteration: true,
            },
        );
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum IterationError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Unable to perform database transaction: {0}")]
    DatabaseError(#[from] DatabaseError),
    #[error("A task panicked: {0}")]
    Panic(#[from] tokio::task::JoinError),
    #[error("State handler error: {0}")]
    StateHandlerError(#[from] StateHandlerError),
}

#[allow(clippy::too_many_arguments)]
async fn process_object<IO: StateControllerIO>(
    object_id: IO::ObjectId,
    pool: sqlx::PgPool,
    mut services: <IO::ContextObjects as StateHandlerContextObjects>::Services,
    io: Arc<IO>,
    handler: Arc<
        dyn StateHandler<
                State = IO::State,
                ControllerState = IO::ControllerState,
                ContextObjects = IO::ContextObjects,
                ObjectId = IO::ObjectId,
            >,
    >,
    max_object_handling_time: std::time::Duration,
    metrics_emitter: Option<Arc<StateProcessorMetricEmitter<IO>>>,
    state_change_emitter: Arc<StateChangeEmitter<IO::ObjectId, IO::ControllerState>>,
) -> ObjectHandlerMetrics<IO> {
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
        metrics.common.time_in_state_above_sla = state_sla.time_in_state_above_sla;

        let mut ctx = StateHandlerContext {
            services: &mut services,
            metrics: &mut metrics.specific,
        };

        // Commit the transaction now, since we don't want to leave a txn open
        // throughout handle_object_state.
        txn.commit().await?;

        let handler_output = handler
            .handle_object_state(&object_id, &mut snapshot, &controller_state.value, &mut ctx)
            .await;

        // What transaction should we use for persisting the outcome? If the
        // handler was successful and gave us back a transaction, use that,
        // otherwise make our own.
        let (handler_outcome, mut txn) = match handler_output {
            Ok(StateHandlerOutcomeWithTransaction {
                outcome,
                transaction,
            }) => {
                if let Some(txn) = transaction {
                    (Ok(outcome), txn)
                } else {
                    (Ok(outcome), pool.begin().await?)
                }
            }
            Err(e) => (Err(e), pool.begin().await?),
        };

        let mut next_state = None;
        if let Ok(StateHandlerOutcome::Transition {
            next_state: next, ..
        }) = &handler_outcome
        {
            next_state = Some(next.clone());

            if *next == controller_state.value {
                tracing::warn!(state=?next, %object_id, "Transition to current state");
            }
            io.persist_controller_state(&mut txn, &object_id, controller_state.version, next)
                .await?;
        }

        let is_success = handler_outcome.is_ok();

        // If the state handler neither transitioned nor returned no error,
        // but the object is stuck in the state for longer than the defined SLA,
        // then transform the outcome into an error
        let handler_outcome = match handler_outcome {
            Ok(StateHandlerOutcome::Wait { reason, .. }) if state_sla.time_in_state_above_sla => {
                Err(StateHandlerError::TimeInStateAboveSla {
                    handler_outcome: format!("Wait(\"{reason}\")"),
                })
            }
            Ok(StateHandlerOutcome::DoNothing { .. }) if state_sla.time_in_state_above_sla => {
                Err(StateHandlerError::TimeInStateAboveSla {
                    handler_outcome: "DoNothing".to_string(),
                })
            }
            _ => handler_outcome,
        };

        if is_success {
            // Commit transaction only when handler returned the Success.
            if !matches!(handler_outcome, Ok(StateHandlerOutcome::Deleted { .. })) {
                let db_outcome =
                    PersistentStateHandlerOutcome::from_result(handler_outcome.as_ref());
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
        Ok(Ok(_result)) => Ok(()),
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
    if let Err(e) = result {
        tracing::warn!(%object_id, error = ?e, "State handler error");
        metrics.common.error = Some(e);
    }

    metrics
}

#[derive(Debug)]
pub(super) struct ProcessorMetricsEmitter {
    controller_iteration_latency: Histogram<f64>,
    dispatched_tasks_counter: Counter<u64>,
    completed_tasks_counter: Counter<u64>,
    requeued_tasks_counter: Counter<u64>,
    db: sqlx_query_tracing::DatabaseMetricEmitters,
}

impl ProcessorMetricsEmitter {
    pub(super) fn new(object_type: &str, meter: &Meter) -> Self {
        let db = sqlx_query_tracing::DatabaseMetricEmitters::new(meter);

        let controller_iteration_latency = meter
            .f64_histogram(format!("{object_type}_iteration_latency"))
            .with_description(format!(
                "The overall time it took to handle state for all {object_type} in the system"
            ))
            .with_unit("ms")
            .build();

        let dispatched_tasks_counter = meter
            .u64_counter(format!("{object_type}_object_tasks_dispatched"))
            .with_description(format!(
                "The amount of types that object handling tasks that have been dequeued and dispatched for processing for objects of type {object_type}"
            ))
            .build();

        let completed_tasks_counter = meter
            .u64_counter(format!("{object_type}_object_tasks_completed"))
            .with_description(format!(
                "The amount of object handling tasks that have been completed for objects of type {object_type}"
            ))
            .build();

        let requeued_tasks_counter = meter
            .u64_counter(format!("{object_type}_object_tasks_requeued"))
            .with_description(format!(
                "The amount of object handling tasks that have been requeued for objects of type {object_type}"
            ))
            .build();

        Self {
            controller_iteration_latency,
            db,
            dispatched_tasks_counter,
            completed_tasks_counter,
            requeued_tasks_counter,
        }
    }

    fn emit_db_ops_metrics(
        &self,
        db_metrics: &sqlx_query_tracing::SqlxQueryDataAggregation,
        log_span_name: &str,
    ) {
        // We use an attribute to distinguish the query counter from the
        // ones that are used for other state controller and for gRPC requests
        let attrs = &[KeyValue::new("operation", log_span_name.to_string())];
        self.db.emit(db_metrics, attrs);
    }

    fn emit_iteration_counters_and_histograms(&self, iteration_data: &DataSinceStartOfIteration) {
        self.controller_iteration_latency.record(
            1000.0 * iteration_data.iteration_started_at.elapsed().as_secs_f64(),
            &[],
        );
    }
}

/// Emits the metrics that had been collected during a state controller iteration
/// as a single log line.
fn emit_iteration_log<IO: StateControllerIO>(
    iteration_id: Option<ControllerIterationId>,
    iteration_processing_started_at: chrono::DateTime<chrono::Utc>,
    iteration_metrics: &IterationMetrics<IO>,
) {
    let timing_start_time = format!("{:?}", iteration_processing_started_at);
    let elapsed = chrono::Utc::now().signed_duration_since(iteration_processing_started_at);
    let timing_elapsed_us = elapsed.num_microseconds().unwrap_or_default().to_string();
    let iteration_id = iteration_id.map(|id| id.0).unwrap_or_default().to_string();

    let mut total_objects = 0;
    let mut states: HashMap<String, usize> = HashMap::new();
    let mut states_above_sla: HashMap<String, usize> = HashMap::new();
    let mut error_types: HashMap<String, HashMap<String, usize>> = HashMap::new();
    for (full_state, state_metrics) in iteration_metrics.common.state_metrics.iter() {
        total_objects += state_metrics.num_objects;

        let full_state_name = if !full_state.substate.is_empty() {
            format!("{}.{}", full_state.state, full_state.substate)
        } else {
            full_state.state.to_string()
        };

        for (error, &count) in state_metrics.handling_errors_per_type.iter() {
            *error_types
                .entry(full_state_name.clone())
                .or_default()
                .entry(error.to_string())
                .or_default() += count;
        }

        states.insert(full_state_name.clone(), state_metrics.num_objects);
        if state_metrics.num_objects_above_sla > 0 {
            states_above_sla.insert(full_state_name.clone(), state_metrics.num_objects_above_sla);
        }
    }

    let states = serde_json::to_string(&states).unwrap_or_else(|_| "{}".to_string());
    let states_above_sla =
        serde_json::to_string(&states_above_sla).unwrap_or_else(|_| "{}".to_string());
    let error_types = serde_json::to_string(&error_types).unwrap_or_else(|_| "{}".to_string());

    tracing::info!(name: "state_controller_iteration", controller = IO::LOG_SPAN_CONTROLLER_NAME, %iteration_id, %total_objects, %states, %states_above_sla, %error_types, %timing_start_time, %timing_elapsed_us);
}
