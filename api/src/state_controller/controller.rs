/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{sync::oneshot, task::JoinSet};
use tracing::Instrument;

use crate::{
    logging::sqlx_query_tracing,
    state_controller::{
        config::IterationConfig,
        io::StateControllerIO,
        metrics::{IterationMetrics, MetricHolder, ObjectHandlerMetrics},
        snapshot_loader::SnapshotLoaderError,
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
            StateHandlerOutcome, StateHandlerServices,
        },
    },
};

mod builder;

/// The object static controller evaluates the current state of all objects of a
/// certain type in a Forge site, and decides which actions the system should
/// undertake to bring the state inline with the state users requested.
///
/// Each Forge API server is running a StateController instance for each object type.
/// While all instances run in parallel, the StateController uses internal
/// synchronization to make sure that inside a single site - only a single controller
/// will decide the next step for a single object.
pub struct StateController<IO: StateControllerIO> {
    handler_services: Arc<StateHandlerServices>,
    io: Arc<IO>,
    lock_query: String,
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
            let jitter = rand::thread_rng().gen::<u64>()
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
            tracing::Level::INFO,
            "state_controller_iteration",
            span_id,
            controller = IO::LOG_SPAN_CONTROLLER_NAME,
            otel.status_code = tracing::field::Empty,
            otel.status_message = tracing::field::Empty,
            skipped_iteration = tracing::field::Empty,
            num_objects = tracing::field::Empty,
            num_errors = tracing::field::Empty,
            states = tracing::field::Empty,
            states_above_sla = tracing::field::Empty,
            error_types = tracing::field::Empty,
            times_in_state_s = tracing::field::Empty,
            handler_latencies_us = tracing::field::Empty,
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
                controller_span.record("otel.status_message", format!("{:?}", e));
            }
        }

        // Immediately emit latency metrics
        // These will be emitted both in cases where we actually acted on objects
        // as well as for cases where we didn't get the lock. Since the
        // latter case doesn't handle any objects it will be a no-op apart
        // from emitting the latency for not getting the lock.
        if let Some(emitter) = self.metric_holder.emitter.as_ref() {
            emitter.emit_latency_metrics(IO::LOG_SPAN_CONTROLLER_NAME, &metrics, &db_query_metrics);
            emitter.set_iteration_span_attributes(&controller_span, &metrics);
        }

        // If we actually performed an iteration (and not failed to obtain the lock),
        // cache all other metrics that have been captured in this iteration.
        // Those will be queried by OTEL on demand
        if res.is_ok() {
            self.metric_holder
                .last_iteration_metrics
                .store(Some(Arc::new(metrics)));
        }

        iteration_result
    }

    async fn lock_and_handle_iteration(
        &mut self,
        iteration_metrics: &mut IterationMetrics<IO>,
    ) -> Result<(), IterationError> {
        let mut txn = self.handler_services.pool.begin().await?;

        let locked: bool = sqlx::query_scalar(&self.lock_query)
            .fetch_one(&mut *txn)
            .await?;
        tracing::Span::current().record("skipped_iteration", !locked);

        if !locked {
            tracing::info!(
                lock = IO::DB_LOCK_NAME,
                "State controller was not able to obtain the lock",
            );
            return Err(IterationError::LockError);
        }
        tracing::trace!(
            lock = IO::DB_LOCK_NAME,
            "State controller acquired the lock",
        );

        self.handle_iteration(iteration_metrics).await?;

        txn.commit().await?;

        Ok(())
    }

    async fn handle_iteration(
        &mut self,
        iteration_metrics: &mut IterationMetrics<IO>,
    ) -> Result<(), IterationError> {
        // We start by grabbing a list of objects that should be active
        // The list might change until we fetch more data. However that should be ok:
        // The next iteration of the controller would also find objects that
        // have been added to the system. And no object should ever be removed
        // outside of the state controller
        let mut txn = self.handler_services.pool.begin().await?;
        let object_ids = self.io.list_objects(&mut txn).await?;
        txn.commit().await?;

        let mut task_set = JoinSet::new();

        let concurrency_limiter = Arc::new(tokio::sync::Semaphore::new(
            self.iteration_config.max_concurrency,
        ));

        for object_id in object_ids.iter() {
            let object_id = object_id.clone();
            let services = self.handler_services.clone();
            let io = self.io.clone();
            let handler = self.state_handler.clone();
            let concurrency_limiter = concurrency_limiter.clone();
            let max_object_handling_time = self.iteration_config.max_object_handling_time;

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
                            let mut txn = services.pool.begin().await?;
                            let mut snapshot = io.load_object_state(&mut txn, &object_id).await?;
                            let mut controller_state = io
                                .load_controller_state(&mut txn, &object_id, &snapshot)
                                .await?;
                            metrics.common.initial_state = Some(controller_state.value.clone());
                            // Unwrap uses a very large duration as default to show something is wrong
                            metrics.common.time_in_state = chrono::Utc::now()
                                .signed_duration_since(controller_state.version.timestamp())
                                .to_std()
                                .unwrap_or(Duration::from_secs(60 * 60 * 24));
                            metrics.common.time_in_state_above_sla =
                                IO::time_in_state_above_sla(&controller_state);

                            let mut ctx = StateHandlerContext {
                                services: &services,
                                metrics: &mut metrics.specific,
                            };

                            let mut state_holder =
                                ControllerStateReader::new(&mut controller_state.value);

                            let handler_outcome = handler
                                .handle_object_state(
                                    &object_id,
                                    &mut snapshot,
                                    &mut state_holder,
                                    &mut txn,
                                    &mut ctx,
                                )
                                .await;

                            let mut next_state = None;
                            if let Ok(StateHandlerOutcome::Transition(next)) = &handler_outcome {
                                next_state = Some(next.clone());

                                io.persist_controller_state(
                                    &mut txn,
                                    &object_id,
                                    controller_state.version,
                                    next.clone(),
                                )
                                .await?;
                            }
                            if !matches!(handler_outcome, Ok(StateHandlerOutcome::Deleted)) {
                                let db_outcome = handler_outcome.as_ref().into();
                                io.persist_outcome(&mut txn, &object_id, db_outcome).await?;
                            }
                            txn.commit()
                                .await
                                .map_err(StateHandlerError::TransactionError)?;

                            // Only emit the next state as metric if the transaction was actually
                            // committed and we are sure we reached the next state
                            metrics.common.next_state = next_state;

                            handler_outcome
                        })
                        .await;
                        metrics.common.handler_latency = start.elapsed();

                        let result = match result {
                            Ok(Ok(result)) => Ok(result),
                            Ok(Err(err)) => Err(err),
                            Err(_timeout) => Err(StateHandlerError::Timeout {
                                object_id: object_id.to_string(),
                                state: metrics
                                    .common
                                    .initial_state
                                    .as_ref()
                                    .map(|state| format!("{:?}", state))
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

        if let Some(emitter) = self.metric_holder.emitter.as_ref() {
            emitter.update_histograms(iteration_metrics);
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
    #[error("Unable to acquire lock")]
    LockError,
    #[error("A task panicked: {0}")]
    Panic(#[from] tokio::task::JoinError),
    #[error("State handler error: {0}")]
    StateHandlerError(#[from] StateHandlerError),
    #[error("Snapshot loader error: {0}")]
    SnapshotLoaderError(#[from] SnapshotLoaderError),
}

/// A remote handle for the state controller
pub struct StateControllerHandle {
    /// Instructs the controller to stop.
    /// We rely on the handle being dropped to instruct the controller to stop performing actions
    _stop_sender: oneshot::Sender<()>,
}
