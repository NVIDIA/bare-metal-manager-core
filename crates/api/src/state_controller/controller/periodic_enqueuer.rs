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

use std::sync::Arc;
use std::time::{Duration, Instant};

use ::db::work_lock_manager::WorkLockManagerHandle;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::{
    ControllerIteration, ControllerIterationId, IterationError, db,
};
use crate::state_controller::io::StateControllerIO;

/// Periodically enqueues state handling tasks for all objects that are managed by the
/// state controller.
/// The task is guaranteed to only run on a single carbide instance at a time.
pub(super) struct PeriodicEnqueuer<IO: StateControllerIO> {
    /// A database connection pool that can be used for additional queries
    pub(super) pool: sqlx::PgPool,
    pub(super) work_lock_manager_handle: WorkLockManagerHandle,
    pub(super) io: Arc<IO>,
    pub(super) metric_emitter: Option<EnqueuerMetricsEmitter>,
    pub(super) stop_token: CancellationToken,
    pub(super) iteration_config: IterationConfig,
}

pub(super) struct SingleIterationResult {
    /// Whether the iteration was skipped due to not being able to obtain the lock.
    /// This will be `true` if the lock could not be obtained.
    pub(super) skipped_iteration: bool,
    /// The iteration that was started
    pub(super) iteration: Option<ControllerIteration>,
}

impl<IO: StateControllerIO> PeriodicEnqueuer<IO> {
    /// Runs the state handler task repeadetly, while waiting for the configured
    /// amount of time between runs.
    ///
    /// The controller task will continue to run until `stop_receiver` was signaled
    pub(super) async fn run(mut self) {
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
            let iteration_max_jitter = if iteration_result.skipped_iteration {
                err_jitter
            } else {
                max_jitter
            };
            let jitter = if iteration_max_jitter > 0 {
                rand::rng().random::<u64>() % iteration_max_jitter
            } else {
                0
            };
            let sleep_time = self
                .iteration_config
                .iteration_time
                .saturating_sub(start.elapsed())
                .saturating_add(Duration::from_millis(jitter));

            let cancelled_future = self.stop_token.cancelled();
            tokio::pin!(cancelled_future);
            tokio::select! {
                biased;
                _ = &mut cancelled_future => {
                    tracing::info!(controller=IO::LOG_SPAN_CONTROLLER_NAME, "PeriodicEnqueuer stop was requested");
                    return;
                }
                _ = tokio::time::sleep(sleep_time) => {}
            }
        }
    }

    /// Performs a single enqueuer iteration
    ///
    /// This includes
    /// - Generating a Span for the iteration
    /// - Loading all object IDs
    /// - Generate tasks that request state handling for all objects
    /// - Storing and emitting metrics for the run
    pub(super) async fn run_single_iteration(&mut self) -> SingleIterationResult {
        let span_id = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));
        let mut metrics = PeriodicEnqueuerMetrics::default();
        let mut iteration_result = SingleIterationResult {
            skipped_iteration: false,
            iteration: None,
        };

        let controller_span = tracing::span!(
            parent: None,
            tracing::Level::INFO,
            "periodic_enqueuer_iteration",
            span_id,
            controller = IO::LOG_SPAN_CONTROLLER_NAME,
            iteration_id = tracing::field::Empty,
            otel.status_code = tracing::field::Empty,
            otel.status_message = tracing::field::Empty,
            skipped_iteration = tracing::field::Empty,
            num_enqueued_objects = tracing::field::Empty,
            app_timing_start_time = format!("{:?}", chrono::Utc::now()),
            app_timing_end_time = tracing::field::Empty,
        );

        let res = self
            .lock_and_handle_iteration(&mut metrics)
            .instrument(controller_span.clone())
            .await;
        metrics.recording_finished_at = std::time::Instant::now();

        controller_span.record("otel.status_code", if res.is_ok() { "ok" } else { "error" });

        match res {
            Ok(iteration_data) => {
                iteration_result.iteration = Some(iteration_data);
                controller_span.record("otel.status_code", "ok");
            }
            Err(IterationError::LockError) => {
                controller_span.record("otel.status_code", "ok");
                iteration_result.skipped_iteration = true;
            }
            Err(e) => {
                tracing::error!(controller=IO::LOG_SPAN_CONTROLLER_NAME, err=?e, "PeriodicEnqueuer iteration failed");
                controller_span.record("otel.status_code", "error");
                // Writing this field will set the span status to error
                // Therefore we only write it on errors
                controller_span.record("otel.status_message", format!("{e:?}"));
            }
        }

        if let Some(emitter) = self.metric_emitter.as_ref() {
            emitter.emit_iteration_counters_and_histograms(&metrics);
            emitter.set_iteration_span_attributes(&controller_span, &metrics);
        }

        controller_span.record("app_timing_end_time", format!("{:?}", chrono::Utc::now()));

        iteration_result
    }

    async fn lock_and_handle_iteration(
        &mut self,
        iteration_metrics: &mut PeriodicEnqueuerMetrics,
    ) -> Result<ControllerIteration, IterationError> {
        let locked_controller_iteration = match db::lock_and_start_iteration(
            &self.pool,
            &self.work_lock_manager_handle,
            IO::DB_ITERATION_ID_TABLE_NAME,
        )
        .await
        {
            Ok(locked_controller_iteration) => locked_controller_iteration,
            Err(e) => {
                tracing::Span::current().record("skipped_iteration", true);
                tracing::error!(
                    iteration_table_id = IO::DB_ITERATION_ID_TABLE_NAME,
                    error = %e,
                    "PeriodicEnqueuer was not able to start run"
                );
                return Err(IterationError::LockError);
            }
        };

        tracing::trace!(iteration_data = ?locked_controller_iteration.iteration_data, "Starting iteration with ID ");
        iteration_metrics.iteration_id = Some(locked_controller_iteration.iteration_data.id);

        self.enqueue_objects(iteration_metrics).await?;

        Ok(locked_controller_iteration.iteration_data)
    }

    /// Identifies all active objects that the PeriodicEnqueuer manages
    /// and enqueues them for state handler execution
    async fn enqueue_objects(
        &mut self,
        iteration_metrics: &mut PeriodicEnqueuerMetrics,
    ) -> Result<(), IterationError> {
        // We start by grabbing a list of objects that should be active
        // The list might change until we fetch more data. However that should be ok:
        // The next iteration of the controller would also find objects that
        // have been added to the system. And no object should ever be removed
        // outside of the state controller
        let mut txn = self.pool.begin().await?;
        let object_ids = self.io.list_objects(&mut txn).await?;

        let queued_objects: Vec<_> = object_ids
            .iter()
            .map(|object_id| object_id.to_string())
            .collect();
        txn.commit().await?;

        // The transactions for listing and enqueuing are decoupled to avoid
        // any locking side-effects
        let mut txn = self.pool.begin().await?;
        iteration_metrics.num_enqueued_objects =
            db::queue_objects(&mut txn, IO::DB_QUEUED_OBJECTS_TABLE_NAME, &queued_objects).await?;

        txn.commit().await?;

        Ok(())
    }
}

/// Metrics that are produced by a state controller iteration
#[derive(Debug)]
pub(super) struct PeriodicEnqueuerMetrics {
    /// When we started recording these metrics
    pub recording_started_at: std::time::Instant,
    /// When we finished recording the metrics
    pub recording_finished_at: std::time::Instant,
    /// The iteration ID
    pub iteration_id: Option<ControllerIterationId>,
    /// The amount of objects which have been enqueued in this run
    pub num_enqueued_objects: usize,
}

impl Default for PeriodicEnqueuerMetrics {
    fn default() -> Self {
        Self {
            recording_started_at: std::time::Instant::now(),
            recording_finished_at: std::time::Instant::now(),
            iteration_id: None,
            num_enqueued_objects: 0,
        }
    }
}

#[derive(Debug)]
pub(super) struct EnqueuerMetricsEmitter {
    enqueuer_iteration_latency: Histogram<f64>,
    num_enqueued_objects_counter: Counter<u64>,
}

impl EnqueuerMetricsEmitter {
    pub(super) fn new(object_type: &str, meter: &Meter) -> Self {
        let enqueuer_iteration_latency = meter
            .f64_histogram(format!("{object_type}_enqueuer_iteration_latency"))
            .with_description(format!(
                "The overall time it took to enqueue state handling tasks for all {object_type} in the system"
            ))
            .with_unit("ms")
            .build();

        let num_enqueued_objects_counter = meter
            .u64_counter(format!("{object_type}_object_tasks_enqueued"))
            .with_description(format!(
                "The amount of types that object handling tasks that have been freshly enqueued for objects of type {object_type}"
            ))
            .build();

        Self {
            enqueuer_iteration_latency,
            num_enqueued_objects_counter,
        }
    }

    fn emit_iteration_counters_and_histograms(&self, iteration_metrics: &PeriodicEnqueuerMetrics) {
        self.enqueuer_iteration_latency.record(
            1000.0
                * iteration_metrics
                    .recording_started_at
                    .elapsed()
                    .as_secs_f64(),
            &[],
        );

        self.num_enqueued_objects_counter
            .add(iteration_metrics.num_enqueued_objects as u64, &[]);
    }

    /// Emits the metrics that had been collected during a state controller iteration
    /// as attributes on the tracing/OpenTelemetry span.
    ///
    /// This is different from the metrics being emitted as gauges since the span
    /// will be emitted immediately after the iteration finishes. It will provide
    /// exact information for the single run. However the information can not
    /// be retrieved at any later time. The values for gauges are however cached
    /// and can be consumed until the next iteration.
    pub(super) fn set_iteration_span_attributes(
        &self,
        span: &tracing::Span,
        iteration_metrics: &PeriodicEnqueuerMetrics,
    ) {
        span.record(
            "num_enqueued_objects",
            iteration_metrics.num_enqueued_objects,
        );
        if let Some(iteration_id) = iteration_metrics.iteration_id.as_ref() {
            span.record("iteration_id", iteration_id.0);
        }
    }
}
