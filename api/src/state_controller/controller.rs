/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use arc_swap::ArcSwapOption;
use opentelemetry::metrics::Meter;
use tokio::{sync::oneshot, task::JoinSet};
use tracing::Instrument;

use crate::{
    ib::IBFabricManager,
    logging::sqlx_query_tracing,
    model::config_version::{ConfigVersion, Versioned},
    redfish::RedfishClientPool,
    resource_pool::DbResourcePool,
    state_controller::{
        metrics::{IterationMetrics, ObjectHandlerMetrics, StateControllerMetricEmitter},
        snapshot_loader::SnapshotLoaderError,
        state_handler::{
            ControllerStateReader, NoopStateHandler, StateHandler, StateHandlerContext,
            StateHandlerError, StateHandlerServices,
        },
    },
};

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
            ObjectId = IO::ObjectId,
        >,
    >,
    metric_holder: Arc<MetricHolder>,
    stop_receiver: oneshot::Receiver<()>,
    config: Config,
}

/// Stores Metric data shared between the Controller and the OpenTelemetry background task
struct MetricHolder {
    emitter: Option<StateControllerMetricEmitter>,
    last_iteration_metrics: ArcSwapOption<IterationMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Option<Meter>, object_type_for_metrics: &str) -> Self {
        let emitter = meter
            .as_ref()
            .map(|meter| StateControllerMetricEmitter::new(object_type_for_metrics, meter.clone()));

        Self {
            emitter,
            last_iteration_metrics: ArcSwapOption::const_empty(),
        }
    }
}

/// This trait defines on what objects a state controller instance will act,
/// and how it loads the objects state.
#[async_trait::async_trait]
pub trait StateControllerIO: Send + Sync + std::fmt::Debug + 'static + Default {
    type ObjectId: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static + Clone;
    type State: Send + Sync + 'static;
    type ControllerState: std::fmt::Debug + Send + Sync + 'static + Clone;

    /// Returns the name of the table in the database that will be used for advisory locking
    ///
    /// This lock will prevent multiple instances of controller running on multiple nodes
    /// from making changes to objects at the same time
    fn db_lock_name() -> &'static str;

    /// The name that will be used for the logging span created by the State Controller
    const LOG_SPAN_CONTROLLER_NAME: &'static str;

    /// Resolves the list of objects that the state controller should act upon
    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError>;

    /// Loads a state of an object
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError>;

    /// Loads the object state that is owned by the state controller
    async fn load_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, SnapshotLoaderError>;

    /// Persists the object state that is owned by the state controller
    async fn persist_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        old_version: ConfigVersion,
        new_state: Self::ControllerState,
    ) -> Result<(), SnapshotLoaderError>;

    /// Returns the names that should be used in metrics for a given object state
    /// The first returned value is the value that will be used for the main `state`
    /// attribute on each metric. The 2nd value - if not empty - will be used for
    /// an optional substate attribute.
    fn metric_state_names(state: &Self::ControllerState) -> (&'static str, &'static str);
}

/// Creates the query that will be used for advisory locking of a postgres table
/// with the given name.
///
/// Note that there is no real relation between the table and the query
/// We just use it to get an object identifier
fn create_lock_query(db_lock_name: &str) -> String {
    format!(
        "SELECT pg_try_advisory_xact_lock((SELECT '{}'::regclass::oid)::integer);",
        db_lock_name
    )
}

impl<IO: StateControllerIO> StateController<IO> {
    /// Returns a [`Builder`] for configuring `StateController`
    pub fn builder() -> Builder<IO> {
        Builder::new()
    }

    /// Runs the object state controller task
    pub async fn run(mut self) {
        let max_jitter = (self.config.iteration_time.as_millis() / 3) as u64;
        let err_jitter = (self.config.iteration_time.as_millis() / 5) as u64;

        loop {
            let mut metrics = IterationMetrics::default();

            let controller_span = tracing::span!(
                tracing::Level::INFO,
                "state_controller_iteration",
                start_time = format!("{:?}", chrono::Utc::now()),
                elapsed_us = tracing::field::Empty,
                controller = IO::LOG_SPAN_CONTROLLER_NAME,
                otel.status_code = tracing::field::Empty,
                otel.status_message = tracing::field::Empty,
                skipped_iteration = tracing::field::Empty,
                num_objects = tracing::field::Empty,
                num_errors = tracing::field::Empty,
                states = tracing::field::Empty,
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
                .single_iteration(&mut metrics)
                .instrument(controller_span.clone())
                .await;
            let elapsed = metrics.elapsed();

            controller_span.record("elapsed_us", elapsed.as_micros());
            controller_span.record("otel.status_code", if res.is_ok() { "ok" } else { "error" });

            {
                let _e: tracing::span::Entered<'_> = controller_span.enter();
                sqlx_query_tracing::update_current_span_attributes();
            }

            match &res {
                Ok(()) | Err(IterationError::LockError) => {
                    controller_span.record("otel.status_code", "ok");
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
                emitter.emit_latency_metrics(&metrics);
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

            // We add some jitter before sleeping, to give other controller instances
            // a chance to pick up the lock.
            // If a controller got the lock, the maximum delay is higher than for controllers
            // which failed to get the lock, which aims to give another bias to
            // a different controller.
            use rand::Rng;
            let jitter = rand::thread_rng().gen::<u64>()
                % if res.is_err() { err_jitter } else { max_jitter };
            let sleep_time = self
                .config
                .iteration_time
                .saturating_sub(elapsed)
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

    async fn single_iteration(
        &mut self,
        iteration_metrics: &mut IterationMetrics,
    ) -> Result<(), IterationError> {
        let mut txn = self.handler_services.pool.begin().await?;

        let locked: bool = sqlx::query_scalar(&self.lock_query)
            .fetch_one(&mut *txn)
            .await?;
        tracing::Span::current().record("skipped_iteration", !locked);

        if !locked {
            tracing::info!(
                "State controller was not able to obtain the lock {}",
                IO::db_lock_name()
            );
            return Err(IterationError::LockError);
        }
        tracing::trace!("State controller acquired the lock {}", IO::db_lock_name());

        handle_controller_iteration::<IO>(
            &self.io,
            &self.state_handler,
            &self.handler_services,
            &self.config,
            iteration_metrics,
        )
        .await?;

        txn.commit().await?;

        Ok(())
    }
}

async fn handle_controller_iteration<IO: StateControllerIO>(
    io: &Arc<IO>,
    state_handler: &Arc<
        dyn StateHandler<
            State = IO::State,
            ControllerState = IO::ControllerState,
            ObjectId = IO::ObjectId,
        >,
    >,
    handler_services: &Arc<StateHandlerServices>,
    config: &Config,
    iteration_metrics: &mut IterationMetrics,
) -> Result<(), IterationError> {
    // We start by grabbing a list of objects that should be active
    // The list might change until we fetch more data. However that should be ok:
    // The next iteration of the controller would also find objects that
    // have been added to the system. And no object should ever be removed
    // outside of the state controller
    let mut txn = handler_services.pool.begin().await?;
    let object_ids = io.list_objects(&mut txn).await?;
    txn.commit().await?;

    let mut task_set = JoinSet::new();

    let concurrency_limiter = Arc::new(tokio::sync::Semaphore::new(config.max_concurrency));

    for object_id in object_ids.iter() {
        let object_id = object_id.clone();
        let services = handler_services.clone();
        let io = io.clone();
        let handler = state_handler.clone();
        let concurrency_limiter = concurrency_limiter.clone();

        let _abort_handle = task_set.spawn(
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

                let mut metrics = ObjectHandlerMetrics::<IO> {
                    state: None,
                    handler_latency: Duration::from_secs(0),
                    time_in_state: Duration::from_secs(0),
                    error: None,
                };

                let start = Instant::now();

                // Note that this inner async block is required to be able to use
                // the ? operator in the inner block, and then return a `Result`
                // from the other outer block.
                let result: Result<(), StateHandlerError> = async {
                    let mut txn = services.pool.begin().await?;
                    let mut snapshot = io.load_object_state(&mut txn, &object_id).await?;
                    let mut controller_state = io
                        .load_controller_state(&mut txn, &object_id, &snapshot)
                        .await?;
                    metrics.state = Some(controller_state.value.clone());
                    // Unwrap uses a very large duration as default to show something is wrong
                    metrics.time_in_state = chrono::Utc::now()
                        .signed_duration_since(controller_state.version.timestamp())
                        .to_std()
                        .unwrap_or(Duration::from_secs(60 * 60 * 24));

                    let mut ctx = StateHandlerContext {
                        services: &services,
                    };

                    let mut state_holder = ControllerStateReader::new(&mut controller_state.value);

                    match handler
                        .handle_object_state(
                            &object_id,
                            &mut snapshot,
                            &mut state_holder,
                            &mut txn,
                            &mut ctx,
                        )
                        .await
                    {
                        Ok(()) => {
                            if state_holder.is_modified() {
                                io.persist_controller_state(
                                    &mut txn,
                                    &object_id,
                                    controller_state.version,
                                    controller_state.value,
                                )
                                .await?;
                            }

                            txn.commit()
                                .await
                                .map_err(StateHandlerError::TransactionError)
                        }
                        Err(e) => Err(e),
                    }
                }
                .await;

                metrics.handler_latency = start.elapsed();

                if let Err(e) = &result {
                    tracing::warn!("State handler for {} returned error: {:?}", object_id, e);
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
                metrics.error = Some(handler_error);
                iteration_metrics.merge_object_handling_metrics(&metrics);
                // Since we log StateHandlerErrors including the objectId inside the
                // handling task themselves, we don't have to forward these errors.
                // This avoids double logging of the results of individual tasks.
            }
            Ok((metrics, Ok(()))) => {
                iteration_metrics.merge_object_handling_metrics(&metrics);
            }
        }
    }

    if let Some(err) = last_join_error.take() {
        return Err(err.into());
    }

    Ok(())
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

#[derive(Debug)]
struct Config {
    /// Iteration time
    iteration_time: Duration,
    /// Maximum concurrency level
    max_concurrency: usize,
    /// The name that will be assigned for state controller metrics
    object_type_for_metrics: String,
}

/// A remote handle for the state controller
pub struct StateControllerHandle {
    /// Instructs the controller to stop.
    /// We rely on the handle being dropped to instruct the controller to stop performing actions
    _stop_sender: oneshot::Sender<()>,
}

#[derive(Debug, thiserror::Error)]
pub enum StateControllerBuildError {
    #[error("Missing parameter {0}")]
    MissingArgument(&'static str),
}

/// Default iteration time for the state controller
const DEFAULT_ITERATION_TIME: Duration = Duration::from_secs(30);
/// Default maximum concurrency for the state controller
///
/// The controller will act on this amount of instances in parallel
const DEFAULT_MAX_CONCURRENCY: usize = 10;

/// A builder for `StateController`
pub struct Builder<IO: StateControllerIO> {
    database: Option<sqlx::PgPool>,
    redfish_client_pool: Option<Arc<dyn RedfishClientPool>>,
    ib_fabric_manager: Option<Arc<dyn IBFabricManager>>,
    iteration_time: Option<Duration>,
    max_concurrency: usize,
    object_type_for_metrics: Option<String>,
    meter: Option<Meter>,
    state_handler: Arc<
        dyn StateHandler<
            State = IO::State,
            ControllerState = IO::ControllerState,
            ObjectId = IO::ObjectId,
        >,
    >,
    forge_api: Option<Arc<dyn rpc::forge::forge_server::Forge>>,
    pool_pkey: Option<Arc<DbResourcePool<i16>>>,
    reachability_params: Option<ReachabilityParams>,
}

#[derive(Clone)]
pub struct ReachabilityParams {
    pub dpu_wait_time: chrono::Duration,
}

impl<IO: StateControllerIO> Builder<IO> {
    /// Creates a new `Builder`
    ///
    /// This is not deriving [`Default`] since the method is only intended to be
    /// called by [`StateController::builder()`].
    fn new() -> Self {
        Self {
            database: None,
            redfish_client_pool: None,
            ib_fabric_manager: None,
            iteration_time: None,
            state_handler: Arc::new(NoopStateHandler::<
                IO::ObjectId,
                IO::State,
                IO::ControllerState,
            >::default()),
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            meter: None,
            object_type_for_metrics: None,
            forge_api: None,
            reachability_params: None,
            pool_pkey: None,
        }
    }

    /// Builds a [`StateController`] with all configured options
    pub fn build(mut self) -> Result<StateControllerHandle, StateControllerBuildError> {
        let database = self
            .database
            .take()
            .ok_or(StateControllerBuildError::MissingArgument("database"))?;

        let object_type_for_metrics = self.object_type_for_metrics.take();
        let meter = self.meter.take();

        let redfish_client_pool =
            self.redfish_client_pool
                .take()
                .ok_or(StateControllerBuildError::MissingArgument(
                    "redfish_client_pool",
                ))?;

        let forge_api = self
            .forge_api
            .take()
            .ok_or(StateControllerBuildError::MissingArgument("forge_api"))?;

        let reachability_params =
            self.reachability_params
                .take()
                .ok_or(StateControllerBuildError::MissingArgument(
                    "reachability_params",
                ))?;

        let ib_fabric_manager =
            self.ib_fabric_manager
                .take()
                .ok_or(StateControllerBuildError::MissingArgument(
                    "ib_fabric_manager",
                ))?;

        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.max_concurrency == 0 {
            return Err(StateControllerBuildError::MissingArgument(
                "max_concurrency",
            ));
        }
        let config = Config {
            iteration_time: self.iteration_time.unwrap_or(DEFAULT_ITERATION_TIME),
            max_concurrency: self.max_concurrency,
            object_type_for_metrics: object_type_for_metrics
                .unwrap_or_else(|| "undefined".to_string()),
        };

        let handler_services = Arc::new(StateHandlerServices {
            pool: database,
            ib_fabric_manager,
            redfish_client_pool,
            forge_api,
            reachability_params,
            meter: meter.clone(),
            pool_pkey: self.pool_pkey.take(),
        });

        // This defines the shared storage location for metrics between the state handler
        // and the OTEL framework
        let metric_holder = Arc::new(MetricHolder::new(meter, &config.object_type_for_metrics));
        // Now configure OpenTelemetry to fetch those metrics via a callback
        // This callback will get executed whenever OTEL needs to publish metrics
        if let Some(meter) = handler_services.meter.as_ref() {
            let metric_holder_clone = metric_holder.clone();
            meter
                .register_callback(move |otel_cx| {
                    if let Some(emitter) = metric_holder_clone.emitter.as_ref() {
                        if let Some(metrics) =
                            metric_holder_clone.last_iteration_metrics.load_full()
                        {
                            emitter.emit_gauges(&metrics, otel_cx);
                        }
                    }
                })
                .unwrap();
        }

        let controller = StateController::<IO> {
            stop_receiver,
            config,
            lock_query: create_lock_query(IO::db_lock_name()),
            handler_services,
            io: Arc::new(IO::default()),
            state_handler: self.state_handler.clone(),
            metric_holder,
        };
        tokio::spawn(async move { controller.run().await });

        let handle = StateControllerHandle {
            _stop_sender: stop_sender,
        };

        Ok(handle)
    }

    /// Configures the forge grpc api
    pub fn forge_api(mut self, forge_api: Arc<dyn rpc::forge::forge_server::Forge>) -> Self {
        self.forge_api = Some(forge_api);
        self
    }

    /// Configures the utilized database
    pub fn database(mut self, db: sqlx::PgPool) -> Self {
        self.database = Some(db);
        self
    }

    /// Configures the Meter that will be used for emitting metrics
    pub fn meter(mut self, object_type_for_metrics: impl Into<String>, meter: Meter) -> Self {
        self.object_type_for_metrics = Some(object_type_for_metrics.into());
        self.meter = Some(meter);
        self
    }

    /// Configures the utilized Redfish client pool
    pub fn redfish_client_pool(mut self, redfish_client_pool: Arc<dyn RedfishClientPool>) -> Self {
        self.redfish_client_pool = Some(redfish_client_pool);
        self
    }

    /// Configures the utilized IBService
    pub fn ib_fabric_manager(mut self, ib_fabric_manager: Arc<dyn IBFabricManager>) -> Self {
        self.ib_fabric_manager = Some(ib_fabric_manager);
        self
    }

    /// Configures the resource pool for allocation / release pkey
    pub fn pool_pkey(mut self, pool_pkey: Arc<DbResourcePool<i16>>) -> Self {
        self.pool_pkey = Some(pool_pkey);
        self
    }

    /// Configures the desired duration for one state controller iteration
    ///
    /// Lower iteration times will make the controller react faster to state changes.
    /// However they will also increase the load on the system
    pub fn iteration_time(mut self, time: Duration) -> Self {
        self.iteration_time = Some(time);
        self
    }

    /// Configures the maximum amount of concurrency for the object state controller
    ///
    /// The controller will attempt to advance the state of this amount of instances
    /// in parallel.
    pub fn max_concurrency(mut self, max_concurrency: usize) -> Self {
        self.max_concurrency = max_concurrency;
        self
    }

    /// Configures the parameters used to check DPU's reachability.
    pub fn reachability_params(mut self, reachability_params: ReachabilityParams) -> Self {
        self.reachability_params = Some(reachability_params);
        self
    }

    /// Sets the function that will be called to advance the state of a single object
    pub fn state_handler(
        mut self,
        handler: Arc<
            dyn StateHandler<
                State = IO::State,
                ControllerState = IO::ControllerState,
                ObjectId = IO::ObjectId,
            >,
        >,
    ) -> Self {
        self.state_handler = handler;
        self
    }
}
