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

use tokio::{sync::oneshot, task::JoinSet};

use crate::{
    kubernetes::VpcApi,
    model::config_version::{ConfigVersion, Versioned},
    reachability::Reachability,
    redfish::RedfishClientPool,
    resource_pool::ResourcePool,
    state_controller::{
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
    stop_receiver: oneshot::Receiver<()>,
    config: Config,
}

/// This trait defines on what objects a state controller instance will act,
/// and how it loads the objects state.
#[async_trait::async_trait]
pub trait StateControllerIO: Send + Sync + std::fmt::Debug + 'static + Default {
    type ObjectId: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static + Clone;
    type State: Send + Sync + 'static;
    type ControllerState: Send + Sync + 'static;

    /// Returns the name of the table in the database that will be used for advisory locking
    ///
    /// This lock will prevent multiple instances of controller running on multiple nodes
    /// from making changes to objects at the same time
    fn db_lock_name() -> &'static str;

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
            let start = Instant::now();
            let res = self.single_iteration().await;
            let elapsed = start.elapsed();

            match &res {
                Ok(()) | Err(IterationError::LockError) => {}
                Err(e) => {
                    tracing::error!("StateController iteration failed due to: {:?}", e);
                }
            }

            // TODO: Emit metric for loop duration

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

    async fn single_iteration(&mut self) -> Result<(), IterationError> {
        let mut txn = self.handler_services.pool.begin().await?;

        let locked: bool = sqlx::query_scalar(&self.lock_query)
            .fetch_one(&mut txn)
            .await?;

        if !locked {
            tracing::info!(
                "State controller was not able to obtain the lock {}",
                IO::db_lock_name()
            );
            return Err(IterationError::LockError);
        }
        tracing::debug!("State controller acquired the lock {}", IO::db_lock_name());

        handle_controller_iteration::<IO>(
            &self.io,
            &self.state_handler,
            &self.handler_services,
            &self.config,
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

        let _abort_handle = task_set.spawn(async move {
            // Acquire a permit which will block more than `MAX_CONCURRENCY`
            // tasks from running.
            // Note that assigning the permit to a named variable is necessary
            // to make it live until the end of the scope. Using `_` would
            // immediately dispose the permit.
            let _permit = concurrency_limiter
                .acquire()
                .await
                .expect("Semaphore can't be closed");

            // Note that this inner async block is required to be able to use
            // the ? operator in the inner block, and then return a `Result`
            // from the other outer block.
            let result: Result<(), StateHandlerError> = async {
                let mut txn = services.pool.begin().await?;
                let mut snapshot = io.load_object_state(&mut txn, &object_id).await?;
                let mut controller_state = io
                    .load_controller_state(&mut txn, &object_id, &snapshot)
                    .await?;

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

            if let Err(e) = &result {
                tracing::warn!("State handler for {} returned error: {:?}", object_id, e);
            }

            result
        });
    }

    // We want for all tasks to run to completion here and therefore can't
    // return early until the `TaskSet` is fully consumed.
    // If we would return early then some tasks might still work on an object
    // even thought the next controller iteration already started.
    // Therefore we drain the `task_set` here completely and record all errors
    // before returning.
    let mut errors: Vec<IterationError> = vec![];
    while let Some(result) = task_set.join_next().await {
        match result {
            Err(join_error) => {
                // Since we only want to return a single error and prefer to return
                // the panic information, we push it at front
                errors.insert(0, join_error.into());
            }
            Ok(Err(handler_error)) => {
                errors.push(handler_error.into());
            }
            Ok(Ok(())) => {}
        }
    }

    if !errors.is_empty() {
        return Err(errors.swap_remove(0));
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
    #[error("Invalid parameter {0}")]
    InvalidArgument(&'static str),
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
    vpc_api: Option<Arc<dyn VpcApi>>,
    iteration_time: Option<Duration>,
    max_concurrency: usize,
    state_handler: Arc<
        dyn StateHandler<
            State = IO::State,
            ControllerState = IO::ControllerState,
            ObjectId = IO::ObjectId,
        >,
    >,
    forge_api: Option<Arc<dyn rpc::forge::forge_server::Forge>>,
    pool_vlan_id: Option<Arc<dyn ResourcePool<i16>>>,
    pool_vni: Option<Arc<dyn ResourcePool<i32>>>,
    reachability_params: Option<ReachabilityParams>,
}

#[derive(Clone)]
pub struct ReachabilityParams {
    pub dpu_wait_time: chrono::Duration,
    pub checker: Arc<dyn Reachability>,
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
            vpc_api: None,
            iteration_time: None,
            state_handler: Arc::new(NoopStateHandler::<
                IO::ObjectId,
                IO::State,
                IO::ControllerState,
            >::default()),
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            forge_api: None,
            reachability_params: None,
            pool_vlan_id: None,
            pool_vni: None,
        }
    }

    /// Builds a [`StateController`] with all configured options
    pub fn build(mut self) -> Result<StateControllerHandle, StateControllerBuildError> {
        let database = self
            .database
            .take()
            .ok_or(StateControllerBuildError::MissingArgument("database"))?;

        let redfish_client_pool =
            self.redfish_client_pool
                .take()
                .ok_or(StateControllerBuildError::MissingArgument(
                    "redfish_client_pool",
                ))?;

        let vpc_api = self
            .vpc_api
            .take()
            .ok_or(StateControllerBuildError::MissingArgument("vpc_api"))?;

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

        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.max_concurrency == 0 {
            return Err(StateControllerBuildError::MissingArgument(
                "max_concurrency",
            ));
        }
        let config = Config {
            iteration_time: self.iteration_time.unwrap_or(DEFAULT_ITERATION_TIME),
            max_concurrency: self.max_concurrency,
        };

        let handler_services = Arc::new(StateHandlerServices {
            pool: database,
            vpc_api,
            redfish_client_pool,
            forge_api,
            reachability_params,
            pool_vlan_id: self.pool_vlan_id.take(),
            pool_vni: self.pool_vni.take(),
        });

        let controller = StateController::<IO> {
            stop_receiver,
            config,
            lock_query: create_lock_query(IO::db_lock_name()),
            handler_services,
            io: Arc::new(IO::default()),
            state_handler: self.state_handler.clone(),
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

    /// Configures the utilized Redfish client pool
    pub fn redfish_client_pool(mut self, redfish_client_pool: Arc<dyn RedfishClientPool>) -> Self {
        self.redfish_client_pool = Some(redfish_client_pool);
        self
    }

    /// Configures the utilized VPC API
    pub fn vpc_api(mut self, vpc_api: Arc<dyn VpcApi>) -> Self {
        self.vpc_api = Some(vpc_api);
        self
    }

    /// Configures the resource pool for allocation / release VLAN IDs
    pub fn pool_vlan_id(mut self, pool_vlan_id: Arc<dyn ResourcePool<i16>>) -> Self {
        self.pool_vlan_id = Some(pool_vlan_id);
        self
    }

    /// Configures the resource pool for allocation / release VNI (VXLAN IDs)
    pub fn pool_vni(mut self, pool_vni: Arc<dyn ResourcePool<i32>>) -> Self {
        self.pool_vni = Some(pool_vni);
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
