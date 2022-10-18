/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    db::machine::Machine,
    machine_state_controller::{
        snapshot_loader::MachineStateSnapshotLoader,
        state_handler::{
            MachineStateHandler, MachineStateHandlerContext, MachineStateHandlerError,
            MachineStateHandlerServices, NoopMachineStateHandler,
        },
    },
};

/// The machine static controller evaluates the current state of all instance in
/// a Forge site, and decides which actions the system should undertake to
/// bring the state inline with the state users requested.
///
/// Each Forge API server is running a MachineStateController instance.
/// While all instances run in parallel, the MachineStateController uses internal
/// synchronization to make sure that inside a single site - only a single controller
/// will decide the next step for a single Machine.
#[derive(Debug)]
pub struct MachineStateController {
    handler_services: Arc<MachineStateHandlerServices>,
    state_handler: Arc<dyn MachineStateHandler>,
    stop_receiver: oneshot::Receiver<()>,
    config: Config,
}

/// Query to get an advisory lock on the table machine_state_controller_lock
///
/// Note that there is no real relation between the table and the query
/// We just use it to get an object identifier
const LOCK_QUERY: &str = "SELECT pg_try_advisory_xact_lock((SELECT 'machine_state_controller_lock'::regclass::oid)::integer);";

impl MachineStateController {
    /// Returns a [`Builder`] for configuring `MachineStateController`
    pub fn builder() -> Builder {
        Builder::new()
    }

    /// Runs the machine state controller task
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
                    tracing::error!("MachineStateController iteration failed due to: {:?}", e);
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
                    tracing::info!("MachineStateController stop was requested");
                    return;
                }
            }
        }
    }

    async fn single_iteration(&mut self) -> Result<(), IterationError> {
        let mut txn = self.handler_services.pool.begin().await?;

        let locked: bool = sqlx::query_scalar(LOCK_QUERY).fetch_one(&mut txn).await?;

        if !locked {
            tracing::info!("Machine state controller was not able to obtain the lock");
            return Err(IterationError::LockError);
        }
        tracing::info!("Machine state controller acquired the lock");

        handle_controller_iteration(&self.state_handler, &self.handler_services, &self.config)
            .await?;

        txn.commit().await?;

        Ok(())
    }
}

async fn handle_controller_iteration(
    state_handler: &Arc<dyn MachineStateHandler>,
    handler_services: &Arc<MachineStateHandlerServices>,
    config: &Config,
) -> Result<(), IterationError> {
    // We start by grabbing a list of Machine's that should be active
    // The list might change until we fetch more data. However that should be ok:
    // The next iteration of the controller would also find machines that
    // have been added to the system. And no Machine should ever be removed
    // outside of the state controller
    let mut txn = handler_services.pool.begin().await?;
    let machine_ids = Machine::list_active_machine_ids(&mut txn).await?;
    txn.commit().await?;

    let mut task_set = JoinSet::new();

    let concurrency_limiter = Arc::new(tokio::sync::Semaphore::new(config.max_concurrency));

    for &machine_id in &machine_ids {
        let services = handler_services.clone();
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
            let result: Result<(), MachineStateHandlerError> = async move {
                let mut txn = services.pool.begin().await?;
                let mut snapshot = services
                    .snapshot_loader
                    .load_machine_snapshot(&mut txn, machine_id)
                    .await?;

                let mut ctx = MachineStateHandlerContext {
                    services: &services,
                };

                handler
                    .handle_machine_state(&mut snapshot, &mut txn, &mut ctx)
                    .await
            }
            .await;
            result
        });
    }

    // We want for all tasks to run to completion here and therefore can't
    // return early until the `TaskSet` is fully consumed.
    // If we would return early then some tasks might still work on a `Machine`
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
    #[error("Machine state handler error: {0}")]
    MachineStateHandlerError(#[from] MachineStateHandlerError),
}

#[derive(Debug)]
struct Config {
    /// Iteration time
    iteration_time: Duration,
    /// Maximum concurrency level
    max_concurrency: usize,
}

/// A remote handle for the machine state controller
pub struct MachineStateControllerHandle {
    /// Instructs the machine to stop.
    /// We rely on the handle being dropped to instruct the controller to stop performing actions
    _stop_sender: oneshot::Sender<()>,
}

#[derive(Debug, thiserror::Error)]
pub enum MachineStateControllerBuildError {
    #[error("Missing parameter {0}")]
    MissingArgument(&'static str),
    #[error("Invalid parameter {0}")]
    InvalidArgument(&'static str),
}

/// Default iteration time for the state controller
const DEFAULT_ITERATION_TIME: Duration = Duration::from_secs(30);
/// Default maximum concurrency for the machine state controller
///
/// The controller will act on this amount of instances in parallel
const DEFAULT_MAX_CONCURRENCY: usize = 10;

/// A builder for `MachineStateController`
#[derive(Debug)]
pub struct Builder {
    database: Option<sqlx::PgPool>,
    iteration_time: Option<Duration>,
    max_concurrency: usize,
    snapshot_loader: Option<Box<dyn MachineStateSnapshotLoader>>,
    state_handler: Arc<dyn MachineStateHandler>,
}

impl Builder {
    /// Creates a new `Builder`
    ///
    /// This is not deriving [`Default`] since the method is only intended to be
    /// called by [`MachineStateController::builder()`].
    fn new() -> Self {
        Self {
            database: None,
            iteration_time: None,
            snapshot_loader: None,
            state_handler: Arc::new(NoopMachineStateHandler::default()),
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
        }
    }

    /// Builds a [´MachineStateController`] with all configured options
    pub fn build(
        mut self,
    ) -> Result<MachineStateControllerHandle, MachineStateControllerBuildError> {
        let database =
            self.database
                .take()
                .ok_or(MachineStateControllerBuildError::MissingArgument(
                    "database",
                ))?;

        let snapshot_loader = self.snapshot_loader.take().ok_or(
            MachineStateControllerBuildError::MissingArgument("snapshot_loader"),
        )?;

        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.max_concurrency == 0 {
            return Err(MachineStateControllerBuildError::MissingArgument(
                "max_concurrency",
            ));
        }
        let config = Config {
            iteration_time: self.iteration_time.unwrap_or(DEFAULT_ITERATION_TIME),
            max_concurrency: self.max_concurrency,
        };

        let handler_services = Arc::new(MachineStateHandlerServices {
            snapshot_loader,
            pool: database,
        });

        let controller = MachineStateController {
            stop_receiver,
            config,
            handler_services,
            state_handler: self.state_handler.clone(),
        };
        tokio::spawn(async move { controller.run().await });

        let handle = MachineStateControllerHandle {
            _stop_sender: stop_sender,
        };

        Ok(handle)
    }

    /// Configures the utilized database
    pub fn database(mut self, db: sqlx::PgPool) -> Self {
        self.database = Some(db);
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

    /// Configures the maximum amount of concurrency for the machine state controller
    ///
    /// The controller will attempt to advance the state of this amount of instances
    /// in parallel.
    pub fn max_concurrency(mut self, max_concurrency: usize) -> Self {
        self.max_concurrency = max_concurrency;
        self
    }

    /// Sets the function that will be called to load the full state of a `Machine`
    pub fn snapshot_loader(mut self, handler: Box<dyn MachineStateSnapshotLoader>) -> Self {
        self.snapshot_loader = Some(handler);
        self
    }

    /// Sets the function that will be called to advance the state of a single `Machine`
    pub fn state_handler(mut self, handler: Arc<dyn MachineStateHandler>) -> Self {
        self.state_handler = handler;
        self
    }
}
