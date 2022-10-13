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

use std::time::{Duration, Instant};

use tokio::sync::oneshot;

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
    database: sqlx::PgPool,
    iteration_handler: Box<dyn IterationHandler>,
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
        let _ = &mut self.database;

        let mut txn = self.database.begin().await?;

        let locked: bool = sqlx::query_scalar(LOCK_QUERY).fetch_one(&mut txn).await?;

        if !locked {
            tracing::info!("Machine state controller was not able to obtain the lock");
            return Err(IterationError::LockError);
        }
        tracing::info!("Machine state controller acquired the lock");

        self.iteration_handler.handle_iteration(&mut txn).await;

        txn.commit().await?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum IterationError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Unable to acquire lock")]
    LockError,
}

#[derive(Debug)]
struct Config {
    /// Iteration time
    iteration_time: Duration,
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
}

/// A handler that will be called for each iteration where the MachineStateController
/// has successfully obtained the lock of the database
#[async_trait::async_trait]
pub trait IterationHandler: std::fmt::Debug + Send {
    async fn handle_iteration(&mut self, txn: &mut sqlx::Transaction<sqlx::Postgres>);
}

/// A machine state controller handler which does nothing.
#[derive(Default, Debug)]
pub struct NoopIterationHandler {}

#[async_trait::async_trait]
impl IterationHandler for NoopIterationHandler {
    async fn handle_iteration(&mut self, _txn: &mut sqlx::Transaction<sqlx::Postgres>) {}
}

/// Default iteration time for the state controller
const DEFAULT_ITERATION_TIME: Duration = Duration::from_secs(30);

/// A builder for `MachineStateController`
#[derive(Debug, Default)]
pub struct Builder {
    database: Option<sqlx::PgPool>,
    iteration_time: Option<Duration>,
    iteration_handler: Option<Box<dyn IterationHandler>>,
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
            iteration_handler: None,
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
        let iteration_handler = self.iteration_handler.take().ok_or(
            MachineStateControllerBuildError::MissingArgument("iteration_handler"),
        )?;
        let (stop_sender, stop_receiver) = oneshot::channel();

        let config = Config {
            iteration_time: self.iteration_time.unwrap_or(DEFAULT_ITERATION_TIME),
        };

        let controller = MachineStateController {
            database,
            stop_receiver,
            config,
            iteration_handler,
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

    /// Sets the function that will be called for every iteration
    pub fn iteration_handler(mut self, handler: Box<dyn IterationHandler>) -> Self {
        self.iteration_handler = Some(handler);
        self
    }
}
