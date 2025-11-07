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

use std::sync::Arc;

use opentelemetry::metrics::Meter;
use tokio::sync::oneshot;

use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::{StateController, StateControllerHandle};
use crate::state_controller::io::StateControllerIO;
use crate::state_controller::metrics::MetricHolder;
use crate::state_controller::state_handler::{
    NoopStateHandler, StateHandler, StateHandlerContextObjects,
};

/// The return value of `[Builder::build_internal]`
struct BuildOrSpawn<IO: StateControllerIO> {
    /// Instructs the controller to stop.
    /// We rely on the handle being dropped to instruct the controller to stop performing actions
    stop_sender: oneshot::Sender<()>,
    controller_name: String,
    controller: StateController<IO>,
}

#[derive(Debug, thiserror::Error)]
pub enum StateControllerBuildError {
    #[error("Missing parameter {0}")]
    MissingArgument(&'static str),

    #[error("Task spawn error: {0}")]
    IOError(#[from] std::io::Error),
}

/// A builder for `StateController`
pub struct Builder<IO: StateControllerIO> {
    database: Option<sqlx::PgPool>,
    iteration_config: IterationConfig,
    object_type_for_metrics: Option<String>,
    meter: Option<Meter>,
    io: Option<Arc<IO>>,
    state_handler: Arc<
        dyn StateHandler<
                State = IO::State,
                ControllerState = IO::ControllerState,
                ContextObjects = IO::ContextObjects,
                ObjectId = IO::ObjectId,
            >,
    >,
    services: Option<Arc<<IO::ContextObjects as StateHandlerContextObjects>::Services>>,
}

impl<IO: StateControllerIO> Default for Builder<IO> {
    /// Creates a new `Builder`
    fn default() -> Self {
        Self {
            database: None,
            iteration_config: IterationConfig::default(),
            io: None,
            state_handler: Arc::new(NoopStateHandler::<
                IO::ObjectId,
                IO::State,
                IO::ControllerState,
                IO::ContextObjects,
            >::default()),
            meter: None,
            object_type_for_metrics: None,
            services: None,
        }
    }
}

impl<IO: StateControllerIO> Builder<IO> {
    /// Builds a [`StateController`] with all configured options with the intention
    /// of calling the `run_single_iteration` whenever required
    #[cfg(test)]
    pub fn build_for_manual_iterations(
        self,
    ) -> Result<StateController<IO>, StateControllerBuildError> {
        let build_or_spawn = self.build_internal()?;
        Ok(build_or_spawn.controller)
    }

    /// Builds a [`StateController`] with all configured options
    /// and spawns the state controller as background task.
    ///
    /// The state controller will continue to run as long as the returned `StateControllerHandle`
    /// is kept alive.
    pub fn build_and_spawn(self) -> Result<StateControllerHandle, StateControllerBuildError> {
        let build_or_spawn = self.build_internal()?;

        tokio::task::Builder::new()
            .name(&format!(
                "state_controller {}",
                build_or_spawn.controller_name
            ))
            .spawn(async move { build_or_spawn.controller.run().await })?;

        Ok(StateControllerHandle {
            _stop_sender: build_or_spawn.stop_sender,
        })
    }

    /// Builds a [`StateController`] with all configured options
    fn build_internal(mut self) -> Result<BuildOrSpawn<IO>, StateControllerBuildError> {
        let database = self
            .database
            .take()
            .ok_or(StateControllerBuildError::MissingArgument("database"))?;

        let object_type_for_metrics = self.object_type_for_metrics.take();
        let meter = self.meter.take();

        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.iteration_config.max_concurrency == 0 {
            return Err(StateControllerBuildError::MissingArgument(
                "max_concurrency",
            ));
        }
        let controller_name = object_type_for_metrics.unwrap_or_else(|| "undefined".to_string());

        let services = self
            .services
            .take()
            .ok_or(StateControllerBuildError::MissingArgument("services"))?;

        // This defines the shared storage location for metrics between the state handler
        // and the OTEL framework
        let metric_holder = Arc::new(MetricHolder::new(meter, &controller_name));

        let controller = StateController::<IO> {
            pool: database,
            stop_receiver,
            iteration_config: self.iteration_config,
            lock_query: create_lock_query(IO::DB_LOCK_NAME),
            handler_services: services,
            io: self.io.unwrap_or_default(),
            state_handler: self.state_handler.clone(),
            metric_holder,
        };

        Ok(BuildOrSpawn {
            controller,
            controller_name,
            stop_sender,
        })
    }

    /// Configures the utilized database
    pub fn database(mut self, db: sqlx::PgPool) -> Self {
        self.database = Some(db);
        self
    }

    /// Configures the services that will be available within the StateHandlerContext
    pub fn services(
        mut self,
        services: Arc<<IO::ContextObjects as StateHandlerContextObjects>::Services>,
    ) -> Self {
        self.services = Some(services);
        self
    }

    /// Configures the Meter that will be used for emitting metrics
    pub fn meter(mut self, object_type_for_metrics: impl Into<String>, meter: Meter) -> Self {
        self.object_type_for_metrics = Some(object_type_for_metrics.into());
        self.meter = Some(meter);
        self
    }

    /// Configures how the state controller performs iterations
    pub fn iteration_config(mut self, config: IterationConfig) -> Self {
        self.iteration_config = config;
        self
    }

    /// Sets the IO handler configuration
    pub fn io(mut self, io: Arc<IO>) -> Self {
        self.io = Some(io);
        self
    }

    /// Sets the function that will be called to advance the state of a single object
    pub fn state_handler(
        mut self,
        handler: Arc<
            dyn StateHandler<
                    State = IO::State,
                    ControllerState = IO::ControllerState,
                    ContextObjects = IO::ContextObjects,
                    ObjectId = IO::ObjectId,
                >,
        >,
    ) -> Self {
        self.state_handler = handler;
        self
    }
}

/// Creates the query that will be used for advisory locking of a postgres table
/// with the given name.
///
/// Note that there is no real relation between the table and the query
/// We just use it to get an object identifier
///
/// For each of the lock names (e.g. network_segments_controller_lock, machine_state_controller_lock),
/// the inner select statement will return its OID.
/// For example, SELECT 'network_segments_controller_lock'::regclass::oid will return the same int
/// everytime (for example 17308). Each advisory lock is identified by a single bigint
/// And SELECT pg_try_advisory_xact_lock(17308) will acquire the lock and return TRUE if no one else
/// has locked that table. Otherwise it will return FALSE immediately. The acquired lock is held
/// for the duration of the current transaction.
fn create_lock_query(db_lock_name: &str) -> String {
    format!("SELECT pg_try_advisory_xact_lock((SELECT '{db_lock_name}'::regclass::oid)::integer);")
}
