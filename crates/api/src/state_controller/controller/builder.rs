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

use db::work_lock_manager::WorkLockManagerHandle;
use opentelemetry::metrics::Meter;
use tokio::sync::oneshot;

use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::{StateController, StateControllerHandle};
use crate::state_controller::io::StateControllerIO;
use crate::state_controller::metrics::MetricHolder;
use crate::state_controller::state_change_emitter::StateChangeEmitter;
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
    work_lock_manager_handle: Option<WorkLockManagerHandle>,
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
    state_change_emitter: Arc<StateChangeEmitter<IO::ObjectId, IO::ControllerState>>,
}

impl<IO: StateControllerIO> Default for Builder<IO> {
    /// Creates a new `Builder`
    fn default() -> Self {
        Self {
            database: None,
            work_lock_manager_handle: None,
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
            state_change_emitter: Arc::new(StateChangeEmitter::default()),
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

        let work_lock_manager_handle = self.work_lock_manager_handle.take().ok_or(
            StateControllerBuildError::MissingArgument("work_lock_manager_handle"),
        )?;

        let controller = StateController::<IO> {
            pool: database,
            work_lock_manager_handle,
            stop_receiver,
            iteration_config: self.iteration_config,
            work_key: IO::DB_WORK_KEY,
            handler_services: services,
            io: self.io.unwrap_or_default(),
            state_handler: self.state_handler.clone(),
            metric_holder,
            state_change_emitter: self.state_change_emitter,
        };

        Ok(BuildOrSpawn {
            controller,
            controller_name,
            stop_sender,
        })
    }

    /// Configures the utilized database, and the singleton work_lock_manager that corresponds to it
    pub fn database(
        mut self,
        db: sqlx::PgPool,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        self.database = Some(db);
        self.work_lock_manager_handle = Some(work_lock_manager_handle);
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

    /// Sets the state change emitter for broadcasting state transitions to hooks
    pub fn state_change_emitter(
        mut self,
        emitter: StateChangeEmitter<IO::ObjectId, IO::ControllerState>,
    ) -> Self {
        self.state_change_emitter = Arc::new(emitter);
        self
    }
}
