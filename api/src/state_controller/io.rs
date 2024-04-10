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

use config_version::{ConfigVersion, Versioned};

use crate::state_controller::{
    metrics::MetricsEmitter, snapshot_loader::SnapshotLoaderError,
    state_handler::StateHandlerContextObjects,
};

/// This trait defines on what objects a state controller instance will act,
/// and how it loads the objects state.
#[async_trait::async_trait]
pub trait StateControllerIO: Send + Sync + std::fmt::Debug + 'static + Default {
    /// Uniquely identifies the object that is controlled
    type ObjectId: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static + Clone;
    /// The full state of the object.
    /// This might contain all kinds of information, which different pieces of the full
    /// state being updated by various components.
    type State: Send + Sync + 'static;
    /// This defines the state that the state machine implemented in the state handler
    /// actively acts upon. It is passed via the `controller_state` parameter to
    /// each state handler, and can be modified via this parameter.
    /// This state may not be updated by any other component.
    type ControllerState: std::fmt::Debug + Send + Sync + 'static + Clone;
    /// Defines how metrics that are specific to this kind of object are handled
    type MetricsEmitter: MetricsEmitter;
    /// The collection of generic objects which are referenced in StateHandlerContext
    type ContextObjects: StateHandlerContextObjects<
        ObjectMetrics = <Self::MetricsEmitter as MetricsEmitter>::ObjectMetrics,
    >;

    /// The name of the table in the database that will be used for advisory locking
    ///
    /// This lock will prevent multiple instances of controller running on multiple nodes
    /// from making changes to objects at the same time
    const DB_LOCK_NAME: &'static str;

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

    /// Defines whether an object is in a certain state for longer than allowed
    /// by the SLA.
    ///
    /// If an object stays in a state for longer than expected, a metric will
    /// be emitted.
    ///
    /// `false` can be used to indicate that an object can stay in any state
    /// for an indefinite time in a state.
    fn time_in_state_above_sla(state: &Versioned<Self::ControllerState>) -> bool;
}
