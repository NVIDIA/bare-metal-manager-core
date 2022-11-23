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
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::{
    machine_state_controller::snapshot_loader::{MachineStateSnapshotLoader, SnapshotLoaderError},
    model::{instance::status::SyncState, machine::MachineStateSnapshot},
};

/// Services that are accessible to the `MachineStateHandler`
#[derive(Debug)]
pub struct MachineStateHandlerServices {
    /// A database connection pool that can be used for additional queries
    pub pool: sqlx::PgPool,
    /// Allows to load the latest `MachineStateSnapshot` for a `Machine`
    pub snapshot_loader: Box<dyn MachineStateSnapshotLoader>,
}

/// Context parameter passed to `MachineStateHandler`
pub struct MachineStateHandlerContext<'a> {
    /// Services that are available to the `MachineStateHandler`
    pub services: &'a Arc<MachineStateHandlerServices>,
}

/// Defines a function that will be called to determine the next step in
/// a `Machine`s lifecycle.
///
/// The function retrieves the full `Machine` state as loaded from the database
/// as input, and can take any decisions to advance the `Machine` state.
#[async_trait::async_trait]
pub trait MachineStateHandler: std::fmt::Debug + Send + Sync + 'static {
    async fn handle_machine_state(
        &self,
        state: &mut MachineStateSnapshot,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut MachineStateHandlerContext,
    ) -> Result<(), MachineStateHandlerError>;
}

/// Error type for handling a Machine State
#[derive(Debug, thiserror::Error)]
pub enum MachineStateHandlerError {
    #[error("Unable to load state snapshot: {0}")]
    LoadSnapshotError(#[from] SnapshotLoaderError),
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
}

/// A `MachineStateHandler` implementation which does nothing
#[derive(Debug, Default)]
pub struct NoopMachineStateHandler {}

#[async_trait::async_trait]
impl MachineStateHandler for NoopMachineStateHandler {
    async fn handle_machine_state(
        &self,
        _state: &mut MachineStateSnapshot,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut MachineStateHandlerContext,
    ) -> Result<(), MachineStateHandlerError> {
        Ok(())
    }
}

/// A `MachineStateHandler` implementation which does nothing
#[derive(Debug, Default)]
pub struct RealMachineStateHandler {
    host_handler: HostMachineStateHandler,
    dpu_handler: DpuMachineStateHandler,
}

#[async_trait::async_trait]
impl MachineStateHandler for RealMachineStateHandler {
    async fn handle_machine_state(
        &self,
        state: &mut MachineStateSnapshot,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut MachineStateHandlerContext,
    ) -> Result<(), MachineStateHandlerError> {
        if state.hardware_info.is_dpu() {
            self.dpu_handler.handle_machine_state(state, txn, ctx).await
        } else {
            self.host_handler
                .handle_machine_state(state, txn, ctx)
                .await
        }
    }
}

/// A `MachineStateHandler` implementation for DPU machines
#[derive(Debug, Default)]
pub struct DpuMachineStateHandler {}

#[async_trait::async_trait]
impl MachineStateHandler for DpuMachineStateHandler {
    async fn handle_machine_state(
        &self,
        state: &mut MachineStateSnapshot,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut MachineStateHandlerContext,
    ) -> Result<(), MachineStateHandlerError> {
        let mut guard = LAST_DPU_LOG_TIME.lock().unwrap();
        if guard.elapsed() >= Duration::from_secs(60) {
            tracing::info!("MachineStateHandler is acting on DPU machine: {:?}", state);
            *guard = Instant::now();
        }
        drop(guard);

        Ok(())
    }
}

/// A `MachineStateHandler` implementation for host machines
#[derive(Debug, Default)]
pub struct HostMachineStateHandler {}

#[async_trait::async_trait]
impl MachineStateHandler for HostMachineStateHandler {
    async fn handle_machine_state(
        &self,
        state: &mut MachineStateSnapshot,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut MachineStateHandlerContext,
    ) -> Result<(), MachineStateHandlerError> {
        // This block is just here to get some debug output on the cluster and see whether
        // the controller gets the right data. We will remove it later on.
        let mut guard = LAST_HOST_LOG_TIME.lock().unwrap();
        if guard.elapsed() >= Duration::from_secs(60) {
            tracing::info!("MachineStateHandler is acting on host machine: {:?}", state);
            *guard = Instant::now();
        }
        drop(guard);

        if let Some(instance) = state.instance.as_ref() {
            let status = instance.derive_status();
            if status.configs_synced == SyncState::Pending {
                // This is a separate logging block to be guaranteed to get logging
                // output of instances that are not fully initiated, to see
                // what is missing.
                let mut guard = LAST_INSTANCE_LOG_TIME.lock().unwrap();
                if guard.elapsed() >= Duration::from_secs(90) {
                    tracing::info!(
                        "Configs of instance {:?} are not in sync. State {:?}nStatus: {:?}",
                        instance.instance_id,
                        instance,
                        status
                    );
                    *guard = Instant::now();
                }
            }
        }

        Ok(())
    }
}

static LAST_DPU_LOG_TIME: once_cell::sync::Lazy<Mutex<Instant>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Instant::now()));

static LAST_HOST_LOG_TIME: once_cell::sync::Lazy<Mutex<Instant>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Instant::now()));

static LAST_INSTANCE_LOG_TIME: once_cell::sync::Lazy<Mutex<Instant>> =
    once_cell::sync::Lazy::new(|| Mutex::new(Instant::now()));
