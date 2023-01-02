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

//! State Handler implementation for Machines

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use crate::{
    model::{instance::status::SyncState, machine::MachineStateSnapshot},
    state_controller::state_handler::{
        ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
    },
};

/// The actual Machine State handler
#[derive(Debug, Default)]
pub struct MachineStateHandler {
    host_handler: HostMachineStateHandler,
    dpu_handler: DpuMachineStateHandler,
}

#[async_trait::async_trait]
impl StateHandler for MachineStateHandler {
    type State = MachineStateSnapshot;
    type ControllerState = ();
    type ObjectId = uuid::Uuid;

    async fn handle_object_state(
        &self,
        machine_id: &uuid::Uuid,
        state: &mut MachineStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        if state.hardware_info.is_dpu() {
            self.dpu_handler
                .handle_object_state(machine_id, state, controller_state, txn, ctx)
                .await
        } else {
            self.host_handler
                .handle_object_state(machine_id, state, controller_state, txn, ctx)
                .await
        }
    }
}

/// A `StateHandler` implementation for DPU machines
#[derive(Debug, Default)]
pub struct DpuMachineStateHandler {}

#[async_trait::async_trait]
impl StateHandler for DpuMachineStateHandler {
    type State = MachineStateSnapshot;
    type ControllerState = ();
    type ObjectId = uuid::Uuid;

    async fn handle_object_state(
        &self,
        _machine_id: &uuid::Uuid,
        state: &mut MachineStateSnapshot,
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let mut guard = LAST_DPU_LOG_TIME.lock().unwrap();
        if guard.elapsed() >= Duration::from_secs(60) {
            tracing::info!("StateHandler is acting on DPU machine: {:?}", state);
            *guard = Instant::now();
        }
        drop(guard);

        Ok(())
    }
}

/// A `StateHandler` implementation for host machines
#[derive(Debug, Default)]
pub struct HostMachineStateHandler {}

#[async_trait::async_trait]
impl StateHandler for HostMachineStateHandler {
    type State = MachineStateSnapshot;
    type ControllerState = ();
    type ObjectId = uuid::Uuid;

    async fn handle_object_state(
        &self,
        _machine_id: &uuid::Uuid,
        state: &mut MachineStateSnapshot,
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        // This block is just here to get some debug output on the cluster and see whether
        // the controller gets the right data. We will remove it later on.
        let mut guard = LAST_HOST_LOG_TIME.lock().unwrap();
        if guard.elapsed() >= Duration::from_secs(60) {
            tracing::info!("StateHandler is acting on host machine: {:?}", state);
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
