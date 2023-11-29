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

use crate::{
    db::bmc_machine::BmcMachine,
    model::{
        bmc_machine::BmcMachineState,
        config_version::{ConfigVersion, Versioned},
    },
    state_controller::{
        bmc_machine::context::BmcMachineStateHandlerContextObjects, io::StateControllerIO,
        metrics::NoopMetricsEmitter, snapshot_loader::SnapshotLoaderError,
    },
};

/// State Controller IO implementation for network segments
#[derive(Default, Debug)]
pub struct BmcMachineStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for BmcMachineStateControllerIO {
    type ObjectId = uuid::Uuid;
    type State = BmcMachine;
    type ControllerState = BmcMachineState;
    type MetricsEmitter = NoopMetricsEmitter;
    type ContextObjects = BmcMachineStateHandlerContextObjects;

    const DB_LOCK_NAME: &'static str = "bmc_machine_controller_lock";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "bmc_machine_controller";

    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError> {
        BmcMachine::list_bmc_machines(txn)
            .await
            .map_err(SnapshotLoaderError::from)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        machine_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        BmcMachine::get_by_id(txn, *machine_id)
            .await
            .map_err(|_| SnapshotLoaderError::InstanceNotFound(*machine_id))
    }

    async fn load_controller_state(
        &self,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, SnapshotLoaderError> {
        Ok(state.controller_state.clone())
    }

    async fn persist_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        old_version: ConfigVersion,
        new_state: Self::ControllerState,
    ) -> Result<(), SnapshotLoaderError> {
        BmcMachine::try_update_controller_state(txn, *object_id, old_version, &new_state).await?;
        Ok(())
    }

    fn metric_state_names(state: &Self::ControllerState) -> (&'static str, &'static str) {
        match state {
            BmcMachineState::Initializing => ("bmc-init", ""),
            BmcMachineState::Configuring => ("bmc-configure", ""),
            BmcMachineState::DpuReboot => ("dpu-reboot", ""),
            BmcMachineState::Initialized => ("dpu-intialized", ""),
            BmcMachineState::Error(_) => ("bmc-error", ""),
            BmcMachineState::FirmwareUpdate { .. } => ("bmc-firmware-update", ""),
            BmcMachineState::BmcReboot => ("bmc-reboot", ""),
        }
    }
}
