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

//! State Controller IO implementation for Machines

use crate::{
    db::dpu_machine::DpuMachine,
    model::{
        config_version::{ConfigVersion, Versioned},
        machine::{machine_id::MachineId, ManagedHostState, ManagedHostStateSnapshot},
    },
    state_controller::{
        controller::StateControllerIO,
        snapshot_loader::{DbSnapshotLoader, MachineStateSnapshotLoader, SnapshotLoaderError},
    },
};

/// State Controller IO implementation for Machines
#[derive(Default, Debug)]
pub struct MachineStateControllerIO {
    snapshot_loader: DbSnapshotLoader,
}

#[async_trait::async_trait]
impl StateControllerIO for MachineStateControllerIO {
    type ObjectId = MachineId;
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;

    fn db_lock_name() -> &'static str {
        "machine_state_controller_lock"
    }

    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError> {
        Ok(crate::db::dpu_machine::DpuMachine::list_active_dpu_ids(txn)
            .await
            .map_err(|x| SnapshotLoaderError::GenericError(x.into()))?)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        machine_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        self.snapshot_loader
            .load_machine_snapshot(txn, machine_id)
            .await
    }

    async fn load_controller_state(
        &self,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, SnapshotLoaderError> {
        let current = state.dpu_snapshot.current.clone();

        Ok(Versioned::new(current.state, current.version))
    }

    async fn persist_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        _old_version: ConfigVersion,
        new_state: Self::ControllerState,
    ) -> Result<(), SnapshotLoaderError> {
        DpuMachine::update_state(txn, object_id, new_state)
            .await
            .map_err(|err| SnapshotLoaderError::GenericError(err.into()))?;

        Ok(())
    }
}
