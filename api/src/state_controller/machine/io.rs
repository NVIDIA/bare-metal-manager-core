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

//! State Controller IO implementation for Machines

use crate::{
    model::{
        config_version::{ConfigVersion, Versioned},
        machine::MachineStateSnapshot,
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
    type ObjectId = uuid::Uuid;
    type State = MachineStateSnapshot;
    type ControllerState = ();

    fn db_lock_name() -> &'static str {
        "machine_state_controller_lock"
    }

    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError> {
        Ok(crate::db::machine::Machine::list_active_machine_ids(txn).await?)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        machine_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        self.snapshot_loader
            .load_machine_snapshot(txn, *machine_id)
            .await
    }

    async fn load_controller_state(
        &self,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _object_id: &Self::ObjectId,
        _state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, SnapshotLoaderError> {
        Ok(Versioned::new((), ConfigVersion::initial()))
    }

    async fn persist_controller_state(
        &self,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _object_id: &Self::ObjectId,
        _old_version: ConfigVersion,
        _new_state: Self::ControllerState,
    ) -> Result<(), SnapshotLoaderError> {
        Ok(())
    }
}
