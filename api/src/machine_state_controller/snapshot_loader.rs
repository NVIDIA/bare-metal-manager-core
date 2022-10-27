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

use crate::{
    db::machine_topology::MachineTopology,
    model::machine::{CurrentMachineState, MachineConfig, MachineStateSnapshot},
};

/// A service which allows to load a machine state snapshot from the database
#[async_trait::async_trait]
pub trait MachineStateSnapshotLoader: Send + Sync + std::fmt::Debug {
    /// Loads a machine state snapshot from the database
    async fn load_machine_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        uuid: uuid::Uuid,
    ) -> Result<MachineStateSnapshot, MachineStateSnapshotLoaderError>;
}

/// Enumerates errors that are returned by [`MachineStateSnapshotLoader`]
#[derive(Debug, thiserror::Error)]
pub enum MachineStateSnapshotLoaderError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Unable to load Hardware information: {0}")]
    HardwareInfoSqlError(sqlx::Error),
    #[error("Hardware information for Machine {0} is missing")]
    MissingHardwareInfo(uuid::Uuid),
}

/// Load a machine state snapshot from a postgres database
#[derive(Debug, Default)]
pub struct DbMachineStateSnapshotLoader;

#[async_trait::async_trait]
impl MachineStateSnapshotLoader for DbMachineStateSnapshotLoader {
    async fn load_machine_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        uuid: uuid::Uuid,
    ) -> Result<MachineStateSnapshot, MachineStateSnapshotLoaderError> {
        let mut hardware_infos = MachineTopology::find_latest_by_machine_ids(txn, &[uuid])
            .await
            .map_err(MachineStateSnapshotLoaderError::HardwareInfoSqlError)?;
        let info = hardware_infos
            .remove(&uuid)
            .ok_or(MachineStateSnapshotLoaderError::MissingHardwareInfo(uuid))?;

        let snapshot = MachineStateSnapshot {
            machine_id: uuid,
            hardware_info: info.topology().discovery_data.info.clone(),
            current: CurrentMachineState {},
            config: MachineConfig {},
        };

        Ok(snapshot)
    }
}
