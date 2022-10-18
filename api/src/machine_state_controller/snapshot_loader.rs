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

use crate::model::machine::{CurrentMachineState, MachineConfig, MachineStateSnapshot};

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

#[derive(Debug, thiserror::Error)]
pub enum MachineStateSnapshotLoaderError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
}

/// Load a machine state snapshot from a postgres database
#[derive(Debug, Default)]
pub struct DbMachineStateSnapshotLoader;

#[async_trait::async_trait]
impl MachineStateSnapshotLoader for DbMachineStateSnapshotLoader {
    async fn load_machine_snapshot(
        &self,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        uuid: uuid::Uuid,
    ) -> Result<MachineStateSnapshot, MachineStateSnapshotLoaderError> {
        // TODO: Implement me properly
        let snapshot = MachineStateSnapshot {
            id: uuid,
            current: CurrentMachineState {},
            config: MachineConfig {},
        };

        Ok(snapshot)
    }
}
