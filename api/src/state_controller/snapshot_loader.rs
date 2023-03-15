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
    db::{
        instance::{
            config::network::load_instance_network_config,
            status::network::load_instance_network_status_observation, Instance,
        },
        machine::{Machine, MachineSearchConfig},
        machine_topology::MachineTopology,
        DatabaseError,
    },
    model::{
        instance::{
            config::InstanceConfig, snapshot::InstanceSnapshot, status::InstanceStatusObservations,
        },
        machine::{CurrentMachineState, MachineStateSnapshot},
    },
};

/// A service which allows to load a machine state snapshot from the database
#[async_trait::async_trait]
pub trait MachineStateSnapshotLoader: Send + Sync + std::fmt::Debug {
    /// Loads a machine state snapshot from the database
    async fn load_machine_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        machine_id: uuid::Uuid,
    ) -> Result<MachineStateSnapshot, SnapshotLoaderError>;
}

/// A service which allows to load a instance snapshot from the database
#[async_trait::async_trait]
pub trait InstanceSnapshotLoader: Send + Sync + std::fmt::Debug {
    /// Loads a instance snapshot from the database
    async fn load_instance_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        instance_id: uuid::Uuid,
    ) -> Result<InstanceSnapshot, SnapshotLoaderError>;
}

/// Enumerates errors that are returned by [`MachineStateSnapshotLoader`]
#[derive(Debug, thiserror::Error)]
pub enum SnapshotLoaderError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] DatabaseError),
    #[error("Unable to load Hardware information: {0}")]
    HardwareInfoSqlError(sqlx::Error),
    #[error("Hardware information for Machine {0} is missing")]
    MissingHardwareInfo(uuid::Uuid),
    #[error("Instance with ID {0} was not found")]
    InstanceNotFound(uuid::Uuid),
    #[error("Invalid result: {0}")]
    InvalidResult(String),
    #[error("Machine with ID {0} was not found.")]
    MachineNotFound(uuid::Uuid),
    #[error("Expected 1 instance with id {0} found {1}")]
    MultipleInstances(uuid::Uuid, usize),
}

/// Load a machine state snapshot from a postgres database
#[derive(Debug, Default)]
pub struct DbSnapshotLoader;

#[async_trait::async_trait]
impl MachineStateSnapshotLoader for DbSnapshotLoader {
    async fn load_machine_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        machine_id: uuid::Uuid,
    ) -> Result<MachineStateSnapshot, SnapshotLoaderError> {
        let mut hardware_infos = MachineTopology::find_latest_by_machine_ids(txn, &[machine_id])
            .await
            .map_err(|e| SnapshotLoaderError::HardwareInfoSqlError(e.source))?;
        let info = hardware_infos
            .remove(&machine_id)
            .ok_or(SnapshotLoaderError::MissingHardwareInfo(machine_id))?;

        let instance_id = Instance::find_id_by_machine_id(txn, machine_id).await?;
        let instance_snapshot = match instance_id {
            Some(instance_id) => Some(self.load_instance_snapshot(txn, instance_id).await?),
            None => None,
        };

        let machine = Machine::find_one(txn, machine_id, MachineSearchConfig::default())
            .await?
            .ok_or(SnapshotLoaderError::MachineNotFound(machine_id))?;

        let snapshot = MachineStateSnapshot {
            machine_id,
            hardware_info: info.topology().discovery_data.info.clone(),
            current: CurrentMachineState {
                state: machine.current_state(),
                version: machine.current_version(),
            },
            instance: instance_snapshot,
        };

        Ok(snapshot)
    }
}

#[async_trait::async_trait]
impl InstanceSnapshotLoader for DbSnapshotLoader {
    async fn load_instance_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        instance_id: uuid::Uuid,
    ) -> Result<InstanceSnapshot, SnapshotLoaderError> {
        let mut instances =
            Instance::find(txn, crate::db::UuidKeyedObjectFilter::One(instance_id)).await?;
        if instances.is_empty() {
            return Err(SnapshotLoaderError::InstanceNotFound(instance_id));
        } else if instances.len() != 1 {
            return Err(SnapshotLoaderError::MultipleInstances(
                instance_id,
                instances.len(),
            ));
        }
        let instance = instances.pop().unwrap();

        let network_config = load_instance_network_config(txn, instance_id).await?;
        let network_config_version = network_config.version;
        let network_status_observations =
            load_instance_network_status_observation(txn, instance_id).await?;

        let snapshot = InstanceSnapshot {
            instance_id,
            machine_id: instance.machine_id,
            config: InstanceConfig {
                tenant: Some(instance.tenant_config),
                network: network_config.value,
            },
            network_config_version,
            observations: InstanceStatusObservations {
                network: network_status_observations,
            },
        };

        Ok(snapshot)
    }
}
