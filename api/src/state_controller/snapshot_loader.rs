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
    db::{
        instance::{
            config::network::load_instance_network_config,
            status::network::load_instance_network_status_observation, Instance,
        },
        machine::Machine,
        machine_topology::MachineTopology,
        DatabaseError,
    },
    model::{
        instance::{
            config::InstanceConfig, snapshot::InstanceSnapshot, status::InstanceStatusObservations,
        },
        machine::{
            machine_id::MachineId, CurrentMachineState, MachineSnapshot, ManagedHostState,
            ManagedHostStateSnapshot,
        },
    },
};

/// A service which allows to load a machine state snapshot from the database
#[async_trait::async_trait]
pub trait MachineStateSnapshotLoader: Send + Sync + std::fmt::Debug {
    /// Loads a machine state snapshot from the database
    async fn load_machine_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        machine_id: &MachineId,
    ) -> Result<ManagedHostStateSnapshot, SnapshotLoaderError>;

    /// Loads a machine state snapshot from the database for a given instance
    async fn load_machine_snapshot_for_host(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        host_machine_id: &MachineId,
    ) -> Result<ManagedHostStateSnapshot, SnapshotLoaderError>;
}

/// A service which allows to load a instance snapshot from the database
#[async_trait::async_trait]
pub trait InstanceSnapshotLoader: Send + Sync + std::fmt::Debug {
    /// Loads a instance snapshot from the database
    async fn load_instance_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        instance_id: uuid::Uuid,
        machine_state: ManagedHostState,
    ) -> Result<InstanceSnapshot, SnapshotLoaderError>;
}

/// Enumerates errors that are returned by [`MachineStateSnapshotLoader`]
#[derive(Debug, thiserror::Error)]
pub enum SnapshotLoaderError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] DatabaseError),
    #[error("Unable to load Hardware information: {0}")]
    HardwareInfoSqlError(String),
    #[error("Hardware information for Machine {0} is missing")]
    MissingHardwareInfo(MachineId),
    #[error("Instance with ID {0} was not found")]
    InstanceNotFound(uuid::Uuid),
    #[error("Invalid result: {0}")]
    InvalidResult(String),
    #[error("Machine with ID {0} was not found.")]
    MachineNotFound(MachineId),
    #[error("DPU for host machine with ID {0} was not found.")]
    DPUNotFound(MachineId),
    #[error("Expected 1 instance with id {0} found {1}")]
    MultipleInstances(uuid::Uuid, usize),
    #[error("State handling generic error: {0}")]
    GenericError(anyhow::Error),
}

/// Load a machine state snapshot from a postgres database
#[derive(Debug, Default)]
pub struct DbSnapshotLoader;

pub async fn get_machine_snapshot(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
) -> Result<MachineSnapshot, SnapshotLoaderError> {
    let mut hardware_infos =
        MachineTopology::find_latest_by_machine_ids(txn, &[machine_id.clone()])
            .await
            .map_err(|e| SnapshotLoaderError::HardwareInfoSqlError(e.to_string()))?;
    let info = hardware_infos.remove(machine_id);
    let machine = Machine::find_one(
        txn,
        machine_id,
        crate::db::machine::MachineSearchConfig::default(),
    )
    .await
    .map_err(|err| SnapshotLoaderError::GenericError(err.into()))?
    .ok_or(SnapshotLoaderError::MachineNotFound(machine_id.clone()))?;
    let snapshot = MachineSnapshot {
        machine_id: machine_id.clone(),
        hardware_info: info.map(|x| x.topology().discovery_data.info.clone()),
        current: CurrentMachineState {
            state: machine.current_state(),
            version: machine.current_version(),
        },
        last_discovery_time: machine.last_discovery_time(),
        last_reboot_time: machine.last_reboot_time(),
        last_cleanup_time: machine.last_cleanup_time(),
    };

    Ok(snapshot)
}

#[async_trait::async_trait]
impl MachineStateSnapshotLoader for DbSnapshotLoader {
    async fn load_machine_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        dpu_machine_id: &MachineId,
    ) -> Result<ManagedHostStateSnapshot, SnapshotLoaderError> {
        let host = Machine::find_host_by_dpu_machine_id(txn, dpu_machine_id)
            .await
            .map_err(|err| SnapshotLoaderError::GenericError(err.into()))?;

        let dpu_snapshot = get_machine_snapshot(txn, dpu_machine_id).await?;
        let instance_snapshot = match &host {
            None => None,
            Some(machine) => {
                let instance_id = Instance::find_id_by_machine_id(txn, machine.id()).await?;
                match instance_id {
                    Some(instance_id) => Some(
                        self.load_instance_snapshot(
                            txn,
                            instance_id,
                            dpu_snapshot.current.state.clone(),
                        )
                        .await?,
                    ),
                    None => None,
                }
            }
        };

        let snapshot = ManagedHostStateSnapshot {
            host_snapshot: if let Some(host) = host {
                Some(get_machine_snapshot(txn, host.id()).await?)
            } else {
                None
            },
            dpu_snapshot: dpu_snapshot.clone(),
            instance: instance_snapshot,
            managed_state: dpu_snapshot.current.state,
        };

        Ok(snapshot)
    }

    async fn load_machine_snapshot_for_host(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        host_machine_id: &MachineId,
    ) -> Result<ManagedHostStateSnapshot, SnapshotLoaderError> {
        let Some(dpu) = Machine::find_dpu_by_host_machine_id(txn, host_machine_id)
            .await
            .map_err(|err| SnapshotLoaderError::GenericError(err.into()))? else {
            return Err(SnapshotLoaderError::DPUNotFound(host_machine_id.clone()));
        };

        self.load_machine_snapshot(txn, dpu.id()).await
    }
}

#[async_trait::async_trait]
impl InstanceSnapshotLoader for DbSnapshotLoader {
    async fn load_instance_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        instance_id: uuid::Uuid,
        machine_state: ManagedHostState,
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
            machine_state,
            config: InstanceConfig {
                tenant: Some(instance.tenant_config),
                network: network_config.value,
            },
            network_config_version,
            observations: InstanceStatusObservations {
                network: network_status_observations,
            },
            delete_requested: instance.deleted.is_some(),
        };

        Ok(snapshot)
    }
}
