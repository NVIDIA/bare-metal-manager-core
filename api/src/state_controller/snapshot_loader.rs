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
        instance::{Instance, InstanceId},
        machine::Machine,
        machine_interface::MachineInterface,
        machine_interface_address::MachineInterfaceAddress,
        network_segment::{
            NetworkSegment, NetworkSegmentIdKeyedObjectFilter, NetworkSegmentSearchConfig,
        },
        DatabaseError,
    },
    model::{
        instance::{snapshot::InstanceSnapshot, status::InstanceStatusObservations},
        machine::{
            machine_id::MachineId, CurrentMachineState, MachineInterfaceSnapshot, MachineSnapshot,
            ManagedHostState, ManagedHostStateSnapshot, ReprovisionRequest,
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
}

/// A service which allows to load a instance snapshot from the database
#[async_trait::async_trait]
pub trait InstanceSnapshotLoader: Send + Sync + std::fmt::Debug {
    /// Loads a instance snapshot from the database
    async fn load_instance_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        instance_id: InstanceId,
        machine_state: ManagedHostState,
        reprovision_request: Option<ReprovisionRequest>,
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
    InstanceNotFound(InstanceId),
    #[error("Invalid result: {0}")]
    InvalidResult(String),
    #[error("Machine with ID {0} was not found.")]
    MachineNotFound(MachineId),
    #[error("DPU for host machine with ID {0} was not found.")]
    DPUNotFound(MachineId),
    #[error("Host for dpu machine with ID {0} was not found.")]
    HostNotFound(MachineId),
    #[error("Expected 1 instance with id {0} found {1}")]
    MultipleInstances(uuid::Uuid, usize),
    #[error("State handling generic error: {0}")]
    GenericError(eyre::Report),
}

/// Load a machine state snapshot from a postgres database
#[derive(Debug, Default)]
pub struct DbSnapshotLoader;

pub async fn get_machine_snapshot(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine: &Machine,
) -> Result<MachineSnapshot, SnapshotLoaderError> {
    let snapshot = MachineSnapshot {
        machine_id: machine.id().clone(),
        bmc_info: machine.bmc_info().clone(),
        bmc_vendor: machine.bmc_vendor(),
        hardware_info: machine.hardware_info().cloned(),
        inventory: machine.inventory().cloned().unwrap_or_default(),
        network_config: machine.network_config().clone(),
        interfaces: interface_to_snapshot(txn, machine.interfaces()).await?,
        network_status_observation: machine.network_status_observation().cloned(),
        current: CurrentMachineState {
            state: machine.current_state(),
            version: machine.current_version(),
        },
        last_discovery_time: machine.last_discovery_time(),
        last_reboot_time: machine.last_reboot_time(),
        last_cleanup_time: machine.last_cleanup_time(),
        failure_details: machine.failure_details(),
        reprovision_requested: machine.reprovisioning_requested(),
        last_reboot_requested: machine.last_reboot_requested(),
        bios_password_set_time: machine.bios_password_set_time(),
        last_machine_validation_time: machine.last_machine_validation_time(),
        current_machine_validation_id: machine.current_machine_validation_id(),
    };

    Ok(snapshot)
}

pub async fn interface_to_snapshot(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    interfaces: &[MachineInterface],
) -> Result<Vec<MachineInterfaceSnapshot>, SnapshotLoaderError> {
    let mut out = Vec::new();
    for iface in interfaces {
        let segments = NetworkSegment::find(
            txn,
            NetworkSegmentIdKeyedObjectFilter::One(iface.segment_id()),
            NetworkSegmentSearchConfig::default(),
        )
        .await?;
        // machine_interfaces to network_segments is many-to-one, so this can only be 0 or 1
        if segments.len() != 1 {
            return Err(SnapshotLoaderError::GenericError(eyre::eyre!(
                "Interface {} has {} segments, expected 1",
                iface.id,
                segments.len()
            )));
        }
        let segment = &segments[0];

        let prefix = match segment.prefixes.first() {
            Some(p) => p,
            None => {
                return Err(SnapshotLoaderError::GenericError(eyre::eyre!(
                    "Network segment '{}' has no network prefixes, expected 1",
                    segment.id,
                )));
            }
        };

        // One IPv4 and potentially many IPv6, find the IPv4
        let address = MachineInterfaceAddress::find_ipv4_for_interface(txn, iface.id).await?;

        out.push(MachineInterfaceSnapshot {
            id: iface.id,
            hostname: iface.hostname().to_string(),
            is_primary: iface.primary_interface(),
            mac_address: iface.mac_address.to_string(),
            ip_address: address.address,
            vlan_id: segment.vlan_id.unwrap_or_default() as u32,
            vni: segment.vni.map(|v| v as u32).unwrap_or_default(), // not on underlay networks
            gateway_cidr: prefix.gateway_cidr().unwrap_or_default(),
        });
    }
    Ok(out)
}

#[async_trait::async_trait]
impl MachineStateSnapshotLoader for DbSnapshotLoader {
    async fn load_machine_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        machine_id: &MachineId,
    ) -> Result<ManagedHostStateSnapshot, SnapshotLoaderError> {
        let host_machine = if machine_id.machine_type().is_dpu() {
            Machine::find_host_by_dpu_machine_id(txn, machine_id)
                .await
                .map_err(|err| SnapshotLoaderError::GenericError(err.into()))?
                .ok_or_else(|| SnapshotLoaderError::HostNotFound(machine_id.clone()))?
        } else {
            Machine::find_one(
                txn,
                machine_id,
                crate::db::machine::MachineSearchConfig::default(),
            )
            .await
            .map_err(|err| SnapshotLoaderError::GenericError(err.into()))?
            .ok_or_else(|| SnapshotLoaderError::HostNotFound(machine_id.clone()))?
        };

        let dpus = Machine::find_dpus_by_host_machine_id(txn, host_machine.id())
            .await
            .map_err(|err| SnapshotLoaderError::GenericError(err.into()))?;

        let host_snapshot = get_machine_snapshot(txn, &host_machine).await?;

        let mut dpu_snapshots: Vec<MachineSnapshot> = Vec::new();
        for dpu in &dpus {
            dpu_snapshots.push(get_machine_snapshot(txn, dpu).await?);
        }

        // Determine whether there is any outstanding reprovision request which needs
        // to be relayed to the instance.
        // TODO: If there's multiple, it might not be deterinistic which one shows up
        let mut reprovision_request = host_snapshot.reprovision_requested.clone();
        for dpu_snapshot in &dpu_snapshots {
            if let Some(reprovision_requested) = &dpu_snapshot.reprovision_requested {
                reprovision_request = Some(reprovision_requested.clone());
            }
        }

        let instance_id = Instance::find_id_by_machine_id(txn, host_machine.id()).await?;
        let instance_snapshot = match instance_id {
            Some(instance_id) => Some(
                self.load_instance_snapshot(
                    txn,
                    instance_id,
                    host_snapshot.current.state.clone(),
                    reprovision_request,
                )
                .await?,
            ),
            None => None,
        };

        let managed_state = host_snapshot.current.state.clone();
        let snapshot = ManagedHostStateSnapshot {
            host_snapshot,
            dpu_snapshots,
            instance: instance_snapshot,
            managed_state,
        };

        Ok(snapshot)
    }
}

#[async_trait::async_trait]
impl InstanceSnapshotLoader for DbSnapshotLoader {
    async fn load_instance_snapshot(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        instance_id: InstanceId,
        machine_state: ManagedHostState,
        reprovision_request: Option<ReprovisionRequest>,
    ) -> Result<InstanceSnapshot, SnapshotLoaderError> {
        let instance = Instance::find_by_id(txn, instance_id)
            .await
            .map_err(|err| SnapshotLoaderError::GenericError(err.into()))?
            .ok_or_else(|| SnapshotLoaderError::InstanceNotFound(instance_id))?;

        let snapshot = InstanceSnapshot {
            instance_id,
            machine_id: instance.machine_id,
            machine_state,
            metadata: instance.metadata,
            config: instance.config,
            config_version: instance.config_version,
            network_config_version: instance.network_config_version,
            ib_config_version: instance.ib_config_version,
            observations: InstanceStatusObservations {
                network: instance.network_status_observation,
                infiniband: instance.ib_status_observation,
                phone_home_last_contact: instance.phone_home_last_contact,
            },
            delete_requested: instance.deleted.is_some(),
            reprovision_request,
        };

        Ok(snapshot)
    }
}
