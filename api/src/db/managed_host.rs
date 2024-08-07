/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
//!
//! Database access methods for manipulating the state of a ManagedHost (Host+DPUs)
//!

use std::collections::HashMap;

use crate::{
    db::{
        self,
        instance::{FindInstanceTypeFilter, Instance, InstanceId, InstanceIdKeyedObjectFilter},
        machine::Machine,
        DatabaseError,
    },
    model::{
        instance::snapshot::InstanceSnapshot,
        machine::{machine_id::MachineId, MachineSnapshot, ManagedHostStateSnapshot},
    },
};

/// Loads a ManagedHost snapshot from the database
pub async fn load_snapshot(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
    options: LoadSnapshotOptions,
) -> Result<Option<ManagedHostStateSnapshot>, DatabaseError> {
    let host_machine = if machine_id.machine_type().is_dpu() {
        Machine::find_host_by_dpu_machine_id(txn, machine_id).await?
    } else {
        Machine::find_one(
            txn,
            machine_id,
            crate::db::machine::MachineSearchConfig::default(),
        )
        .await?
    };

    let Some(host_machine) = host_machine else {
        return Ok(None);
    };

    let dpus = Machine::find_dpus_by_host_machine_id(txn, host_machine.id()).await?;

    let host_snapshot: MachineSnapshot = host_machine.into();

    let mut dpu_snapshots: Vec<MachineSnapshot> = Vec::new();
    for dpu in dpus {
        dpu_snapshots.push(dpu.into());
    }

    let instance = match options.include_instance_data {
        true => Instance::find_by_machine_id(txn, &host_snapshot.machine_id).await?,
        false => None,
    };

    let managed_state = host_snapshot.current.state.clone();
    let mut snapshot = ManagedHostStateSnapshot {
        host_snapshot,
        dpu_snapshots,
        instance,
        managed_state,
        aggregate_health: health_report::HealthReport::empty("".to_string()),
    };
    snapshot.derive_aggregate_health();

    if options.include_history {
        let mut machine_ids = vec![snapshot.host_snapshot.machine_id.clone()];
        machine_ids.extend(
            snapshot
                .dpu_snapshots
                .iter()
                .map(|dpu| dpu.machine_id.clone()),
        );
        // TODO: Instead of loading this for DPUs and Host, we might just load it for the host and either copy
        // to all Machine Snapshots, or just keep a single history in `[ManagedHostSnapshot]`.
        let histories = db::machine_state_history::find_by_machine_ids(txn, &machine_ids).await?;

        for (machine_id, history) in histories.into_iter() {
            if !machine_id.machine_type().is_dpu() {
                snapshot.host_snapshot.history = history;
            } else if let Some(dpu_snapshot) = snapshot
                .dpu_snapshots
                .iter_mut()
                .find(|dpu| dpu.machine_id == machine_id)
            {
                dpu_snapshot.history = history;
            }
        }
    }

    Ok(Some(snapshot))
}

/// Loads a ManagedHost snapshots from the database based on a list of Instance IDs
pub async fn load_by_instance_ids(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_ids: &[InstanceId],
) -> Result<Vec<ManagedHostStateSnapshot>, DatabaseError> {
    let instance_snapshots = Instance::find(
        txn,
        FindInstanceTypeFilter::Id(&InstanceIdKeyedObjectFilter::List(instance_ids)),
    )
    .await?;

    load_by_instance_snapshots(txn, instance_snapshots).await
}

/// Loads a ManagedHost snapshots from the database based on a pre-loaded list of InstanceSnapshots
pub async fn load_by_instance_snapshots(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_snapshots: Vec<InstanceSnapshot>,
) -> Result<Vec<ManagedHostStateSnapshot>, DatabaseError> {
    let mut host_machine_ids = Vec::with_capacity(instance_snapshots.len());
    let mut instance_snapshots_by_machine_id = HashMap::with_capacity(instance_snapshots.len());
    for instance_snapshot in instance_snapshots.into_iter() {
        host_machine_ids.push(instance_snapshot.machine_id.clone());
        instance_snapshots_by_machine_id
            .insert(instance_snapshot.machine_id.clone(), instance_snapshot);
    }

    let mut machines = load_host_and_dpu_machine_states(txn, host_machine_ids.as_ref()).await?;

    let mut managed_hosts = Vec::with_capacity(machines.hosts.len());
    'machine_loop: for host_machine in machines.hosts.into_iter() {
        let mut dpu_snapshots = Vec::with_capacity(host_machine.interfaces().len());
        for iface in host_machine.interfaces().iter() {
            if let Some(dpu_id) = &iface.attached_dpu_machine_id {
                match machines.dpus_by_id.remove(dpu_id) {
                    Some(dpu) => dpu_snapshots.push(dpu.into()),
                    None => {
                        tracing::warn!(
                            "DPU with ID {dpu_id} for Host {} was not found",
                            host_machine.id()
                        );
                        continue 'machine_loop;
                    }
                }
            }
        }

        let instance = instance_snapshots_by_machine_id.remove(host_machine.id());
        let managed_state = host_machine.current_state();
        let mut snapshot = ManagedHostStateSnapshot {
            host_snapshot: host_machine.into(),
            dpu_snapshots,
            instance,
            managed_state,
            aggregate_health: health_report::HealthReport::empty("".to_string()),
        };
        snapshot.derive_aggregate_health();
        managed_hosts.push(snapshot);
    }

    Ok(managed_hosts)
}

async fn load_host_and_dpu_machine_states(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_machine_ids: &[MachineId],
) -> Result<LoadHostAndDpuMachinesResult, DatabaseError> {
    let hosts = Machine::find(
        txn,
        super::ObjectFilter::List(host_machine_ids),
        crate::db::machine::MachineSearchConfig::default(),
    )
    .await?;

    let mut dpu_machine_ids = Vec::with_capacity(hosts.len());
    for host_machine in hosts.iter() {
        for iface in host_machine.interfaces().iter() {
            if let Some(dpu_id) = &iface.attached_dpu_machine_id {
                dpu_machine_ids.push(dpu_id.clone());
            }
        }
    }
    let dpus = Machine::find(
        txn,
        super::ObjectFilter::List(dpu_machine_ids.as_ref()),
        crate::db::machine::MachineSearchConfig::default(),
    )
    .await?;
    let dpus_by_id: HashMap<MachineId, Machine> = dpus
        .into_iter()
        .map(|dpu| (dpu.id().clone(), dpu))
        .collect();

    Ok(LoadHostAndDpuMachinesResult { hosts, dpus_by_id })
}

struct LoadHostAndDpuMachinesResult {
    pub hosts: Vec<Machine>,
    pub dpus_by_id: HashMap<MachineId, Machine>,
}

pub struct LoadSnapshotOptions {
    /// Whether to also load the Machines history
    pub include_history: bool,
    /// Whether to load instance details
    pub include_instance_data: bool,
}

impl Default for LoadSnapshotOptions {
    fn default() -> Self {
        Self {
            include_history: false,
            include_instance_data: true,
        }
    }
}
