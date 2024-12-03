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

use std::collections::{HashMap, HashSet};

use crate::db::{instance, ObjectColumnFilter};
use crate::{
    cfg::file::HardwareHealthReportsConfig,
    db::{
        self,
        instance::{FindInstanceTypeFilter, Instance},
        machine::Machine,
        DatabaseError,
    },
    model::{
        instance::snapshot::InstanceSnapshot,
        machine::{MachineSnapshot, ManagedHostStateSnapshot},
    },
};
use forge_uuid::{instance::InstanceId, machine::MachineId};

/// Loads a ManagedHost snapshot from the database
pub async fn load_snapshot(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
    options: LoadSnapshotOptions,
) -> Result<Option<ManagedHostStateSnapshot>, DatabaseError> {
    let mut snapshots = load_by_machine_ids(txn, &[machine_id.clone()], options).await?;
    Ok(snapshots.remove(machine_id))
}

/// Loads ManagedHost snapshots from the database for all enumerated machines
///
/// The method works for Host and DPU Machine IDs
/// When used for DPU Machine IDs, the returned HashMap will contain an entry
/// that maps from the DPU Machine ID to the ManagedHost snapshot
pub async fn load_by_machine_ids(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_ids: &[MachineId],
    options: LoadSnapshotOptions,
) -> Result<HashMap<MachineId, ManagedHostStateSnapshot>, DatabaseError> {
    // If DPU IDs are specified, we really need to find the associated hosts for
    // some follow-up queries. However we also need to keep track of which Host
    // and DPU IDs have been **explicitly** requested, in order to build the result map.
    let mut all_host_ids = HashSet::new();
    let mut requested_host_ids = HashSet::new();
    let mut host_ids_by_requested_dpu_ids = HashMap::new();
    for machine_id in machine_ids.iter() {
        if !machine_id.machine_type().is_dpu() {
            all_host_ids.insert(machine_id.clone());
            requested_host_ids.insert(machine_id.clone());
        } else {
            // TODO: This is slow. We should have an API which loads us all the associated host IDs
            // However the Method is not used in a hot path - only debug tools query for DPU information
            match Machine::find_host_machine_id_by_dpu_machine_id(txn, machine_id).await? {
                Some(host_id) => {
                    host_ids_by_requested_dpu_ids.insert(machine_id.clone(), host_id.clone());
                    all_host_ids.insert(host_id);
                }
                None => {
                    tracing::warn!(
                        "Could not find any Host Machine ID for DPU Machine {machine_id}"
                    );
                }
            }
        }
    }

    let all_host_ids_vec: Vec<MachineId> = all_host_ids.into_iter().collect();
    let mut states =
        load_host_and_dpu_machine_states(txn, &all_host_ids_vec, options.include_history).await?;

    let instances = if options.include_instance_data {
        Instance::find_by_machine_ids(txn, &all_host_ids_vec).await?
    } else {
        Vec::new()
    };
    let mut instances_by_host_id: HashMap<MachineId, InstanceSnapshot> = instances
        .into_iter()
        .map(|instance| (instance.machine_id.clone(), instance))
        .collect();

    let mut snapshots_by_host_id = HashMap::with_capacity(states.hosts_by_id.len());
    'machine_loop: for (host_machine_id, host_snapshot) in states.hosts_by_id.into_iter() {
        let mut dpu_snapshots = Vec::with_capacity(host_snapshot.interfaces.len());
        for iface in host_snapshot.interfaces.iter() {
            if let Some(dpu_id) = &iface.attached_dpu_machine_id {
                match states.dpus_by_id.remove(dpu_id) {
                    Some(dpu) => dpu_snapshots.push(dpu),
                    None => {
                        tracing::warn!(
                            "DPU with ID {dpu_id} for Host {} was not found",
                            host_snapshot.machine_id
                        );
                        continue 'machine_loop;
                    }
                }
            }
        }

        let instance = instances_by_host_id.remove(&host_machine_id);
        let managed_state = host_snapshot.current.state.clone();

        let snapshot = ManagedHostStateSnapshot::create(
            host_snapshot,
            dpu_snapshots,
            instance,
            managed_state,
            options.hardware_health,
        )
        .map_err(|x| DatabaseError {
            file: file!(),
            line: line!(),
            query: "managed_host creation".to_string(),
            source: sqlx::error::Error::Protocol(x.to_string()),
        })?;

        snapshots_by_host_id.insert(host_machine_id, snapshot);
    }

    // Now that we've built the snapshots for all hosts that have been somehow referenced
    // in the query, go back and fulfill the original request
    let mut result = HashMap::with_capacity(machine_ids.len());
    // First loop is for requested DPUs
    // Since their snapshot might also have been queried for a host in the same query,
    // we have to clone from snapshots_by_host_id
    for (dpu_machine_id, host_machine_id) in host_ids_by_requested_dpu_ids.iter() {
        if let Some(snapshot) = snapshots_by_host_id.get(host_machine_id) {
            result.insert(dpu_machine_id.clone(), snapshot.clone());
        }
    }
    // Then extract the explicitly requested host snapshots. Since they can't be requested
    // by any DPU anymore, we can move them out of the map
    for host_machine_id in requested_host_ids.iter() {
        if let Some(snapshot) = snapshots_by_host_id.remove(host_machine_id) {
            result.insert(host_machine_id.clone(), snapshot);
        }
    }

    Ok(result)
}

/// Loads a ManagedHost snapshots from the database based on a list of Instance IDs
pub async fn load_by_instance_ids(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_ids: &[InstanceId],
    load_snapshot_options: LoadSnapshotOptions,
) -> Result<Vec<ManagedHostStateSnapshot>, DatabaseError> {
    let instance_snapshots = Instance::find(
        txn,
        FindInstanceTypeFilter::Id(ObjectColumnFilter::List(instance::IdColumn, instance_ids)),
    )
    .await?;

    load_by_instance_snapshots(txn, instance_snapshots, load_snapshot_options).await
}

/// Loads a ManagedHost snapshots from the database based on a pre-loaded list of InstanceSnapshots
pub async fn load_by_instance_snapshots(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_snapshots: Vec<InstanceSnapshot>,
    options: LoadSnapshotOptions,
) -> Result<Vec<ManagedHostStateSnapshot>, DatabaseError> {
    let mut host_machine_ids = Vec::with_capacity(instance_snapshots.len());
    let mut instance_snapshots_by_machine_id = HashMap::with_capacity(instance_snapshots.len());
    for instance_snapshot in instance_snapshots.into_iter() {
        host_machine_ids.push(instance_snapshot.machine_id.clone());
        instance_snapshots_by_machine_id
            .insert(instance_snapshot.machine_id.clone(), instance_snapshot);
    }

    let mut machines =
        load_host_and_dpu_machine_states(txn, host_machine_ids.as_ref(), options.include_history)
            .await?;

    let mut managed_hosts = Vec::with_capacity(machines.hosts_by_id.len());
    'machine_loop: for (host_machine_id, host_machine) in machines.hosts_by_id.into_iter() {
        let mut dpu_snapshots = Vec::with_capacity(host_machine.interfaces.len());
        for iface in host_machine.interfaces.iter() {
            if let Some(dpu_id) = &iface.attached_dpu_machine_id {
                match machines.dpus_by_id.remove(dpu_id) {
                    Some(dpu) => dpu_snapshots.push(dpu),
                    None => {
                        tracing::warn!(
                            "DPU with ID {dpu_id} for Host {} was not found",
                            host_machine.machine_id
                        );
                        continue 'machine_loop;
                    }
                }
            }
        }

        let instance = instance_snapshots_by_machine_id.remove(&host_machine_id);
        let managed_state = host_machine.current.state.clone();
        let snapshot = ManagedHostStateSnapshot::create(
            host_machine,
            dpu_snapshots,
            instance,
            managed_state,
            options.hardware_health,
        )
        .map_err(|x| DatabaseError {
            file: file!(),
            line: line!(),
            query: "managed_host creation".to_string(),
            source: sqlx::error::Error::Protocol(x.to_string()),
        })?;

        managed_hosts.push(snapshot);
    }

    Ok(managed_hosts)
}

async fn load_host_and_dpu_machine_states(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_machine_ids: &[MachineId],
    include_history: bool,
) -> Result<LoadHostAndDpuMachinesResult, DatabaseError> {
    let hosts = Machine::find(
        txn,
        super::ObjectFilter::List(host_machine_ids),
        crate::db::machine::MachineSearchConfig::default(),
    )
    .await?;

    let mut hosts_by_id: HashMap<MachineId, MachineSnapshot> =
        HashMap::with_capacity(host_machine_ids.len());
    let mut dpu_machine_ids = Vec::with_capacity(hosts.len());
    for host_machine in hosts.into_iter() {
        for iface in host_machine.interfaces().iter() {
            if let Some(dpu_id) = &iface.attached_dpu_machine_id {
                dpu_machine_ids.push(dpu_id.clone());
            }
        }
        hosts_by_id.insert(host_machine.id().clone(), host_machine.into());
    }
    let dpus = Machine::find(
        txn,
        super::ObjectFilter::List(dpu_machine_ids.as_ref()),
        crate::db::machine::MachineSearchConfig::default(),
    )
    .await?;
    let mut dpus_by_id: HashMap<MachineId, MachineSnapshot> = dpus
        .into_iter()
        .map(|dpu| (dpu.id().clone(), dpu.into()))
        .collect();

    if include_history {
        let mut all_machine_ids: Vec<MachineId> = host_machine_ids.to_vec();
        all_machine_ids.extend(dpu_machine_ids.into_iter());
        // TODO: Instead of loading this for DPUs and Host, we might just load it for the host and either copy
        // to all Machine Snapshots, or just keep a single history in `[ManagedHostSnapshot]`.
        let histories =
            db::machine_state_history::find_by_machine_ids(txn, &all_machine_ids).await?;

        for (machine_id, history) in histories.into_iter() {
            if !machine_id.machine_type().is_dpu() {
                if let Some(host) = hosts_by_id.get_mut(&machine_id) {
                    host.history = history;
                }
            } else if let Some(dpu) = dpus_by_id.get_mut(&machine_id) {
                dpu.history = history;
            }
        }
    }

    Ok(LoadHostAndDpuMachinesResult {
        hosts_by_id,
        dpus_by_id,
    })
}

struct LoadHostAndDpuMachinesResult {
    pub hosts_by_id: HashMap<MachineId, MachineSnapshot>,
    pub dpus_by_id: HashMap<MachineId, MachineSnapshot>,
}

pub struct LoadSnapshotOptions {
    /// Whether to also load the Machines history
    pub include_history: bool,
    /// Whether to load instance details
    pub include_instance_data: bool,
    /// How to use hardware health for health report aggregation
    pub hardware_health: HardwareHealthReportsConfig,
}

impl Default for LoadSnapshotOptions {
    fn default() -> Self {
        Self {
            include_history: false,
            include_instance_data: true,
            hardware_health: Default::default(),
        }
    }
}

impl LoadSnapshotOptions {
    pub fn with_hw_health(mut self, value: HardwareHealthReportsConfig) -> Self {
        self.hardware_health = value;
        self
    }
}
