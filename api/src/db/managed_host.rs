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

use crate::db::machine::{MACHINE_SNAPSHOT_QUERY, MACHINE_SNAPSHOT_WITH_HISTORY_QUERY};
use crate::{
    cfg::file::HardwareHealthReportsConfig, db::DatabaseError,
    model::machine::ManagedHostStateSnapshot,
};
use forge_uuid::{instance::InstanceId, machine::MachineId};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

const MANAGED_HOST_SNAPSHOTS_QUERY_TEMPLATE: &str = r#"
    WITH
    machine_snapshots AS (
        __MACHINE_SNAPSHOT_QUERY__
    ),
    dpu_snapshots AS (
        SELECT i.machine_id AS managed_host_id, m.*
        FROM machine_interfaces i
        INNER JOIN machine_snapshots m ON m.id = i.attached_dpu_machine_id
        WHERE i.attached_dpu_machine_id <> i.machine_id
    ),
    dpu_snapshots_agg AS (
        SELECT dpus.managed_host_id, JSON_AGG(dpus.*) AS json
        FROM dpu_snapshots dpus
        GROUP BY dpus.managed_host_id
    )
    SELECT m.id, row_to_json(m.*) AS host_snapshot, COALESCE(dpu_snapshots_agg.json, '[]') AS dpu_snapshots
    FROM machine_snapshots m
    LEFT JOIN dpu_snapshots_agg ON dpu_snapshots_agg.managed_host_id = m.id
    "#;

/// Loads a ManagedHost snapshot from the database
pub async fn load_snapshot(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
    options: LoadSnapshotOptions,
) -> Result<Option<ManagedHostStateSnapshot>, DatabaseError> {
    let mut snapshots = load_by_machine_ids(txn, &[*machine_id], options).await?;
    Ok(snapshots.remove(machine_id))
}

/// Loads ManagedHost snapshots from the database for all enumerated machines
///
/// The method works for Host and DPU Machine IDs
/// When used for DPU Machine IDs, the returned HashMap will contain an entry
/// that maps from the DPU Machine ID to the ManagedHost snapshot
pub async fn load_by_machine_ids(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    requested_machine_ids: &[MachineId],
    options: LoadSnapshotOptions,
) -> Result<HashMap<MachineId, ManagedHostStateSnapshot>, DatabaseError> {
    let query = managed_host_snapshots_query(&options);

    // Partition the ID's by whether or not they're DPU's.
    let (requested_dpu_ids, requested_host_ids): (Vec<MachineId>, Vec<MachineId>) =
        requested_machine_ids
            .iter()
            .partition(|id| id.machine_type().is_dpu());

    // Index snapshots into a HashMap by their machine_id, while calling derive_aggregate_health on
    // each. It's mut because we are going to re-index by the ID's that the user requested, which
    // may be different from the managed_host ID.
    let mut snapshots_by_host_id: HashMap<MachineId, ManagedHostStateSnapshot> = [
        // Find host snapshots directly
        if requested_host_ids.is_empty() {
            vec![]
        } else {
            sqlx::QueryBuilder::new(format!(r#"{query} WHERE m.id = ANY("#))
                .push_bind(&requested_host_ids)
                .push(")")
                .build_query_as::<ManagedHostStateSnapshot>()
                .fetch_all(txn.deref_mut())
                .await
                .map_err(|e| {
                    DatabaseError::new(file!(), line!(), "managed_host::load_by_machine_ids", e)
                })?
        },
        // Find snapshots by DPU ID by going through the machine_interfaces table
        if requested_dpu_ids.is_empty() {
            vec![]
        } else {
            sqlx::QueryBuilder::new(format!(
                r#"{query}
                  INNER JOIN machine_interfaces mi ON mi.machine_id = m.id
                  WHERE mi.attached_dpu_machine_id <> mi.machine_id
                  AND mi.attached_dpu_machine_id = ANY("#
            ))
            .push_bind(&requested_dpu_ids)
            .push(")")
            .build_query_as::<ManagedHostStateSnapshot>()
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "managed_host::load_by_machine_ids", e)
            })?
        },
    ]
    .concat()
    .into_iter()
    .map(|mut snapshot| {
        snapshot.derive_aggregate_health(options.hardware_health);
        (snapshot.host_snapshot.id, snapshot)
    })
    .collect();

    // Make another level of index that gets the host snapshot ID's by a DPU ID
    let host_ids_by_dpu_id: HashMap<MachineId, MachineId> = snapshots_by_host_id
        .values()
        .flat_map(|snapshot| {
            snapshot
                .dpu_snapshots
                .iter()
                .map(|d| (d.id, snapshot.host_snapshot.id))
        })
        .collect();

    // Now that we've built the snapshots for all hosts that have been somehow referenced
    // in the query, go back and fulfill the original request
    let result = [
        // First loop is for requested DPUs
        // Since their snapshot might also have been queried for a host in the same query,
        // we have to clone from snapshots_by_host_id
        requested_dpu_ids
            .into_iter()
            .filter_map(|dpu_id| {
                host_ids_by_dpu_id.get(&dpu_id).and_then(|host_id| {
                    snapshots_by_host_id
                        .get(host_id)
                        .map(|snapshot| (dpu_id, snapshot.clone()))
                })
            })
            .collect::<Vec<_>>(),
        // Then extract the explicitly requested host snapshots. Since we already scanned through
        // requested DPUs, we can move them out of the map
        requested_host_ids
            .into_iter()
            .filter_map(|host_id| {
                snapshots_by_host_id
                    .remove(&host_id)
                    .map(|snapshot| (host_id, snapshot))
            })
            .collect::<Vec<_>>(),
    ]
    .concat()
    .into_iter()
    .collect::<HashMap<_, _>>();

    Ok(result)
}

/// Loads a ManagedHost snapshots from the database based on a list of Instance IDs
pub async fn load_by_instance_ids(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_ids: &[InstanceId],
    load_snapshot_options: LoadSnapshotOptions,
) -> Result<Vec<ManagedHostStateSnapshot>, DatabaseError> {
    let query = format!(
        r#"WITH managed_host_snapshots AS ({})
        SELECT m.* FROM managed_host_snapshots m
        INNER JOIN instances i ON i.machine_id = m.id
        WHERE i.id = ANY(
    "#,
        managed_host_snapshots_query(&load_snapshot_options)
    );
    let result: Vec<ManagedHostStateSnapshot> = sqlx::QueryBuilder::new(query)
        .push_bind(instance_ids)
        .push(")")
        .build_query_as()
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "managed_host::load_by_instance_ids", e))?
        .into_iter()
        .map(|mut s: ManagedHostStateSnapshot| {
            s.derive_aggregate_health(load_snapshot_options.hardware_health);
            s
        })
        .collect();
    Ok(result)
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

// Return the appropriate query to use for finding managed hosts, depending on the options
fn managed_host_snapshots_query(options: &LoadSnapshotOptions) -> &str {
    // Use lazy_static so we don't have to interpolate strings every time
    lazy_static! {
        static ref managed_host_snapshots_query: String = MANAGED_HOST_SNAPSHOTS_QUERY_TEMPLATE
            .replace(
                "__MACHINE_SNAPSHOT_QUERY__",
                MACHINE_SNAPSHOT_QUERY.as_ref()
            );
        static ref managed_host_snapshots_with_history_query: String =
            MANAGED_HOST_SNAPSHOTS_QUERY_TEMPLATE.replace(
                "__MACHINE_SNAPSHOT_QUERY__",
                MACHINE_SNAPSHOT_WITH_HISTORY_QUERY.as_ref()
            );
        static ref managed_host_snapshots_with_instances_query: String = format!(
            r#"
        WITH machine_snapshots AS ({})
        SELECT m.*, COALESCE(row_to_json(i.*), 'null') AS instance
        FROM machine_snapshots m
        LEFT JOIN instances i ON i.machine_id = m.id
        "#,
            managed_host_snapshots_query.deref()
        );
        static ref managed_host_snapshots_with_instances_and_history_query: String = format!(
            r#"
        WITH machine_snapshots AS ({})
        SELECT m.*, COALESCE(row_to_json(i.*), 'null') AS instance
        FROM machine_snapshots m
        LEFT JOIN instances i ON i.machine_id = m.id
        "#,
            managed_host_snapshots_with_history_query.deref()
        );
    }

    if options.include_instance_data {
        if options.include_history {
            managed_host_snapshots_with_instances_and_history_query.deref()
        } else {
            managed_host_snapshots_with_instances_query.deref()
        }
    } else if options.include_history {
        managed_host_snapshots_with_history_query.deref()
    } else {
        managed_host_snapshots_query.deref()
    }
}
