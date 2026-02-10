/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//!
//! Database access methods for manipulating the state of a ManagedHost (Host+DPUs)
//!

use std::collections::HashMap;
use std::ops::Deref;

use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{MachineId, MachineType};
use itertools::Itertools;
use lazy_static::lazy_static;
use model::machine::{LoadSnapshotOptions, ManagedHostStateSnapshot};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, queries};

/// Loads a ManagedHost snapshot from the database
pub async fn load_snapshot<DB>(
    txn: &mut DB,
    machine_id: &MachineId,
    options: LoadSnapshotOptions,
) -> Result<Option<ManagedHostStateSnapshot>, DatabaseError>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    let mut snapshots = load_by_machine_ids(txn, &[*machine_id], options).await?;
    Ok(snapshots.remove(machine_id))
}

/// Loads all ManagedHosts, including predicted hosts
pub async fn load_all(
    txn: impl DbReader<'_>,
    options: LoadSnapshotOptions,
) -> Result<Vec<ManagedHostStateSnapshot>, DatabaseError> {
    let query = managed_host_snapshots_query(&options);
    Ok(sqlx::query_as(&format!(
        r#"{query} WHERE NOT starts_with(m.id, '{}')"#,
        MachineType::Dpu.id_prefix(),
    ))
    .fetch_all(txn)
    .await
    .map_err(|e| DatabaseError::new("managed_host::load_all", e))?
    .into_iter()
    .map(|mut snapshot: ManagedHostStateSnapshot| {
        snapshot.derive_aggregate_health(options.host_health_config);
        snapshot
    })
    .collect())
}

/// Loads ManagedHost snapshots from the database for all enumerated machines
///
/// The method works for Host and DPU Machine IDs
/// When used for DPU Machine IDs, the returned HashMap will contain an entry
/// that maps from the DPU Machine ID to the ManagedHost snapshot
pub async fn load_by_machine_ids<DB>(
    txn: &mut DB,
    requested_machine_ids: &[MachineId],
    options: LoadSnapshotOptions,
) -> Result<HashMap<MachineId, ManagedHostStateSnapshot>, DatabaseError>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    // Partition the ID's by whether or not they're DPU's.
    let (requested_dpu_ids, requested_host_ids): (Vec<MachineId>, Vec<MachineId>) =
        requested_machine_ids
            .iter()
            .partition(|id| id.machine_type().is_dpu());

    // Perf optimization: Joining through machine_interfaces to look up by DPU ID is slower by 100x
    // or so. If we're searching for DPU ID's, resolve their host ID's now.
    let requested_host_id_strings = requested_host_ids
        .iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>();
    let host_ids = if !requested_dpu_ids.is_empty() {
        [
            requested_host_id_strings,
            crate::machine::lookup_host_machine_ids_by_dpu_ids(&mut *txn, &requested_dpu_ids)
                .await?
                .into_iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>(),
        ]
        .concat()
        .into_iter()
        .unique()
        .collect()
    } else {
        requested_host_id_strings
    };

    // Perf optimization: If we're only requesting one ID, do `WHERE m.id = $1`. In practice on a db
    // with lots of hosts, this reduces the query time from ~20ms down to ~0.7ms.
    let query: String; // make sure it lives long enough
    let sqlx_query = if host_ids.len() == 1 {
        query = format!("{} WHERE m.id = $1", managed_host_snapshots_query(&options));
        sqlx::query_as(&query).bind(&host_ids[0])
    } else {
        query = format!(
            "{} WHERE m.id = ANY($1)",
            managed_host_snapshots_query(&options)
        );
        sqlx::query_as(&query).bind(host_ids)
    };

    // Index snapshots into a HashMap by their machine_id, while calling derive_aggregate_health on
    // each. It's mut because we are going to re-index by the ID's that the user requested, which
    // may be different from the managed_host ID.
    let mut snapshots_by_host_id: HashMap<MachineId, ManagedHostStateSnapshot> = sqlx_query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("managed_host::load_by_machine_ids", e))?
        .into_iter()
        .map(|mut snapshot: ManagedHostStateSnapshot| {
            snapshot.derive_aggregate_health(options.host_health_config);
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
    txn: &mut PgConnection,
    instance_ids: &[InstanceId],
    load_snapshot_options: LoadSnapshotOptions,
) -> Result<Vec<ManagedHostStateSnapshot>, DatabaseError> {
    let query = format!(
        r#"SELECT m.* FROM ({}) m
        INNER JOIN instances i ON i.machine_id = m.id
        WHERE i.id = ANY(
    "#,
        managed_host_snapshots_query(&load_snapshot_options)
    );
    let result: Vec<ManagedHostStateSnapshot> = sqlx::QueryBuilder::new(query)
        .push_bind(instance_ids)
        .push(")")
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("managed_host::load_by_instance_ids", e))?
        .into_iter()
        .map(|mut s: ManagedHostStateSnapshot| {
            s.derive_aggregate_health(load_snapshot_options.host_health_config);
            s
        })
        .collect();
    Ok(result)
}

// Return the appropriate query to use for finding managed hosts, depending on the options
fn managed_host_snapshots_query(options: &LoadSnapshotOptions) -> &str {
    // Use lazy_static so we don't have to interpolate strings every time
    lazy_static! {
        static ref managed_host_snapshots_with_instances_query: String = format!(
            r#"
        SELECT m.*, COALESCE(row_to_json(i.*), 'null') AS instance
        FROM ({}) m
        LEFT JOIN instances i ON i.machine_id = m.id
        "#,
            queries::MANAGED_HOSTS_NO_HISTORY.as_str(),
        );
        static ref managed_host_snapshots_with_instances_and_history_query: String = format!(
            r#"
        SELECT m.*, COALESCE(row_to_json(i.*), 'null') AS instance
        FROM ({}) m
        LEFT JOIN instances i ON i.machine_id = m.id
        "#,
            queries::MANAGED_HOSTS_WITH_HISTORY.as_str(),
        );
    }

    if options.include_instance_data {
        if options.include_history {
            managed_host_snapshots_with_instances_and_history_query.deref()
        } else {
            managed_host_snapshots_with_instances_query.deref()
        }
    } else if options.include_history {
        &queries::MANAGED_HOSTS_WITH_HISTORY
    } else {
        &queries::MANAGED_HOSTS_NO_HISTORY
    }
}
