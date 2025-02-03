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

//! InfiniBand related functions that are used in the Machine handler

use std::collections::{HashMap, HashSet};

use chrono::Utc;

use crate::db::ObjectColumnFilter;
use crate::{
    db,
    db::ib_partition,
    ib::{
        self,
        types::{IBNetwork, IBPortState},
        DEFAULT_IB_FABRIC_NAME,
    },
    model::instance::config::infiniband::InstanceIbInterfaceConfig,
    model::machine::{
        infiniband::{MachineIbInterfaceStatusObservation, MachineInfinibandStatusObservation},
        ManagedHostStateSnapshot,
    },
    state_controller::state_handler::{StateHandlerError, StateHandlerServices},
};
use forge_uuid::{infiniband::IBPartitionId, instance::InstanceId};

pub(crate) async fn record_machine_infiniband_status_observation(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mh_snapshot: &mut ManagedHostStateSnapshot,
) -> Result<(), StateHandlerError> {
    if mh_snapshot.host_snapshot.hardware_info.is_none() {
        // Skip status update during DPU initialization
        return Ok(());
    }

    let machine_id = &mh_snapshot.host_snapshot.machine_id;
    let ib_hw_info = &mh_snapshot
        .host_snapshot
        .hardware_info
        .as_ref()
        .unwrap()
        .infiniband_interfaces;

    // Form list of requested guids
    let mut guids: Vec<String> = Vec::new();
    for ib_interface in ib_hw_info.iter() {
        guids.push(ib_interface.guid.clone());
    }

    let mut prev = mh_snapshot
        .host_snapshot
        .infiniband_status_observation
        .clone()
        .unwrap_or_default();

    let cur = if guids.is_empty() {
        // Create empty infiniband statuses record.
        if mh_snapshot
            .host_snapshot
            .infiniband_status_observation
            .is_none()
        {
            MachineInfinibandStatusObservation {
                observed_at: Utc::now(),
                ib_interfaces: vec![],
            }
        } else {
            // This allows to update an empty record once.
            prev.clone()
        }
    } else {
        // Collect actual infiniband statuses.
        let ib_fabric = services
            .ib_fabric_manager
            .connect(DEFAULT_IB_FABRIC_NAME)
            .await
            .map_err(|e| StateHandlerError::IBFabricError {
                operation: "connect".to_string(),
                error: e.into(),
            })?;

        // Get the status of ports from UFM, and persist it as observed status.
        // Not filter by pkey and check port status directly.
        let filter = ib::Filter {
            guids: Some(guids.iter().cloned().collect()),
            pkey: None,
            state: Some(IBPortState::Active),
        };
        let ports = ib_fabric
            .find_ib_port(Some(filter))
            .await
            .map_err(|err| StateHandlerError::GenericError(err.into()))?;

        if ports.len() != guids.len() {
            let mut expected_guids = HashSet::new();
            expected_guids.extend(guids.clone());
            for port in ports.iter() {
                expected_guids.remove(&port.guid);
            }

            let e = StateHandlerError::IBFabricError {
                operation: "find_ib_port".to_string(),
                error: eyre::eyre!(format!(
                    "UFM did not return port information for GUIDs: {}",
                    expected_guids
                        .into_iter()
                        .collect::<Vec<String>>()
                        .join(", ")
                )),
            };
            tracing::error!("Detected invalid infiniband configuration {e}");
        }

        let mut ib_interfaces_status: Vec<MachineIbInterfaceStatusObservation> =
            Vec::with_capacity(guids.len());
        for iter_if in guids.iter() {
            ib_interfaces_status.push(MachineIbInterfaceStatusObservation {
                guid: iter_if.clone(),
                lid: 0xffff_u16,
            })
        }

        for port in ports.iter() {
            for iter_status in ib_interfaces_status.iter_mut() {
                if port.guid == iter_status.guid.clone() {
                    let status = MachineIbInterfaceStatusObservation::from(port);
                    iter_status.lid = status.lid;
                    break;
                }
            }
        }

        let cur = MachineInfinibandStatusObservation {
            observed_at: Utc::now(),
            ib_interfaces: ib_interfaces_status,
        };
        // This allows to update a record just in case any changes.
        prev.observed_at = cur.observed_at;
        cur
    };

    // Update Machine infiniband status in case any changes only
    // Vector of statuses is based on guids vector that is formed
    // from hardware_info.infiniband_interfaces[]
    // So it guarantees stable order between function calls
    if prev != cur {
        db::machine::update_infiniband_status_observation(txn, machine_id, &cur).await?;
    }

    Ok(())
}

pub(crate) async fn bind_ib_ports(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: InstanceId,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<IBPartitionId, Vec<String>>::new();
    for ib in ib_interfaces {
        let guid = ib.guid.ok_or(StateHandlerError::MissingData {
            object_id: instance_id.to_string(),
            missing: "GUID of IB Port",
        })?;

        ibconf.entry(ib.ib_partition_id).or_default().push(guid);
    }

    if ibconf.is_empty() {
        return Ok(());
    }

    let ib_fabric = services
        .ib_fabric_manager
        .connect(DEFAULT_IB_FABRIC_NAME)
        .await
        .map_err(|e| StateHandlerError::IBFabricError {
            operation: "connect".to_string(),
            error: e.into(),
        })?;

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find_by(
            txn,
            ObjectColumnFilter::One(ib_partition::IdColumn, &k),
            ib_partition::IBPartitionSearchConfig {
                include_history: false,
            },
        )
        .await?;

        let ibpartition = ib_partitions
            .first()
            .ok_or(StateHandlerError::MissingData {
                object_id: k.to_string(),
                missing: "ib_partition not found",
            })?;

        ib_fabric
            .bind_ib_ports(IBNetwork::from(ibpartition), v)
            .await
            .map_err(|e| StateHandlerError::IBFabricError {
                operation: "bind_ib_ports".to_string(),
                error: e.into(),
            })?;
    }

    Ok(())
}

pub(crate) async fn unbind_ib_ports(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: InstanceId,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<IBPartitionId, Vec<String>>::new();

    for ib in ib_interfaces {
        let guid = ib.guid.ok_or(StateHandlerError::MissingData {
            object_id: instance_id.to_string(),
            missing: "GUID of IB Port",
        })?;
        ibconf.entry(ib.ib_partition_id).or_default().push(guid);
    }

    if ibconf.is_empty() {
        return Ok(());
    }

    let ib_fabric = services
        .ib_fabric_manager
        .connect(DEFAULT_IB_FABRIC_NAME)
        .await
        .map_err(|e| StateHandlerError::IBFabricError {
            operation: "connect".to_string(),
            error: e.into(),
        })?;

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find_by(
            txn,
            ObjectColumnFilter::One(ib_partition::IdColumn, &k),
            ib_partition::IBPartitionSearchConfig {
                include_history: false,
            },
        )
        .await?;

        let ibpartition = ib_partitions
            .first()
            .ok_or(StateHandlerError::MissingData {
                object_id: k.to_string(),
                missing: "ib_partition not found",
            })?;
        let pkey = ibpartition
            .config
            .pkey
            .ok_or(StateHandlerError::MissingData {
                object_id: ibpartition.id.to_string(),
                missing: "ib_partition pkey",
            })?;

        ib_fabric
            .unbind_ib_ports(pkey, v)
            .await
            .map_err(|e| StateHandlerError::IBFabricError {
                operation: "unbind_ib_ports".to_string(),
                error: e.into(),
            })?;
    }

    Ok(())
}
