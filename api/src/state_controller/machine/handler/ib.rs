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
    db::{ib_partition, instance::Instance},
    ib::{self, types::IBNetwork, DEFAULT_IB_FABRIC_NAME},
    model::instance::{
        config::infiniband::InstanceIbInterfaceConfig,
        snapshot::InstanceSnapshot,
        status::infiniband::{
            InstanceIbInterfaceStatusObservation, InstanceInfinibandStatusObservation,
        },
    },
    state_controller::state_handler::{StateHandlerError, StateHandlerServices},
};
use forge_uuid::{infiniband::IBPartitionId, instance::InstanceId};

pub(crate) async fn record_infiniband_status_observation(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance: &InstanceSnapshot,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<IBPartitionId, Vec<String>>::new();

    for ib in &ib_interfaces {
        let guid = ib.guid.clone().ok_or(StateHandlerError::MissingData {
            object_id: instance.id.to_string(),
            missing: "GUID of IB Port",
        })?;

        ibconf.entry(ib.ib_partition_id).or_default().push(guid);
    }

    if ibconf.is_empty() {
        // Update an empty record for ib.
        let status = InstanceInfinibandStatusObservation {
            config_version: instance.ib_config_version,
            ib_interfaces: vec![],
            observed_at: Utc::now(),
        };
        Instance::update_infiniband_status_observation(txn, instance.id, &status).await?;

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

    let mut ib_interfaces_status: Vec<InstanceIbInterfaceStatusObservation> =
        Vec::with_capacity(ib_interfaces.len());
    for iter_if in ib_interfaces.iter() {
        ib_interfaces_status.push(InstanceIbInterfaceStatusObservation {
            guid: iter_if.clone().guid,
            lid: 0xffff_u32,
            addresses: vec![],
        })
    }

    for (k, guids) in ibconf {
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

        // Get the status of ports from UFM, and persist it as observed status.
        let filter = ib::Filter {
            guids: Some(guids.clone()),
            pkey: ibpartition.config.pkey,
        };
        let ports = ib_fabric
            .find_ib_port(Some(filter))
            .await
            .map_err(|err| StateHandlerError::GenericError(err.into()))?;

        for port in ports.iter() {
            for iter_status in ib_interfaces_status.iter_mut() {
                if port.guid == iter_status.guid.clone().unwrap_or_default() {
                    let status = InstanceIbInterfaceStatusObservation::from(port);
                    iter_status.lid = status.lid;
                    iter_status.addresses = status.addresses;
                    break;
                }
            }
        }

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
            tracing::error!("Detected invalid infiniband confiuration {e}");
        }
    }

    let status = InstanceInfinibandStatusObservation {
        config_version: instance.ib_config_version,
        ib_interfaces: ib_interfaces_status,
        observed_at: Utc::now(),
    };
    Instance::update_infiniband_status_observation(txn, instance.id, &status).await?;

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
