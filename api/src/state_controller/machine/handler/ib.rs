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

use std::collections::HashMap;

use chrono::Utc;

use crate::{
    db::{
        ib_partition,
        instance::{Instance, InstanceId},
    },
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

pub(crate) async fn record_infiniband_status_observation(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance: &InstanceSnapshot,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<ib_partition::IBPartitionId, Vec<String>>::new();

    for ib in &ib_interfaces {
        let guid = ib.guid.clone().ok_or(StateHandlerError::MissingData {
            object_id: instance.instance_id.to_string(),
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
        Instance::update_infiniband_status_observation(txn, instance.instance_id, &status).await?;

        return Ok(());
    }

    let ib_fabric = services
        .ib_fabric_manager
        .connect(DEFAULT_IB_FABRIC_NAME)
        .await
        .map_err(|x| {
            StateHandlerError::IBFabricError(format!("Failed to connect to fabric manager: {x}"))
        })?;

    let mut ib_interfaces_status = Vec::with_capacity(ib_interfaces.len());

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            ib_partition::IBPartitionIdKeyedObjectFilter::One(k),
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
            guids: Some(v),
            pkey: ibpartition.config.pkey,
        };
        let ports = ib_fabric
            .find_ib_port(Some(filter))
            .await
            .map_err(|err| StateHandlerError::GenericError(err.into()))?;

        ib_interfaces_status.extend(
            ports
                .iter()
                .map(InstanceIbInterfaceStatusObservation::from)
                .collect::<Vec<_>>(),
        );
    }

    if ib_interfaces.len() != ib_interfaces_status.len() {
        return Err(StateHandlerError::InvalidState(format!(
            "{} infiniband interfaces with {} statuses",
            ib_interfaces.len(),
            ib_interfaces_status.len()
        )));
    }

    let status = InstanceInfinibandStatusObservation {
        config_version: instance.ib_config_version,
        ib_interfaces: ib_interfaces_status,
        observed_at: Utc::now(),
    };
    Instance::update_infiniband_status_observation(txn, instance.instance_id, &status).await?;

    Ok(())
}

pub(crate) async fn bind_ib_ports(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: InstanceId,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<ib_partition::IBPartitionId, Vec<String>>::new();
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
        .map_err(|_| StateHandlerError::IBFabricError("can not get IB fabric".to_string()))?;

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            ib_partition::IBPartitionIdKeyedObjectFilter::One(k),
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
            .map_err(|_| StateHandlerError::IBFabricError("bind_ib_ports".to_string()))?;
    }

    Ok(())
}

pub(crate) async fn unbind_ib_ports(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: InstanceId,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<ib_partition::IBPartitionId, Vec<String>>::new();

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
        .map_err(|_| StateHandlerError::IBFabricError("can not get IB fabric".to_string()))?;

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            ib_partition::IBPartitionIdKeyedObjectFilter::One(k),
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
            .map_err(|_| StateHandlerError::IBFabricError("unbind_ib_ports".to_string()))?;
    }

    Ok(())
}
