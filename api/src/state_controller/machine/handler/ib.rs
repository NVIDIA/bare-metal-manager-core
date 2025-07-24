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

use forge_uuid::{infiniband::IBPartitionId, instance::InstanceId};
use sqlx::PgConnection;

use crate::{
    db::{ObjectColumnFilter, ib_partition},
    ib::{DEFAULT_IB_FABRIC_NAME, types::IBNetwork},
    model::instance::config::infiniband::InstanceIbInterfaceConfig,
    state_controller::state_handler::{StateHandlerError, StateHandlerServices},
};

pub(crate) async fn bind_ib_ports(
    services: &StateHandlerServices,
    txn: &mut PgConnection,
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
            ib_partition::IBPartitionSearchConfig {},
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
    txn: &mut PgConnection,
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
            ib_partition::IBPartitionSearchConfig {},
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
