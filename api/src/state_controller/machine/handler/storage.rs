/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use chrono::Utc;
use forge_uuid::instance::InstanceId;
use forge_uuid::machine::MachineId;
use sqlx::PgConnection;

use crate::db;
use crate::model::instance::config::storage::InstanceStorageConfig;
use crate::model::instance::snapshot::InstanceSnapshot;
use crate::model::instance::status::storage::InstanceStorageStatusObservation;
use crate::state_controller::state_handler::{StateHandlerError, StateHandlerServices};
use crate::storage::{attach_volume_to_client, detach_volume_from_client};

pub(crate) async fn attach_storage_volumes(
    services: &StateHandlerServices,
    txn: &mut PgConnection,
    instance_id: InstanceId,
    dpu_machine_id: &MachineId,
    config: InstanceStorageConfig,
    detach: bool,
) -> Result<(), StateHandlerError> {
    if config.volumes.is_empty() {
        return Ok(());
    }
    let cluster_id = config.volumes[0].cluster_id;
    let cluster = db::storage_cluster::get(txn, cluster_id)
        .await
        .map_err(StateHandlerError::DBError)?;
    let nvmesh_api = services
        .nvmesh_client_pool
        .create_client(
            &cluster.attributes.host[0],
            Some(cluster.attributes.port),
            None,
            None,
            Some(cluster.id),
        )
        .await
        .map_err(StateHandlerError::StorageError)?;

    for attr in config.volumes.iter() {
        if detach {
            let _ = detach_volume_from_client(
                txn,
                attr.id,
                instance_id,
                dpu_machine_id,
                nvmesh_api.as_ref(),
            )
            .await
            .map_err(StateHandlerError::StorageError)?;
        } else {
            let _ = attach_volume_to_client(
                txn,
                attr.id,
                instance_id,
                dpu_machine_id,
                nvmesh_api.as_ref(),
            )
            .await
            .map_err(StateHandlerError::StorageError)?;
        }
    }
    Ok(())
}

pub(crate) async fn record_storage_status_observation(
    _services: &StateHandlerServices,
    txn: &mut PgConnection,
    instance: &InstanceSnapshot,
    _config: InstanceStorageConfig,
) -> Result<(), StateHandlerError> {
    // todo: walk through the volumes and collect status
    let status = InstanceStorageStatusObservation {
        config_version: instance.storage_config_version,
        volumes: vec![],
        observed_at: Utc::now(),
    };
    db::instance::update_storage_status_observation(txn, instance.id, &status).await?;
    Ok(())
}
