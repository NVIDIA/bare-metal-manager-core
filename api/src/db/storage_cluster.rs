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

use chrono::{DateTime, Utc};
use libnvmesh::nvmesh_model as nvmesh;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::db::DatabaseError;
use crate::model::storage::{StorageCluster, StorageClusterAttributes};

// actual carbide storage objects handling happens here
// calls go to api/src/storage.rs for nvmesh cluster mgmt api
// Objects have list, get, create, delete, update, persist, ... (object specific) methods
// list, get, create can be called without the actual object as Object::list,get,create
// all other methods require the object
// list always returns Vec<Object> on success
// get always returns the Object on success
// create always returns the Object created on success
// delete returns nothing on success
// update returns nothing on success
// persist returns nothing on success

pub async fn list(txn: &mut PgConnection) -> Result<Vec<StorageCluster>, DatabaseError> {
    let query = "SELECT * from storage_clusters".to_string();
    sqlx::query_as(&query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("storage_cluster list", e))
}

pub async fn get(
    txn: &mut PgConnection,
    cluster_id: Uuid,
) -> Result<StorageCluster, DatabaseError> {
    let query = "SELECT * from storage_clusters l WHERE l.id=$1".to_string();
    sqlx::query_as(&query)
        .bind(cluster_id.to_string())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("storage_cluster get", e))
}

/// make sure we can login to it and get some status info before storing it
pub async fn import(
    txn: &mut PgConnection,
    attrs: &StorageClusterAttributes,
    nvmesh_cluster: nvmesh::ClusterId,
    cluster_capacity: nvmesh::ClusterCapacity,
) -> Result<StorageCluster, DatabaseError> {
    let timestamp: DateTime<Utc> = Utc::now();
    let id: Uuid = Uuid::try_from(nvmesh_cluster.uuid.as_str()).map_err(|e| {
        DatabaseError::new(
            "storage_cluster import",
            sqlx::Error::Protocol(e.to_string()),
        )
    })?;
    let cluster = StorageCluster {
        name: nvmesh_cluster.id,
        id,
        capacity: cluster_capacity.total_capacity_in_bytes,
        allocated: 0, // cluster_capacity.total_reserved_in_bytes?
        available: cluster_capacity.available_space_in_bytes,
        healthy: true,
        attributes: attrs.clone(),
        created_at: Some(timestamp.to_string()),
        modified_at: Some(timestamp.to_string()),
    };
    persist(cluster, txn, false).await
}

/// delete only removes from the db if there's no storage pools, there's no impact to the actual storage cluster
pub async fn delete(value: &StorageCluster, txn: &mut PgConnection) -> Result<(), DatabaseError> {
    let query = "DELETE FROM storage_clusters WHERE id = $1";
    sqlx::query(query)
        .bind(value.id.to_string())
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// allow updating hostname/ip/port/auth for the storage cluster
pub async fn update(
    value: &StorageCluster,
    txn: &mut PgConnection,
    new_attrs: &StorageClusterAttributes,
    cluster_capacity: nvmesh::ClusterCapacity,
) -> Result<StorageCluster, DatabaseError> {
    let timestamp: DateTime<Utc> = Utc::now();
    // todo: maybe validate all storage pools and volumes in db match the updated storage cluster?
    let cluster = StorageCluster {
        name: value.name.clone(),
        id: value.id,
        capacity: cluster_capacity.total_capacity_in_bytes,
        allocated: 0, // cluster_capacity.total_reserved_in_bytes,
        available: cluster_capacity.available_space_in_bytes,
        healthy: true,
        attributes: new_attrs.clone(),
        created_at: value.created_at.clone(),
        modified_at: Some(timestamp.to_string()),
    };
    persist(cluster, txn, true).await
}

/// implement the inverse of sqlx::from_row for the object
async fn persist(
    value: StorageCluster,
    txn: &mut PgConnection,
    update: bool,
) -> Result<StorageCluster, DatabaseError> {
    let query;
    let cluster = if update {
        query = "UPDATE storage_clusters(name, description, host, port, capacity, allocated, available, healthy) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9) WHERE id = $10 RETURNING *";
        sqlx::query_as(query)
            .bind(&value.name)
            .bind(&value.attributes.description)
            .bind(&value.attributes.host)
            .bind(value.attributes.port.to_string())
            .bind(value.capacity as i64)
            .bind(value.allocated as i64)
            .bind(value.available as i64)
            .bind(value.healthy)
            .bind(&value.modified_at)
            .bind(value.id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    } else {
        query = "INSERT INTO storage_clusters(name, description, host, port, capacity, allocated, available, healthy, created_at, modified_at, id) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *";
        sqlx::query_as(query)
            .bind(&value.name)
            .bind(&value.attributes.description)
            .bind(&value.attributes.host)
            .bind(value.attributes.port.to_string())
            .bind(value.capacity as i64)
            .bind(value.allocated as i64)
            .bind(value.available as i64)
            .bind(value.healthy)
            .bind(&value.created_at)
            .bind(&value.modified_at)
            .bind(value.id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };

    Ok(cluster)
}
