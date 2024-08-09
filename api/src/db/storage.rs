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
use sqlx::postgres::PgRow;
use sqlx::{Error, Postgres, Row, Transaction};
use std::str::FromStr;
use uuid::Uuid;

use crate::db::DatabaseError;
use crate::model::machine::machine_id::MachineId;
use crate::model::storage::{
    OsImage, OsImageAttributes, OsImageStatus, StorageCluster, StorageClusterAttributes,
    StoragePool, StoragePoolAttributes, StorageRaidLevels, StorageVolume, StorageVolumeAttributes,
    StorageVolumeFilter, StorageVolumeHealth, StorageVolumeStatus,
};
use crate::model::tenant::TenantOrganizationId;

/// actual carbide storage objects handling happens here
/// calls go to api/src/storage.rs for nvmesh cluster mgmt api
/// Objects have list, get, create, delete, update, persist, ... (object specific) methods
/// list, get, create can be called without the actual object as Object::list,get,create
/// all other methods require the object
/// Object::list always returns Vec<Object> on success
/// Object::get always returns the Object on success
/// Object::create always returns the Object created on success
/// Object::delete returns nothing on success
/// Object::update returns nothing on success
/// Object::persist returns nothing on success

impl StorageCluster {
    pub async fn list(txn: &mut Transaction<'_, Postgres>) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * from storage_clusters".to_string();
        let clusters = sqlx::query_as::<_, StorageCluster>(&query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "storage_cluster list", e))?;

        Ok(clusters)
    }

    pub async fn get(
        txn: &mut Transaction<'_, Postgres>,
        cluster_id: Uuid,
    ) -> Result<Self, DatabaseError> {
        let query = "SELECT * from storage_clusters l WHERE l.id=$1".to_string();

        let cluster = sqlx::query_as::<_, StorageCluster>(&query)
            .bind(cluster_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "storage_cluster get", e))?;

        Ok(cluster)
    }

    /// make sure we can login to it and get some status info before storing it
    pub async fn import(
        txn: &mut Transaction<'_, Postgres>,
        attrs: &StorageClusterAttributes,
        nvmesh_cluster: nvmesh::ClusterId,
        cluster_status: nvmesh::ClusterStatus,
    ) -> Result<Self, DatabaseError> {
        let timestamp: DateTime<Utc> = Utc::now();
        let id: Uuid = Uuid::try_from(nvmesh_cluster.uuid.as_str()).map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "storage_cluster import",
                sqlx::Error::Protocol(e.to_string()),
            )
        })?;
        let cluster = StorageCluster {
            name: nvmesh_cluster.id,
            id,
            capacity: cluster_status.total_space,
            allocated: cluster_status.allocated_space,
            available: cluster_status.free_space,
            healthy: true,
            attributes: attrs.clone(),
            created_at: Some(timestamp.to_string()),
            modified_at: Some(timestamp.to_string()),
        };
        cluster.persist(txn, false).await
    }

    /// delete only removes from the db if there's no storage pools, there's no impact to the actual storage cluster
    pub async fn delete(&self, txn: &mut Transaction<'_, Postgres>) -> Result<(), DatabaseError> {
        let query = "DELETE FROM storage_clusters WHERE id = $1";
        let _ = sqlx::query(query)
            .bind(self.id.to_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    /// allow updating hostname/ip/port/auth for the storage cluster
    pub async fn update(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        new_attrs: &StorageClusterAttributes,
        cluster_status: nvmesh::ClusterStatus,
    ) -> Result<Self, DatabaseError> {
        let timestamp: DateTime<Utc> = Utc::now();
        // todo: maybe validate all storage pools and volumes in db match the updated storage cluster?
        let cluster = StorageCluster {
            name: self.name.clone(),
            id: self.id,
            capacity: cluster_status.total_space,
            allocated: cluster_status.allocated_space,
            available: cluster_status.free_space,
            healthy: true,
            attributes: new_attrs.clone(),
            created_at: self.created_at.clone(),
            modified_at: Some(timestamp.to_string()),
        };
        cluster.persist(txn, true).await
    }

    /// implement the inverse of sqlx::from_row for the object
    async fn persist(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        update: bool,
    ) -> Result<Self, DatabaseError> {
        let query;
        let cluster = if update {
            query = "UPDATE storage_clusters(name, description, host, port, capacity, allocated, available, healthy) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9) WHERE id = $10 RETURNING *";
            sqlx::query_as(query)
                .bind(&self.name)
                .bind(&self.attributes.description)
                .bind(&self.attributes.host)
                .bind(self.attributes.port.to_string())
                .bind(self.capacity as i64)
                .bind(self.allocated as i64)
                .bind(self.available as i64)
                .bind(self.healthy)
                .bind(&self.modified_at)
                .bind(self.id)
                .fetch_one(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        } else {
            query = "INSERT INTO storage_clusters(name, description, host, port, capacity, allocated, available, healthy, created_at, modified_at, id) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *";
            sqlx::query_as(query)
                .bind(&self.name)
                .bind(&self.attributes.description)
                .bind(&self.attributes.host)
                .bind(self.attributes.port.to_string())
                .bind(self.capacity as i64)
                .bind(self.allocated as i64)
                .bind(self.available as i64)
                .bind(self.healthy)
                .bind(&self.created_at)
                .bind(&self.modified_at)
                .bind(self.id)
                .fetch_one(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        };

        Ok(cluster)
    }
}

impl StoragePool {
    pub async fn list(
        txn: &mut Transaction<'_, Postgres>,
        cluster_id: Option<Uuid>,
        tenant_organization_id: Option<TenantOrganizationId>,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * from storage_pools l {where}".to_string();
        let mut where_clause = String::new();
        let mut filter = String::new();
        if cluster_id.is_some() {
            where_clause = "WHERE l.cluster_id=$1".to_string();
            filter = cluster_id.unwrap().to_string();
        } else if tenant_organization_id.is_some() {
            where_clause = "WHERE l.organization_id=$1".to_string();
            filter = tenant_organization_id.unwrap().to_string();
        }
        if filter.is_empty() {
            let pools = sqlx::query_as::<_, StoragePool>(&query.replace("{where}", ""))
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "storage_pools All", e))?;
            return Ok(pools);
        }
        let pools = sqlx::query_as::<_, StoragePool>(&query.replace("{where}", &where_clause))
            .bind(filter)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "storage_pool list", e))?;
        Ok(pools)
    }

    pub async fn get(
        txn: &mut Transaction<'_, Postgres>,
        pool_id: Uuid,
    ) -> Result<Self, DatabaseError> {
        let query = "SELECT * from storage_pools l WHERE l.id=$1".to_string();

        let pool = sqlx::query_as::<_, StoragePool>(&query)
            .bind(pool_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "storage_pool get", e))?;

        Ok(pool)
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        attrs: &StoragePoolAttributes,
        nvmesh_pool: &nvmesh::VolumeProvisioningGroup,
    ) -> Result<Self, DatabaseError> {
        let nvmesh_uuid: Uuid = Uuid::try_from(nvmesh_pool.id.as_str()).map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "storage_pool create",
                sqlx::Error::Protocol(e.to_string()),
            )
        })?;
        let pool = StoragePool {
            nvmesh_uuid,
            allocated: 0,
            available: 0,
            attributes: attrs.clone(),
            created_at: Some(nvmesh_pool.date_created.clone()),
            modified_at: Some(nvmesh_pool.date_modified.clone()),
        };
        pool.persist(txn, false).await
    }

    pub async fn delete(&self, txn: &mut Transaction<'_, Postgres>) -> Result<(), DatabaseError> {
        let query = "DELETE FROM storage_pools WHERE id = $1";
        let _ = sqlx::query(query)
            .bind(self.attributes.id.to_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    /// only name and description can be updated
    /// capacity can be increased, never reduced
    pub async fn update(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        new_attrs: &StoragePoolAttributes,
        modified_at: Option<String>,
    ) -> Result<Self, DatabaseError> {
        let pool = StoragePool {
            nvmesh_uuid: self.nvmesh_uuid,
            allocated: self.allocated,
            available: self.available,
            attributes: StoragePoolAttributes {
                cluster_id: self.attributes.cluster_id,
                raid_level: self.attributes.raid_level.clone(),
                capacity: new_attrs.capacity,
                tenant_organization_id: self.attributes.tenant_organization_id.clone(),
                use_for_boot_volumes: self.attributes.use_for_boot_volumes,
                id: self.attributes.id,
                name: new_attrs.name.clone(),
                description: new_attrs.description.clone(),
            },
            created_at: self.created_at.clone(),
            modified_at,
        };
        pool.persist(txn, true).await
    }

    async fn persist(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        update: bool,
    ) -> Result<Self, DatabaseError> {
        let query;
        let pool = if update {
            query = "UPDATE storage_pools SET name = $1, description = $2, capacity = $3, allocated = $4, available = $5, modified_at = $6 WHERE id = $7 RETURNING *";
            sqlx::query_as(query)
                .bind(&self.attributes.name)
                .bind(&self.attributes.description)
                .bind(self.attributes.capacity as i64)
                .bind(self.allocated as i64)
                .bind(self.available as i64)
                .bind(&self.modified_at)
                .bind(self.attributes.id)
                .fetch_one(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        } else {
            query = "INSERT INTO storage_pools(id, name, description, raid_level, capacity, allocated, available, organization_id, use_for_boot_volumes, nvmesh_uuid, cluster_id, created_at, modified_at) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *";
            sqlx::query_as(query)
                .bind(self.attributes.id)
                .bind(&self.attributes.name)
                .bind(&self.attributes.description)
                .bind(self.attributes.raid_level.to_string())
                .bind(self.attributes.capacity as i64)
                .bind(self.allocated as i64)
                .bind(self.available as i64)
                .bind(self.attributes.tenant_organization_id.to_string())
                .bind(self.attributes.use_for_boot_volumes)
                .bind(self.nvmesh_uuid)
                .bind(self.attributes.cluster_id)
                .bind(&self.created_at)
                .bind(&self.modified_at)
                .fetch_one(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        };
        Ok(pool)
    }
}

impl StorageVolume {
    pub async fn list(
        txn: &mut Transaction<'_, Postgres>,
        filters: StorageVolumeFilter,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * from storage_volumes l {where}".to_string();
        let mut where_clause = String::new();
        if filters.volume_id.is_some() {
            where_clause = format!("WHERE l.id='{}'", filters.volume_id.unwrap());
        } else if filters.instance_id.is_some() {
            where_clause = format!(
                "WHERE ANY(l.instance_id) = '{}'",
                filters.instance_id.unwrap()
            );
        } else if filters.machine_id.is_some() {
            // find the dpu ids for the machine
        } else if filters.pool_id.is_some() {
            where_clause = format!("WHERE l.pool_id='{}'", filters.pool_id.unwrap());
        } else if filters.cluster_id.is_some() {
            where_clause = format!("WHERE l.cluster_id='{}'", filters.cluster_id.unwrap());
        } else if filters.source_id.is_some() {
            where_clause = format!("WHERE l.source_id='{}'", filters.source_id.unwrap());
        } else if filters.boot_volumes.is_some() {
            where_clause = format!("WHERE l.boot_volume='{}'", filters.boot_volumes.unwrap());
        } else if filters.os_images.is_some() {
            where_clause = "WHERE l.os_image_id IS NOT NULL".to_string();
        } else if filters.exclude_snapshots.is_some() {
            where_clause = "WHERE l.source_id IS NULL".to_string();
        } else {
            return Err(DatabaseError::new(
                file!(),
                line!(),
                "storage_volume list",
                sqlx::Error::Protocol("invalid filters".to_string()),
            ));
        }
        let volumes = sqlx::query_as::<_, StorageVolume>(&query.replace("{where}", &where_clause))
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "storage_volume list", e))?;
        Ok(volumes)
    }

    pub async fn get(
        txn: &mut Transaction<'_, Postgres>,
        volume_id: Uuid,
    ) -> Result<Self, DatabaseError> {
        let query = "SELECT * from storage_volumes l WHERE l.id=$1".to_string();
        let volume = sqlx::query_as::<_, StorageVolume>(&query)
            .bind(volume_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "storage_volumes One", e))?;

        Ok(volume)
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        attrs: &StorageVolumeAttributes,
        instance_id: Option<Uuid>,
        dpu_id: Option<&MachineId>,
        nvmesh_vol: &nvmesh::Volume,
    ) -> Result<Self, DatabaseError> {
        let mut instance_ids: Vec<Uuid> = Vec::new();
        if let Some(instance_id) = instance_id {
            instance_ids.push(instance_id);
        }
        let mut machine_ids: Vec<MachineId> = Vec::new();
        if let Some(dpu_id) = dpu_id {
            machine_ids.push(dpu_id.clone());
        }
        let nvmesh_uuid: Uuid = Uuid::try_from(nvmesh_vol.uuid.as_str()).map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "storage_volume create",
                sqlx::Error::Protocol(e.to_string()),
            )
        })?;
        let volume = StorageVolume {
            nvmesh_uuid,
            attributes: attrs.clone(),
            status: StorageVolumeStatus {
                health: StorageVolumeHealth::Initializing,
                attached: false,
                status_message: None,
            },
            instance_id: instance_ids,
            dpu_machine_id: machine_ids,
            created_at: Some(nvmesh_vol.date_created.clone()),
            modified_at: Some(nvmesh_vol.date_modified.clone()),
        };
        volume.persist(txn, false).await
    }

    /// delete the actual volume on the storage cluster and the db
    /// ensure its detached from any dpu clients prior to deleting
    pub async fn delete(&self, txn: &mut Transaction<'_, Postgres>) -> Result<(), DatabaseError> {
        let query = "DELETE FROM storage_volumes WHERE id = $1";
        let _ = sqlx::query(query)
            .bind(self.attributes.id.to_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    /// the actual volume attach on the nvmesh cluster will happen later
    /// update the db for the volume
    pub async fn attach(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        instance_id: &Uuid,
        dpu_machine_id: &MachineId,
    ) -> Result<Self, DatabaseError> {
        self.status.attached = true;
        if !self.instance_id.contains(instance_id) {
            self.instance_id.push(*instance_id);
        }
        if !self.dpu_machine_id.contains(dpu_machine_id) {
            self.dpu_machine_id.push(dpu_machine_id.clone());
        }
        self.persist(txn, true).await
    }

    /// the actual detach of the dpu nvmesh client from the volume will happen later
    /// update the db for the volume
    pub async fn detach(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        instance_id: &Uuid,
        dpu_machine_id: &MachineId,
    ) -> Result<Self, DatabaseError> {
        self.instance_id.retain(|id| *id != *instance_id);
        self.dpu_machine_id.retain(|id| *id != *dpu_machine_id);
        if self.dpu_machine_id.is_empty() {
            self.status.attached = false;
        }
        self.persist(txn, true).await
    }

    /// only name, description, delete_with_instance attributes can be updated
    /// capacity can be increased, never reduced
    pub async fn update(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        new_attrs: StorageVolumeAttributes,
        modified_at: Option<String>,
    ) -> Result<Self, DatabaseError> {
        let volume = StorageVolume {
            nvmesh_uuid: self.nvmesh_uuid,
            attributes: new_attrs,
            status: self.status.clone(),
            instance_id: self.instance_id.clone(),
            dpu_machine_id: self.dpu_machine_id.clone(),
            created_at: self.created_at.clone(),
            modified_at,
        };
        volume.persist(txn, true).await
    }

    async fn persist(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        update: bool,
    ) -> Result<Self, DatabaseError> {
        let volume = if update {
            let query = "UPDATE storage_volumes SET name = $1, description = $2, capacity = $3, delete_with_instance = $4, health = $5, attached = $6, modified_at = $7, status_message = $8, instance_id = $9::json, dpu_machine_id = $10::json WHERE id = $9 RETURNING *";
            sqlx::query_as(query)
                .bind(&self.attributes.name)
                .bind(&self.attributes.description)
                .bind(self.attributes.capacity as i64)
                .bind(self.attributes.delete_with_instance)
                .bind(self.status.health.to_string())
                .bind(self.status.attached)
                .bind(&self.modified_at)
                .bind(&self.status.status_message)
                .bind(&self.instance_id)
                .bind(&self.dpu_machine_id)
                .bind(self.attributes.id)
                .fetch_one(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        } else {
            let query = "INSERT INTO storage_volumes(id, name, description, capacity, delete_with_instance, boot_volume, pool_id, cluster_id, nvmesh_uuid, os_image_id, source_id, health, attached, status_message, created_at, modified_at) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::json, $18::json)";
            sqlx::query_as(query)
                .bind(self.attributes.id)
                .bind(&self.attributes.name)
                .bind(&self.attributes.description)
                .bind(self.attributes.capacity as i64)
                .bind(self.attributes.delete_with_instance)
                .bind(self.attributes.boot_volume)
                .bind(self.attributes.pool_id)
                .bind(self.attributes.cluster_id)
                .bind(self.nvmesh_uuid)
                .bind(self.attributes.os_image_id)
                .bind(self.attributes.source_id)
                .bind(self.status.health.to_string())
                .bind(self.status.attached)
                .bind(&self.status.status_message)
                .bind(&self.created_at)
                .bind(&self.modified_at)
                .bind(&self.instance_id)
                .bind(&self.dpu_machine_id)
                .fetch_one(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        };
        Ok(volume)
    }
}

impl OsImage {
    pub async fn list(
        txn: &mut Transaction<'_, Postgres>,
        tenant_organization_id: Option<TenantOrganizationId>,
    ) -> Result<Vec<Self>, DatabaseError> {
        let mut query = "SELECT * from os_images l ".to_string();
        if tenant_organization_id.is_some() {
            let where_clause = format!(
                "WHERE l.organization_id='{}'",
                tenant_organization_id.unwrap()
            );
            query.push_str(&where_clause);
        }
        let os_images = sqlx::query_as::<_, OsImage>(&query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "os_images All", e))?;
        Ok(os_images)
    }

    pub async fn get(
        txn: &mut Transaction<'_, Postgres>,
        os_image_id: Uuid,
    ) -> Result<Self, DatabaseError> {
        let query = "SELECT * from os_images l WHERE l.id = $1".to_string();
        let os_image = sqlx::query_as::<_, OsImage>(&query)
            .bind(os_image_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "os_images All", e))?;

        Ok(os_image)
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        attrs: &OsImageAttributes,
        volume_id: Option<Uuid>,
    ) -> Result<Self, DatabaseError> {
        let timestamp: DateTime<Utc> = Utc::now();
        let os_image = OsImage {
            attributes: attrs.clone(),
            status: OsImageStatus::Uninitialized,
            status_message: None,
            created_at: Some(timestamp.to_string()),
            modified_at: None,
            volume_id,
        };

        os_image.persist(txn, false).await
    }

    pub async fn delete(&self, txn: &mut Transaction<'_, Postgres>) -> Result<(), DatabaseError> {
        let query = "DELETE FROM os_images WHERE id = $1";
        let _ = sqlx::query(query)
            .bind(self.attributes.id.to_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn update(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        new_attrs: OsImageAttributes,
    ) -> Result<Self, DatabaseError> {
        let timestamp: DateTime<Utc> = Utc::now();
        let os_image = OsImage {
            attributes: new_attrs,
            status: self.status.clone(),
            status_message: self.status_message.clone(),
            created_at: self.created_at.clone(),
            modified_at: Some(timestamp.to_string()),
            volume_id: self.volume_id,
        };
        os_image.persist(txn, true).await
    }

    async fn persist(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        update: bool,
    ) -> Result<Self, DatabaseError> {
        let os_image = if update {
            let query = "UPDATE os_images SET name = $1, description = $2, auth_type = $3, auth_token = $4, rootfs_id = $5, rootfs_label = $6, boot_disk = $7, modified_at = $8, status = $9, status_message = $10 WHERE id = $11 RETURNING *";
            sqlx::query_as(query)
                .bind(&self.attributes.name)
                .bind(&self.attributes.description)
                .bind(&self.attributes.auth_type)
                .bind(&self.attributes.auth_token)
                .bind(&self.attributes.rootfs_id)
                .bind(&self.attributes.rootfs_label)
                .bind(&self.attributes.boot_disk)
                .bind(&self.modified_at)
                .bind(self.status.to_string())
                .bind(&self.status_message)
                .bind(self.attributes.id)
                .fetch_one(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        } else {
            let capacity = match self.attributes.capacity {
                Some(x) => x as i64,
                None => 0,
            };
            let query = "INSERT INTO os_images(id, name, description, source_url, digest, organization_id, auth_type, auth_token, rootfs_id, rootfs_label, boot_disk, capacity, volume_id, status, status_message, created_at, modified_at) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING *";
            sqlx::query_as(query)
                .bind(self.attributes.id)
                .bind(&self.attributes.name)
                .bind(&self.attributes.description)
                .bind(&self.attributes.source_url)
                .bind(&self.attributes.digest)
                .bind(self.attributes.tenant_organization_id.to_string())
                .bind(&self.attributes.auth_type)
                .bind(&self.attributes.auth_token)
                .bind(&self.attributes.rootfs_id)
                .bind(&self.attributes.rootfs_label)
                .bind(&self.attributes.boot_disk)
                .bind(capacity)
                .bind(self.volume_id)
                .bind(self.status.to_string())
                .bind(&self.status_message)
                .bind(&self.created_at)
                .bind(&self.modified_at)
                .fetch_one(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        };
        Ok(os_image)
    }
}

/// sqlx helpers for db table rows to structs
impl<'r> sqlx::FromRow<'r, PgRow> for StorageCluster {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        let capacity: i64 = row.try_get("capacity")?;
        let allocated: i64 = row.try_get("allocated")?;
        let available: i64 = row.try_get("available")?;
        let port: i16 = row.try_get("port")?;
        Ok(StorageCluster {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            capacity: capacity as u64,
            allocated: allocated as u64,
            available: available as u64,
            healthy: row.try_get("healthy")?,
            attributes: StorageClusterAttributes {
                host: row.try_get("host")?,
                port: port as u16,
                username: None,
                password: None,
                description: row.try_get("description")?,
            },
            created_at: row.try_get("created_at")?,
            modified_at: row.try_get("modified_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for StoragePool {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        let capacity: i64 = row.try_get("capacity")?;
        let allocated: i64 = row.try_get("allocated")?;
        let available: i64 = row.try_get("available")?;
        let raid_level: String = row.try_get("raid_level")?;
        let tenant_organization_id: String = row.try_get("organization_id")?;
        Ok(StoragePool {
            nvmesh_uuid: row.try_get("nvmesh_uuid")?,
            allocated: allocated as u64,
            available: available as u64,
            attributes: StoragePoolAttributes {
                id: row.try_get("id")?,
                cluster_id: row.try_get("cluster_id")?,
                raid_level: StorageRaidLevels::from_str(&raid_level)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                capacity: capacity as u64,
                tenant_organization_id: TenantOrganizationId::from_str(&tenant_organization_id)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                use_for_boot_volumes: row.try_get("use_for_boot_volumes")?,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
            },
            created_at: row.try_get("created_at")?,
            modified_at: row.try_get("modified_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for StorageVolume {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        let capacity: i64 = row.try_get("capacity")?;
        let health: String = row.try_get("health")?;
        let dpu_ids: Vec<String> = row.try_get("dpu_machine_id")?;
        let mut dpus: Vec<MachineId> = Vec::new();
        for id in dpu_ids.iter() {
            let dpu: MachineId =
                MachineId::from_str(id).map_err(|e| sqlx::error::Error::Protocol(e.to_string()))?;
            dpus.push(dpu);
        }
        Ok(StorageVolume {
            nvmesh_uuid: row.try_get("nvmesh_uuid")?,
            attributes: StorageVolumeAttributes {
                id: row.try_get("id")?,
                cluster_id: row.try_get("cluster_id")?,
                pool_id: row.try_get("pool_id")?,
                capacity: capacity as u64,
                delete_with_instance: row.try_get("delete_with_instance")?,
                use_existing_volume: None,
                boot_volume: row.try_get("boot_volume")?,
                os_image_id: row.try_get("os_image_id")?,
                source_id: row.try_get("source_id")?,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
            },
            status: StorageVolumeStatus {
                health: StorageVolumeHealth::from_str(&health)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                attached: row.try_get("attached")?,
                status_message: row.try_get("status_message")?,
            },
            instance_id: row.try_get("instance_id")?,
            dpu_machine_id: dpus, // todo: add dpu ids array get
            created_at: row.try_get("created_at")?,
            modified_at: row.try_get("modified_at")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for OsImage {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        let vol_id: String = row.try_get("volume_id")?;
        let mut volume_id: Option<Uuid> = None;
        let mut create_volume = false;
        let tenant_organization_id: String = row.try_get("organization_id")?;
        let status: String = row.try_get("status")?;
        let cap: i64 = row.try_get("capacity")?;
        let capacity = if cap == 0 { None } else { Some(cap as u64) };
        if !vol_id.is_empty() {
            let id = Uuid::from_str(&vol_id).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
            volume_id = Some(id);
            create_volume = true;
        }
        Ok(OsImage {
            volume_id,
            attributes: OsImageAttributes {
                id: row.try_get("id")?,
                source_url: row.try_get("source_url")?,
                digest: row.try_get("digest")?,
                tenant_organization_id: TenantOrganizationId::from_str(&tenant_organization_id)
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                create_volume,
                name: row.try_get("name")?,
                description: row.try_get("description")?,
                auth_type: row.try_get("auth_type")?,
                auth_token: row.try_get("auth_token")?,
                rootfs_id: row.try_get("rootfs_id")?,
                rootfs_label: row.try_get("rootfs_label")?,
                boot_disk: row.try_get("boot_disk")?,
                capacity,
            },
            status: OsImageStatus::from_str(&status)
                .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
            status_message: row.try_get("status_message")?,
            created_at: row.try_get("created_at")?,
            modified_at: row.try_get("modified_at")?,
        })
    }
}
