use forge_uuid::instance::InstanceId;
use forge_uuid::machine::MachineId;
use libnvmesh::nvmesh_model;
use model::storage::{
    StorageVolume, StorageVolumeAttributes, StorageVolumeFilter, StorageVolumeHealth,
    StorageVolumeStatus,
};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::db;
use crate::db::DatabaseError;

pub async fn list(
    txn: &mut PgConnection,
    filters: StorageVolumeFilter,
) -> Result<Vec<StorageVolume>, DatabaseError> {
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
            "storage_volume list",
            sqlx::Error::Protocol("invalid filters".to_string()),
        ));
    }

    sqlx::query_as(&query.replace("{where}", &where_clause))
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("storage_volume list", e))
}

pub async fn get(txn: &mut PgConnection, volume_id: Uuid) -> Result<StorageVolume, DatabaseError> {
    let query = "SELECT * from storage_volumes l WHERE l.id=$1".to_string();
    sqlx::query_as(&query)
        .bind(volume_id.to_string())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("storage_volumes One", e))
}

pub async fn create(
    txn: &mut PgConnection,
    attrs: &StorageVolumeAttributes,
    instance_id: Option<InstanceId>,
    dpu_id: Option<MachineId>,
    nvmesh_vol: &nvmesh_model::Volume,
) -> Result<StorageVolume, DatabaseError> {
    let instance_id = instance_id.map(|id| vec![id]).unwrap_or_default();
    let dpu_machine_id = dpu_id.map(|id| vec![id]).unwrap_or_default();
    let nvmesh_uuid: Uuid = Uuid::try_from(nvmesh_vol.uuid.as_str()).map_err(|e| {
        DatabaseError::new(
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
        instance_id,
        dpu_machine_id,
        created_at: nvmesh_vol.date_created.clone(),
        modified_at: nvmesh_vol.date_modified.clone(),
    };
    persist(&volume, txn, false).await
}

/// delete the actual volume on the storage cluster and the db
/// ensure its detached from any dpu clients prior to deleting
pub async fn delete(value: &StorageVolume, txn: &mut PgConnection) -> Result<(), DatabaseError> {
    let query = "DELETE FROM storage_volumes WHERE id = $1";
    sqlx::query(query)
        .bind(value.attributes.id.to_string())
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// the actual volume attach on the nvmesh cluster will happen later
/// update the db for the volume
pub async fn attach(
    value: &mut StorageVolume,
    txn: &mut PgConnection,
    instance_id: &InstanceId,
    dpu_machine_id: &MachineId,
) -> Result<StorageVolume, DatabaseError> {
    value.status.attached = true;
    if !value.instance_id.contains(instance_id) {
        value.instance_id.push(*instance_id);
    }
    if !value.dpu_machine_id.contains(dpu_machine_id) {
        value.dpu_machine_id.push(*dpu_machine_id);
    }
    db::storage_volume::persist(value, txn, true).await
}

/// the actual detach of the dpu nvmesh client from the volume will happen later
/// update the db for the volume
pub async fn detach(
    value: &mut StorageVolume,
    txn: &mut PgConnection,
    instance_id: &InstanceId,
    dpu_machine_id: &MachineId,
) -> Result<StorageVolume, DatabaseError> {
    value.instance_id.retain(|id| id != instance_id);
    value.dpu_machine_id.retain(|id| id != dpu_machine_id);
    if value.dpu_machine_id.is_empty() {
        value.status.attached = false;
    }
    db::storage_volume::persist(value, txn, true).await
}

/// only name, description, delete_with_instance attributes can be updated
/// capacity can be increased, never reduced
pub async fn update(
    value: &StorageVolume,
    txn: &mut PgConnection,
    new_attrs: StorageVolumeAttributes,
    modified_at: Option<String>,
) -> Result<StorageVolume, DatabaseError> {
    let volume = StorageVolume {
        nvmesh_uuid: value.nvmesh_uuid,
        attributes: new_attrs,
        status: value.status.clone(),
        instance_id: value.instance_id.clone(),
        dpu_machine_id: value.dpu_machine_id.clone(),
        created_at: value.created_at.clone(),
        modified_at,
    };
    persist(&volume, txn, true).await
}

async fn persist(
    value: &StorageVolume,
    txn: &mut PgConnection,
    update: bool,
) -> Result<StorageVolume, DatabaseError> {
    let volume = if update {
        let query = "UPDATE storage_volumes SET name = $1, description = $2, capacity = $3, delete_with_instance = $4, health = $5, attached = $6, modified_at = $7, status_message = $8, instance_id = $9::json, dpu_machine_id = $10::json WHERE id = $9 RETURNING *";
        sqlx::query_as(query)
            .bind(&value.attributes.name)
            .bind(&value.attributes.description)
            .bind(value.attributes.capacity as i64)
            .bind(value.attributes.delete_with_instance)
            .bind(value.status.health.to_string())
            .bind(value.status.attached)
            .bind(&value.modified_at)
            .bind(&value.status.status_message)
            .bind(&value.instance_id)
            .bind(&value.dpu_machine_id)
            .bind(value.attributes.id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    } else {
        let query = "INSERT INTO storage_volumes(id, name, description, capacity, delete_with_instance, boot_volume, pool_id, cluster_id, nvmesh_uuid, os_image_id, source_id, health, attached, status_message, created_at, modified_at) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::json, $18::json)";
        sqlx::query_as(query)
            .bind(value.attributes.id)
            .bind(&value.attributes.name)
            .bind(&value.attributes.description)
            .bind(value.attributes.capacity as i64)
            .bind(value.attributes.delete_with_instance)
            .bind(value.attributes.boot_volume)
            .bind(value.attributes.pool_id)
            .bind(value.attributes.cluster_id)
            .bind(value.nvmesh_uuid)
            .bind(value.attributes.os_image_id)
            .bind(value.attributes.source_id)
            .bind(value.status.health.to_string())
            .bind(value.status.attached)
            .bind(&value.status.status_message)
            .bind(&value.created_at)
            .bind(&value.modified_at)
            .bind(&value.instance_id)
            .bind(&value.dpu_machine_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };
    Ok(volume)
}
