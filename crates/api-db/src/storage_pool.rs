use libnvmesh::nvmesh_model;
use model::storage::{StoragePool, StoragePoolAttributes};
use model::tenant::TenantOrganizationId;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::DatabaseError;

pub async fn list(
    txn: &mut PgConnection,
    cluster_id: Option<Uuid>,
    tenant_organization_id: Option<TenantOrganizationId>,
) -> Result<Vec<StoragePool>, DatabaseError> {
    let query = "SELECT * from storage_pools l {where}".to_string();
    let mut where_clause = String::new();
    let mut filter = String::new();
    if let Some(cluster_id) = cluster_id {
        where_clause = "WHERE l.cluster_id=$1".to_string();
        filter = cluster_id.to_string();
    } else if let Some(tenant_organization_id) = tenant_organization_id {
        where_clause = "WHERE l.organization_id=$1".to_string();
        filter = tenant_organization_id.to_string();
    }
    if filter.is_empty() {
        let pools = sqlx::query_as(&query.replace("{where}", ""))
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new("storage_pools All", e))?;
        return Ok(pools);
    }
    let pools = sqlx::query_as(&query.replace("{where}", &where_clause))
        .bind(filter)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("storage_pool list", e))?;
    Ok(pools)
}

pub async fn get(txn: &mut PgConnection, pool_id: Uuid) -> Result<StoragePool, DatabaseError> {
    let query = "SELECT * from storage_pools l WHERE l.id=$1".to_string();
    sqlx::query_as(&query)
        .bind(pool_id.to_string())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("storage_pool get", e))
}

pub async fn create(
    txn: &mut PgConnection,
    attrs: &StoragePoolAttributes,
    nvmesh_pool: &nvmesh_model::VolumeProvisioningGroup,
) -> Result<StoragePool, DatabaseError> {
    let nvmesh_uuid: Uuid = Uuid::try_from(nvmesh_pool.id.as_str()).map_err(|e| {
        DatabaseError::new("storage_pool create", sqlx::Error::Protocol(e.to_string()))
    })?;

    let pool = StoragePool {
        nvmesh_uuid,
        allocated: 0,
        available: 0,
        attributes: attrs.clone(),
        created_at: nvmesh_pool.date_created.clone(),
        modified_at: nvmesh_pool.date_modified.clone(),
    };
    persist(&pool, txn, false).await
}

pub async fn delete(value: &StoragePool, txn: &mut PgConnection) -> Result<(), DatabaseError> {
    let query = "DELETE FROM storage_pools WHERE id = $1";
    sqlx::query(query)
        .bind(value.attributes.id.to_string())
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// only name and description can be updated
/// capacity can be increased, never reduced
pub async fn update(
    value: &StoragePool,
    txn: &mut PgConnection,
    new_attrs: &StoragePoolAttributes,
    modified_at: Option<String>,
) -> Result<StoragePool, DatabaseError> {
    let pool = StoragePool {
        nvmesh_uuid: value.nvmesh_uuid,
        allocated: value.allocated,
        available: value.available,
        attributes: StoragePoolAttributes {
            cluster_id: value.attributes.cluster_id,
            raid_level: value.attributes.raid_level.clone(),
            capacity: new_attrs.capacity,
            tenant_organization_id: value.attributes.tenant_organization_id.clone(),
            use_for_boot_volumes: value.attributes.use_for_boot_volumes,
            id: value.attributes.id,
            name: new_attrs.name.clone(),
            description: new_attrs.description.clone(),
        },
        created_at: value.created_at.clone(),
        modified_at,
    };
    persist(&pool, txn, true).await
}

async fn persist(
    value: &StoragePool,
    txn: &mut PgConnection,
    update: bool,
) -> Result<StoragePool, DatabaseError> {
    let query;
    let pool = if update {
        query = "UPDATE storage_pools SET name = $1, description = $2, capacity = $3, allocated = $4, available = $5, modified_at = $6 WHERE id = $7 RETURNING *";
        sqlx::query_as(query)
            .bind(&value.attributes.name)
            .bind(&value.attributes.description)
            .bind(value.attributes.capacity as i64)
            .bind(value.allocated as i64)
            .bind(value.available as i64)
            .bind(&value.modified_at)
            .bind(value.attributes.id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    } else {
        query = "INSERT INTO storage_pools(id, name, description, raid_level, capacity, allocated, available, organization_id, use_for_boot_volumes, nvmesh_uuid, cluster_id, created_at, modified_at) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *";
        sqlx::query_as(query)
            .bind(value.attributes.id)
            .bind(&value.attributes.name)
            .bind(&value.attributes.description)
            .bind(value.attributes.raid_level.to_string())
            .bind(value.attributes.capacity as i64)
            .bind(value.allocated as i64)
            .bind(value.available as i64)
            .bind(value.attributes.tenant_organization_id.to_string())
            .bind(value.attributes.use_for_boot_volumes)
            .bind(value.nvmesh_uuid)
            .bind(value.attributes.cluster_id)
            .bind(&value.created_at)
            .bind(&value.modified_at)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };
    Ok(pool)
}
