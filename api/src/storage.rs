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

use std::cmp::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use forge_secrets::credentials::{CredentialKey, CredentialProvider, Credentials};
use libnvmesh::{Nvmesh, NvmeshApiError};
use sqlx::{Postgres, Transaction};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::api::Api;
use crate::db::DatabaseError;
use crate::model::storage::{
    OsImage, OsImageAttributes, OsImageStatus, StorageCluster, StorageClusterAttributes,
    StoragePool, StoragePoolAttributes, StorageVolume, StorageVolumeAttributes,
    StorageVolumeFilter,
};
use crate::model::tenant::TenantOrganizationId;
use crate::CarbideError;
use forge_uuid::machine::MachineId;

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("Failed to look up credentials {0}")]
    MissingCredentials(eyre::Report),
    #[error("Failed to store credentials {0}")]
    StoringCredentials(eyre::Report),
    #[error("Failed nvmesh api request {0}")]
    NvmeshApiError(NvmeshApiError),
    #[error("Failed subtask to create nvmesh client  {0}")]
    SubtaskError(tokio::task::JoinError),
    #[error("Database error {0}")]
    DbError(DatabaseError),
    #[error("{0}: {1} in use / busy")]
    ObjectInUse(String, String),
    #[error("{0} is unhealthy, cannot proceed for {1}")]
    ObjectUnhealthy(String, String),
    #[error("{0}: {1} missing {2}")]
    ObjectIncomplete(String, String, String),
    #[error("{0}: {1} Busy, retry later")]
    ObjectBusy(String, String),
    #[error("Not empty: {0}")]
    NotEmpty(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("No allocation for {0}")]
    NoAllocation(String),
    #[error("Mismatch {0}: {1} != {2}")]
    Mismatch(String, String, String),
    #[error("Cannot shrink {0}: new size {1} < current size {2}")]
    NoShrinking(String, String, String),
    #[error("Invalid arguments")]
    InvalidArguments,
    #[error("Invalid API response")]
    InvalidApiResponse,
    #[error("Not implemented")]
    NotImplemented,
}

#[async_trait]
pub trait NvmeshClientPool: Send + Sync + 'static {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        username: Option<String>,
        password: Option<String>,
        cluster_id: Option<Uuid>,
    ) -> Result<Box<dyn Nvmesh>, StorageError>;
}

#[derive(Debug)]
pub struct NvmeshClientPoolImpl<C> {
    pool: libnvmesh::NvmeshClientPool,
    credential_provider: Arc<C>,
}

impl<C: CredentialProvider + 'static> NvmeshClientPoolImpl<C> {
    pub fn new(credential_provider: Arc<C>, pool: libnvmesh::NvmeshClientPool) -> Self {
        NvmeshClientPoolImpl {
            credential_provider,
            pool,
        }
    }
}

#[async_trait]
impl<C: CredentialProvider + 'static> NvmeshClientPool for NvmeshClientPoolImpl<C> {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        username: Option<String>,
        password: Option<String>,
        cluster_id: Option<Uuid>,
    ) -> Result<Box<dyn Nvmesh>, StorageError> {
        let user;
        let pass;
        if username.is_none() && password.is_none() {
            if let Some(id) = cluster_id {
                (user, pass) =
                    get_auth_for_storage_cluster(id, self.credential_provider.as_ref()).await?;
            } else {
                return Err(StorageError::InvalidArguments);
            }
        } else {
            user = username.unwrap_or_default();
            pass = password.unwrap_or_default();
        }
        let endpoint = libnvmesh::Endpoint {
            host: host.to_string(),
            port,
            username: Some(user),
            password: Some(pass),
            use_https: None,
        };

        self.pool
            .create_client(endpoint)
            .await
            .map_err(StorageError::NvmeshApiError)
        // todo: test live-ness of storage cluster mgmt endpoint and switch to alternates if not reachable
    }
}

pub async fn get_auth_for_storage_cluster(
    cluster_id: Uuid,
    credential_provider: &dyn CredentialProvider,
) -> Result<(String, String), StorageError> {
    let credentials = credential_provider
        .get_credentials(CredentialKey::NvmeshCluster {
            cluster_id: cluster_id.to_string(),
        })
        .await
        .map_err(StorageError::MissingCredentials)?;
    let (user, pass) = match credentials {
        Credentials::UsernamePassword { username, password } => (username, password),
    };
    Ok((user, pass))
}

pub async fn create_volume(
    txn: &mut Transaction<'_, Postgres>,
    attrs: &StorageVolumeAttributes,
    nvmesh_api: &dyn Nvmesh,
) -> Result<StorageVolume, StorageError> {
    let pool = nvmesh_api
        .volume_group_get(Some(attrs.pool_id.to_string()), None, None)
        .await
        .map_err(StorageError::NvmeshApiError)?;
    if pool.is_empty() {
        return Err(StorageError::NotFound(format!(
            "storage pool {} for volume",
            attrs.pool_id
        )));
    }
    // todo: optionally handle os_image_id being set, map to source_id
    let response = match attrs.source_id {
        // snapshot volume
        Some(source_id) => {
            let source_vol = StorageVolume::get(txn, source_id)
                .await
                .map_err(StorageError::DbError)?;
            nvmesh_api
                .volumes_create_snapshot(
                    attrs.id.to_string(),
                    attrs.capacity, // todo: round up to 16 byte boundary
                    source_id.to_string(),
                    source_vol.nvmesh_uuid.to_string(),
                    pool[0].clone(),
                )
                .await
                .map_err(StorageError::NvmeshApiError)?
        }
        // regular volume
        None => nvmesh_api
            .volumes_create(attrs.id.to_string(), attrs.capacity, pool[0].clone())
            .await
            .map_err(StorageError::NvmeshApiError)?,
    };
    if response.id.is_none() || response.uuid.is_none() {
        return Err(StorageError::InvalidApiResponse);
    }
    let nvmesh_vol = nvmesh_api
        .volumes_get(response.id, None, None)
        .await
        .map_err(StorageError::NvmeshApiError)?;
    if nvmesh_vol.is_empty() {
        return Err(StorageError::NotFound(
            "newly created storage volume".to_string(),
        ));
    }
    StorageVolume::create(txn, attrs, None, None, &nvmesh_vol[0])
        .await
        .map_err(StorageError::DbError)
}

pub async fn attach_volume_to_client(
    txn: &mut Transaction<'_, Postgres>,
    volume_id: Uuid,
    instance_id: Uuid,
    dpu_machine_id: &MachineId,
    nvmesh_api: &dyn Nvmesh,
) -> Result<StorageVolume, StorageError> {
    let mut volume = StorageVolume::get(txn, volume_id)
        .await
        .map_err(StorageError::DbError)?;
    // snapshots are not multi-attach
    // snapshot volumes can only have one dpu machine id
    if volume.attributes.source_id.is_some() && volume.dpu_machine_id[0] != *dpu_machine_id {
        return Err(StorageError::ObjectInUse(
            "Volume".to_string(),
            volume.attributes.id.to_string(),
        ));
    }

    nvmesh_api
        .volumes_attach(
            dpu_machine_id.to_string(),
            volume.attributes.id.to_string(),
            volume.nvmesh_uuid.to_string(),
        )
        .await
        .map_err(StorageError::NvmeshApiError)?;
    volume
        .attach(txn, &instance_id, dpu_machine_id)
        .await
        .map_err(StorageError::DbError)
}

pub async fn detach_volume_from_client(
    txn: &mut Transaction<'_, Postgres>,
    volume_id: Uuid,
    instance_id: Uuid,
    dpu_machine_id: &MachineId,
    nvmesh_api: &dyn Nvmesh,
) -> Result<StorageVolume, StorageError> {
    let mut volume = StorageVolume::get(txn, volume_id)
        .await
        .map_err(StorageError::DbError)?;

    if !volume.status.attached || !volume.dpu_machine_id.contains(dpu_machine_id) {
        return Err(StorageError::NotFound(format!(
            "dpu {} for volume {}",
            dpu_machine_id, volume_id
        )));
    }
    nvmesh_api
        .volumes_detach(
            dpu_machine_id.to_string(),
            volume.attributes.id.to_string(),
            volume.nvmesh_uuid.to_string(),
        )
        .await
        .map_err(StorageError::NvmeshApiError)?;
    volume
        .detach(txn, &instance_id, dpu_machine_id)
        .await
        .map_err(StorageError::DbError)
}

// these functions are the grpc api handlers called from api.rs
// todo: maybe move these to api/src/handlers directory

pub(crate) async fn import_storage_cluster(
    api: &Api,
    request: Request<crate::api::rpc::StorageClusterAttributes>,
) -> Result<Response<crate::api::rpc::StorageCluster>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin import_storage_cluster",
            e,
        ))
    })?;
    let attrs = StorageClusterAttributes::try_from(request.into_inner())
        .map_err(|e| Status::internal(e.to_string()))?;

    let nvmesh_api = api
        .nvmesh_pool
        .create_client(
            &attrs.host[0],
            Some(attrs.port),
            attrs.username.clone(),
            attrs.password.clone(),
            None,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let cluster_id = nvmesh_api
        .cluster_get_id()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let cluster_capacity = nvmesh_api
        .cluster_get_capacity()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let cluster = StorageCluster::import(&mut txn, &attrs.clone(), cluster_id, cluster_capacity)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let response = crate::api::rpc::StorageCluster::try_from(cluster)
        .map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(response))
}

pub(crate) async fn list_storage_cluster(
    api: &Api,
    _request: Request<crate::api::rpc::ListStorageClusterRequest>,
) -> Result<Response<crate::api::rpc::ListStorageClusterResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin list_storage_cluster",
            e,
        ))
    })?;
    let clusters_internal = StorageCluster::list(&mut txn)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut clusters: Vec<crate::api::rpc::StorageCluster> = Vec::new();
    for cluster in clusters_internal.iter() {
        let rpc_cluster = crate::api::rpc::StorageCluster::try_from(cluster.clone())
            .map_err(|e| Status::internal(e.to_string()))?;
        clusters.push(rpc_cluster);
    }
    let response = crate::api::rpc::ListStorageClusterResponse { clusters };
    Ok(Response::new(response))
}

pub(crate) async fn get_storage_cluster(
    api: &Api,
    request: Request<rpc::Uuid>,
) -> Result<Response<crate::api::rpc::StorageCluster>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_storage_cluster",
            e,
        ))
    })?;
    let cluster_id = Uuid::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let cluster = StorageCluster::get(&mut txn, cluster_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let response = crate::api::rpc::StorageCluster::try_from(cluster)
        .map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(response))
}

pub(crate) async fn delete_storage_cluster(
    api: &Api,
    request: Request<crate::api::rpc::DeleteStorageClusterRequest>,
) -> Result<Response<crate::api::rpc::DeleteStorageClusterResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_storage_cluster",
            e,
        ))
    })?;
    let cluster_name_id = request.into_inner();
    if cluster_name_id.id.is_none() {
        return Err(Status::invalid_argument("storage cluster id"));
    }
    let cluster_id: Uuid = Uuid::try_from(cluster_name_id.id.unwrap())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let cluster = StorageCluster::get(&mut txn, cluster_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if cluster.name != cluster_name_id.name {
        return Err(Status::invalid_argument("storage cluster name"));
    }
    cluster
        .delete(&mut txn)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let response = crate::api::rpc::DeleteStorageClusterResponse::default();
    Ok(Response::new(response))
}

pub(crate) async fn update_storage_cluster(
    api: &Api,
    request: Request<crate::api::rpc::UpdateStorageClusterRequest>,
) -> Result<Response<crate::api::rpc::StorageCluster>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_storage_cluster",
            e,
        ))
    })?;

    let req = request.into_inner();
    if req.cluster_id.is_none() || req.attributes.is_none() {
        return Err(Status::invalid_argument("storage cluster id or attributes"));
    }
    let cluster_id = Uuid::try_from(req.cluster_id.unwrap())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let new_attrs = StorageClusterAttributes::try_from(req.attributes.unwrap())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let cluster = StorageCluster::get(&mut txn, cluster_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    // use new attrs to connect to cluster
    let nvmesh_api = api
        .nvmesh_pool
        .create_client(
            &new_attrs.host[0],
            Some(new_attrs.port),
            new_attrs.username.clone(),
            new_attrs.password.clone(),
            None,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let updated_cluster_id = nvmesh_api
        .cluster_get_id()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let updated_cluster_capacity = nvmesh_api
        .cluster_get_capacity()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    // now get cluster stored in the db

    if cluster.id.to_string() != updated_cluster_id.uuid {
        return Err(Status::invalid_argument(format!(
            "Cluster ID {} != {}",
            cluster.id, updated_cluster_id.uuid
        )));
    }

    let updated = cluster
        .update(&mut txn, &new_attrs.clone(), updated_cluster_capacity)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let response = crate::api::rpc::StorageCluster::try_from(updated)
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(response))
}

pub(crate) async fn create_storage_pool(
    api: &Api,
    request: Request<crate::api::rpc::StoragePoolAttributes>,
) -> Result<Response<crate::api::rpc::StoragePool>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_storage_pool",
            e,
        ))
    })?;

    let attrs = StoragePoolAttributes::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let cluster = StorageCluster::get(&mut txn, attrs.cluster_id)
        .await
        .map_err(|e| Status::not_found(e.to_string()))?;
    if !cluster.healthy {
        return Err(Status::failed_precondition(cluster.id));
    }
    let nvmesh_api = api
        .nvmesh_pool
        .create_client(
            &cluster.attributes.host[0],
            Some(cluster.attributes.port),
            None,
            None,
            Some(cluster.id),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let response = nvmesh_api
        .volume_group_create(
            attrs.id.to_string(),
            libnvmesh::nvmesh_model::RaidLevels::try_from(attrs.raid_level.clone())
                .map_err(|e| Status::invalid_argument(e.to_string()))?,
            attrs.capacity, // todo: round up to 16 byte boundary
            None,
            false,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if response.id.is_none() || response.uuid.is_none() {
        return Err(Status::internal("Invalid nvmesh api response".to_string()));
    }
    let nvmesh_pool = nvmesh_api
        .volume_group_get(response.id, None, None)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if nvmesh_pool.is_empty() {
        return Err(Status::internal(
            "nvmesh api error, pool not found".to_string(),
        ));
    }

    let pool = StoragePool::create(&mut txn, &attrs, &nvmesh_pool[0])
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let response = crate::api::rpc::StoragePool::try_from(pool)
        .map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(response))
}

pub(crate) async fn list_storage_pool(
    api: &Api,
    request: Request<crate::api::rpc::ListStoragePoolRequest>,
) -> Result<Response<crate::api::rpc::ListStoragePoolResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin list_storage_pool",
            e,
        ))
    })?;
    let req = request.into_inner();
    let mut cluster_id: Option<Uuid> = None;
    let mut org_id: Option<TenantOrganizationId> = None;
    if req.cluster_id.is_some() {
        cluster_id = Some(
            Uuid::try_from(req.cluster_id.unwrap())
                .map_err(|e| Status::invalid_argument(e.to_string()))?,
        );
    }
    if req.tenant_organization_id.is_some() {
        org_id = Some(
            TenantOrganizationId::try_from(req.tenant_organization_id.unwrap())
                .map_err(|e| Status::invalid_argument(e.to_string()))?,
        );
    }
    let pools_internal = StoragePool::list(&mut txn, cluster_id, org_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut pools: Vec<crate::api::rpc::StoragePool> = Vec::new();
    for p in pools_internal.iter() {
        let pool = crate::api::rpc::StoragePool::try_from(p.clone())
            .map_err(|e| Status::internal(e.to_string()))?;
        pools.push(pool);
    }
    let response = crate::api::rpc::ListStoragePoolResponse { pools };
    Ok(Response::new(response))
}

pub(crate) async fn get_storage_pool(
    api: &Api,
    request: Request<rpc::Uuid>,
) -> Result<Response<crate::api::rpc::StoragePool>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_storage_pool",
            e,
        ))
    })?;
    let pool_id: Uuid = Uuid::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let pool = StoragePool::get(&mut txn, pool_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let response = crate::api::rpc::StoragePool::try_from(pool)
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(response))
}

pub(crate) async fn delete_storage_pool(
    api: &Api,
    request: Request<crate::api::rpc::DeleteStoragePoolRequest>,
) -> Result<Response<crate::api::rpc::DeleteStoragePoolResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_storage_pool",
            e,
        ))
    })?;
    let req = request.into_inner();
    if req.cluster_id.is_none() || req.pool_id.is_none() {
        return Err(Status::invalid_argument("storage cluster id or pool id"));
    }
    let cluster_id: Uuid = req
        .cluster_id
        .unwrap()
        .try_into()
        .map_err(|_e| Status::invalid_argument("cluster id"))?;
    let pool_id: Uuid = req
        .pool_id
        .unwrap()
        .try_into()
        .map_err(|_e| Status::invalid_argument("pool id"))?;
    let pool = StoragePool::get(&mut txn, pool_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if pool.attributes.cluster_id != cluster_id {
        return Err(Status::invalid_argument("storage cluster id for pool"));
    }
    let cluster = StorageCluster::get(&mut txn, cluster_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let nvmesh_api = api
        .nvmesh_pool
        .create_client(
            &cluster.attributes.host[0],
            Some(cluster.attributes.port),
            None,
            None,
            Some(cluster.id),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let filter = StorageVolumeFilter {
        volume_id: None,
        instance_id: None,
        machine_id: None,
        pool_id: Some(pool.attributes.id),
        cluster_id: None,
        source_id: None,
        boot_volumes: None,
        os_images: None,
        exclude_snapshots: None,
    };
    let volumes = StorageVolume::list(&mut txn, filter)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if !volumes.is_empty() {
        return Err(Status::failed_precondition("pool has volumes"));
    }

    nvmesh_api
        .volume_group_delete(pool.attributes.id.to_string(), pool.nvmesh_uuid.to_string())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    pool.delete(&mut txn)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp = crate::api::rpc::DeleteStoragePoolResponse::default();
    Ok(Response::new(resp))
}

pub(crate) async fn update_storage_pool(
    api: &Api,
    request: Request<crate::api::rpc::StoragePoolAttributes>,
) -> Result<Response<crate::api::rpc::StoragePool>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_storage_pool",
            e,
        ))
    })?;
    let new_attrs: StoragePoolAttributes = StoragePoolAttributes::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let pool = StoragePool::get(&mut txn, new_attrs.id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let cluster = StorageCluster::get(&mut txn, pool.attributes.cluster_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if !cluster.healthy {
        return Err(Status::failed_precondition(cluster.id));
    }
    let nvmesh_api = api
        .nvmesh_pool
        .create_client(
            &cluster.attributes.host[0],
            Some(cluster.attributes.port),
            None,
            None,
            Some(cluster.id),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut modified_at = pool.modified_at.clone();
    let mut nvmesh_pool = nvmesh_api
        .volume_group_get(Some(pool.attributes.id.to_string()), None, None)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if nvmesh_pool.is_empty() {
        return Err(Status::not_found("storage pool for updating"));
    }
    // we don't alter these, but if the caller changed them from what was set, return error
    if new_attrs.raid_level != pool.attributes.raid_level
        || new_attrs.cluster_id != pool.attributes.cluster_id
        || new_attrs.tenant_organization_id != pool.attributes.tenant_organization_id
    {
        return Err(Status::invalid_argument(
            "storage pool read-only attributes changed",
        ));
    }
    match new_attrs.capacity.cmp(&pool.attributes.capacity) {
        Ordering::Less => {
            return Err(Status::invalid_argument("storage pool cannot be shrunk"));
        }
        Ordering::Greater => {
            nvmesh_api
                .volume_group_extend(
                    pool.attributes.id.to_string(),
                    pool.nvmesh_uuid.to_string(),
                    new_attrs.capacity, // todo: round up to 16 byte boundary
                )
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            nvmesh_pool = nvmesh_api
                .volume_group_get(Some(pool.attributes.id.to_string()), None, None)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if nvmesh_pool.is_empty() {
                return Err(Status::not_found("storage pool after extending"));
            }
            modified_at = nvmesh_pool[0].date_modified.clone();
        }
        Ordering::Equal => {}
    }
    let updated = pool
        .update(&mut txn, &new_attrs, modified_at)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp: crate::api::rpc::StoragePool =
        rpc::forge::StoragePool::try_from(updated).map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(resp))
}

pub(crate) async fn create_storage_volume(
    api: &Api,
    request: Request<crate::api::rpc::StorageVolumeAttributes>,
) -> Result<Response<crate::api::rpc::StorageVolume>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_storage_volume",
            e,
        ))
    })?;
    let attrs: StorageVolumeAttributes = StorageVolumeAttributes::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let cluster = StorageCluster::get(&mut txn, attrs.cluster_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if !cluster.healthy {
        return Err(Status::failed_precondition(cluster.id));
    }
    let nvmesh_api = api
        .nvmesh_pool
        .create_client(
            &cluster.attributes.host[0],
            Some(cluster.attributes.port),
            None,
            None,
            Some(cluster.id),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let volume = create_volume(&mut txn, &attrs, nvmesh_api.as_ref())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp: crate::api::rpc::StorageVolume =
        rpc::forge::StorageVolume::try_from(volume).map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(resp))
}

pub(crate) async fn list_storage_volume(
    api: &Api,
    request: Request<crate::api::rpc::StorageVolumeFilter>,
) -> Result<Response<crate::api::rpc::ListStorageVolumeResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin list_storage_volume",
            e,
        ))
    })?;
    let filter = request.into_inner();
    let volume_filter: StorageVolumeFilter = StorageVolumeFilter::try_from(filter)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let vols = StorageVolume::list(&mut txn, volume_filter)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut volumes: Vec<crate::api::rpc::StorageVolume> = Vec::new();
    for vol in vols.iter() {
        let v = rpc::forge::StorageVolume::try_from(vol.clone())
            .map_err(|e| Status::internal(e.to_string()))?;
        volumes.push(v);
    }
    let resp = crate::api::rpc::ListStorageVolumeResponse { volumes };
    Ok(Response::new(resp))
}

pub(crate) async fn get_storage_volume(
    api: &Api,
    request: Request<rpc::Uuid>,
) -> Result<Response<crate::api::rpc::StorageVolume>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_storage_volume",
            e,
        ))
    })?;
    let volume_id: Uuid = request
        .into_inner()
        .try_into()
        .map_err(|_e| Status::invalid_argument("volume id"))?;
    let volume = StorageVolume::get(&mut txn, volume_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp: crate::api::rpc::StorageVolume =
        rpc::forge::StorageVolume::try_from(volume).map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(resp))
}

pub(crate) async fn delete_storage_volume(
    api: &Api,
    request: Request<crate::api::rpc::DeleteStorageVolumeRequest>,
) -> Result<Response<crate::api::rpc::DeleteStorageVolumeResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_storage_volume",
            e,
        ))
    })?;
    let req = request.into_inner();
    if req.volume_id.is_none() || req.pool_id.is_none() || req.cluster_id.is_none() {
        return Err(Status::invalid_argument(
            "volume delete request missing ids",
        ));
    }
    let volume_id: Uuid = req
        .volume_id
        .unwrap()
        .try_into()
        .map_err(|_e| Status::invalid_argument("volume id"))?;
    let pool_id: Uuid = req
        .pool_id
        .unwrap()
        .try_into()
        .map_err(|_e| Status::invalid_argument("pool id"))?;
    let cluster_id: Uuid = req
        .cluster_id
        .unwrap()
        .try_into()
        .map_err(|_e| Status::invalid_argument("cluster id"))?;
    let volume = StorageVolume::get(&mut txn, volume_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if volume.status.attached || !volume.dpu_machine_id.is_empty() {
        return Err(Status::failed_precondition("volume is in use"));
    }
    if volume.attributes.pool_id != pool_id || volume.attributes.cluster_id != cluster_id {
        return Err(Status::invalid_argument(
            "volume cluster_id or pool_id invalid",
        ));
    }
    let cluster = StorageCluster::get(&mut txn, cluster_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    let nvmesh_api = api
        .nvmesh_pool
        .create_client(
            &cluster.attributes.host[0],
            Some(cluster.attributes.port),
            None,
            None,
            Some(cluster.id),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    nvmesh_api
        .volumes_delete(
            volume.attributes.id.to_string(),
            volume.nvmesh_uuid.to_string(),
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    volume
        .delete(&mut txn)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp = crate::api::rpc::DeleteStorageVolumeResponse::default();
    Ok(Response::new(resp))
}

pub(crate) async fn update_storage_volume(
    api: &Api,
    request: Request<crate::api::rpc::StorageVolumeAttributes>,
) -> Result<Response<crate::api::rpc::StorageVolume>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_storage_volume",
            e,
        ))
    })?;

    let new_attrs: StorageVolumeAttributes =
        StorageVolumeAttributes::try_from(request.into_inner())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let volume = StorageVolume::get(&mut txn, new_attrs.id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if new_attrs.id != volume.attributes.id
        || new_attrs.cluster_id != volume.attributes.cluster_id
        || new_attrs.pool_id != volume.attributes.pool_id
        || new_attrs.boot_volume != volume.attributes.boot_volume
        || new_attrs.os_image_id != volume.attributes.os_image_id
        || new_attrs.source_id != volume.attributes.source_id
    {
        return Err(Status::invalid_argument(
            "volume read-only attributes changed",
        ));
    }
    let mut modified_at = volume.modified_at.clone();
    match new_attrs.capacity.cmp(&volume.attributes.capacity) {
        Ordering::Less => {
            return Err(Status::invalid_argument("volume cannot be shrunk"));
        }
        Ordering::Greater => {
            let cluster = StorageCluster::get(&mut txn, volume.attributes.cluster_id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if !cluster.healthy {
                return Err(Status::failed_precondition(cluster.id));
            }
            let nvmesh_api = api
                .nvmesh_pool
                .create_client(
                    &cluster.attributes.host[0],
                    Some(cluster.attributes.port),
                    None,
                    None,
                    Some(cluster.id),
                )
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            nvmesh_api
                .volumes_extend(
                    volume.attributes.id.to_string(),
                    volume.nvmesh_uuid.to_string(),
                    new_attrs.capacity,
                )
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            let nvmesh_vol = nvmesh_api
                .volumes_get(Some(volume.attributes.id.to_string()), None, None)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if nvmesh_vol.is_empty() {
                return Err(Status::not_found("volume after extending"));
            }
            modified_at = nvmesh_vol[0].date_modified.clone();
        }
        Ordering::Equal => {}
    }
    let updated = volume
        .update(&mut txn, new_attrs, modified_at)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp: crate::api::rpc::StorageVolume = rpc::forge::StorageVolume::try_from(updated)
        .map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(resp))
}

pub(crate) async fn create_os_image(
    api: &Api,
    request: Request<crate::api::rpc::OsImageAttributes>,
) -> Result<Response<crate::api::rpc::OsImage>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_os_image",
            e,
        ))
    })?;
    let attrs: OsImageAttributes = OsImageAttributes::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    if attrs.source_url.is_empty() || attrs.digest.is_empty() {
        return Err(Status::invalid_argument("os_image url or digest is empty"));
    }
    let mut volume_id: Option<Uuid> = None;
    // if the size is not provided, this can be done later by the os imaging agent
    // it will have the actual size of the qcow image disk to create the volume
    if attrs.create_volume && attrs.capacity.is_some() {
        // get storage pool for this tenant with boot_volumes set
        let pools = StoragePool::list(&mut txn, None, Some(attrs.tenant_organization_id.clone()))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if pools.is_empty() {
            return Err(Status::not_found("storage pool for tenant"));
        }
        let pool = pools
            .iter()
            .find(|p| p.attributes.use_for_boot_volumes)
            .map(|p| p.to_owned());
        if pool.is_none() {
            return Err(Status::not_found(
                "storage pool for os images and boot volumes",
            ));
        }
        let p = pool.unwrap();
        let vol_attrs = StorageVolumeAttributes {
            cluster_id: p.attributes.cluster_id,
            pool_id: p.attributes.id,
            capacity: attrs.capacity.unwrap(),
            delete_with_instance: false,
            use_existing_volume: None,
            boot_volume: Some(false),
            os_image_id: Some(attrs.id),
            source_id: None,
            id: attrs.id, // we reuse the os image id as the volume id too for golden volumes
            name: attrs.name.clone(),
            description: attrs.description.clone(),
        };
        let cluster = StorageCluster::get(&mut txn, p.attributes.cluster_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let nvmesh_api = api
            .nvmesh_pool
            .create_client(
                &cluster.attributes.host[0],
                Some(cluster.attributes.port),
                None,
                None,
                Some(cluster.id),
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let volume = create_volume(&mut txn, &vol_attrs, nvmesh_api.as_ref())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        volume_id = Some(volume.attributes.id);
    }
    let image = OsImage::create(&mut txn, &attrs, volume_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp: crate::api::rpc::OsImage =
        rpc::forge::OsImage::try_from(image).map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(resp))
}

pub(crate) async fn list_os_image(
    api: &Api,
    request: Request<crate::api::rpc::ListOsImageRequest>,
) -> Result<Response<crate::api::rpc::ListOsImageResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin list_os_image",
            e,
        ))
    })?;
    let tenant: Option<TenantOrganizationId> = match request.into_inner().tenant_organization_id {
        Some(x) => Some(
            TenantOrganizationId::try_from(x)
                .map_err(|e| Status::invalid_argument(e.to_string()))?,
        ),
        None => None,
    };
    let os_images = OsImage::list(&mut txn, tenant)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let mut images: Vec<crate::api::rpc::OsImage> = Vec::new();
    for os_image in os_images.iter() {
        let image = rpc::forge::OsImage::try_from(os_image.clone())
            .map_err(|e| Status::internal(e.to_string()))?;
        images.push(image);
    }
    let resp = crate::api::rpc::ListOsImageResponse { images };
    Ok(Response::new(resp))
}

pub(crate) async fn get_os_image(
    api: &Api,
    request: Request<rpc::Uuid>,
) -> Result<Response<crate::api::rpc::OsImage>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_os_image",
            e,
        ))
    })?;
    let image_id: Uuid = Uuid::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let image = OsImage::get(&mut txn, image_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp: crate::api::rpc::OsImage =
        rpc::forge::OsImage::try_from(image).map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(resp))
}

pub(crate) async fn delete_os_image(
    api: &Api,
    request: Request<crate::api::rpc::DeleteOsImageRequest>,
) -> Result<Response<crate::api::rpc::DeleteOsImageResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_os_image",
            e,
        ))
    })?;
    let req = request.into_inner();
    if req.id.is_none() {
        return Err(Status::invalid_argument("os image id missing"));
    }
    let image_id: Uuid =
        Uuid::try_from(req.id.unwrap()).map_err(|e| Status::invalid_argument(e.to_string()))?;
    let tenant: TenantOrganizationId = TenantOrganizationId::try_from(req.tenant_organization_id)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let image = OsImage::get(&mut txn, image_id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if image.attributes.tenant_organization_id != tenant {
        return Err(Status::invalid_argument("os image tenant mismatch"));
    }
    if image.status == OsImageStatus::InProgress {
        return Err(Status::failed_precondition("os image busy"));
    }

    if image.volume_id.is_some() {
        let filter = StorageVolumeFilter {
            volume_id: None,
            instance_id: None,
            machine_id: None,
            pool_id: None,
            cluster_id: None,
            source_id: image.volume_id,
            boot_volumes: None,
            os_images: None,
            exclude_snapshots: None,
        };
        let snapshots = StorageVolume::list(&mut txn, filter)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if !snapshots.is_empty() {
            return Err(Status::failed_precondition(
                "os image volume snapshots exist",
            ));
        }
        let volume = StorageVolume::get(&mut txn, image.volume_id.unwrap())
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let cluster = StorageCluster::get(&mut txn, volume.attributes.cluster_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let nvmesh_api = api
            .nvmesh_pool
            .create_client(
                &cluster.attributes.host[0],
                Some(cluster.attributes.port),
                None,
                None,
                Some(cluster.id),
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        nvmesh_api
            .volumes_delete(
                volume.attributes.id.to_string(),
                volume.nvmesh_uuid.to_string(),
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
    }

    image
        .delete(&mut txn)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp = crate::api::rpc::DeleteOsImageResponse::default();
    Ok(Response::new(resp))
}

pub(crate) async fn update_os_image(
    api: &Api,
    request: Request<crate::api::rpc::OsImageAttributes>,
) -> Result<Response<crate::api::rpc::OsImage>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_os_image",
            e,
        ))
    })?;

    let new_attrs: OsImageAttributes = OsImageAttributes::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    let image = OsImage::get(&mut txn, new_attrs.id)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    if new_attrs.source_url != image.attributes.source_url
        || new_attrs.digest != image.attributes.digest
        || new_attrs.tenant_organization_id != image.attributes.tenant_organization_id
        || new_attrs.create_volume != image.attributes.create_volume
        || new_attrs.rootfs_id != image.attributes.rootfs_id
        || new_attrs.rootfs_label != image.attributes.rootfs_label
        || new_attrs.capacity != image.attributes.capacity
    {
        return Err(Status::invalid_argument(
            "os_image update read-only attributes changed",
        ));
    }
    let updated = image
        .update(&mut txn, new_attrs)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let resp: crate::api::rpc::OsImage =
        rpc::forge::OsImage::try_from(updated).map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(resp))
}

// mock similar to RedfishSim
#[derive(Debug, Default)]
pub struct NvmeshSimClient {
    _state: u32,
}

#[async_trait]
impl Nvmesh for NvmeshSimClient {
    async fn login(
        &self,
        _endpoint: libnvmesh::Endpoint,
    ) -> Result<Box<dyn Nvmesh>, NvmeshApiError> {
        todo!()
    }

    async fn logout(&self) -> Result<(), NvmeshApiError> {
        todo!()
    }

    fn api_response_decode(
        &self,
        _response: Option<libnvmesh::nvmesh_model::ApiReply>,
        _url: &str,
        _status: http::StatusCode,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    fn api_response_decode_return(
        &self,
        _response: Option<libnvmesh::nvmesh_model::ApiReply>,
        _url: &str,
        _status: http::StatusCode,
    ) -> Result<libnvmesh::nvmesh_model::ApiReply, NvmeshApiError> {
        todo!()
    }

    fn post_api_response_decode(
        &self,
        _response: Option<Vec<libnvmesh::nvmesh_model::ApiReply>>,
        _url: &str,
        _status: http::StatusCode,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    fn post_api_response_decode_return(
        &self,
        _response: Option<Vec<libnvmesh::nvmesh_model::ApiReply>>,
        _url: &str,
        _status: http::StatusCode,
    ) -> Result<libnvmesh::nvmesh_model::ApiReply, NvmeshApiError> {
        todo!()
    }

    async fn access_token_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn access_token_create(
        &self,
        _id: String,
        _description: String,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn access_token_delete(&self, _id: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn access_token_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::AccessToken>, NvmeshApiError> {
        todo!()
    }

    async fn access_token_set(
        &self,
        _id: String,
        _description: String,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn alerts_ack(&self, _id: Option<String>) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn alerts_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn alerts_get(
        &self,
        _filter: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::LogEntry>, NvmeshApiError> {
        todo!()
    }

    async fn clients_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn clients_delete(&self, _id: Vec<String>) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn clients_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::Client>, NvmeshApiError> {
        todo!()
    }

    async fn conf_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn conf_create(
        &self,
        _config: libnvmesh::nvmesh_model::ConfigurationSettings,
        _name: String,
        _description: Option<String>,
        _labels: Vec<String>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn conf_delete(&self, _id: String, _uuid: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn conf_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::ConfigurationProfile>, NvmeshApiError> {
        todo!()
    }

    async fn conf_set(
        &self,
        _config: libnvmesh::nvmesh_model::ConfigurationSettings,
        _name: String,
        _description: Option<String>,
        _labels: Vec<String>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn cluster_get_id(&self) -> Result<libnvmesh::nvmesh_model::ClusterId, NvmeshApiError> {
        todo!()
    }

    async fn cluster_set_id(&self, _id: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn cluster_get_capacity(
        &self,
    ) -> Result<libnvmesh::nvmesh_model::ClusterCapacity, NvmeshApiError> {
        todo!()
    }

    async fn cluster_get_settings(
        &self,
    ) -> Result<libnvmesh::nvmesh_model::ClusterSettings, NvmeshApiError> {
        todo!()
    }

    async fn cluster_set_settings(
        &self,
        _settings: libnvmesh::nvmesh_model::ClusterSettings,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn cluster_get_status(
        &self,
    ) -> Result<libnvmesh::nvmesh_model::ClusterStatus, NvmeshApiError> {
        todo!()
    }

    async fn disk_class_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn disk_class_create(
        &self,
        _class: libnvmesh::nvmesh_model::DiskClassSet,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn disk_class_delete(&self, _id: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn disk_class_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::DiskClass>, NvmeshApiError> {
        todo!()
    }

    async fn disk_class_set(
        &self,
        _class: libnvmesh::nvmesh_model::DiskClassSet,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn disks_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn disks_delete(&self, _id: Vec<String>) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn disks_evict(
        &self,
        _disks: Vec<libnvmesh::nvmesh_model::DiskId>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn disks_format(
        &self,
        _id: Vec<String>,
        _format_type: libnvmesh::nvmesh_model::DiskFormatTypes,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn disks_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::Disk>, NvmeshApiError> {
        todo!()
    }

    async fn logs_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn logs_get(
        &self,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::LogEntry>, NvmeshApiError> {
        todo!()
    }

    async fn security_group_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn security_group_create(
        &self,
        _id: String,
        _description: String,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn security_group_delete(&self, _id: String) -> Result<(), NvmeshApiError> {
        todo!()
    }
    async fn security_group_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::VolumeSecurityGroup>, NvmeshApiError> {
        todo!()
    }

    async fn security_group_set(
        &self,
        _vsgs: Vec<libnvmesh::nvmesh_model::VolumeSecurityGroup>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn server_class_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn server_class_create(
        &self,
        _servers: Vec<String>,
        _name: String,
        _description: Option<String>,
        _domains: Vec<libnvmesh::nvmesh_model::Domain>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn server_class_delete(&self, _id: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn server_class_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::ServerClass>, NvmeshApiError> {
        todo!()
    }
    async fn server_class_set(
        &self,
        _id: String,
        _servers: Vec<String>,
        _description: Option<String>,
        _domains: Vec<libnvmesh::nvmesh_model::Domain>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn servers_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn servers_delete(&self, _id: Vec<String>) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn servers_evict(&self, _id: Vec<String>) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn servers_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::Server>, NvmeshApiError> {
        todo!()
    }

    async fn users_create(
        &self,
        _email: String,
        _role: libnvmesh::nvmesh_model::UserRoles,
        _notification_level: libnvmesh::nvmesh_model::UserNotification,
        _password: String,
        _relogin: Option<bool>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn users_delete(&self, _id: String, _uuid: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn users_get(&self) -> Result<Vec<libnvmesh::nvmesh_model::User>, NvmeshApiError> {
        todo!()
    }

    async fn users_set(
        &self,
        _id: String,
        _uuid: String,
        _role: libnvmesh::nvmesh_model::UserRoles,
        _notification_level: libnvmesh::nvmesh_model::UserNotification,
        _relogin: Option<bool>,
        _reset_password: Option<bool>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn users_set_password(
        &self,
        _id: String,
        _uuid: String,
        _password: String,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volume_group_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn volume_group_create(
        &self,
        _name: String,
        _raid_level: libnvmesh::nvmesh_model::RaidLevels,
        _capacity: u64,
        _description: Option<String>,
        _single_node: bool,
    ) -> Result<libnvmesh::nvmesh_model::ApiReply, NvmeshApiError> {
        todo!()
    }

    async fn volume_group_create_advanced(
        &self,
        _vpg_conf: libnvmesh::nvmesh_model::VolumeProvisioningGroupAttrs,
    ) -> Result<libnvmesh::nvmesh_model::ApiReply, NvmeshApiError> {
        todo!()
    }

    async fn volume_group_delete(&self, _id: String, _uuid: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volume_group_extend(
        &self,
        _id: String,
        _uuid: String,
        _capacity: u64,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volume_group_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::VolumeProvisioningGroup>, NvmeshApiError> {
        todo!()
    }

    async fn volume_group_set(
        &self,
        _id: String,
        _uuid: String,
        _description: String,
        _vsg_id: Vec<String>,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volumes_attach(
        &self,
        _client: String,
        _id: String,
        _uuid: String,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volumes_count(&self) -> Result<u32, NvmeshApiError> {
        todo!()
    }

    async fn volumes_create(
        &self,
        _name: String,
        _capacity: u64,
        _vpg: libnvmesh::nvmesh_model::VolumeProvisioningGroup,
    ) -> Result<libnvmesh::nvmesh_model::ApiReply, NvmeshApiError> {
        todo!()
    }

    async fn volumes_create_advanced(
        &self,
        _attrs: libnvmesh::nvmesh_model::VolumeCreate,
    ) -> Result<libnvmesh::nvmesh_model::ApiReply, NvmeshApiError> {
        todo!()
    }

    async fn volumes_create_snapshot(
        &self,
        _name: String,
        _capacity: u64,
        _source_id: String,
        _source_uuid: String,
        _vpg: libnvmesh::nvmesh_model::VolumeProvisioningGroup,
    ) -> Result<libnvmesh::nvmesh_model::ApiReply, NvmeshApiError> {
        todo!()
    }

    async fn volumes_delete(&self, _id: String, _uuid: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volumes_detach(
        &self,
        _client: String,
        _id: String,
        _uuid: String,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volumes_extend(
        &self,
        _id: String,
        _uuid: String,
        _capacity: u64,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volumes_get(
        &self,
        _id: Option<String>,
        _page: Option<u32>,
        _items: Option<u32>,
    ) -> Result<Vec<libnvmesh::nvmesh_model::Volume>, NvmeshApiError> {
        todo!()
    }

    async fn volumes_rebuild(&self, _id: String, _uuid: String) -> Result<(), NvmeshApiError> {
        todo!()
    }

    async fn volumes_set(
        &self,
        _attrs: libnvmesh::nvmesh_model::VolumeUpdate,
    ) -> Result<(), NvmeshApiError> {
        todo!()
    }
}

#[async_trait]
impl NvmeshClientPool for NvmeshSimClient {
    async fn create_client(
        &self,
        _host: &str,
        _port: Option<u16>,
        _username: Option<String>,
        _password: Option<String>,
        _cluster_id: Option<Uuid>,
    ) -> Result<Box<dyn Nvmesh>, StorageError> {
        Ok(Box::new(NvmeshSimClient { _state: 0 }))
    }
}
