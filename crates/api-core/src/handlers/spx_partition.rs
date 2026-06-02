/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use ::rpc::forge as rpc;
use db::resource_pool::ResourcePoolDatabaseError;
use db::{ObjectColumnFilter, WithTransaction, spx_partition};
use futures_util::FutureExt;
use model::resource_pool;
use model::spx_partition::NewSpxPartition;
use sqlx::PgConnection;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data, log_tenant_organization_id};

async fn allocate_dpa_vni(
    api: &Api,
    txn: &mut PgConnection,
    owner_id: &str,
    requested_vni: Option<i32>,
) -> Result<i32, CarbideError> {
    let source_pool = &api.common_pools.ethernet.pool_dpa_vni;

    match db::resource_pool::allocate(
        source_pool,
        txn,
        resource_pool::OwnerType::SpxPartition,
        owner_id,
        requested_vni,
    )
    .await
    {
        Ok(val) => Ok(val),
        Err(ResourcePoolDatabaseError::ResourcePool(resource_pool::ResourcePoolError::Empty)) => {
            tracing::error!(
                owner_id,
                pool = source_pool.name(),
                "Pool exhausted, cannot allocate"
            );
            Err(CarbideError::ResourceExhausted(format!(
                "pool {}",
                source_pool.name
            )))
        }
        Err(ResourcePoolDatabaseError::Database(e)) if requested_vni.is_some() => Err(match *e {
            db::DatabaseError::FailedPrecondition(_s) => {
                tracing::error!(
                    owner_id,
                    pool = source_pool.name(),
                    value = requested_vni,
                    "invalid pool value requested, cannot allocate"
                );
                CarbideError::FailedPrecondition(format!(
                    "VNI `{}` cannot be requested or is already allocated",
                    requested_vni.unwrap_or_default()
                ))
            }
            e => e.into(),
        }),
        Err(err) => {
            tracing::error!(owner_id, error = %err, pool = source_pool.name, "Error allocating from resource pool");
            Err(err.into())
        }
    }
}

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::SpxPartitionCreationRequest>,
) -> Result<Response<rpc::SpxPartition>, Status> {
    log_request_data(&request);

    let request_inner = request.into_inner();
    log_tenant_organization_id(&request_inner.tenant_organization_id);

    let req = NewSpxPartition::try_from(request_inner)?;

    let mut txn = api.txn_begin().await?;

    let vni = allocate_dpa_vni(api, &mut txn, &req.id.to_string(), req.vni).await?;

    let partition = db::spx_partition::create(&req, vni, &mut txn)
        .await
        .map_err(CarbideError::from)?;
    let resp = rpc::SpxPartition::try_from(partition).map(Response::new)?;
    txn.commit().await?;
    Ok(resp)
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::SpxPartitionDeletionRequest>,
) -> Result<Response<rpc::SpxPartitionDeletionResult>, Status> {
    log_request_data(&request);

    let id = request
        .into_inner()
        .id
        .ok_or_else(|| CarbideError::MissingArgument("id"))?;

    let resp = api
        .with_txn(|txn| db::spx_partition::mark_as_deleted(id, txn).boxed())
        .await?
        .map_err(CarbideError::from)?;

    if let Some(vni) = resp.vni {
        let mut txn = api.txn_begin().await?;

        db::resource_pool::release(&api.common_pools.ethernet.pool_dpa_vni, &mut txn, vni)
            .await
            .map_err(CarbideError::from)?;

        txn.commit().await?;
    }

    Ok(Response::new(rpc::SpxPartitionDeletionResult {}))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::SpxPartitionSearchFilter>,
) -> Result<Response<rpc::SpxPartitionIdList>, Status> {
    log_request_data(&request);

    let rpc_filter = request.into_inner();
    if let Some(ref tenant_org_id) = rpc_filter.tenant_org_id {
        log_tenant_organization_id(tenant_org_id);
    }

    let filter: model::spx_partition::SpxPartitionSearchFilter = rpc_filter.into();
    let spx_partition_ids = db::spx_partition::find_ids(&api.database_connection, filter).await?;

    Ok(Response::new(rpc::SpxPartitionIdList { spx_partition_ids }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::SpxPartitionsByIdsRequest>,
) -> Result<Response<rpc::SpxPartitionList>, Status> {
    log_request_data(&request);

    let rpc::SpxPartitionsByIdsRequest {
        spx_partition_ids, ..
    } = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if spx_partition_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if spx_partition_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut reader = api.db_reader();
    let partitions = db::spx_partition::find_by(
        reader.as_mut(),
        ObjectColumnFilter::List(spx_partition::IdColumn, &spx_partition_ids),
    )
    .await
    .map_err(CarbideError::from)?;

    let mut spx_partitions = Vec::with_capacity(partitions.len());
    for p in partitions {
        spx_partitions.push(p.try_into()?);
    }

    Ok(Response::new(rpc::SpxPartitionList { spx_partitions }))
}

#[cfg(test)]
mod tests {
    use ::rpc::forge as rpc;
    use model::spx_partition::NewSpxPartition;

    #[test]
    fn test_create_spx_partition_valid_request() {
        let request = rpc::SpxPartitionCreationRequest {
            metadata: Some(rpc::Metadata {
                name: "test-partition".to_string(),
                description: "A test SPX partition".to_string(),
                ..Default::default()
            }),
            id: None,
            vni: Some(100),
            tenant_organization_id: "tenant-org-123".to_string(),
        };

        let result = NewSpxPartition::try_from(request);
        assert!(result.is_ok());

        let partition = result.unwrap();
        assert_eq!(partition.name, "test-partition");
        assert_eq!(partition.description, "A test SPX partition");
        assert_eq!(partition.tenant_organization_id, "tenant-org-123");
        assert_eq!(partition.vni, Some(100));
    }

    #[test]
    fn test_create_spx_partition_missing_tenant_organization_id() {
        let request = rpc::SpxPartitionCreationRequest {
            metadata: Some(rpc::Metadata {
                name: "test-partition".to_string(),
                description: "A test SPX partition".to_string(),
                ..Default::default()
            }),
            id: None,
            vni: Some(100),
            tenant_organization_id: String::new(),
        };

        let result = NewSpxPartition::try_from(request);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("tenant_organization_id"));
    }

    #[test]
    fn test_create_spx_partition_auto_generates_id() {
        let request = rpc::SpxPartitionCreationRequest {
            metadata: Some(rpc::Metadata {
                name: "test-partition".to_string(),
                description: "".to_string(),
                ..Default::default()
            }),
            id: None,
            vni: None,
            tenant_organization_id: "tenant-org-123".to_string(),
        };

        let result = NewSpxPartition::try_from(request);
        assert!(result.is_ok());

        let partition = result.unwrap();
        assert_ne!(partition.id, carbide_uuid::spx::SpxPartitionId::nil());
    }

    #[test]
    fn test_create_spx_partition_uses_provided_id() {
        let provided_id: carbide_uuid::spx::SpxPartitionId = uuid::Uuid::new_v4().into();

        let request = rpc::SpxPartitionCreationRequest {
            metadata: Some(rpc::Metadata {
                name: "test-partition".to_string(),
                description: "".to_string(),
                ..Default::default()
            }),
            id: Some(provided_id),
            vni: None,
            tenant_organization_id: "tenant-org-123".to_string(),
        };

        let result = NewSpxPartition::try_from(request);
        assert!(result.is_ok());

        let partition = result.unwrap();
        assert_eq!(partition.id, provided_id);
    }

    #[test]
    fn test_create_spx_partition_without_metadata() {
        let request = rpc::SpxPartitionCreationRequest {
            metadata: None,
            id: None,
            vni: Some(200),
            tenant_organization_id: "tenant-org-456".to_string(),
        };

        let result = NewSpxPartition::try_from(request);
        assert!(result.is_ok());

        let partition = result.unwrap();
        assert!(partition.name.is_empty());
        assert!(partition.description.is_empty());
        assert_eq!(partition.vni, Some(200));
    }

    #[test]
    fn test_create_spx_partition_without_vni() {
        let request = rpc::SpxPartitionCreationRequest {
            metadata: Some(rpc::Metadata {
                name: "no-vni-partition".to_string(),
                description: "".to_string(),
                ..Default::default()
            }),
            id: None,
            vni: None,
            tenant_organization_id: "tenant-org-789".to_string(),
        };

        let result = NewSpxPartition::try_from(request);
        assert!(result.is_ok());

        let partition = result.unwrap();
        assert!(partition.vni.is_none());
    }
}
