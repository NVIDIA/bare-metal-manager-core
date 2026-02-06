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
use config_version::ConfigVersion;
use db::nvl_logical_partition::{self, NewLogicalPartition};
use db::{self, ObjectColumnFilter, WithTransaction, nvl_partition};
use futures_util::FutureExt;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data, log_tenant_organization_id};

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::NvLinkLogicalPartitionCreationRequest>,
) -> Result<Response<rpc::NvLinkLogicalPartition>, Status> {
    log_request_data(&request);

    let request_inner = request.into_inner();

    // Log tenant organization ID if present in the config
    if let Some(ref config) = request_inner.config {
        log_tenant_organization_id(&config.tenant_organization_id);
    }

    let mut txn = api.txn_begin().await?;

    let req = NewLogicalPartition::try_from(request_inner)?;

    let metadata = req.config.metadata.clone();
    metadata.validate(true).map_err(CarbideError::from)?;

    let resp = req.create(&mut txn).await.map_err(CarbideError::from)?;
    let resp = rpc::NvLinkLogicalPartition::try_from(resp).map(Response::new)?;
    txn.commit().await?;

    Ok(resp)
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::NvLinkLogicalPartitionSearchFilter>,
) -> Result<Response<rpc::NvLinkLogicalPartitionIdList>, Status> {
    log_request_data(&request);

    let filter: rpc::NvLinkLogicalPartitionSearchFilter = request.into_inner();

    let partition_ids = api
        .with_txn(|txn| db::nvl_logical_partition::find_ids(txn, filter).boxed())
        .await??;

    Ok(Response::new(rpc::NvLinkLogicalPartitionIdList {
        partition_ids,
    }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::NvLinkLogicalPartitionsByIdsRequest>,
) -> Result<Response<rpc::NvLinkLogicalPartitionList>, Status> {
    log_request_data(&request);

    let rpc::NvLinkLogicalPartitionsByIdsRequest { partition_ids, .. } = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if partition_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if partition_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let partitions = api
        .with_txn(|txn| {
            db::nvl_logical_partition::find_by(
                txn,
                ObjectColumnFilter::List(nvl_logical_partition::IdColumn, &partition_ids),
            )
            .boxed()
        })
        .await?
        .map_err(CarbideError::from)?;

    let mut result = Vec::with_capacity(partitions.len());
    for lp in partitions {
        result.push(lp.try_into()?);
    }

    Ok(Response::new(rpc::NvLinkLogicalPartitionList {
        partitions: result,
    }))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::NvLinkLogicalPartitionDeletionRequest>,
) -> Result<Response<rpc::NvLinkLogicalPartitionDeletionResult>, Status> {
    log_request_data(&request);

    let id = request
        .into_inner()
        .id
        .ok_or_else(|| CarbideError::MissingArgument("id"))?;

    let mut txn = api.txn_begin().await?;

    let mut partitions = db::nvl_logical_partition::find_by(
        &mut txn,
        ObjectColumnFilter::One(nvl_logical_partition::IdColumn, &id),
    )
    .await
    .map_err(CarbideError::from)?;

    let partition = match partitions.len() {
        1 => partitions.remove(0),
        _ => {
            return Err(CarbideError::NotFoundError {
                kind: "logical_partition",
                id: id.to_string(),
            }
            .into());
        }
    };

    // check if there any physical partitions already part of this logical partition
    let db_nvl_partitions =
        db::nvl_partition::find_by(&mut txn, ObjectColumnFilter::<nvl_partition::IdColumn>::All)
            .await?;
    if db_nvl_partitions
        .iter()
        .any(|p| p.logical_partition_id == Some(id))
    {
        return Err(CarbideError::InvalidArgument(
            "logical partition still has physical partition(s) attached to it".to_string(),
        )
        .into());
    }

    let resp = db::nvl_logical_partition::mark_as_deleted(&partition, &mut txn)
        .await
        .map(|_| rpc::NvLinkLogicalPartitionDeletionResult {})
        .map(Response::new)?;

    txn.commit().await?;

    Ok(resp)
}

pub(crate) async fn for_tenant(
    api: &Api,
    request: Request<rpc::TenantSearchQuery>,
) -> Result<Response<rpc::NvLinkLogicalPartitionList>, Status> {
    log_request_data(&request);

    let rpc::TenantSearchQuery {
        tenant_organization_id,
    } = request.into_inner();

    let tenant_org_id_str: String = match tenant_organization_id {
        Some(id) => id,
        None => {
            return Err(CarbideError::MissingArgument("tenant_organization_id").into());
        }
    };

    log_tenant_organization_id(&tenant_org_id_str);

    let results = api
        .with_txn(|txn| db::nvl_logical_partition::for_tenant(txn, tenant_org_id_str).boxed())
        .await?
        .map_err(CarbideError::from)?;

    let mut partitions = Vec::with_capacity(results.len());

    for result in results {
        partitions.push(result.try_into()?);
    }

    Ok(Response::new(rpc::NvLinkLogicalPartitionList {
        partitions,
    }))
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::NvLinkLogicalPartitionUpdateRequest>,
) -> Result<Response<rpc::NvLinkLogicalPartitionUpdateResult>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let id = req
        .id
        .ok_or_else(|| CarbideError::InvalidArgument("ID must be provided".to_string()))?;

    let config = req
        .config
        .ok_or_else(|| CarbideError::InvalidArgument("Config must be provided".to_string()))?;

    let metadata: model::metadata::Metadata = config
        .metadata
        .clone()
        .ok_or_else(|| CarbideError::InvalidArgument("Metadata must be provided".to_string()))?
        .try_into()?;
    metadata.validate(true).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    let mut partitions = db::nvl_logical_partition::find_by(
        &mut txn,
        ObjectColumnFilter::One(nvl_logical_partition::IdColumn, &id),
    )
    .await
    .map_err(CarbideError::from)?;

    let partition = match partitions.len() {
        1 => partitions.remove(0),
        _ => {
            return Err(CarbideError::NotFoundError {
                kind: "logical_partition",
                id: id.to_string(),
            }
            .into());
        }
    };

    log_tenant_organization_id(&config.tenant_organization_id);

    if config.tenant_organization_id != partition.tenant_organization_id.to_string() {
        return Err(CarbideError::InvalidArgument(
            "Tenant organization ID should not be updated".to_string(),
        )
        .into());
    }

    if let Some(if_version_match) = req.if_version_match {
        let target_version = if_version_match
            .parse::<ConfigVersion>()
            .map_err(CarbideError::from)?;

        if partition.config_version != target_version {
            return Err(CarbideError::ConcurrentModificationError(
                "LogicalPartition",
                target_version.to_string(),
            )
            .into());
        }
    };

    let name = metadata.name;
    let resp = db::nvl_logical_partition::update(&partition, name, &mut txn)
        .await
        .map(|_| rpc::NvLinkLogicalPartitionUpdateResult {})
        .map(Response::new)?;

    txn.commit().await?;

    Ok(resp)
}
