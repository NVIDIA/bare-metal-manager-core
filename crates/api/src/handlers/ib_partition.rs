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

use ::rpc::forge as rpc;
use db::ObjectColumnFilter;
use db::ib_partition::{self, IBPartitionSearchConfig, NewIBPartition};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::IbPartitionCreationRequest>,
) -> Result<Response<rpc::IbPartition>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin("create_ib_partition").await?;

    let mut resp = NewIBPartition::try_from(request.into_inner())?;
    let fabric_config = api.ib_fabric_manager.get_config();

    // IB Configurations.
    resp.config.mtu = Some(fabric_config.mtu.clone());
    resp.config.rate_limit = Some(fabric_config.rate_limit.clone());
    resp.config.service_level = Some(fabric_config.service_level.clone());

    resp.config.pkey = api.allocate_pkey(&mut txn, &resp.config.name).await?;
    let resp = db::ib_partition::create(resp, &mut txn, fabric_config.max_partition_per_tenant)
        .await
        .map_err(|e| {
            if e.is_not_found() {
                // During IB paritiont creation, it will check the existing partition by a 'select' query.
                // The 'RowNotFound' error means that the carbide can not find a valid row for the new IBPartition.
                Status::invalid_argument("Maximum Limit of Infiniband partitions had been reached")
            } else {
                CarbideError::from(e).into()
            }
        })?;
    let resp = rpc::IbPartition::try_from(resp).map(Response::new)?;

    txn.commit().await?;

    Ok(resp)
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::IbPartitionSearchFilter>,
) -> Result<Response<rpc::IbPartitionIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin("ib_partition::find_ids").await?;

    let filter: rpc::IbPartitionSearchFilter = request.into_inner();

    let ib_partition_ids = db::ib_partition::find_ids(&mut txn, filter).await?;

    Ok(Response::new(rpc::IbPartitionIdList { ib_partition_ids }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::IbPartitionsByIdsRequest>,
) -> Result<Response<rpc::IbPartitionList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin("ib_partition::find_by_ids").await?;

    let rpc::IbPartitionsByIdsRequest {
        ib_partition_ids, ..
    } = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if ib_partition_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if ib_partition_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let partitions = db::ib_partition::find_by(
        &mut txn,
        ObjectColumnFilter::List(ib_partition::IdColumn, &ib_partition_ids),
        IBPartitionSearchConfig {},
    )
    .await?;

    let mut result = Vec::with_capacity(partitions.len());
    for ibp in partitions {
        result.push(ibp.try_into()?);
    }
    Ok(Response::new(rpc::IbPartitionList {
        ib_partitions: result,
    }))
}

// DEPRECATED: use find_ids and find_by_ids instead
pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::IbPartitionQuery>,
) -> Result<Response<rpc::IbPartitionList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin("find_ib_partitions").await?;

    let rpc::IbPartitionQuery {
        id, search_config, ..
    } = request.into_inner();

    let uuid_filter = match id.as_ref() {
        Some(id) => ObjectColumnFilter::One(ib_partition::IdColumn, id),
        None => ObjectColumnFilter::All,
    };

    let search_config = search_config
        .map(IBPartitionSearchConfig::from)
        .unwrap_or(IBPartitionSearchConfig::default());
    let results = db::ib_partition::find_by(&mut txn, uuid_filter, search_config).await?;
    let mut ib_partitions = Vec::with_capacity(results.len());
    for result in results {
        ib_partitions.push(result.try_into()?);
    }

    Ok(Response::new(rpc::IbPartitionList { ib_partitions }))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::IbPartitionDeletionRequest>,
) -> Result<Response<rpc::IbPartitionDeletionResult>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin("delete_ib_partition").await?;

    let rpc::IbPartitionDeletionRequest { id, .. } = request.into_inner();

    let uuid = id.ok_or(CarbideError::MissingArgument("id"))?;

    let mut segments = db::ib_partition::find_by(
        &mut txn,
        ObjectColumnFilter::One(ib_partition::IdColumn, &uuid),
        IBPartitionSearchConfig::default(),
    )
    .await?;

    let segment = match segments.len() {
        1 => segments.remove(0),
        _ => {
            return Err(CarbideError::NotFoundError {
                kind: "ib_partition",
                id: uuid.to_string(),
            }
            .into());
        }
    };

    let resp = db::ib_partition::mark_as_deleted(&segment, &mut txn)
        .await
        .map(|_| rpc::IbPartitionDeletionResult {})
        .map(Response::new)?;

    txn.commit().await?;

    Ok(resp)
}

pub(crate) async fn for_tenant(
    api: &Api,
    request: Request<rpc::TenantSearchQuery>,
) -> Result<Response<rpc::IbPartitionList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin("find_ib_partions_for_tenant").await?;

    let rpc::TenantSearchQuery {
        tenant_organization_id,
    } = request.into_inner();

    let _tenant_organization_id: String = match tenant_organization_id {
        Some(id) => id,
        None => {
            return Err(CarbideError::MissingArgument("tenant_organization_id").into());
        }
    };

    let results = db::ib_partition::for_tenant(&mut txn, _tenant_organization_id).await?;

    let mut ib_partitions = Vec::with_capacity(results.len());

    for result in results {
        ib_partitions.push(result.try_into()?);
    }

    Ok(Response::new(rpc::IbPartitionList { ib_partitions }))
}
