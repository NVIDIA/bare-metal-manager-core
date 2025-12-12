/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
// use db::nvl_logical_partition::{LogicalPartition, LogicalPartitionSearchConfig};
use db::nvl_partition;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::NvLinkPartitionSearchFilter>,
) -> Result<Response<rpc::NvLinkPartitionIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let filter: rpc::NvLinkPartitionSearchFilter = request.into_inner();

    let partition_ids = db::nvl_partition::find_ids(&mut txn, filter).await?;

    Ok(Response::new(rpc::NvLinkPartitionIdList { partition_ids }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::NvLinkPartitionsByIdsRequest>,
) -> Result<Response<rpc::NvLinkPartitionList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let rpc::NvLinkPartitionsByIdsRequest { partition_ids, .. } = request.into_inner();

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

    let partitions = db::nvl_partition::find_by(
        &mut txn,
        ObjectColumnFilter::List(nvl_partition::IdColumn, &partition_ids),
    )
    .await?;

    let mut result = Vec::with_capacity(partitions.len());
    for ibp in partitions {
        result.push(ibp.try_into()?);
    }
    Ok(Response::new(rpc::NvLinkPartitionList {
        partitions: result,
    }))
}

pub(crate) async fn for_tenant(
    api: &Api,
    request: Request<rpc::TenantSearchQuery>,
) -> Result<Response<rpc::NvLinkPartitionList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let rpc::TenantSearchQuery {
        tenant_organization_id,
    } = request.into_inner();

    let _tenant_organization_id: String = match tenant_organization_id {
        Some(id) => id,
        None => {
            return Err(CarbideError::MissingArgument("tenant_organization_id").into());
        }
    };

    let results = db::nvl_partition::for_tenant(&mut txn, _tenant_organization_id)
        .await
        .map_err(CarbideError::from)?;

    let mut partitions = Vec::with_capacity(results.len());

    for result in results {
        partitions.push(result.try_into()?);
    }

    Ok(Response::new(rpc::NvLinkPartitionList { partitions }))
}
