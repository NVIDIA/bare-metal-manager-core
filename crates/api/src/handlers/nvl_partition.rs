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
use db::{ObjectColumnFilter, nvl_partition};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data, log_tenant_organization_id};

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::NvLinkPartitionSearchFilter>,
) -> Result<Response<rpc::NvLinkPartitionIdList>, Status> {
    log_request_data(&request);

    let filter: rpc::NvLinkPartitionSearchFilter = request.into_inner();

    if let Some(ref tenant_org_id_str) = filter.tenant_organization_id {
        log_tenant_organization_id(tenant_org_id_str);
    }

    let partition_ids = db::nvl_partition::find_ids(&api.database_connection, filter).await?;

    Ok(Response::new(rpc::NvLinkPartitionIdList { partition_ids }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::NvLinkPartitionsByIdsRequest>,
) -> Result<Response<rpc::NvLinkPartitionList>, Status> {
    log_request_data(&request);

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
        &api.database_connection,
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

    let results =
        db::nvl_partition::for_tenant(&api.database_connection, tenant_org_id_str).await?;

    let mut partitions = Vec::with_capacity(results.len());

    for result in results {
        partitions.push(result.try_into()?);
    }

    Ok(Response::new(rpc::NvLinkPartitionList { partitions }))
}

pub(crate) async fn nmxm_browse(
    api: &Api,
    request: Request<rpc::NmxmBrowseRequest>,
) -> Result<tonic::Response<rpc::NmxmBrowseResponse>, Status> {
    log_request_data(&request);

    let request = request.into_inner();

    if let Some(nvlink_config) = api.runtime_config.nvlink_config.as_ref()
        && nvlink_config.enabled
    {
        let nmx_m_client = api
            .nmxm_pool
            .create_client(&nvlink_config.nmx_m_endpoint, None)
            .await
            .map_err(|e| CarbideError::internal(format!("Failed to create NMX-M client: {e}")))?;

        let response = nmx_m_client
            .raw_get(&request.path)
            .await
            .map_err(|e| CarbideError::internal(format!("Failed to get raw response: {e}")))?;

        Ok(tonic::Response::new(::rpc::forge::NmxmBrowseResponse {
            body: response.body,
            code: response.code.into(),
            headers: response
                .headers
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.map(|k| k.to_string()).unwrap_or_default(),
                        String::from_utf8_lossy(v.as_bytes()).to_string(),
                    )
                })
                .collect(),
        }))
    } else {
        Err(CarbideError::internal("nvlink config not enabled".to_string()).into())
    }
}
