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
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::db::ib_partition::{self, IBPartition, IBPartitionSearchConfig, NewIBPartition};
use crate::db::{DatabaseError, ObjectColumnFilter};
use ::rpc::errors::RpcDataConversionError;
use forge_uuid::infiniband::IBPartitionId;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::IbPartitionCreationRequest>,
) -> Result<Response<rpc::IbPartition>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "create_ib_partition";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let mut resp = NewIBPartition::try_from(request.into_inner())?;
    let fabric_config = api.ib_fabric_manager.get_config();

    // IB Configurations.
    resp.config.mtu = Some(fabric_config.mtu.clone());
    resp.config.rate_limit = Some(fabric_config.rate_limit.clone());
    resp.config.service_level = Some(fabric_config.service_level.clone());

    resp.config.pkey = api.allocate_pkey(&mut txn, &resp.config.name).await?;
    let resp = resp
        .create(&mut txn, &fabric_config)
        .await
        .map_err(|e| match e.source {
            // During IB paritiont creation, it will check the existing partition by a 'select' query.
            // The 'RowNotFound' error means that the carbide can not find a valid row for the new IBPartition.
            sqlx::Error::RowNotFound => {
                Status::invalid_argument("Maximum Limit of Infiniband partitions had been reached")
            }
            _ => CarbideError::from(e).into(),
        })?;
    let resp = rpc::IbPartition::try_from(resp).map(Response::new)?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(resp)
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::IbPartitionSearchFilter>,
) -> Result<Response<rpc::IbPartitionIdList>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "ib_partition::find_ids";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let filter: rpc::IbPartitionSearchFilter = request.into_inner();

    let ib_partition_ids = IBPartition::find_ids(&mut txn, filter).await?;

    Ok(Response::new(rpc::IbPartitionIdList {
        ib_partition_ids: ib_partition_ids
            .into_iter()
            .map(|id| ::rpc::common::Uuid {
                value: id.to_string(),
            })
            .collect(),
    }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::IbPartitionsByIdsRequest>,
) -> Result<Response<rpc::IbPartitionList>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "ib_partition::find_by_ids";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let rpc::IbPartitionsByIdsRequest {
        ib_partition_ids, ..
    } = request.into_inner();

    let partition_ids: Result<Vec<IBPartitionId>, CarbideError> = ib_partition_ids
        .iter()
        .map(|id| {
            IBPartitionId::try_from(id.clone()).map_err(|_| {
                CarbideError::from(RpcDataConversionError::InvalidIbPartitionId(
                    id.value.to_string(),
                ))
            })
        })
        .collect();
    let partition_ids = partition_ids?;

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

    let partitions = IBPartition::find_by(
        &mut txn,
        ObjectColumnFilter::List(ib_partition::IdColumn, &partition_ids),
        IBPartitionSearchConfig {},
    )
    .await
    .map_err(CarbideError::from)?;

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

    const DB_TXN_NAME: &str = "find_ib_partitions";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let rpc::IbPartitionQuery {
        id, search_config, ..
    } = request.into_inner();

    let mut binding = None;
    let uuid_filter = match id {
        Some(id) => match IBPartitionId::try_from(id) {
            Ok(uuid) => ObjectColumnFilter::One(ib_partition::IdColumn, binding.insert(uuid)),
            Err(err) => {
                return Err(Status::invalid_argument(format!(
                    "Supplied invalid UUID: {err}"
                )));
            }
        },
        None => ObjectColumnFilter::All,
    };

    let search_config = search_config
        .map(IBPartitionSearchConfig::from)
        .unwrap_or(IBPartitionSearchConfig::default());
    let results = IBPartition::find_by(&mut txn, uuid_filter, search_config)
        .await
        .map_err(CarbideError::from)?;
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

    const DB_TXN_NAME: &str = "delete_ib_partition";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let rpc::IbPartitionDeletionRequest { id, .. } = request.into_inner();

    let uuid = IBPartitionId::from_grpc(id)?;

    let mut segments = IBPartition::find_by(
        &mut txn,
        ObjectColumnFilter::One(ib_partition::IdColumn, &uuid),
        IBPartitionSearchConfig::default(),
    )
    .await
    .map_err(CarbideError::from)?;

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

    let resp = segment
        .mark_as_deleted(&mut txn)
        .await
        .map(|_| rpc::IbPartitionDeletionResult {})
        .map(Response::new)?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    Ok(resp)
}

pub(crate) async fn for_tenant(
    api: &Api,
    request: Request<rpc::TenantSearchQuery>,
) -> Result<Response<rpc::IbPartitionList>, Status> {
    log_request_data(&request);

    const DB_TXN_NAME: &str = "find_ib_partions_for_tenant";

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let rpc::TenantSearchQuery {
        tenant_organization_id,
    } = request.into_inner();

    let _tenant_organization_id: String = match tenant_organization_id {
        Some(id) => id,
        None => {
            return Err(CarbideError::MissingArgument("tenant_organization_id").into());
        }
    };

    let results = IBPartition::for_tenant(&mut txn, _tenant_organization_id)
        .await
        .map_err(CarbideError::from)?;

    let mut ib_partitions = Vec::with_capacity(results.len());

    for result in results {
        ib_partitions.push(result.try_into()?);
    }

    Ok(Response::new(rpc::IbPartitionList { ib_partitions }))
}
