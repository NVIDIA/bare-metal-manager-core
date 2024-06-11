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
use uuid::Uuid;

use crate::api::Api;
use crate::db::ib_partition::{IBPartition, IBPartitionSearchConfig, NewIBPartition};
use crate::db::{DatabaseError, UuidKeyedObjectFilter};
use crate::CarbideError;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::IbPartitionCreationRequest>,
) -> Result<Response<rpc::IbPartition>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_ib_partition",
            e,
        ))
    })?;

    let mut resp = NewIBPartition::try_from(request.into_inner())?;
    resp.config.pkey = api.allocate_pkey(&mut txn, &resp.config.name).await?;
    let resp = resp
        .create(&mut txn, &api.ib_fabric_manager.get_config())
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

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit create_ib_partition",
            e,
        ))
    })?;

    Ok(resp)
}

pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::IbPartitionQuery>,
) -> Result<Response<rpc::IbPartitionList>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_ib_partitions",
            e,
        ))
    })?;

    let rpc::IbPartitionQuery {
        id, search_config, ..
    } = request.into_inner();

    let uuid_filter = match id {
        Some(id) => match Uuid::try_from(id) {
            Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
            Err(err) => {
                return Err(Status::invalid_argument(format!(
                    "Supplied invalid UUID: {}",
                    err
                )));
            }
        },
        None => UuidKeyedObjectFilter::All,
    };

    let search_config = search_config
        .map(IBPartitionSearchConfig::from)
        .unwrap_or(IBPartitionSearchConfig::default());
    let results = IBPartition::find(&mut txn, uuid_filter, search_config)
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
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_ib_partition",
            e,
        ))
    })?;

    let rpc::IbPartitionDeletionRequest { id, .. } = request.into_inner();

    let uuid = match id {
        Some(id) => match Uuid::try_from(id) {
            Ok(uuid) => uuid,
            Err(_err) => {
                return Err(CarbideError::InvalidArgument("id".to_string()).into());
            }
        },
        None => {
            return Err(CarbideError::MissingArgument("id").into());
        }
    };

    let mut segments = IBPartition::find(
        &mut txn,
        UuidKeyedObjectFilter::One(uuid),
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
            .into())
        }
    };

    let resp = segment
        .mark_as_deleted(&mut txn)
        .await
        .map(|_| rpc::IbPartitionDeletionResult {})
        .map(Response::new)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit delete_ib_partition",
            e,
        ))
    })?;

    Ok(resp)
}

pub(crate) async fn for_tenant(
    api: &Api,
    request: Request<rpc::TenantSearchQuery>,
) -> Result<Response<rpc::IbPartitionList>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_ib_partions_for_tenant",
            e,
        ))
    })?;

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
