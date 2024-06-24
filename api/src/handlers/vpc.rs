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

use crate::api::{log_request_data, Api};
use crate::db::vpc::{NewVpc, UpdateVpc, Vpc};
use crate::db::{DatabaseError, UuidKeyedObjectFilter};
use crate::model::RpcDataConversionError;
use crate::CarbideError;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::VpcCreationRequest>,
) -> Result<Response<rpc::Vpc>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin create_vpc", e))
    })?;

    let mut vpc = NewVpc::try_from(request.into_inner())?
        .persist(&mut txn)
        .await
        .map_err(CarbideError::from)?;
    vpc.vni = Some(api.allocate_vpc_vni(&mut txn, &vpc.id.to_string()).await?);
    Vpc::set_vni(&mut txn, vpc.id, vpc.vni.unwrap())
        .await
        .map_err(CarbideError::from)?;

    let rpc_out: rpc::Vpc = vpc.into();

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit create_vpc", e))
    })?;

    Ok(Response::new(rpc_out))
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::VpcUpdateRequest>,
) -> Result<Response<rpc::VpcUpdateResult>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin update_vpc", e))
    })?;

    UpdateVpc::try_from(request.into_inner())?
        .update(&mut txn)
        .await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit update_vpc", e))
    })?;

    Ok(Response::new(rpc::VpcUpdateResult {}))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::VpcDeletionRequest>,
) -> Result<Response<rpc::VpcDeletionResult>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin delete_vpc", e))
    })?;

    // TODO: This needs to validate that nothing references the VPC anymore
    // (like NetworkSegments)
    let vpc_id: uuid::Uuid = request
        .into_inner()
        .id
        .ok_or(CarbideError::MissingArgument("id"))?
        .try_into()
        .map_err(CarbideError::from)?;

    let vpc = match Vpc::try_delete(&mut txn, vpc_id)
        .await
        .map_err(CarbideError::from)?
    {
        Some(vpc) => vpc,
        None => {
            // VPC didn't exist or was deleted in the past. We are not allowed
            // to free the VNI again
            return Err(CarbideError::NotFoundError {
                kind: "vpc",
                id: vpc_id.to_string(),
            }
            .into());
        }
    };

    if let Some(vni) = vpc.vni {
        api.common_pools
            .ethernet
            .pool_vpc_vni
            .release(&mut txn, vni)
            .await
            .map_err(CarbideError::from)?;
    }

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit delete_vpc", e))
    })?;

    Ok(Response::new(rpc::VpcDeletionResult {}))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::VpcSearchFilter>,
) -> Result<Response<rpc::VpcIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin vpc::find_ids",
            e,
        ))
    })?;

    let filter: rpc::VpcSearchFilter = request.into_inner();

    let vpc_ids = Vpc::find_ids(&mut txn, filter).await?;

    Ok(Response::new(rpc::VpcIdList {
        vpc_ids: vpc_ids
            .into_iter()
            .map(|id| rpc::Uuid {
                value: id.to_string(),
            })
            .collect(),
    }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::VpcIdList>,
) -> Result<Response<rpc::VpcList>, Status> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin vpc::find_by_ids",
            e,
        ))
    })?;

    let vpc_ids: Result<Vec<uuid::Uuid>, CarbideError> = request
        .into_inner()
        .vpc_ids
        .iter()
        .map(|id| {
            uuid::Uuid::try_from(id.value.as_str()).map_err(|_| {
                CarbideError::from(RpcDataConversionError::InvalidVpcId(id.value.to_string()))
            })
        })
        .collect();
    let vpc_ids = vpc_ids?;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if vpc_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if vpc_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let db_vpcs = Vpc::find(&mut txn, UuidKeyedObjectFilter::List(&vpc_ids)).await;

    let result = db_vpcs
        .map(|vpc| rpc::VpcList {
            vpcs: vpc.into_iter().map(rpc::Vpc::from).collect(),
        })
        .map(Response::new)
        .map_err(CarbideError::from)?;

    Ok(result)
}

// DEPRECATED: use find_ids and find_by_ids instead
pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::VpcSearchQuery>,
) -> Result<Response<rpc::VpcList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin find_vpcs", e))
    })?;

    let rpc::VpcSearchQuery { id, name, .. } = request.into_inner();

    let vpcs = match (id, name) {
        (Some(id), _) => {
            let uuid = match uuid::Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Supplied invalid UUID: {}",
                        err
                    )));
                }
            };
            Vpc::find(&mut txn, uuid).await
        }
        (None, Some(name)) => Vpc::find_by_name(&mut txn, &name).await,
        (None, None) => Vpc::find(&mut txn, UuidKeyedObjectFilter::All).await,
    };

    let result = vpcs
        .map(|vpc| rpc::VpcList {
            vpcs: vpc.into_iter().map(rpc::Vpc::from).collect(),
        })
        .map(Response::new)
        .map_err(CarbideError::from)?;

    Ok(result)
}
