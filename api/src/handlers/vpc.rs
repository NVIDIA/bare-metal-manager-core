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
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::api::Api;
use crate::db::vpc::{NewVpc, UpdateVpc, Vpc};
use crate::db::{DatabaseError, UuidKeyedObjectFilter};
use crate::CarbideError;

pub(crate) async fn create<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::VpcCreationRequest>,
) -> Result<Response<rpc::Vpc>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

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

pub(crate) async fn update<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::VpcUpdateRequest>,
) -> Result<Response<rpc::VpcUpdateResult>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

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

pub(crate) async fn delete<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::VpcDeletionRequest>,
) -> Result<Response<rpc::VpcDeletionResult>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

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

pub(crate) async fn find<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::VpcSearchQuery>,
) -> Result<Response<rpc::VpcList>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin find_vpcs", e))
    })?;

    let rpc::VpcSearchQuery { id, name, .. } = request.into_inner();

    let vpcs = match (id, name) {
        (Some(id), _) => {
            let uuid = match Uuid::try_from(id) {
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
