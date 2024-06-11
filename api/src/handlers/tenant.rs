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

use crate::api::Api;
use crate::db::DatabaseError;
use crate::model::tenant::Tenant;
use crate::CarbideError;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::CreateTenantRequest>,
) -> Result<Response<rpc::CreateTenantResponse>, Status> {
    crate::api::log_request_data(&request);

    let rpc::CreateTenantRequest { organization_id } = request.into_inner();

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_tenant",
            e,
        ))
    })?;

    let response = Tenant::create_and_persist(organization_id, &mut txn)
        .await
        .map(|x| x.into())
        .map(Response::new)
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit create_tenant",
            e,
        ))
    })?;

    Ok(response)
}

pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::FindTenantRequest>,
) -> Result<Response<rpc::FindTenantResponse>, Status> {
    crate::api::log_request_data(&request);

    let rpc::FindTenantRequest {
        tenant_organization_id,
    } = request.into_inner();

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin find_tenant", e))
    })?;

    let response = Tenant::find(tenant_organization_id, &mut txn)
        .await
        .map(|x| {
            x.map(|a| a.into())
                .unwrap_or(rpc::FindTenantResponse { tenant: None })
        })
        .map(Response::new)
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_tenant",
            e,
        ))
    })?;

    Ok(response)
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::UpdateTenantRequest>,
) -> Result<Response<rpc::UpdateTenantResponse>, Status> {
    crate::api::log_request_data(&request);

    // This doesn't update anything yet :|
    let rpc::UpdateTenantRequest {
        organization_id,
        if_version_match,
        ..
    } = request.into_inner();

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_tenant",
            e,
        ))
    })?;

    let if_version_match: Option<config_version::ConfigVersion> =
        if let Some(config_version_str) = if_version_match {
            Some(config_version_str.parse().map_err(CarbideError::from)?)
        } else {
            None
        };

    let response = Tenant::update(organization_id, if_version_match, &mut txn)
        .await
        .map(|x| x.into())
        .map(Response::new)
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_tenant",
            e,
        ))
    })?;

    Ok(response)
}
