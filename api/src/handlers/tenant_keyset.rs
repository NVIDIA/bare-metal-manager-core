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

use crate::api::Api;
use crate::db::{DatabaseError, ObjectFilter};
use crate::model::tenant::{
    TenantKeyset, TenantKeysetIdentifier, TenantPublicKeyValidationRequest, UpdateTenantKeyset,
};
use crate::CarbideError;

pub(crate) async fn create<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::CreateTenantKeysetRequest>,
) -> Result<Response<rpc::CreateTenantKeysetResponse>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let keyset_request: TenantKeyset = request
        .into_inner()
        .try_into()
        .map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_tenant_keyset",
            e,
        ))
    })?;

    let keyset = keyset_request
        .create(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit create_tenant_keyset",
            e,
        ))
    })?;

    Ok(Response::new(rpc::CreateTenantKeysetResponse {
        keyset: Some(keyset.into()),
    }))
}

pub(crate) async fn find<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::FindTenantKeysetRequest>,
) -> Result<Response<rpc::TenantKeySetList>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let rpc::FindTenantKeysetRequest {
        organization_id,
        keyset_id,
        include_key_data,
    } = request.into_inner();

    if organization_id.is_none() && keyset_id.is_some() {
        return Err(CarbideError::InvalidArgument(
            "Keyset id is given but Organization id is missing.".to_string(),
        )
        .into());
    }

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_tenant_keyset",
            e,
        ))
    })?;

    let keyset_ids = if let Some(keyset_id) = keyset_id {
        ObjectFilter::One(keyset_id)
    } else {
        ObjectFilter::All
    };

    let keyset = TenantKeyset::find(organization_id, keyset_ids, include_key_data, &mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_tenant_keyset",
            e,
        ))
    })?;

    Ok(Response::new(rpc::TenantKeySetList {
        keyset: keyset.into_iter().map(|x| x.into()).collect(),
    }))
}

pub(crate) async fn update<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::UpdateTenantKeysetRequest>,
) -> Result<Response<rpc::UpdateTenantKeysetResponse>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let update_request: UpdateTenantKeyset = request
        .into_inner()
        .try_into()
        .map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_tenant_keyset",
            e,
        ))
    })?;

    update_request
        .update(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_tenant_keyset",
            e,
        ))
    })?;

    Ok(Response::new(rpc::UpdateTenantKeysetResponse {}))
}

pub(crate) async fn delete<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::DeleteTenantKeysetRequest>,
) -> Result<Response<rpc::DeleteTenantKeysetResponse>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let rpc::DeleteTenantKeysetRequest { keyset_identifier } = request.into_inner();

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_tenant_keyset",
            e,
        ))
    })?;

    let Some(keyset_identifier) = keyset_identifier else {
        return Err(CarbideError::MissingArgument("keyset_identifier").into());
    };

    let keyset_identifier: TenantKeysetIdentifier =
        keyset_identifier.try_into().map_err(CarbideError::from)?;

    TenantKeyset::delete(keyset_identifier, &mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit delete_tenant_keyset",
            e,
        ))
    })?;

    Ok(Response::new(rpc::DeleteTenantKeysetResponse {}))
}

pub(crate) async fn validate_public_key<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::ValidateTenantPublicKeyRequest>,
) -> Result<Response<rpc::ValidateTenantPublicKeyResponse>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    let request = TenantPublicKeyValidationRequest::try_from(request.into_inner())
        .map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin validate_tenant_public_key",
            e,
        ))
    })?;

    request.validate(&mut txn).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit validate_tenant_public_key",
            e,
        ))
    })?;
    Ok(Response::new(rpc::ValidateTenantPublicKeyResponse {}))
}
