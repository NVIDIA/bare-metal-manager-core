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
use crate::db::{DatabaseError, ObjectFilter};
use crate::model::tenant::{
    TenantKeyset, TenantKeysetIdentifier, TenantPublicKeyValidationRequest, UpdateTenantKeyset,
};
use crate::CarbideError;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::CreateTenantKeysetRequest>,
) -> Result<Response<rpc::CreateTenantKeysetResponse>, Status> {
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

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::TenantKeysetSearchFilter>,
) -> Result<Response<rpc::TenantKeysetIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin tenant_keyset::find_ids",
            e,
        ))
    })?;

    let filter: rpc::TenantKeysetSearchFilter = request.into_inner();

    let keyset_ids = TenantKeyset::find_ids(&mut txn, filter)
        .await
        .map_err(CarbideError::from)?;

    Ok(Response::new(rpc::TenantKeysetIdList {
        keyset_ids: keyset_ids
            .into_iter()
            .map(rpc::TenantKeysetIdentifier::from)
            .collect(),
    }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::TenantKeysetsByIdsRequest>,
) -> Result<Response<rpc::TenantKeySetList>, Status> {
    log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin tenant_keyset::find_by_ids",
            e,
        ))
    })?;

    let rpc::TenantKeysetsByIdsRequest {
        keyset_ids,
        include_key_data,
        ..
    } = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if keyset_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if keyset_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let keysets = TenantKeyset::find_by_ids(&mut txn, keyset_ids, include_key_data).await;

    let result = keysets
        .map(|vpc| rpc::TenantKeySetList {
            keyset: vpc.into_iter().map(rpc::TenantKeyset::from).collect(),
        })
        .map(Response::new)
        .map_err(CarbideError::from)?;

    Ok(result)
}

// DEPRECATED: use find_ids and find_by_ids instead
pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::FindTenantKeysetRequest>,
) -> Result<Response<rpc::TenantKeySetList>, Status> {
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

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::UpdateTenantKeysetRequest>,
) -> Result<Response<rpc::UpdateTenantKeysetResponse>, Status> {
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

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::DeleteTenantKeysetRequest>,
) -> Result<Response<rpc::DeleteTenantKeysetResponse>, Status> {
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

pub(crate) async fn validate_public_key(
    api: &Api,
    request: Request<rpc::ValidateTenantPublicKeyRequest>,
) -> Result<Response<rpc::ValidateTenantPublicKeyResponse>, Status> {
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
