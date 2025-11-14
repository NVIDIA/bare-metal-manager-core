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
use model::tenant::{
    TenantKeyset, TenantKeysetIdentifier, TenantPublicKeyValidationRequest, UpdateTenantKeyset,
};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::CreateTenantKeysetRequest>,
) -> Result<Response<rpc::CreateTenantKeysetResponse>, Status> {
    crate::api::log_request_data(&request);

    let keyset_request: TenantKeyset = request
        .into_inner()
        .try_into()
        .map_err(CarbideError::from)?;

    let mut txn = api.txn_begin("create_tenant_keyset").await?;

    let keyset = db::tenant_keyset::create(&keyset_request, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(rpc::CreateTenantKeysetResponse {
        keyset: Some(keyset.into()),
    }))
}

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::TenantKeysetSearchFilter>,
) -> Result<Response<rpc::TenantKeysetIdList>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin("tenant_keyset::find_ids").await?;

    let filter: rpc::TenantKeysetSearchFilter = request.into_inner();

    let keyset_ids = db::tenant_keyset::find_ids(&mut txn, filter).await?;

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
    let mut txn = api.txn_begin("tenant_keyset::find_by_ids").await?;

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

    let keysets = db::tenant_keyset::find_by_ids(&mut txn, keyset_ids, include_key_data).await;

    let result = keysets
        .map(|vpc| rpc::TenantKeySetList {
            keyset: vpc.into_iter().map(rpc::TenantKeyset::from).collect(),
        })
        .map(Response::new)?;

    Ok(result)
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

    let mut txn = api.txn_begin("update_tenant_keyset").await?;

    db::tenant_keyset::update(&update_request, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(rpc::UpdateTenantKeysetResponse {}))
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::DeleteTenantKeysetRequest>,
) -> Result<Response<rpc::DeleteTenantKeysetResponse>, Status> {
    crate::api::log_request_data(&request);

    let rpc::DeleteTenantKeysetRequest { keyset_identifier } = request.into_inner();

    let mut txn = api.txn_begin("delete_tenant_keyset").await?;

    let Some(keyset_identifier) = keyset_identifier else {
        return Err(CarbideError::MissingArgument("keyset_identifier").into());
    };

    let keyset_identifier: TenantKeysetIdentifier =
        keyset_identifier.try_into().map_err(CarbideError::from)?;

    if !db::tenant_keyset::delete(&keyset_identifier, &mut txn).await? {
        return Err(CarbideError::NotFoundError {
            kind: "keyset",
            id: format!("{keyset_identifier:?}"),
        }
        .into());
    }

    txn.commit().await?;

    Ok(Response::new(rpc::DeleteTenantKeysetResponse {}))
}

pub(crate) async fn validate_public_key(
    api: &Api,
    request: Request<rpc::ValidateTenantPublicKeyRequest>,
) -> Result<Response<rpc::ValidateTenantPublicKeyResponse>, Status> {
    let request = TenantPublicKeyValidationRequest::try_from(request.into_inner())
        .map_err(CarbideError::from)?;

    let mut txn = api.txn_begin("validate_tenant_public_key").await?;

    db::tenant::validate_public_key(&request, &mut txn).await?;

    txn.commit().await?;

    Ok(Response::new(rpc::ValidateTenantPublicKeyResponse {}))
}
