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

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use model::ConfigValidationError;
use model::metadata::Metadata;
use model::tenant::RoutingProfileType;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

/// Ensures that fields unsupported by the tenant DB model are rejected early.
fn metadata_to_valid_tenant_metadata(metadata: Option<rpc::Metadata>) -> Result<Metadata, Status> {
    Ok(match metadata {
        None => return Err(CarbideError::MissingArgument("metadata").into()),
        Some(mdata) => {
            if !mdata.description.is_empty() {
                return Err(CarbideError::InvalidConfiguration(
                    ConfigValidationError::InvalidValue(
                        "description not supported for tenant metadata".into(),
                    ),
                )
                .into());
            }

            if !mdata.labels.is_empty() {
                return Err(CarbideError::InvalidConfiguration(
                    ConfigValidationError::InvalidValue(
                        "labels not supported for tenant metadata".into(),
                    ),
                )
                .into());
            }

            mdata.try_into().map_err(CarbideError::from)?
        }
    })
}

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::CreateTenantRequest>,
) -> Result<Response<rpc::CreateTenantResponse>, Status> {
    crate::api::log_request_data(&request);

    let rpc::CreateTenantRequest {
        organization_id,
        metadata,
        routing_profile_type,
    } = request.into_inner();

    let metadata: Metadata = metadata_to_valid_tenant_metadata(metadata)?;

    metadata.validate(true).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin("create_tenant").await?;

    let response = db::tenant::create_and_persist(
        organization_id,
        metadata,
        if api.runtime_config.fnn.is_none() {
            None
        } else {
            routing_profile_type
                .map(rpc::RoutingProfileType::try_from)
                .transpose()
                .map_err(|e| {
                    CarbideError::from(RpcDataConversionError::InvalidValue(
                        e.to_string(),
                        "RoutingProfileType".to_string(),
                    ))
                })?
                .map(RoutingProfileType::try_from)
                .transpose()
                .map_err(CarbideError::from)?
                .or(Some(RoutingProfileType::External))
        },
        &mut txn,
    )
    .await?
    .try_into()
    .map(Response::new)
    .map_err(CarbideError::from)?;

    txn.commit().await?;

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

    let mut txn = api.txn_begin("find_tenant").await?;

    let response = match db::tenant::find(tenant_organization_id, &mut txn)
        .await
        .map(Response::new)?
        .into_inner()
    {
        None => rpc::FindTenantResponse { tenant: None },
        Some(t) => t.try_into().map_err(CarbideError::from)?,
    };

    txn.commit().await?;

    Ok(Response::new(response))
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::UpdateTenantRequest>,
) -> Result<Response<rpc::UpdateTenantResponse>, Status> {
    crate::api::log_request_data(&request);

    let rpc::UpdateTenantRequest {
        organization_id,
        if_version_match,
        metadata,
    } = request.into_inner();

    let metadata: Metadata = metadata_to_valid_tenant_metadata(metadata)?;

    metadata.validate(true).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin("update_tenant").await?;

    let if_version_match: Option<config_version::ConfigVersion> =
        if let Some(config_version_str) = if_version_match {
            Some(config_version_str.parse().map_err(CarbideError::from)?)
        } else {
            None
        };

    let response = db::tenant::update(organization_id, metadata, if_version_match, &mut txn)
        .await?
        .try_into()
        .map(Response::new)
        .map_err(CarbideError::from)?;

    txn.commit().await?;

    Ok(response)
}

pub(crate) async fn find_tenants_by_organization_ids(
    api: &Api,
    request: Request<rpc::TenantByOrganizationIdsRequest>,
) -> Result<Response<rpc::TenantList>, Status> {
    crate::api::log_request_data(&request);
    let request = request.into_inner();

    let mut txn = api.txn_begin("find_tenants_by_organization_ids").await?;

    let tenant_organization_ids: Vec<String> = request.organization_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if tenant_organization_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if tenant_organization_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let tenants: Vec<rpc::Tenant> =
        db::tenant::load_by_organization_ids(&mut txn, &tenant_organization_ids)
            .await?
            .into_iter()
            .filter_map(|tenant| rpc::Tenant::try_from(tenant).ok())
            .collect();

    txn.commit().await?;

    Ok(tonic::Response::new(rpc::TenantList { tenants }))
}

pub(crate) async fn find_tenant_organization_ids(
    api: &Api,
    request: Request<rpc::TenantSearchFilter>,
) -> Result<Response<rpc::TenantOrganizationIdList>, Status> {
    crate::api::log_request_data(&request);
    let mut txn = api.txn_begin("find_tenant_organization_ids").await?;
    let search_config = request.into_inner();
    let tenant_org_ids = db::tenant::find_tenant_organization_ids(&mut txn, search_config).await?;
    Ok(tonic::Response::new(rpc::TenantOrganizationIdList {
        tenant_organization_ids: tenant_org_ids.into_iter().collect(),
    }))
}

#[cfg(test)]
mod tests {
    use ::rpc::forge as rpc;
    use tonic::Code;

    use super::*;

    #[test]
    fn test_metadata_to_valid_tenant_metadata() {
        // Good metadata
        let metadata = metadata_to_valid_tenant_metadata(Some(rpc::Metadata {
            name: "Name".to_string(),
            description: "".to_string(),
            labels: vec![],
        }));

        assert!(metadata.is_ok());

        // No description allowed
        let metadata = metadata_to_valid_tenant_metadata(Some(rpc::Metadata {
            name: "Name".to_string(),
            description: "should not be stored".to_string(),
            labels: vec![],
        }))
        .unwrap_err();

        assert_eq!(metadata.code(), Code::InvalidArgument);
        assert!(metadata.message().contains("description"));

        // No labels allowed
        let metadata = metadata_to_valid_tenant_metadata(Some(rpc::Metadata {
            name: "Name".to_string(),
            description: "".to_string(),
            labels: vec![rpc::Label {
                key: "aaa".to_string(),
                value: Some("bbb".to_string()),
            }],
        }))
        .unwrap_err();

        assert_eq!(metadata.code(), Code::InvalidArgument);
        assert!(metadata.message().contains("labels"));
    }
}
