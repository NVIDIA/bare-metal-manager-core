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
use crate::model::{metadata::Metadata, tenant::Tenant, ConfigValidationError};
use crate::CarbideError;

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
    } = request.into_inner();

    let metadata: Metadata = metadata_to_valid_tenant_metadata(metadata)?;

    metadata.validate(true).map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_tenant",
            e,
        ))
    })?;

    let response = Tenant::create_and_persist(organization_id, metadata, &mut txn)
        .await
        .map_err(CarbideError::from)?
        .try_into()
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

    let response = match Tenant::find(tenant_organization_id, &mut txn)
        .await
        .map(Response::new)
        .map_err(CarbideError::from)?
        .into_inner()
    {
        None => rpc::FindTenantResponse { tenant: None },
        Some(t) => t.try_into().map_err(CarbideError::from)?,
    };

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit find_tenant",
            e,
        ))
    })?;

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

    let response = Tenant::update(organization_id, metadata, if_version_match, &mut txn)
        .await?
        .try_into()
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

#[cfg(test)]
mod tests {
    use super::*;
    use ::rpc::forge as rpc;
    use tonic::Code;

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
