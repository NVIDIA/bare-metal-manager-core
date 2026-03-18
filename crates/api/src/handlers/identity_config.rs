/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use it except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! gRPC handlers for tenant_identity_config table.
//! Identity config: issuer, audiences, TTL, signing key (Get/Set/Delete).
//! Token delegation: token exchange config for external IdP (Get/Set/Delete).

use ::rpc::Timestamp;
use ::rpc::forge::{
    GetIdentityConfigRequest, GetTokenDelegationRequest, IdentityConfig as ProtoIdentityConfig,
    IdentityConfigRequest, IdentityConfigResponse, TokenDelegationRequest, TokenDelegationResponse,
    token_delegation,
};
use db::{WithTransaction, tenant, tenant_identity_config};
use model::tenant::{
    IdentityConfig, IdentityConfigValidationError, InvalidTenantOrg, TenantOrganizationId,
    TokenDelegation, TokenDelegationValidationError,
};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data, log_request_data_redacted};

/// Formats TokenDelegationRequest for logging with client_secret redacted.
fn format_token_delegation_request_redacted(req: &TokenDelegationRequest) -> String {
    let config_str = match &req.config {
        None => "None".to_string(),
        Some(cfg) => {
            let auth_method_config = match &cfg.auth_method_config {
                None => "None".to_string(),
                Some(token_delegation::AuthMethodConfig::ClientSecretBasic(c)) => format!(
                    "Some(ClientSecretBasic {{ client_id: \"{}\", client_secret: \"[REDACTED]\" }})",
                    c.client_id
                ),
            };
            format!(
                "Some(TokenDelegation {{ token_endpoint: \"{}\", subject_token_audience: \"{}\", auth_method_config: {} }})",
                cfg.token_endpoint, cfg.subject_token_audience, auth_method_config
            )
        }
    };
    format!(
        "TokenDelegationRequest {{ organization_id: \"{}\", config: {} }}",
        req.organization_id, config_str
    )
}

// --- Identity configuration handlers ---

/// Handles GetIdentityConfiguration: fetches per-org identity config.
pub(crate) async fn get_identity_configuration(
    api: &Api,
    request: Request<GetIdentityConfigRequest>,
) -> Result<Response<IdentityConfigResponse>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )
        .into());
    }

    let req = request.into_inner();
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(
            CarbideError::InvalidArgument("organization_id is required".to_string()).into(),
        );
    }
    let org_id: TenantOrganizationId = org_id
        .parse()
        .map_err(|e: InvalidTenantOrg| CarbideError::InvalidArgument(e.to_string()))?;
    let org_id_str = org_id.as_str().to_string();

    let cfg = api
        .database_connection
        .with_txn(|txn| Box::pin(async move { tenant_identity_config::find(&org_id, txn).await }))
        .await??;

    let cfg = match cfg {
        Some(c) => c,
        None => {
            return Err(CarbideError::NotFoundError {
                kind: "tenant_identity_config",
                id: org_id_str.clone(),
            }
            .into());
        }
    };

    Ok(Response::new(IdentityConfigResponse {
        organization_id: org_id_str,
        config: Some(ProtoIdentityConfig {
            enabled: cfg.enabled,
            issuer: cfg.issuer.clone(),
            default_audience: cfg.default_audience.clone(),
            allowed_audiences: cfg.allowed_audiences.0.clone(),
            token_ttl_sec: cfg.token_ttl_sec as u32,
            subject_prefix: cfg.subject_prefix.clone(),
            rotate_key: false,
        }),
        created_at: Some(Timestamp::from(cfg.created_at)),
        updated_at: Some(Timestamp::from(cfg.updated_at)),
        key_id: cfg.key_id,
    }))
}

/// Handles DeleteIdentityConfiguration: removes per-org identity config.
pub(crate) async fn delete_identity_configuration(
    api: &Api,
    request: Request<GetIdentityConfigRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )
        .into());
    }

    let req = request.into_inner();
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(
            CarbideError::InvalidArgument("organization_id is required".to_string()).into(),
        );
    }
    let org_id: TenantOrganizationId = org_id
        .parse()
        .map_err(|e: InvalidTenantOrg| CarbideError::InvalidArgument(e.to_string()))?;
    let org_id_str = org_id.as_str().to_string();

    let deleted = api
        .database_connection
        .with_txn(|txn| {
            Box::pin(async move {
                let deleted = tenant_identity_config::delete(&org_id, txn).await?;
                if deleted {
                    tenant::increment_version(org_id.as_str(), txn).await?;
                }
                Ok::<_, db::DatabaseError>(deleted)
            })
        })
        .await??;

    if !deleted {
        return Err(CarbideError::NotFoundError {
            kind: "tenant_identity_config",
            id: org_id_str,
        }
        .into());
    }

    Ok(Response::new(()))
}

/// Handles SetIdentityConfiguration: upserts per-org identity config into tenant_identity_config.
/// Requires auth. Tenant must exist. Key generation is placeholder until Vault integration.
pub(crate) async fn set_identity_configuration(
    api: &Api,
    request: Request<IdentityConfigRequest>,
) -> Result<Response<IdentityConfigResponse>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config before setting identity configuration"
                .to_string(),
        )
        .into());
    }

    let req = request.into_inner();
    let config: IdentityConfig = req
        .config
        .ok_or_else(|| CarbideError::InvalidArgument("IdentityConfig is required".to_string()))
        .and_then(|c| {
            IdentityConfig::try_from_proto(
                c,
                &model::tenant::IdentityConfigValidationBounds::from(
                    api.runtime_config.machine_identity.clone(),
                ),
            )
            .map_err(|e: IdentityConfigValidationError| CarbideError::InvalidArgument(e.0))
        })?;
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(
            CarbideError::InvalidArgument("organization_id is required".to_string()).into(),
        );
    }
    let org_id: TenantOrganizationId = org_id
        .parse()
        .map_err(|e: InvalidTenantOrg| CarbideError::InvalidArgument(e.to_string()))?;
    let org_id_str = org_id.as_str().to_string();

    let cfg = api
        .database_connection
        .with_txn(|txn| {
            Box::pin(async move {
                let tenant_exists = tenant::find(org_id.as_str(), false, txn).await?;
                if tenant_exists.is_none() {
                    return Err(db::DatabaseError::NotFoundError {
                        kind: "Tenant",
                        id: org_id.as_str().to_string(),
                    });
                }
                let cfg = tenant_identity_config::set(&org_id, &config, txn).await?;
                tenant::increment_version(org_id.as_str(), txn).await?;
                Ok(cfg)
            })
        })
        .await??;

    Ok(Response::new(IdentityConfigResponse {
        organization_id: org_id_str,
        config: Some(ProtoIdentityConfig {
            enabled: cfg.enabled,
            issuer: cfg.issuer.clone(),
            default_audience: cfg.default_audience.clone(),
            allowed_audiences: cfg.allowed_audiences.0.clone(),
            token_ttl_sec: cfg.token_ttl_sec as u32,
            subject_prefix: cfg.subject_prefix.clone(),
            rotate_key: false,
        }),
        created_at: Some(Timestamp::from(cfg.created_at)),
        updated_at: Some(Timestamp::from(cfg.updated_at)),
        key_id: cfg.key_id,
    }))
}

// --- Token delegation handlers ---

pub(crate) async fn get_token_delegation(
    api: &Api,
    request: Request<GetTokenDelegationRequest>,
) -> Result<Response<TokenDelegationResponse>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )
        .into());
    }

    let req = request.into_inner();
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(
            CarbideError::InvalidArgument("organization_id is required".to_string()).into(),
        );
    }
    let org_id: TenantOrganizationId = org_id
        .parse()
        .map_err(|e: InvalidTenantOrg| CarbideError::InvalidArgument(e.to_string()))?;
    let org_id_str = org_id.as_str().to_string();

    let cfg = api
        .database_connection
        .with_txn(|txn| Box::pin(async move { tenant_identity_config::find(&org_id, txn).await }))
        .await??;

    let cfg = match cfg {
        Some(c) => c,
        None => {
            return Err(CarbideError::NotFoundError {
                kind: "tenant_identity_config",
                id: org_id_str.clone(),
            }
            .into());
        }
    };

    if cfg.token_endpoint.is_none() || cfg.auth_method.is_none() {
        return Err(Status::from(CarbideError::NotFoundError {
            kind: "token_delegation",
            id: org_id_str.clone(),
        }));
    }

    Ok(Response::new(cfg.try_into().map_err(CarbideError::from)?))
}

pub(crate) async fn set_token_delegation(
    api: &Api,
    request: Request<TokenDelegationRequest>,
) -> Result<Response<TokenDelegationResponse>, Status> {
    log_request_data_redacted(format_token_delegation_request_redacted(request.get_ref()));

    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )
        .into());
    }

    let req = request.into_inner();
    let config: TokenDelegation = req
        .config
        .as_ref()
        .ok_or_else(|| {
            CarbideError::InvalidArgument("TokenDelegation config is required".to_string())
        })
        .and_then(|c| {
            TokenDelegation::try_from(c.clone())
                .map_err(|e: TokenDelegationValidationError| CarbideError::InvalidArgument(e.0))
        })?;
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(
            CarbideError::InvalidArgument("organization_id is required".to_string()).into(),
        );
    }
    let org_id: TenantOrganizationId = org_id.parse().map_err(|e: InvalidTenantOrg| {
        Status::from(CarbideError::InvalidArgument(e.to_string()))
    })?;

    let cfg = api
        .database_connection
        .with_txn(|txn| {
            Box::pin(async move {
                let tenant_exists = tenant::find(org_id.as_str(), false, txn).await?;
                if tenant_exists.is_none() {
                    return Err(db::DatabaseError::NotFoundError {
                        kind: "Tenant",
                        id: org_id.as_str().to_string(),
                    });
                }
                let cfg =
                    tenant_identity_config::set_token_delegation(&org_id, &config, txn).await?;
                tenant::increment_version(org_id.as_str(), txn).await?;
                Ok(cfg)
            })
        })
        .await??;

    Ok(Response::new(cfg.try_into().map_err(CarbideError::from)?))
}

pub(crate) async fn delete_token_delegation(
    api: &Api,
    request: Request<GetTokenDelegationRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )
        .into());
    }

    let req = request.into_inner();
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(
            CarbideError::InvalidArgument("organization_id is required".to_string()).into(),
        );
    }
    let org_id: TenantOrganizationId = org_id
        .parse()
        .map_err(|e: InvalidTenantOrg| CarbideError::InvalidArgument(e.to_string()))?;

    api.database_connection
        .with_txn(|txn| {
            Box::pin(async move {
                let result = tenant_identity_config::delete_token_delegation(&org_id, txn).await?;
                if result.is_some() {
                    tenant::increment_version(org_id.as_str(), txn).await?;
                }
                Ok::<_, db::DatabaseError>(())
            })
        })
        .await??;

    Ok(Response::new(()))
}
