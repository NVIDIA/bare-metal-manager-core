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
    ClientSecretBasic, ClientSecretBasicResponse, GetIdentityConfigRequest,
    GetTokenDelegationRequest, IdentityConfig as ProtoIdentityConfig, IdentityConfigRequest,
    IdentityConfigResponse, TokenDelegationRequest, TokenDelegationResponse, token_delegation,
    token_delegation_response,
};
use db::{WithTransaction, tenant, tenant_identity_config};
use model::tenant::{
    IdentityConfig, IdentityConfigValidationError, InvalidTenantOrg, TenantOrganizationId,
    TokenDelegation, TokenDelegationValidationError, compute_client_secret_hash,
};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data, log_request_data_redacted};

// --- Token delegation: secret hashing and oneof conversion ---

/// Hex chars to show in get_token_delegation response (8 chars + ".." suffix).
const HASH_DISPLAY_HEX_LEN: usize = 8;

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

/// Truncates hash for display in get_token_delegation: algorithm-prefix:XXXXXXXX..
fn truncate_hash_for_display(full_hash: &str) -> String {
    full_hash
        .split_once(':')
        .map(|(prefix, rest)| {
            format!(
                "{}:{}..",
                prefix,
                rest.chars().take(HASH_DISPLAY_HEX_LEN).collect::<String>()
            )
        })
        .unwrap_or_else(|| full_hash.to_string())
}

/// Converts stored config to response oneof. Truncates hashes for display.
/// Only used when auth_method is "client_secret_basic"; for "none" the oneof is omitted.
fn stored_to_response_auth_config(
    auth_method: &str,
    stored: Option<&ClientSecretBasic>,
) -> Option<token_delegation_response::AuthMethodConfig> {
    match auth_method {
        "client_secret_basic" => stored.filter(|s| !s.client_secret.is_empty()).map(|s| {
            let hash = compute_client_secret_hash(&s.client_secret);
            token_delegation_response::AuthMethodConfig::ClientSecretBasic(
                ClientSecretBasicResponse {
                    client_id: s.client_id.clone(),
                    client_secret_hash: truncate_hash_for_display(&hash),
                },
            )
        }),
        _ => None,
    }
}

// --- Identity configuration handlers ---

/// Handles GetIdentityConfiguration: fetches per-org identity config.
pub(crate) async fn get_identity_configuration(
    api: &Api,
    request: Request<GetIdentityConfigRequest>,
) -> Result<Response<IdentityConfigResponse>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::from(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )));
    }

    let req = request.into_inner();
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(Status::from(CarbideError::InvalidArgument(
            "organization_id is required".to_string(),
        )));
    }
    let org_id: TenantOrganizationId = org_id.parse().map_err(|e: InvalidTenantOrg| {
        Status::from(CarbideError::InvalidArgument(e.to_string()))
    })?;
    let org_id_str = org_id.as_str().to_string();

    let cfg = api
        .database_connection
        .with_txn(|txn| Box::pin(async move { tenant_identity_config::find(&org_id, txn).await }))
        .await??;

    let cfg = match cfg {
        Some(c) => c,
        None => {
            return Err(Status::from(CarbideError::NotFoundError {
                kind: "tenant_identity_config",
                id: org_id_str.clone(),
            }));
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
        return Err(Status::from(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )));
    }

    let req = request.into_inner();
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(Status::from(CarbideError::InvalidArgument(
            "organization_id is required".to_string(),
        )));
    }
    let org_id: TenantOrganizationId = org_id.parse().map_err(|e: InvalidTenantOrg| {
        Status::from(CarbideError::InvalidArgument(e.to_string()))
    })?;
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
        return Err(Status::from(CarbideError::NotFoundError {
            kind: "tenant_identity_config",
            id: org_id_str,
        }));
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
        return Err(Status::from(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config before setting identity configuration"
                .to_string(),
        )));
    }

    let req = request.into_inner();
    let config: IdentityConfig = req
        .config
        .ok_or_else(|| {
            Status::from(CarbideError::InvalidArgument(
                "IdentityConfig is required".to_string(),
            ))
        })
        .and_then(|c| {
            IdentityConfig::try_from_proto(
                c,
                &model::tenant::IdentityConfigValidationBounds::from(
                    api.runtime_config.machine_identity.clone(),
                ),
            )
            .map_err(|e: IdentityConfigValidationError| {
                Status::from(CarbideError::InvalidArgument(e.0))
            })
        })?;
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(Status::from(CarbideError::InvalidArgument(
            "organization_id is required".to_string(),
        )));
    }
    let org_id: TenantOrganizationId = org_id.parse().map_err(|e: InvalidTenantOrg| {
        Status::from(CarbideError::InvalidArgument(e.to_string()))
    })?;
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
        return Err(Status::from(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )));
    }

    let req = request.into_inner();
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(Status::from(CarbideError::InvalidArgument(
            "organization_id is required".to_string(),
        )));
    }
    let org_id: TenantOrganizationId = org_id.parse().map_err(|e: InvalidTenantOrg| {
        Status::from(CarbideError::InvalidArgument(e.to_string()))
    })?;
    let org_id_str = org_id.as_str().to_string();

    let cfg = api
        .database_connection
        .with_txn(|txn| Box::pin(async move { tenant_identity_config::find(&org_id, txn).await }))
        .await??;

    let cfg = match cfg {
        Some(c) => c,
        None => {
            return Err(Status::from(CarbideError::NotFoundError {
                kind: "tenant_identity_config",
                id: org_id_str.clone(),
            }));
        }
    };

    let (token_endpoint, auth_method) = match (&cfg.token_endpoint, &cfg.auth_method) {
        (Some(te), Some(am)) => (te.clone(), am.as_str()),
        _ => {
            return Err(Status::from(CarbideError::NotFoundError {
                kind: "token_delegation",
                id: org_id_str.clone(),
            }));
        }
    };

    let stored: Option<ClientSecretBasic> = cfg
        .encrypted_auth_method_config
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok());

    let auth_method_config = if auth_method == "none" {
        None // Omit oneof from response for cleaner JSON
    } else {
        Some(
            stored_to_response_auth_config(auth_method, stored.as_ref()).ok_or_else(|| {
                Status::from(CarbideError::internal(
                    "Stored auth_method_config does not match auth_method".to_string(),
                ))
            })?,
        )
    };

    let created_at = cfg.token_delegation_created_at.map(Timestamp::from);

    Ok(Response::new(TokenDelegationResponse {
        organization_id: org_id_str,
        token_endpoint,
        auth_method_config,
        subject_token_audience: cfg.subject_token_audience.unwrap_or_default(),
        created_at,
        updated_at: Some(Timestamp::from(cfg.updated_at)),
    }))
}

pub(crate) async fn set_token_delegation(
    api: &Api,
    request: Request<TokenDelegationRequest>,
) -> Result<Response<TokenDelegationResponse>, Status> {
    log_request_data_redacted(format_token_delegation_request_redacted(request.get_ref()));

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::from(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )));
    }

    let req = request.into_inner();
    let config: TokenDelegation = req
        .config
        .as_ref()
        .ok_or_else(|| {
            Status::from(CarbideError::InvalidArgument(
                "TokenDelegation config is required".to_string(),
            ))
        })
        .and_then(|c| {
            TokenDelegation::try_from(c.clone()).map_err(|e: TokenDelegationValidationError| {
                Status::from(CarbideError::InvalidArgument(e.0))
            })
        })?;
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(Status::from(CarbideError::InvalidArgument(
            "organization_id is required".to_string(),
        )));
    }
    let org_id: TenantOrganizationId = org_id.parse().map_err(|e: InvalidTenantOrg| {
        Status::from(CarbideError::InvalidArgument(e.to_string()))
    })?;
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
                let cfg =
                    tenant_identity_config::set_token_delegation(&org_id, &config, txn).await?;
                tenant::increment_version(org_id.as_str(), txn).await?;
                Ok(cfg)
            })
        })
        .await??;

    let auth_method = cfg.auth_method.as_ref().map(|m| m.as_str()).unwrap_or("");
    let stored: Option<ClientSecretBasic> = cfg
        .encrypted_auth_method_config
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok());
    let auth_method_config = if auth_method == "none" {
        None // Omit oneof from response for cleaner JSON
    } else {
        Some(
            stored_to_response_auth_config(auth_method, stored.as_ref()).ok_or_else(|| {
                Status::from(CarbideError::internal(
                    "Stored auth_method_config does not match auth_method".to_string(),
                ))
            })?,
        )
    };

    let created_at = cfg.token_delegation_created_at.map(Timestamp::from);

    Ok(Response::new(TokenDelegationResponse {
        organization_id: org_id_str,
        token_endpoint: cfg.token_endpoint.unwrap_or_default(),
        auth_method_config,
        subject_token_audience: cfg.subject_token_audience.unwrap_or_default(),
        created_at,
        updated_at: Some(Timestamp::from(cfg.updated_at)),
    }))
}

pub(crate) async fn delete_token_delegation(
    api: &Api,
    request: Request<GetTokenDelegationRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(Status::from(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config".to_string(),
        )));
    }

    let req = request.into_inner();
    let org_id = req.organization_id.trim();
    if org_id.is_empty() {
        return Err(Status::from(CarbideError::InvalidArgument(
            "organization_id is required".to_string(),
        )));
    }
    let org_id: TenantOrganizationId = org_id.parse().map_err(|e: InvalidTenantOrg| {
        Status::from(CarbideError::InvalidArgument(e.to_string()))
    })?;

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

#[cfg(test)]
mod tests {
    use ::rpc::forge::token_delegation_response::AuthMethodConfig;

    use super::*;

    #[test]
    fn test_truncate_hash_for_display() {
        assert_eq!(
            truncate_hash_for_display("sha256:abcd1234567890abcdef"),
            "sha256:abcd1234.."
        );
        assert_eq!(truncate_hash_for_display("sha512:xyz"), "sha512:xyz..");
        assert_eq!(truncate_hash_for_display("no-colon"), "no-colon");
    }

    #[test]
    fn test_stored_to_response_auth_config_none() {
        // For "none", we omit the oneof from response; stored_to_response_auth_config returns None
        assert!(stored_to_response_auth_config("none", None).is_none());
    }

    #[test]
    fn test_stored_to_response_auth_config_client_secret_basic() {
        let stored = super::ClientSecretBasic {
            client_id: "my-client".to_string(),
            client_secret: "secret".to_string(),
        };
        let out = stored_to_response_auth_config("client_secret_basic", Some(&stored)).unwrap();
        let AuthMethodConfig::ClientSecretBasic(c) = &out;
        assert_eq!(c.client_id, "my-client");
        assert!(c.client_secret_hash.starts_with("sha256:"));
        assert!(c.client_secret_hash.ends_with(".."));
    }

    #[test]
    fn test_stored_to_response_auth_config_omits_cleartext() {
        let stored = super::ClientSecretBasic {
            client_id: "my-client".to_string(),
            client_secret: "secret".to_string(),
        };
        let out = stored_to_response_auth_config("client_secret_basic", Some(&stored)).unwrap();
        let AuthMethodConfig::ClientSecretBasic(c) = &out;
        // ClientSecretBasicResponse has no client_secret field; only client_secret_hash
        assert_eq!(c.client_id, "my-client");
        assert!(!c.client_secret_hash.is_empty());
    }

    #[test]
    fn test_stored_to_response_auth_config_unknown_returns_none() {
        let stored = super::ClientSecretBasic {
            client_id: "x".to_string(),
            client_secret: "secret".to_string(),
        };
        assert!(stored_to_response_auth_config("unknown_method", Some(&stored)).is_none());
    }

    #[test]
    fn test_stored_to_response_auth_config_client_secret_empty_returns_none() {
        // When client_secret is empty (e.g. legacy data), we cannot compute hash for display
        let stored = super::ClientSecretBasic {
            client_id: "x".to_string(),
            client_secret: String::new(),
        };
        assert!(stored_to_response_auth_config("client_secret_basic", Some(&stored)).is_none());
    }
}
