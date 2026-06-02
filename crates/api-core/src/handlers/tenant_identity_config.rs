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
//! JWKS and OpenID discovery RPCs live in [`machine_identity`](super::machine_identity).
//! (Proto message `forge.TenantIdentityConfig` is aliased as `ProtoTenantIdentityConfig` to avoid
//! clashing with the database row type [`TenantIdentityConfig`](TenantIdentityConfig).)

use ::rpc::Timestamp;
use ::rpc::forge::{
    GetTenantIdentityConfigRequest, GetTokenDelegationRequest, SetTenantIdentityConfigRequest,
    TenantIdentityConfig as ProtoTenantIdentityConfig, TenantIdentityConfigResponse,
    TenantIdentitySigningKey, TokenDelegationRequest, TokenDelegationResponse, token_delegation,
};
use db::{WithTransaction, tenant, tenant_identity_config};
use forge_secrets::credentials::CredentialReader;
use forge_secrets::key_encryption;
use model::tenant::identity_config::TenantIdentityCurrentSigningKeySlot;
use model::tenant::{
    EncryptedSigningPrivateKey, EncryptedTokenDelegationAuthConfig, IdentityConfigValidationBounds,
    IdentityConfigValidationError, InvalidNonEmptyStr, InvalidTenantOrg, KeyId, SigningKeyMaterial,
    SigningPublicKeyPem, TenantIdentityConfig, TenantIdentityConfigDecrypted, TenantOrganizationId,
    TokenDelegation, TokenDelegationValidationBounds, TokenDelegationValidationError,
};
use rpc::model::tenant::{identity_config_try_from_proto, validate_identity_overlap_for_rotation};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data, log_request_data_redacted};
use crate::handlers::machine_identity::require_machine_identity_site_enabled;
use crate::machine_identity::{
    decrypt_token_delegation_encrypted_blob, machine_identity_encryption_secret,
};

/// Decrypts DB ciphertext into [`TenantIdentityConfigDecrypted`]: `row` keeps envelope in
/// `encrypted_auth_method_config`; plaintext JSON is only in `auth_method_config`.
async fn tenant_identity_with_decrypted_token_delegation(
    credentials: &dyn CredentialReader,
    cfg: TenantIdentityConfig,
) -> Result<TenantIdentityConfigDecrypted, Status> {
    let auth_method_config = decrypt_token_delegation_encrypted_blob(
        credentials,
        &cfg.encryption_key_id,
        cfg.encrypted_auth_method_config.as_ref(),
    )
    .await
    .inspect_err(|e| {
        tracing::error!(
            org_id = %cfg.organization_id.as_str(),
            message = %e.message(),
            "token delegation auth config decrypt failed"
        );
    })?;
    Ok(TenantIdentityConfigDecrypted {
        row: cfg,
        auth_method_config,
    })
}

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

// --- Tenant identity configuration handlers ---

/// Builds [`TenantIdentitySigningKey`] entries from slotted public JSON; exactly one has
/// `current_signer == true`.
fn tenant_identity_signing_keys_response(
    cfg: &TenantIdentityConfig,
) -> Result<Vec<TenantIdentitySigningKey>, Status> {
    let mut keys = Vec::new();
    if let Some(ref doc) = cfg.signing_key_public_1 {
        let current_signer =
            cfg.current_signing_key_slot == TenantIdentityCurrentSigningKeySlot::SigningKey1;
        keys.push(TenantIdentitySigningKey {
            kid: doc.0.kid().to_string(),
            alg: doc.0.alg().to_string(),
            current_signer,
            expire_at: if current_signer {
                None
            } else {
                cfg.non_active_slot_expires_at.map(Timestamp::from)
            },
        });
    }
    if let Some(ref doc) = cfg.signing_key_public_2 {
        let current_signer =
            cfg.current_signing_key_slot == TenantIdentityCurrentSigningKeySlot::SigningKey2;
        keys.push(TenantIdentitySigningKey {
            kid: doc.0.kid().to_string(),
            alg: doc.0.alg().to_string(),
            current_signer,
            expire_at: if current_signer {
                None
            } else {
                cfg.non_active_slot_expires_at.map(Timestamp::from)
            },
        });
    }
    let n_current = keys.iter().filter(|k| k.current_signer).count();
    if keys.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "tenant identity config has no published signing keys".to_string(),
        )
        .into());
    }
    if n_current != 1 {
        return Err(CarbideError::InvalidArgument(format!(
            "expected exactly one current signer in signing_keys; found {n_current}"
        ))
        .into());
    }
    Ok(keys)
}

/// `Forge::get_tenant_identity_configuration`: fetches per-org identity config.
pub(crate) async fn get_configuration(
    api: &Api,
    request: Request<GetTenantIdentityConfigRequest>,
) -> Result<Response<TenantIdentityConfigResponse>, Status> {
    log_request_data(&request);

    require_machine_identity_site_enabled(api)?;

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
        .with_txn(|txn| {
            Box::pin(async move {
                tenant_identity_config::gc_expired_non_active_signing_key(&org_id, txn).await?;
                tenant_identity_config::find(&org_id, txn).await
            })
        })
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

    let signing_keys = tenant_identity_signing_keys_response(&cfg)?;

    Ok(Response::new(TenantIdentityConfigResponse {
        organization_id: org_id_str,
        config: Some(ProtoTenantIdentityConfig {
            enabled: cfg.enabled,
            issuer: cfg.issuer.as_str().to_string(),
            default_audience: cfg.default_audience.clone(),
            allowed_audiences: cfg.allowed_audiences.0.clone(),
            token_ttl_sec: cfg.token_ttl_sec as u32,
            subject_prefix: Some(cfg.subject_prefix.clone()),
            rotate_key: cfg.response_rotate_key(),
            signing_key_overlap_sec: None,
        }),
        created_at: Some(Timestamp::from(cfg.created_at)),
        updated_at: Some(Timestamp::from(cfg.updated_at)),
        signing_keys,
    }))
}

/// `Forge::delete_tenant_identity_configuration`: removes per-org identity config.
pub(crate) async fn delete_configuration(
    api: &Api,
    request: Request<GetTenantIdentityConfigRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    require_machine_identity_site_enabled(api)?;

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

/// `Forge::set_tenant_identity_configuration`: upserts per-org identity config into tenant_identity_config.
/// Requires auth. Tenant must exist. Key generation is placeholder until credential-backed key provisioning.
pub(crate) async fn set_configuration(
    api: &Api,
    request: Request<SetTenantIdentityConfigRequest>,
) -> Result<Response<TenantIdentityConfigResponse>, Status> {
    log_request_data(&request);

    if !api.runtime_config.machine_identity.enabled {
        return Err(CarbideError::InvalidArgument(
            "Machine identity must be enabled in site config before setting identity configuration"
                .to_string(),
        )
        .into());
    }

    let req = request.into_inner();
    let proto = req.config.ok_or_else(|| {
        CarbideError::InvalidArgument("TenantIdentityConfig is required".to_string())
    })?;
    let config = identity_config_try_from_proto(
        proto,
        &IdentityConfigValidationBounds::from(api.runtime_config.machine_identity.clone()),
    )
    .map_err(|e: IdentityConfigValidationError| CarbideError::InvalidArgument(e.0))?;

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

    let org_id_for_find = org_id.clone();
    let existing = api
        .database_connection
        .with_txn(|txn| {
            Box::pin(async move { tenant_identity_config::find(&org_id_for_find, txn).await })
        })
        .await??;

    validate_identity_overlap_for_rotation(&config)
        .map_err(|e: IdentityConfigValidationError| CarbideError::InvalidArgument(e.0))?;

    let key_material = match (&existing, config.rotate_key) {
        (None, _) | (_, true) => {
            let encryption_key = machine_identity_encryption_secret(
                &api.credential_manager,
                &config.encryption_key_id,
            )
            .await?;
            let (private_pem, public_pem) = key_encryption::generate_es256_key_pair()
                .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?;
            let public_pem_trimmed = public_pem.trim();
            let key_id = KeyId::from_public_key_material(public_pem_trimmed);
            let encrypted_signing_key: EncryptedSigningPrivateKey =
                key_encryption::encrypt(&private_pem, &encryption_key, &config.encryption_key_id)
                    .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?
                    .try_into()
                    .map_err(|e: InvalidNonEmptyStr| {
                        CarbideError::InvalidArgument(e.to_string())
                    })?;
            let signing_key_public: SigningPublicKeyPem = public_pem_trimmed
                .to_string()
                .try_into()
                .map_err(|e: InvalidNonEmptyStr| CarbideError::InvalidArgument(e.to_string()))?;
            Some(SigningKeyMaterial {
                key_id,
                encrypted_signing_key,
                signing_key_public,
            })
        }
        (Some(_), false) => None,
    };

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
                let cfg = tenant_identity_config::set(&org_id, &config, key_material, txn).await?;
                tenant::increment_version(org_id.as_str(), txn).await?;
                Ok(cfg)
            })
        })
        .await??;

    let signing_keys = tenant_identity_signing_keys_response(&cfg)?;

    Ok(Response::new(TenantIdentityConfigResponse {
        organization_id: org_id_str,
        config: Some(ProtoTenantIdentityConfig {
            enabled: cfg.enabled,
            issuer: cfg.issuer.as_str().to_string(),
            default_audience: cfg.default_audience.clone(),
            allowed_audiences: cfg.allowed_audiences.0.clone(),
            token_ttl_sec: cfg.token_ttl_sec as u32,
            subject_prefix: Some(cfg.subject_prefix.clone()),
            rotate_key: cfg.response_rotate_key(),
            signing_key_overlap_sec: None,
        }),
        created_at: Some(Timestamp::from(cfg.created_at)),
        updated_at: Some(Timestamp::from(cfg.updated_at)),
        signing_keys,
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

    let cfg = tenant_identity_with_decrypted_token_delegation(&api.credential_manager, cfg).await?;
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
            ::rpc::model::tenant::token_delegation_try_from_proto(
                c.clone(),
                &TokenDelegationValidationBounds::from(api.runtime_config.machine_identity.clone()),
            )
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

    let org_id_for_find = org_id.clone();
    let id_row = api
        .database_connection
        .with_txn(|txn| {
            Box::pin(async move { tenant_identity_config::find(&org_id_for_find, txn).await })
        })
        .await??
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "tenant_identity_config",
            id: org_id.as_str().to_string(),
        })?;

    let (auth_method, plaintext_json) = config.to_db_format();
    let secret =
        machine_identity_encryption_secret(&api.credential_manager, &id_row.encryption_key_id)
            .await?;
    let encrypted_blob: EncryptedTokenDelegationAuthConfig = key_encryption::encrypt(
        plaintext_json.as_bytes(),
        &secret,
        &id_row.encryption_key_id,
    )
    .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?
    .try_into()
    .map_err(|e: InvalidNonEmptyStr| CarbideError::InvalidArgument(e.to_string()))?;

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
                let cfg = tenant_identity_config::set_token_delegation(
                    &org_id,
                    &config,
                    auth_method,
                    &encrypted_blob,
                    txn,
                )
                .await?;
                tenant::increment_version(org_id.as_str(), txn).await?;
                Ok(cfg)
            })
        })
        .await??;

    let cfg = tenant_identity_with_decrypted_token_delegation(&api.credential_manager, cfg).await?;
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
