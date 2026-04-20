/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

//! Tenant identity config for SPIFFE JWT-SVID machine identity.
//! Stores per-org identity config and signing keys in `tenant_identity_config` table.

use carbide_uuid::machine::MachineId;
use model::tenant::{
    EncryptedTokenDelegationAuthConfig, IdentityConfig, SigningKeyMaterial, TenantIdentityConfig,
    TenantOrganizationId, TokenDelegation, TokenDelegationAuthMethod,
};
use sqlx::PgConnection;
use sqlx::types::Json;

use crate::{DatabaseError, DatabaseResult};

/// Set identity config for an org.
/// When creating new or rotating key, caller must provide `key_material` (generated key pair, encrypted private key, key_id = sha256(public_key)).
/// Caller must ensure tenant exists and global machine-identity is enabled.
pub async fn set(
    org_id: &TenantOrganizationId,
    config: &IdentityConfig,
    key_material: Option<SigningKeyMaterial>,
    txn: &mut PgConnection,
) -> DatabaseResult<TenantIdentityConfig> {
    let allowed: Vec<String> = if config.allowed_audiences.is_empty() {
        vec![config.default_audience.clone()]
    } else {
        config.allowed_audiences.clone()
    };

    let token_ttl_i32: i32 = config
        .token_ttl_sec
        .try_into()
        .map_err(|_| DatabaseError::InvalidArgument("token_ttl out of range".into()))?;

    // Bounds validation is done by the handler using site config (token_ttl_min_sec, token_ttl_max_sec).

    let existing = find(org_id, &mut *txn).await?;
    let (key_id, encrypted_key, public_key) = match (&existing, config.rotate_key, key_material) {
        (None, _, None) | (_, true, None) => {
            return Err(DatabaseError::InvalidArgument(
                "key_material is required when creating or rotating signing key".into(),
            ));
        }
        (_, _, Some(km)) => (km.key_id, km.encrypted_signing_key, km.signing_key_public),
        (Some(ex), false, None) => (
            ex.key_id.clone(),
            ex.encrypted_signing_key.clone(),
            ex.signing_key_public.clone(),
        ),
    };

    let query = r#"
        INSERT INTO tenant_identity_config (
            organization_id, issuer, default_audience, allowed_audiences,
            token_ttl_sec, subject_prefix, enabled, created_at, updated_at,
            encrypted_signing_key, signing_key_public, key_id, algorithm, encryption_key_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), $8, $9, $10, $11, $12)
        ON CONFLICT (organization_id) DO UPDATE SET
            issuer = EXCLUDED.issuer,
            default_audience = EXCLUDED.default_audience,
            allowed_audiences = EXCLUDED.allowed_audiences,
            token_ttl_sec = EXCLUDED.token_ttl_sec,
            subject_prefix = EXCLUDED.subject_prefix,
            enabled = EXCLUDED.enabled,
            updated_at = NOW(),
            encrypted_signing_key = EXCLUDED.encrypted_signing_key,
            signing_key_public = EXCLUDED.signing_key_public,
            key_id = EXCLUDED.key_id,
            algorithm = EXCLUDED.algorithm,
            encryption_key_id = EXCLUDED.encryption_key_id
        RETURNING organization_id,
            issuer::text AS issuer,
            default_audience::text AS default_audience,
            allowed_audiences,
            token_ttl_sec,
            subject_prefix::text AS subject_prefix,
            enabled,
            created_at,
            updated_at,
            encrypted_signing_key,
            signing_key_public::text AS signing_key_public,
            key_id::text AS key_id,
            algorithm,
            encryption_key_id::text AS encryption_key_id,
            token_endpoint::text AS token_endpoint,
            auth_method,
            encrypted_auth_method_config,
            subject_token_audience::text AS subject_token_audience,
            token_delegation_created_at
    "#;

    sqlx::query_as(query)
        .bind(org_id.as_str())
        .bind(&config.issuer)
        .bind(&config.default_audience)
        .bind(Json(allowed))
        .bind(token_ttl_i32)
        .bind(&config.subject_prefix)
        .bind(config.enabled)
        .bind(&encrypted_key)
        .bind(&public_key)
        .bind(&key_id)
        .bind(config.algorithm)
        .bind(&config.encryption_key_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find(
    org_id: &TenantOrganizationId,
    txn: &mut PgConnection,
) -> DatabaseResult<Option<TenantIdentityConfig>> {
    let query = "SELECT organization_id, \
        issuer::text AS issuer, default_audience::text AS default_audience, allowed_audiences, token_ttl_sec, \
        subject_prefix::text AS subject_prefix, enabled, created_at, updated_at, encrypted_signing_key, \
        signing_key_public::text AS signing_key_public, key_id::text AS key_id, algorithm, \
        encryption_key_id::text AS encryption_key_id, token_endpoint::text AS token_endpoint, auth_method, \
        encrypted_auth_method_config, subject_token_audience::text AS subject_token_audience, \
        token_delegation_created_at FROM tenant_identity_config WHERE organization_id = $1";
    sqlx::query_as(query)
        .bind(org_id.as_str())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_by_machine_id(
    txn: &mut PgConnection,
    machine_id: &MachineId,
) -> DatabaseResult<TenantIdentityConfig> {
    const QUERY: &str = r#"
SELECT tic.organization_id,
    tic.issuer::text AS issuer,
    tic.default_audience::text AS default_audience,
    tic.allowed_audiences,
    tic.token_ttl_sec,
    tic.subject_prefix::text AS subject_prefix,
    tic.enabled,
    tic.created_at,
    tic.updated_at,
    tic.encrypted_signing_key,
    tic.signing_key_public::text AS signing_key_public,
    tic.key_id::text AS key_id,
    tic.algorithm,
    tic.encryption_key_id::text AS encryption_key_id,
    tic.token_endpoint::text AS token_endpoint,
    tic.auth_method,
    tic.encrypted_auth_method_config,
    tic.subject_token_audience::text AS subject_token_audience,
    tic.token_delegation_created_at
FROM tenant_identity_config tic
INNER JOIN instances i ON tic.organization_id = i.tenant_org
WHERE i.machine_id = $1 AND i.deleted IS NULL AND tic.enabled = true
"#;
    let row = sqlx::query_as::<_, TenantIdentityConfig>(QUERY)
        .bind(machine_id)
        .fetch_optional(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))?;
    let Some(cfg) = row else {
        return Err(DatabaseError::NotFoundError {
            kind: "machine_identity",
            id: machine_id.to_string(),
        });
    };
    Ok(cfg)
}

/// Set token delegation for an org. Identity config must exist first.
/// `encrypted_auth_method_config` must be standard base64 of JSON envelope v1 from `key_encryption::encrypt`
/// over the UTF-8 JSON produced by [`TokenDelegation::to_db_format`].
pub async fn set_token_delegation(
    org_id: &TenantOrganizationId,
    config: &TokenDelegation,
    auth_method: TokenDelegationAuthMethod,
    encrypted_auth_method_config: &EncryptedTokenDelegationAuthConfig,
    txn: &mut PgConnection,
) -> DatabaseResult<TenantIdentityConfig> {
    let query = r#"
        UPDATE tenant_identity_config
        SET token_endpoint = $2, auth_method = $3, encrypted_auth_method_config = $4,
            subject_token_audience = $5, updated_at = NOW(),
            token_delegation_created_at = COALESCE(token_delegation_created_at, NOW())
        WHERE organization_id = $1
        RETURNING organization_id,
            issuer::text AS issuer,
            default_audience::text AS default_audience,
            allowed_audiences,
            token_ttl_sec,
            subject_prefix::text AS subject_prefix,
            enabled,
            created_at,
            updated_at,
            encrypted_signing_key,
            signing_key_public::text AS signing_key_public,
            key_id::text AS key_id,
            algorithm,
            encryption_key_id::text AS encryption_key_id,
            token_endpoint::text AS token_endpoint,
            auth_method,
            encrypted_auth_method_config,
            subject_token_audience::text AS subject_token_audience,
            token_delegation_created_at
    "#;
    let row = sqlx::query_as::<_, TenantIdentityConfig>(query)
        .bind(org_id.as_str())
        .bind(&config.token_endpoint)
        .bind(auth_method)
        .bind(encrypted_auth_method_config.as_str())
        .bind(Some(config.subject_token_audience.as_str()))
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    row.ok_or_else(|| DatabaseError::NotFoundError {
        kind: "tenant_identity_config",
        id: org_id.as_str().to_string(),
    })
}

/// Delete identity config for an org (removes the entire row).
pub async fn delete(org_id: &TenantOrganizationId, txn: &mut PgConnection) -> DatabaseResult<bool> {
    let result = sqlx::query("DELETE FROM tenant_identity_config WHERE organization_id = $1")
        .bind(org_id.as_str())
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query("DELETE tenant_identity_config", e))?;
    Ok(result.rows_affected() > 0)
}

/// Clear token delegation for an org.
pub async fn delete_token_delegation(
    org_id: &TenantOrganizationId,
    txn: &mut PgConnection,
) -> DatabaseResult<Option<TenantIdentityConfig>> {
    let query = r#"
        UPDATE tenant_identity_config
        SET token_endpoint = NULL, auth_method = NULL, encrypted_auth_method_config = NULL,
            subject_token_audience = NULL, token_delegation_created_at = NULL, updated_at = NOW()
        WHERE organization_id = $1
        RETURNING organization_id,
            issuer::text AS issuer,
            default_audience::text AS default_audience,
            allowed_audiences,
            token_ttl_sec,
            subject_prefix::text AS subject_prefix,
            enabled,
            created_at,
            updated_at,
            encrypted_signing_key,
            signing_key_public::text AS signing_key_public,
            key_id::text AS key_id,
            algorithm,
            encryption_key_id::text AS encryption_key_id,
            token_endpoint::text AS token_endpoint,
            auth_method,
            encrypted_auth_method_config,
            subject_token_audience::text AS subject_token_audience,
            token_delegation_created_at
    "#;
    sqlx::query_as(query)
        .bind(org_id.as_str())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use forge_secrets::key_encryption;
    use model::metadata::Metadata;
    use model::tenant::identity_config::SigningAlgorithm;
    use model::tenant::{
        IdentityConfig, TokenDelegation, TokenDelegationAuthMethod, TokenDelegationAuthMethodConfig,
    };

    use super::*;
    use crate::tenant;

    fn test_org_id() -> TenantOrganizationId {
        "IdentityConfigTestOrg".parse().unwrap()
    }

    async fn ensure_tenant(txn: &mut PgConnection, org_id: &TenantOrganizationId) {
        if tenant::find(org_id.as_str(), false, txn)
            .await
            .unwrap()
            .is_none()
        {
            tenant::create_and_persist(
                org_id.as_str().to_string(),
                Metadata {
                    name: "Test Org".to_string(),
                    description: "".to_string(),
                    labels: HashMap::new(),
                },
                None,
                txn,
            )
            .await
            .unwrap();
        }
    }

    #[crate::sqlx_test]
    async fn test_tenant_identity_config_set_find_delete(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        let org_id = test_org_id();
        ensure_tenant(&mut txn, &org_id).await;

        let config = IdentityConfig {
            issuer: "https://issuer.example.com".parse().unwrap(),
            default_audience: "api".to_string(),
            allowed_audiences: vec!["api".to_string(), "audience2".to_string()],
            token_ttl_sec: 3600,
            subject_prefix: "spiffe://issuer.example.com/org-x".to_string(),
            enabled: true,
            rotate_key: false,
            algorithm: SigningAlgorithm::Es256,
            encryption_key_id: "test-master".parse().unwrap(),
        };

        let key_material = SigningKeyMaterial {
            key_id: "test-key-id".parse().unwrap(),
            encrypted_signing_key: "PLACEHOLDER_ENCRYPTED_KEY".parse().unwrap(),
            signing_key_public: "PLACEHOLDER_PUBLIC_KEY".parse().unwrap(),
        };
        let cfg = set(&org_id, &config, Some(key_material), &mut txn)
            .await
            .unwrap();
        assert_eq!(cfg.issuer.as_str(), "https://issuer.example.com");
        assert_eq!(cfg.default_audience, "api");
        assert_eq!(cfg.allowed_audiences.0, ["api", "audience2"]);
        assert_eq!(cfg.token_ttl_sec, 3600);
        assert_eq!(cfg.subject_prefix, "spiffe://issuer.example.com/org-x");
        assert!(cfg.enabled);
        assert_eq!(cfg.algorithm, SigningAlgorithm::Es256);
        assert_eq!(cfg.encryption_key_id.as_str(), "test-master");

        let found = find(&org_id, &mut txn).await.unwrap().unwrap();
        assert_eq!(found.issuer, cfg.issuer);
        assert_eq!(found.default_audience, cfg.default_audience);
        assert_eq!(found.allowed_audiences.0, cfg.allowed_audiences.0);
        assert_eq!(found.token_ttl_sec, cfg.token_ttl_sec);
        assert_eq!(found.subject_prefix, cfg.subject_prefix);
        assert_eq!(found.enabled, cfg.enabled);
        assert_eq!(found.algorithm, cfg.algorithm);
        assert_eq!(found.encryption_key_id, cfg.encryption_key_id);
        assert_eq!(found.key_id, cfg.key_id);

        let deleted = delete(&org_id, &mut txn).await.unwrap();
        assert!(deleted);

        let not_found = find(&org_id, &mut txn).await.unwrap();
        assert!(not_found.is_none());
    }

    #[crate::sqlx_test]
    async fn test_token_delegation_set_get_delete(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        let org_id = test_org_id();
        ensure_tenant(&mut txn, &org_id).await;

        let config = IdentityConfig {
            issuer: "https://issuer.example.com".parse().unwrap(),
            default_audience: "api".to_string(),
            allowed_audiences: vec!["api".to_string()],
            token_ttl_sec: 3600,
            subject_prefix: "spiffe://issuer.example.com".to_string(),
            enabled: true,
            rotate_key: false,
            algorithm: SigningAlgorithm::Es256,
            encryption_key_id: "test-master".parse().unwrap(),
        };
        let key_material = SigningKeyMaterial {
            key_id: "test-key-id".parse().unwrap(),
            encrypted_signing_key: "PLACEHOLDER_ENCRYPTED_KEY".parse().unwrap(),
            signing_key_public: "PLACEHOLDER_PUBLIC_KEY".parse().unwrap(),
        };
        set(&org_id, &config, Some(key_material), &mut txn)
            .await
            .unwrap();

        let token_delegation = TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: TokenDelegationAuthMethodConfig::ClientSecretBasic {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
            },
        };
        let (auth_method, plaintext_json) = token_delegation.to_db_format();
        let enc_key: key_encryption::Aes256Key = [0u8; 32];
        let enc =
            key_encryption::encrypt(plaintext_json.as_bytes(), &enc_key, "test-master").unwrap();
        let enc: EncryptedTokenDelegationAuthConfig = enc.try_into().unwrap();
        let cfg = set_token_delegation(&org_id, &token_delegation, auth_method, &enc, &mut txn)
            .await
            .unwrap();
        assert_eq!(
            cfg.token_endpoint.as_deref(),
            Some("https://auth.example.com/token")
        );
        assert_eq!(
            cfg.auth_method,
            Some(TokenDelegationAuthMethod::ClientSecretBasic)
        );
        assert_eq!(
            cfg.subject_token_audience.as_deref(),
            Some("https://api.example.com")
        );

        let cleared = delete_token_delegation(&org_id, &mut txn)
            .await
            .unwrap()
            .unwrap();
        assert!(cleared.token_endpoint.is_none());
        assert!(cleared.auth_method.is_none());
    }
}
