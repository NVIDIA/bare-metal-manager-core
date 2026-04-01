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

use model::tenant::{IdentityConfig, TenantIdentityConfig, TenantOrganizationId, TokenDelegation};
use sqlx::PgConnection;
use sqlx::types::Json;

use crate::{DatabaseError, DatabaseResult};

/// Set identity config for an org. On first create, generates a placeholder key.
/// Caller must ensure tenant exists and global machine-identity is enabled.
pub async fn set(
    org_id: &TenantOrganizationId,
    config: &IdentityConfig,
    txn: &mut PgConnection,
) -> DatabaseResult<TenantIdentityConfig> {
    let allowed: Vec<String> = if config.allowed_audiences.is_empty() {
        vec![config.default_audience.clone()]
    } else {
        if !config
            .allowed_audiences
            .iter()
            .any(|a| a == &config.default_audience)
        {
            return Err(DatabaseError::InvalidArgument(
                "default_audience must be in allowed_audiences".into(),
            ));
        }
        config.allowed_audiences.clone()
    };

    let token_ttl_i32: i32 = config
        .token_ttl_sec
        .try_into()
        .map_err(|_| DatabaseError::InvalidArgument("token_ttl out of range".into()))?;

    // Bounds validation is done by the handler using site config (token_ttl_min_sec, token_ttl_max_sec).

    let existing = find(org_id, &mut *txn).await?;
    let (key_id, encrypted_key, public_key) = match (&existing, config.rotate_key) {
        (None, _) | (_, true) => {
            // Generate new key pair (placeholder: use deterministic placeholder for rough impl)
            let key_id = uuid::Uuid::new_v4().to_string();
            let encrypted_key = "PLACEHOLDER_ENCRYPTED_KEY".to_string();
            let public_key = "PLACEHOLDER_PUBLIC_KEY".to_string();
            (key_id, encrypted_key, public_key)
        }
        (Some(ex), false) => (
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
        RETURNING organization_id, issuer, default_audience, allowed_audiences, token_ttl_sec, subject_prefix,
            enabled, created_at, updated_at, encrypted_signing_key, signing_key_public, key_id,
            algorithm, encryption_key_id, token_endpoint, auth_method, encrypted_auth_method_config,
            subject_token_audience, token_delegation_created_at
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
        .bind(&config.algorithm)
        .bind(&config.encryption_key_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find(
    org_id: &TenantOrganizationId,
    txn: &mut PgConnection,
) -> DatabaseResult<Option<TenantIdentityConfig>> {
    let query = "SELECT organization_id, issuer, default_audience, allowed_audiences, token_ttl_sec, subject_prefix, \
        enabled, created_at, updated_at, encrypted_signing_key, signing_key_public, key_id, algorithm, \
        encryption_key_id, token_endpoint, auth_method, encrypted_auth_method_config, subject_token_audience, \
        token_delegation_created_at FROM tenant_identity_config WHERE organization_id = $1";
    sqlx::query_as(query)
        .bind(org_id.as_str())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Set token delegation for an org. Identity config must exist first.
pub async fn set_token_delegation(
    org_id: &TenantOrganizationId,
    config: &TokenDelegation,
    txn: &mut PgConnection,
) -> DatabaseResult<TenantIdentityConfig> {
    let (auth_method, config_json) = config.to_db_format();
    let query = r#"
        UPDATE tenant_identity_config
        SET token_endpoint = $2, auth_method = $3, encrypted_auth_method_config = $4,
            subject_token_audience = $5, updated_at = NOW(),
            token_delegation_created_at = COALESCE(token_delegation_created_at, NOW())
        WHERE organization_id = $1
        RETURNING organization_id, issuer, default_audience, allowed_audiences, token_ttl_sec, subject_prefix,
            enabled, created_at, updated_at, encrypted_signing_key, signing_key_public, key_id,
            algorithm, encryption_key_id, token_endpoint, auth_method, encrypted_auth_method_config,
            subject_token_audience, token_delegation_created_at
    "#;
    let row = sqlx::query_as::<_, TenantIdentityConfig>(query)
        .bind(org_id.as_str())
        .bind(&config.token_endpoint)
        .bind(auth_method)
        .bind(&config_json)
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
        RETURNING organization_id, issuer, default_audience, allowed_audiences, token_ttl_sec, subject_prefix,
            enabled, created_at, updated_at, encrypted_signing_key, signing_key_public, key_id,
            algorithm, encryption_key_id, token_endpoint, auth_method, encrypted_auth_method_config,
            subject_token_audience, token_delegation_created_at
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

    use model::metadata::Metadata;
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
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec!["api".to_string(), "audience2".to_string()],
            token_ttl_sec: 3600,
            subject_prefix: "spiffe://example.com/org-x".to_string(),
            enabled: true,
            rotate_key: false,
            algorithm: "ES256".to_string(),
            encryption_key_id: "test-master".to_string(),
        };

        let cfg = set(&org_id, &config, &mut txn).await.unwrap();
        assert_eq!(cfg.issuer, "https://issuer.example.com");
        assert_eq!(cfg.default_audience, "api");
        assert_eq!(cfg.allowed_audiences.0, ["api", "audience2"]);
        assert_eq!(cfg.token_ttl_sec, 3600);
        assert_eq!(cfg.subject_prefix, "spiffe://example.com/org-x");
        assert!(cfg.enabled);
        assert_eq!(cfg.algorithm, "ES256");
        assert_eq!(cfg.encryption_key_id, "test-master");
        assert!(!cfg.key_id.is_empty());

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
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec!["api".to_string()],
            token_ttl_sec: 3600,
            subject_prefix: "example.com".to_string(),
            enabled: true,
            rotate_key: false,
            algorithm: "ES256".to_string(),
            encryption_key_id: "test-master".to_string(),
        };
        set(&org_id, &config, &mut txn).await.unwrap();

        let token_delegation = TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: TokenDelegationAuthMethodConfig::ClientSecretBasic {
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
            },
        };
        let cfg = set_token_delegation(&org_id, &token_delegation, &mut txn)
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
