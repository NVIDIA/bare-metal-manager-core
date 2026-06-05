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
use std::str::FromStr;

use carbide_uuid::UuidConversionError;
use carbide_uuid::instance::InstanceId;
use config_version::ConfigVersion;
use model::tenant::{
    ClientSecretBasic, IdentityConfig, IdentityConfigValidationBounds,
    IdentityConfigValidationError, PublicKey, Tenant, TenantIdentityConfigDecrypted, TenantKeyset,
    TenantKeysetContent, TenantKeysetId, TenantKeysetIdentifier, TenantKeysetSearchFilter,
    TenantPublicKey, TenantPublicKeyValidationRequest, TenantSearchFilter, TokenDelegation,
    TokenDelegationAuthMethod, TokenDelegationAuthMethodConfig, TokenDelegationValidationBounds,
    TokenDelegationValidationError, UpdateTenantKeyset, compute_client_secret_hash,
    truncate_hash_for_display,
};

use crate as rpc;
use crate::errors::RpcDataConversionError;
use crate::forge as rpc_forge;

impl From<rpc::forge::TenantSearchFilter> for TenantSearchFilter {
    fn from(filter: rpc::forge::TenantSearchFilter) -> Self {
        TenantSearchFilter {
            tenant_organization_name: filter.tenant_organization_name,
        }
    }
}

impl From<rpc::forge::TenantKeysetSearchFilter> for TenantKeysetSearchFilter {
    fn from(filter: rpc::forge::TenantKeysetSearchFilter) -> Self {
        TenantKeysetSearchFilter {
            tenant_org_id: filter.tenant_org_id,
        }
    }
}

impl TryFrom<Tenant> for rpc::forge::Tenant {
    type Error = RpcDataConversionError;

    fn try_from(src: Tenant) -> Result<Self, Self::Error> {
        Ok(Self {
            organization_id: src.organization_id.to_string(),
            metadata: Some(src.metadata.into()),
            version: src.version.version_string(),
            routing_profile_type: src.routing_profile_type,
        })
    }
}

impl TryFrom<Tenant> for rpc::forge::CreateTenantResponse {
    type Error = RpcDataConversionError;

    fn try_from(value: Tenant) -> Result<Self, Self::Error> {
        Ok(rpc::forge::CreateTenantResponse {
            tenant: Some(value.try_into()?),
        })
    }
}

impl TryFrom<Tenant> for rpc::forge::FindTenantResponse {
    type Error = RpcDataConversionError;

    fn try_from(value: Tenant) -> Result<Self, Self::Error> {
        Ok(rpc::forge::FindTenantResponse {
            tenant: Some(value.try_into()?),
        })
    }
}

impl TryFrom<Tenant> for rpc::forge::UpdateTenantResponse {
    type Error = RpcDataConversionError;

    fn try_from(value: Tenant) -> Result<Self, Self::Error> {
        Ok(rpc::forge::UpdateTenantResponse {
            tenant: Some(value.try_into()?),
        })
    }
}

impl TryFrom<rpc::forge::Tenant> for Tenant {
    type Error = RpcDataConversionError;

    fn try_from(src: rpc::forge::Tenant) -> Result<Self, Self::Error> {
        let metadata = src
            .metadata
            .ok_or(RpcDataConversionError::MissingArgument("metadata"))?;
        let version = src
            .version
            .parse::<ConfigVersion>()
            .map_err(|_| RpcDataConversionError::InvalidConfigVersion(src.version))?;
        let organization_id = src
            .organization_id
            .clone()
            .try_into()
            .map_err(|_| RpcDataConversionError::InvalidTenantOrg(src.organization_id))?;

        Ok(Self {
            organization_id,
            metadata: metadata.try_into()?,
            routing_profile_type: src.routing_profile_type,
            version,
        })
    }
}

impl From<rpc::forge::TenantPublicKey> for TenantPublicKey {
    fn from(src: rpc::forge::TenantPublicKey) -> Self {
        let public_key: PublicKey = src.public_key.parse().expect("Key parsing can never fail.");
        Self {
            public_key,
            comment: src.comment,
        }
    }
}

impl From<TenantPublicKey> for rpc::forge::TenantPublicKey {
    fn from(src: TenantPublicKey) -> Self {
        Self {
            public_key: src.public_key.to_string(),
            comment: src.comment,
        }
    }
}

impl From<rpc::forge::TenantKeysetContent> for TenantKeysetContent {
    fn from(src: rpc::forge::TenantKeysetContent) -> Self {
        Self {
            public_keys: src.public_keys.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl From<TenantKeysetContent> for rpc::forge::TenantKeysetContent {
    fn from(src: TenantKeysetContent) -> Self {
        Self {
            public_keys: src.public_keys.into_iter().map(|x| x.into()).collect(),
        }
    }
}

impl TryFrom<rpc::forge::TenantKeysetIdentifier> for TenantKeysetIdentifier {
    type Error = RpcDataConversionError;

    fn try_from(src: rpc::forge::TenantKeysetIdentifier) -> Result<Self, Self::Error> {
        Ok(Self {
            organization_id: src
                .organization_id
                .clone()
                .try_into()
                .map_err(|_| RpcDataConversionError::InvalidTenantOrg(src.organization_id))?,
            keyset_id: src.keyset_id,
        })
    }
}

impl From<TenantKeysetIdentifier> for rpc::forge::TenantKeysetIdentifier {
    fn from(src: TenantKeysetIdentifier) -> Self {
        Self {
            organization_id: src.organization_id.to_string(),
            keyset_id: src.keyset_id,
        }
    }
}

impl TryFrom<rpc::forge::TenantKeyset> for TenantKeyset {
    type Error = RpcDataConversionError;

    fn try_from(src: rpc::forge::TenantKeyset) -> Result<Self, Self::Error> {
        let keyset_identifier: TenantKeysetIdentifier = src
            .keyset_identifier
            .ok_or(RpcDataConversionError::MissingArgument(
                "tenant keyset identifier",
            ))?
            .try_into()?;

        let keyset_content: TenantKeysetContent = src
            .keyset_content
            .ok_or(RpcDataConversionError::MissingArgument(
                "tenant keyset content",
            ))?
            .into();
        let version = src.version;

        Ok(Self {
            keyset_content,
            keyset_identifier,
            version,
        })
    }
}

impl From<TenantKeyset> for rpc::forge::TenantKeyset {
    fn from(src: TenantKeyset) -> Self {
        Self {
            keyset_identifier: Some(src.keyset_identifier.into()),
            keyset_content: Some(src.keyset_content.into()),
            version: src.version,
        }
    }
}

impl TryFrom<rpc::forge::CreateTenantKeysetRequest> for TenantKeyset {
    type Error = RpcDataConversionError;

    fn try_from(src: rpc::forge::CreateTenantKeysetRequest) -> Result<Self, Self::Error> {
        let keyset_identifier: TenantKeysetIdentifier = src
            .keyset_identifier
            .ok_or(RpcDataConversionError::MissingArgument(
                "tenant keyset identifier",
            ))?
            .try_into()?;

        let keyset_content: TenantKeysetContent =
            src.keyset_content
                .map(|x| x.into())
                .unwrap_or(TenantKeysetContent {
                    public_keys: vec![],
                });

        let version = src.version;

        Ok(Self {
            keyset_content,
            keyset_identifier,
            version,
        })
    }
}

impl TryFrom<rpc::forge::UpdateTenantKeysetRequest> for UpdateTenantKeyset {
    type Error = RpcDataConversionError;

    fn try_from(src: rpc::forge::UpdateTenantKeysetRequest) -> Result<Self, Self::Error> {
        let keyset_identifier: TenantKeysetIdentifier = src
            .keyset_identifier
            .ok_or(RpcDataConversionError::MissingArgument(
                "tenant keyset identifier",
            ))?
            .try_into()?;

        let keyset_content: TenantKeysetContent =
            src.keyset_content
                .map(|x| x.into())
                .unwrap_or(TenantKeysetContent {
                    public_keys: vec![],
                });

        Ok(Self {
            keyset_content,
            keyset_identifier,
            version: src.version,
            if_version_match: src.if_version_match,
        })
    }
}

/// Converts stored config to response oneof. Truncates hashes for display.
/// Only used when auth_method is ClientSecretBasic; for None the oneof is omitted.
pub fn stored_to_response_auth_config(
    auth_method: TokenDelegationAuthMethod,
    stored: Option<ClientSecretBasic>,
) -> Option<rpc_forge::token_delegation_response::AuthMethodConfig> {
    match auth_method {
        TokenDelegationAuthMethod::ClientSecretBasic => {
            stored.filter(|s| !s.client_secret.is_empty()).map(|s| {
                let hash = compute_client_secret_hash(&s.client_secret);
                rpc_forge::token_delegation_response::AuthMethodConfig::ClientSecretBasic(
                    rpc_forge::ClientSecretBasicResponse {
                        client_id: s.client_id,
                        client_secret_hash: truncate_hash_for_display(&hash),
                    },
                )
            })
        }
        TokenDelegationAuthMethod::None => None,
    }
}

/// Validates gRPC `TokenDelegation` and converts, including optional `token_endpoint` domain allowlist.
/// When the allowlist is non-empty, `token_endpoint` must be an **`http://` or `https://` URL** with a DNS hostname (not an IP literal).
pub fn token_delegation_try_from_proto(
    value: rpc_forge::TokenDelegation,
    bounds: &TokenDelegationValidationBounds,
) -> Result<TokenDelegation, TokenDelegationValidationError> {
    if value.token_endpoint.is_empty() {
        return Err(TokenDelegationValidationError(
            "token_endpoint is required".to_string(),
        ));
    }
    if value.subject_token_audience.is_empty() {
        return Err(TokenDelegationValidationError(
            "subject_token_audience is required".to_string(),
        ));
    }
    if !bounds.token_endpoint_domain_allowlist.is_empty() {
        let host = model::tenant::identity_config_policy::registered_host_for_token_endpoint(
            &value.token_endpoint,
        )
        .map_err(TokenDelegationValidationError)?;
        model::tenant::identity_config_policy::token_endpoint_domain_matches_allowlist(
            &host,
            &bounds.token_endpoint_domain_allowlist,
        )
        .map_err(TokenDelegationValidationError)?;
    }
    let auth_method_config = match value.auth_method_config {
        None => TokenDelegationAuthMethodConfig::None,
        Some(rpc_forge::token_delegation::AuthMethodConfig::ClientSecretBasic(c)) => {
            if c.client_id.is_empty() {
                return Err(TokenDelegationValidationError(
                    "client_id is required".to_string(),
                ));
            }
            if c.client_secret.is_empty() {
                return Err(TokenDelegationValidationError(
                    "client_secret is required".to_string(),
                ));
            }
            TokenDelegationAuthMethodConfig::ClientSecretBasic {
                client_id: c.client_id,
                client_secret: c.client_secret,
            }
        }
    };
    Ok(TokenDelegation {
        token_endpoint: value.token_endpoint,
        subject_token_audience: value.subject_token_audience,
        auth_method_config,
    })
}

impl TryFrom<rpc_forge::TokenDelegation> for TokenDelegation {
    type Error = TokenDelegationValidationError;

    fn try_from(value: rpc_forge::TokenDelegation) -> Result<Self, Self::Error> {
        token_delegation_try_from_proto(value, &TokenDelegationValidationBounds::default())
    }
}

impl TryFrom<TenantIdentityConfigDecrypted> for rpc_forge::TokenDelegationResponse {
    type Error = RpcDataConversionError;

    fn try_from(value: TenantIdentityConfigDecrypted) -> Result<Self, Self::Error> {
        let row = value.row;
        let token_endpoint = row
            .token_endpoint
            .ok_or(RpcDataConversionError::MissingArgument("token_delegation"))?;
        let auth_method = row
            .auth_method
            .ok_or(RpcDataConversionError::MissingArgument("token_delegation"))?;

        let stored: Option<ClientSecretBasic> = value
            .auth_method_config
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok());

        let auth_method_config = match auth_method {
            TokenDelegationAuthMethod::None => None,
            TokenDelegationAuthMethod::ClientSecretBasic => Some(
                stored_to_response_auth_config(auth_method, stored).ok_or_else(|| {
                    RpcDataConversionError::InvalidArgument(
                        "Stored auth_method_config does not match auth_method".to_string(),
                    )
                })?,
            ),
        };

        let created_at = row.token_delegation_created_at.map(rpc::Timestamp::from);

        Ok(rpc_forge::TokenDelegationResponse {
            organization_id: row.organization_id.as_str().to_string(),
            token_endpoint,
            auth_method_config,
            subject_token_audience: row.subject_token_audience.unwrap_or_default(),
            created_at,
            updated_at: Some(rpc::Timestamp::from(row.updated_at)),
        })
    }
}

impl TryFrom<rpc::forge::ValidateTenantPublicKeyRequest> for TenantPublicKeyValidationRequest {
    type Error = UuidConversionError;
    fn try_from(value: rpc::forge::ValidateTenantPublicKeyRequest) -> Result<Self, Self::Error> {
        let instance_id = InstanceId::from_str(&value.instance_id)?;
        Ok(TenantPublicKeyValidationRequest {
            instance_id,
            public_key: value.tenant_public_key,
        })
    }
}

impl From<TenantKeysetId> for rpc::forge::TenantKeysetIdentifier {
    fn from(src: TenantKeysetId) -> Self {
        Self {
            organization_id: src.organization_id,
            keyset_id: src.keyset_id,
        }
    }
}

/// Validates gRPC `TenantIdentityConfig` and converts to `IdentityConfig`, including SPIFFE
/// `subject_prefix` resolution against `issuer` (optional proto field defaults to
/// `spiffe://<trust-domain-from-issuer>`).
pub fn identity_config_try_from_proto(
    value: rpc_forge::TenantIdentityConfig,
    bounds: &IdentityConfigValidationBounds,
) -> Result<IdentityConfig, IdentityConfigValidationError> {
    if value.default_audience.is_empty() {
        return Err(IdentityConfigValidationError(
            "default_audience is required".to_string(),
        ));
    }
    let (issuer, issuer_td) = model::tenant::identity_config::Issuer::parse(&value.issuer)
        .map_err(|e| IdentityConfigValidationError(e.0))?;
    model::tenant::identity_config_policy::trust_domain_matches_allowlist(
        &issuer_td,
        &bounds.trust_domain_allowlist,
    )
    .map_err(IdentityConfigValidationError)?;
    let subject_prefix = model::tenant::identity_config_policy::resolve_subject_prefix(
        &issuer_td,
        value.subject_prefix.as_deref(),
    )
    .map_err(IdentityConfigValidationError)?;
    if value.token_ttl_sec == 0 {
        return Err(IdentityConfigValidationError(format!(
            "token_ttl_sec is required (must be between {} and {} seconds)",
            bounds.token_ttl_min_sec, bounds.token_ttl_max_sec
        )));
    }
    if value.token_ttl_sec < bounds.token_ttl_min_sec
        || value.token_ttl_sec > bounds.token_ttl_max_sec
    {
        return Err(IdentityConfigValidationError(format!(
            "token_ttl_sec must be between {} and {} seconds",
            bounds.token_ttl_min_sec, bounds.token_ttl_max_sec
        )));
    }
    if !value.allowed_audiences.is_empty()
        && !value
            .allowed_audiences
            .iter()
            .any(|a| a == &value.default_audience)
    {
        return Err(IdentityConfigValidationError(
            "default_audience must be in allowed_audiences".to_string(),
        ));
    }
    if let Some(s) = value.signing_key_overlap_sec
        && s > bounds.signing_key_overlap_max_sec
    {
        return Err(IdentityConfigValidationError(format!(
            "signing_key_overlap_sec must not exceed {} seconds",
            bounds.signing_key_overlap_max_sec
        )));
    }
    if !value.rotate_key && value.signing_key_overlap_sec.is_some() {
        return Err(IdentityConfigValidationError(
            "signing_key_overlap_sec may only be set when rotate_key is true".to_string(),
        ));
    }

    let signing_key_overlap_sec = match value.signing_key_overlap_sec {
        None => None,
        Some(s) => Some(i32::try_from(s).map_err(|_| {
            IdentityConfigValidationError("signing_key_overlap_sec out of range".to_string())
        })?),
    };

    Ok(IdentityConfig {
        issuer,
        default_audience: value.default_audience,
        allowed_audiences: value.allowed_audiences,
        token_ttl_sec: value.token_ttl_sec,
        subject_prefix,
        enabled: value.enabled,
        rotate_key: value.rotate_key,
        algorithm: bounds.algorithm,
        encryption_key_id: bounds.encryption_key_id.clone(),
        signing_key_overlap_sec,
    })
}

/// Ensures rotation requests carry overlap at least [`IdentityConfig::token_ttl_sec`] (see docs).
pub fn validate_identity_overlap_for_rotation(
    config: &IdentityConfig,
) -> Result<(), IdentityConfigValidationError> {
    if !config.rotate_key {
        return Ok(());
    }
    let Some(overlap) = config.signing_key_overlap_sec else {
        return Err(IdentityConfigValidationError(
            "signing_key_overlap_sec is required when rotate_key is true".to_string(),
        ));
    };
    let overlap_u32 = u32::try_from(overlap).map_err(|_| {
        IdentityConfigValidationError("signing_key_overlap_sec out of range".to_string())
    })?;
    if overlap_u32 < config.token_ttl_sec {
        return Err(IdentityConfigValidationError(format!(
            "signing_key_overlap_sec ({overlap_u32}) must be at least token_ttl_sec ({}) \
             so JWTs signed with the previous key stay verifiable until they expire",
            config.token_ttl_sec
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use model::tenant::{identity_config, validate_trust_domain_allowlist_patterns};

    use super::*;
    use crate::forge as rpc_forge;
    use crate::forge::token_delegation_response::AuthMethodConfig;

    #[test]
    fn test_stored_to_response_auth_config_none() {
        assert!(stored_to_response_auth_config(TokenDelegationAuthMethod::None, None).is_none());
    }

    #[test]
    fn test_stored_to_response_auth_config_client_secret_basic() {
        let stored = ClientSecretBasic {
            client_id: "my-client".to_string(),
            client_secret: "secret".to_string(),
        };
        let out = stored_to_response_auth_config(
            TokenDelegationAuthMethod::ClientSecretBasic,
            Some(stored),
        )
        .unwrap();
        let AuthMethodConfig::ClientSecretBasic(c) = &out;
        assert_eq!(c.client_id, "my-client");
        assert!(c.client_secret_hash.starts_with("sha256:"));
        assert!(c.client_secret_hash.ends_with(".."));
    }

    #[test]
    fn test_stored_to_response_auth_config_omits_cleartext() {
        let stored = ClientSecretBasic {
            client_id: "my-client".to_string(),
            client_secret: "secret".to_string(),
        };
        let out = stored_to_response_auth_config(
            TokenDelegationAuthMethod::ClientSecretBasic,
            Some(stored),
        )
        .unwrap();
        let AuthMethodConfig::ClientSecretBasic(c) = &out;
        assert_eq!(c.client_id, "my-client");
        assert!(!c.client_secret_hash.is_empty());
    }

    #[test]
    fn test_stored_to_response_auth_config_client_secret_empty_returns_none() {
        let stored = ClientSecretBasic {
            client_id: "x".to_string(),
            client_secret: String::new(),
        };
        assert!(
            stored_to_response_auth_config(
                TokenDelegationAuthMethod::ClientSecretBasic,
                Some(stored),
            )
            .is_none()
        );
    }

    #[test]
    fn token_delegation_to_db_format_client_secret_basic_hash() {
        let config = TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: TokenDelegationAuthMethodConfig::ClientSecretBasic {
                client_id: "client".to_string(),
                client_secret: "secret".to_string(),
            },
        };
        let (auth_method, config_json) = config.to_db_format();
        assert_eq!(auth_method, TokenDelegationAuthMethod::ClientSecretBasic);
        let stored: ClientSecretBasic = serde_json::from_str(&config_json).unwrap();
        assert_eq!(stored.client_id, "client");
        assert_eq!(stored.client_secret, "secret");
        // Hash is computed on the fly when retrieving
        let hash = compute_client_secret_hash("secret");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64);
    }

    #[test]
    fn identity_config_try_from_proto_success() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec!["api".to_string(), "other".to_string()],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test-master".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604_800,
        };
        let config = identity_config_try_from_proto(proto, &bounds).unwrap();
        assert_eq!(config.issuer.as_str(), "https://issuer.example.com");
        assert_eq!(config.default_audience, "api");
        assert_eq!(config.allowed_audiences, vec!["api", "other"]);
        assert_eq!(config.token_ttl_sec, 3600);
        assert_eq!(config.subject_prefix, "spiffe://issuer.example.com");
        assert!(config.enabled);
        assert!(!config.rotate_key);
        assert_eq!(config.algorithm, identity_config::SigningAlgorithm::Es256);
        assert_eq!(config.encryption_key_id.as_str(), "test-master");
    }

    #[test]
    fn identity_config_try_from_proto_stores_normalized_issuer() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "HTTPS://Issuer.EXAMPLE.COM/wl".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test-master".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let config = identity_config_try_from_proto(proto, &bounds).unwrap();
        assert_eq!(config.issuer.as_str(), "https://issuer.example.com/wl");
        assert_eq!(config.subject_prefix, "spiffe://issuer.example.com");
    }

    #[test]
    fn identity_config_try_from_proto_empty_issuer() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: String::new(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("issuer is required"));
    }

    #[test]
    fn identity_config_try_from_proto_empty_default_audience() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: String::new(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("default_audience is required"));
    }

    #[test]
    fn identity_config_try_from_proto_accepts_custom_subject_prefix_in_proto() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: Some("spiffe://issuer.example.com/workloads".to_string()),
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let config = identity_config_try_from_proto(proto, &bounds).unwrap();
        assert_eq!(
            config.subject_prefix,
            "spiffe://issuer.example.com/workloads"
        );
    }

    #[test]
    fn identity_config_try_from_proto_empty_optional_subject_prefix_defaults() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: Some(String::new()),
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let config = identity_config_try_from_proto(proto, &bounds).unwrap();
        assert_eq!(config.subject_prefix, "spiffe://issuer.example.com");
    }

    #[test]
    fn identity_config_try_from_proto_rejects_non_spiffe_subject_prefix() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: Some("https://issuer.example.com/p".to_string()),
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("spiffe://"));
    }

    #[test]
    fn identity_config_try_from_proto_rejects_subject_prefix_trust_domain_mismatch() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: Some("spiffe://other.example/wl".to_string()),
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("does not match"));
    }

    #[test]
    fn identity_config_try_from_proto_token_ttl_zero() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 0,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("token_ttl_sec"));
    }

    #[test]
    fn identity_config_try_from_proto_token_ttl_below_min() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 30,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("token_ttl_sec must be between"));
    }

    #[test]
    fn identity_config_try_from_proto_token_ttl_above_max() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 100000,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("token_ttl_sec must be between"));
    }

    #[test]
    fn identity_config_try_from_proto_rejects_trust_domain_not_on_allowlist() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://evil.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec!["login.example.com".to_string()],
            signing_key_overlap_max_sec: 604_800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("trust domain"));
        assert!(err.0.contains("allowlist"));
    }

    #[test]
    fn identity_config_try_from_proto_accepts_trust_domain_matching_allowlist() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://auth.login.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec!["**.login.example.com".to_string()],
            signing_key_overlap_max_sec: 604_800,
        };
        let config = identity_config_try_from_proto(proto, &bounds).unwrap();
        assert_eq!(config.subject_prefix, "spiffe://auth.login.example.com");
    }

    #[test]
    fn identity_config_try_from_proto_accepts_issuer_matching_second_allowlist_entry() {
        let allowlist = vec![
            "login.example.com".to_string(),
            "idp.other.example".to_string(),
            "*.tenant.example.net".to_string(),
        ];
        assert!(
            validate_trust_domain_allowlist_patterns(&allowlist).is_ok(),
            "fixture patterns valid at startup"
        );
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://idp.other.example/oidc".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: allowlist,
            signing_key_overlap_max_sec: 604_800,
        };
        let config = identity_config_try_from_proto(proto, &bounds).unwrap();
        assert_eq!(config.issuer.as_str(), "https://idp.other.example/oidc");
        assert_eq!(config.subject_prefix, "spiffe://idp.other.example");
    }

    #[test]
    fn identity_config_try_from_proto_rejects_when_no_allowlist_entry_matches() {
        let allowlist = vec![
            "login.example.com".to_string(),
            "*.tenant.example.net".to_string(),
        ];
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://idp.other.example/".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: None,
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: allowlist,
            signing_key_overlap_max_sec: 604_800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("allowlist"));
    }

    #[test]
    fn identity_config_try_from_proto_rejects_overlap_when_not_rotating() {
        let proto = rpc_forge::TenantIdentityConfig {
            enabled: true,
            issuer: "https://issuer.example.com".to_string(),
            default_audience: "api".to_string(),
            allowed_audiences: vec!["api".to_string()],
            token_ttl_sec: 3600,
            subject_prefix: None,
            rotate_key: false,
            signing_key_overlap_sec: Some(120),
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test-master".parse().unwrap(),
            trust_domain_allowlist: vec![],
            signing_key_overlap_max_sec: 604_800,
        };
        let err = identity_config_try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("signing_key_overlap_sec may only be set"));
    }

    #[test]
    fn validate_identity_overlap_requires_value_when_rotating() {
        let config = IdentityConfig {
            issuer: "https://issuer.example.com".parse().unwrap(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: "spiffe://issuer.example.com".to_string(),
            enabled: true,
            rotate_key: true,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            signing_key_overlap_sec: None,
        };
        let err = validate_identity_overlap_for_rotation(&config).unwrap_err();
        assert!(err.0.contains("signing_key_overlap_sec is required"));
    }

    #[test]
    fn validate_identity_overlap_rejects_less_than_token_ttl() {
        let config = IdentityConfig {
            issuer: "https://issuer.example.com".parse().unwrap(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: "spiffe://issuer.example.com".to_string(),
            enabled: true,
            rotate_key: true,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            signing_key_overlap_sec: Some(120),
        };
        let err = validate_identity_overlap_for_rotation(&config).unwrap_err();
        assert!(
            err.0.contains("must be at least token_ttl_sec"),
            "unexpected: {}",
            err.0
        );
    }

    #[test]
    fn validate_identity_overlap_ok_when_rotating() {
        let config = IdentityConfig {
            issuer: "https://issuer.example.com".parse().unwrap(),
            default_audience: "api".to_string(),
            allowed_audiences: vec![],
            token_ttl_sec: 3600,
            subject_prefix: "spiffe://issuer.example.com".to_string(),
            enabled: true,
            rotate_key: true,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            signing_key_overlap_sec: Some(3600),
        };
        validate_identity_overlap_for_rotation(&config).unwrap();
    }

    #[test]
    fn token_delegation_try_from_success_none() {
        let proto = rpc_forge::TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: None,
        };
        let config = TokenDelegation::try_from(proto).unwrap();
        assert_eq!(config.token_endpoint, "https://auth.example.com/token");
        assert_eq!(config.subject_token_audience, "https://api.example.com");
        matches!(
            config.auth_method_config,
            TokenDelegationAuthMethodConfig::None
        );
    }

    #[test]
    fn token_delegation_try_from_success_client_secret_basic() {
        let proto = rpc_forge::TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: Some(
                rpc_forge::token_delegation::AuthMethodConfig::ClientSecretBasic(
                    rpc_forge::ClientSecretBasic {
                        client_id: "my-client".to_string(),
                        client_secret: "my-secret".to_string(),
                    },
                ),
            ),
        };
        let config = TokenDelegation::try_from(proto).unwrap();
        assert_eq!(config.token_endpoint, "https://auth.example.com/token");
        assert_eq!(config.subject_token_audience, "https://api.example.com");
        match &config.auth_method_config {
            TokenDelegationAuthMethodConfig::ClientSecretBasic {
                client_id,
                client_secret,
            } => {
                assert_eq!(client_id, "my-client");
                assert_eq!(client_secret, "my-secret");
            }
            _ => panic!("expected ClientSecretBasic"),
        }
    }

    #[test]
    fn token_delegation_try_from_empty_token_endpoint() {
        let proto = rpc_forge::TokenDelegation {
            token_endpoint: String::new(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: None,
        };
        let err = TokenDelegation::try_from(proto).unwrap_err();
        assert!(err.0.contains("token_endpoint is required"));
    }

    #[test]
    fn token_delegation_try_from_empty_subject_token_audience() {
        let proto = rpc_forge::TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: String::new(),
            auth_method_config: None,
        };
        let err = TokenDelegation::try_from(proto).unwrap_err();
        assert!(err.0.contains("subject_token_audience is required"));
    }

    #[test]
    fn token_delegation_try_from_empty_client_id() {
        let proto = rpc_forge::TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: Some(
                rpc_forge::token_delegation::AuthMethodConfig::ClientSecretBasic(
                    rpc_forge::ClientSecretBasic {
                        client_id: String::new(),
                        client_secret: "secret".to_string(),
                    },
                ),
            ),
        };
        let err = TokenDelegation::try_from(proto).unwrap_err();
        assert!(err.0.contains("client_id is required"));
    }

    #[test]
    fn token_delegation_try_from_empty_client_secret() {
        let proto = rpc_forge::TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: Some(
                rpc_forge::token_delegation::AuthMethodConfig::ClientSecretBasic(
                    rpc_forge::ClientSecretBasic {
                        client_id: "client".to_string(),
                        client_secret: String::new(),
                    },
                ),
            ),
        };
        let err = TokenDelegation::try_from(proto).unwrap_err();
        assert!(err.0.contains("client_secret is required"));
    }
}
