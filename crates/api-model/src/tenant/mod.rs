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
use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;

use carbide_uuid::UuidConversionError;
use carbide_uuid::instance::InstanceId;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use itertools::Itertools;
use rpc::errors::RpcDataConversionError;
use rpc::forge as rpc_forge;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{FromRow, Row};

use crate::metadata::Metadata;

mod identity_config_policy;

pub mod identity_config;

pub use identity_config::{
    EncryptedSigningPrivateKey, EncryptedTokenDelegationAuthConfig, EncryptionKeyId,
    EncryptionKeyIdTag, EnvelopeCiphertext, InvalidIssuer, InvalidNonEmptyStr, Issuer, KeyId,
    NonEmptyStr, SigningPublicKeyPem, TenantIdentitySigningKeyIdTag,
    TenantSigningPrivateKeyCiphertextTag, TenantSigningPublicKeyPemTag,
    TokenDelegationEncryptedAuthConfigTag,
};
pub use identity_config_policy::{
    validate_token_endpoint_domain_allowlist_patterns, validate_trust_domain_allowlist_patterns,
};

#[derive(Clone, Debug, Default)]
pub struct TenantSearchFilter {
    pub tenant_organization_name: Option<String>,
}

impl From<rpc::forge::TenantSearchFilter> for TenantSearchFilter {
    fn from(filter: rpc::forge::TenantSearchFilter) -> Self {
        TenantSearchFilter {
            tenant_organization_name: filter.tenant_organization_name,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TenantKeysetSearchFilter {
    pub tenant_org_id: Option<String>,
}

impl From<rpc::forge::TenantKeysetSearchFilter> for TenantKeysetSearchFilter {
    fn from(filter: rpc::forge::TenantKeysetSearchFilter) -> Self {
        TenantKeysetSearchFilter {
            tenant_org_id: filter.tenant_org_id,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TenantError {
    #[error("Publickey validation fail for instance {0}, key {1}")]
    PublickeyValidationFailed(InstanceId, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub organization_id: TenantOrganizationId,
    pub routing_profile_type: Option<String>,
    pub metadata: Metadata,
    pub version: ConfigVersion,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeysetIdentifier {
    pub organization_id: TenantOrganizationId,
    pub keyset_id: String,
}

#[allow(rustdoc::invalid_html_tags)]
/// Possible format:
/// 1. <algo> <key> <comment>
/// 2. <algo> <key>
/// 3. <key>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub algo: Option<String>,
    pub key: String,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantPublicKey {
    pub public_key: PublicKey,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeysetContent {
    pub public_keys: Vec<TenantPublicKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyset {
    pub keyset_identifier: TenantKeysetIdentifier,
    pub keyset_content: TenantKeysetContent,
    pub version: String,
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let algo = if let Some(algo) = self.algo.as_ref() {
            format!("{algo} ")
        } else {
            "".to_string()
        };

        let comment = if let Some(comment) = self.comment.as_ref() {
            format!(" {comment}")
        } else {
            "".to_string()
        };

        write!(f, "{}{}{}", algo, self.key, comment)
    }
}

impl FromStr for PublicKey {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key_parts = s.split(' ').collect_vec();

        // If length is greater than 1, key contains algo and key at least.
        Ok(if key_parts.len() > 1 {
            PublicKey {
                algo: Some(key_parts[0].to_string()),
                key: key_parts[1].to_string(),
                comment: key_parts.get(2).map(|x| x.to_string()),
            }
        } else {
            PublicKey {
                algo: None,
                key: s.to_string(),
                comment: None,
            }
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateTenantKeyset {
    pub keyset_identifier: TenantKeysetIdentifier,
    pub keyset_content: TenantKeysetContent,
    pub version: String,
    pub if_version_match: Option<String>,
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

/// Identifies a forge tenant
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantOrganizationId(String);

impl std::fmt::Debug for TenantOrganizationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl std::fmt::Display for TenantOrganizationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TenantOrganizationId {
    /// Returns a String representation of the Tenant Org
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A string is not a valid Tenant ID
#[derive(thiserror::Error, Debug)]
#[error("ID {0} is not a valid Tenant Organization ID")]
pub struct InvalidTenantOrg(String);

impl TryFrom<String> for TenantOrganizationId {
    type Error = InvalidTenantOrg;

    fn try_from(id: String) -> Result<Self, Self::Error> {
        if id.is_empty() {
            return Err(InvalidTenantOrg(id));
        }

        for &ch in id.as_bytes() {
            if !(ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-') {
                return Err(InvalidTenantOrg(id));
            }
        }

        Ok(Self(id))
    }
}

impl FromStr for TenantOrganizationId {
    type Err = InvalidTenantOrg;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

impl sqlx::Type<sqlx::Postgres> for TenantOrganizationId {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for TenantOrganizationId {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer<'_>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <String as sqlx::Encode<'_, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for TenantOrganizationId {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Self::try_from(s).map_err(|e| sqlx::Error::Decode(Box::new(e)).into())
    }
}

/// Database row for tenant_identity_config table.
/// Persisted identity config with signing keys and token delegation.
#[derive(Debug, sqlx::FromRow)]
pub struct TenantIdentityConfig {
    pub organization_id: TenantOrganizationId,
    pub issuer: Issuer,
    pub default_audience: String,
    pub allowed_audiences: Json<Vec<String>>,
    pub token_ttl_sec: i32,
    pub subject_prefix: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub encrypted_signing_key: EncryptedSigningPrivateKey,
    pub signing_key_public: SigningPublicKeyPem,
    pub key_id: KeyId,
    pub algorithm: identity_config::SigningAlgorithm,
    pub encryption_key_id: EncryptionKeyId,
    // Token delegation (optional)
    pub token_endpoint: Option<String>,
    pub auth_method: Option<TokenDelegationAuthMethod>,
    /// Token delegation auth method secrets, **encrypted at rest**: standard base64 of JSON envelope v1
    /// (`key_encryption::encrypt`) over JSON (e.g. client_id and client_secret). Loaded from DB as
    /// ciphertext only; plaintext for gRPC mapping lives on [`TenantIdentityConfigDecrypted::auth_method_config`].
    pub encrypted_auth_method_config: Option<EncryptedTokenDelegationAuthConfig>,
    pub subject_token_audience: Option<String>,
    pub token_delegation_created_at: Option<DateTime<Utc>>,
}

/// [`TenantIdentityConfig`] row plus decrypted token-delegation JSON for handlers / `TryInto` RPC.
/// `row.encrypted_auth_method_config` stays ciphertext from the database; plaintext is only in
/// `auth_method_config`. Do not log.
#[derive(Debug)]
pub struct TenantIdentityConfigDecrypted {
    pub row: TenantIdentityConfig,
    /// UTF-8 JSON from `TokenDelegation::to_db_format` after `key_encryption::decrypt`.
    pub auth_method_config: Option<String>,
}

/// Key material for a new or rotated signing key.
/// Caller generates the key pair, encrypts the private key, and computes key_id = hex(sha256(public_key)).
#[derive(Clone, Debug)]
pub struct SigningKeyMaterial {
    pub key_id: KeyId,
    pub encrypted_signing_key: EncryptedSigningPrivateKey,
    pub signing_key_public: SigningPublicKeyPem,
}

/// Settable fields for tenant identity config (SPIFFE JWT-SVID).
/// Used as input to set identity configuration.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    pub issuer: Issuer,
    pub default_audience: String,
    pub allowed_audiences: Vec<String>,
    pub token_ttl_sec: u32,
    pub subject_prefix: String,
    pub enabled: bool,
    pub rotate_key: bool,
    pub algorithm: identity_config::SigningAlgorithm,
    pub encryption_key_id: EncryptionKeyId,
}

/// Validation bounds for IdentityConfig. Passed from site config (machine_identity).
#[derive(Debug, Clone)]
pub struct IdentityConfigValidationBounds {
    pub token_ttl_min_sec: u32,
    pub token_ttl_max_sec: u32,
    pub algorithm: identity_config::SigningAlgorithm,
    pub encryption_key_id: EncryptionKeyId,
    /// Site policy: JWT issuer trust domain must match at least one entry. Empty = no extra check.
    pub trust_domain_allowlist: Vec<String>,
}

#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub struct IdentityConfigValidationError(pub String);

impl IdentityConfig {
    /// Validates gRPC `TenantIdentityConfig` and converts to `IdentityConfig`, including SPIFFE
    /// `subject_prefix` resolution against `issuer` (optional proto field defaults to
    /// `spiffe://<trust-domain-from-issuer>`).
    pub fn try_from_proto(
        value: rpc_forge::TenantIdentityConfig,
        bounds: &IdentityConfigValidationBounds,
    ) -> Result<Self, IdentityConfigValidationError> {
        if value.default_audience.is_empty() {
            return Err(IdentityConfigValidationError(
                "default_audience is required".to_string(),
            ));
        }
        let (issuer, issuer_td) = identity_config::Issuer::parse(&value.issuer)
            .map_err(|e| IdentityConfigValidationError(e.0))?;
        identity_config_policy::trust_domain_matches_allowlist(
            &issuer_td,
            &bounds.trust_domain_allowlist,
        )
        .map_err(IdentityConfigValidationError)?;
        let subject_prefix = identity_config_policy::resolve_subject_prefix(
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
        })
    }
}

/// Token delegation config for external IdP token exchange (RFC 8693).
/// Used as input to set token delegation.
#[derive(Debug, Clone)]
pub struct TokenDelegation {
    pub token_endpoint: String,
    pub subject_token_audience: String,
    pub auth_method_config: TokenDelegationAuthMethodConfig,
}

/// Auth method for token delegation. Matches proto oneof.
#[derive(Debug, Clone)]
pub enum TokenDelegationAuthMethodConfig {
    None,
    ClientSecretBasic {
        client_id: String,
        client_secret: String,
    },
}

/// Database enum for token_delegation_auth_method_t. Maps to auth_method column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "token_delegation_auth_method_t")]
#[sqlx(rename_all = "snake_case")]
pub enum TokenDelegationAuthMethod {
    None,
    ClientSecretBasic,
}

impl TokenDelegationAuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
        }
    }
}

/// Computes SHA256 hash of client_secret for display (e.g. in get_token_delegation response).
pub fn compute_client_secret_hash(client_secret: &str) -> String {
    let h = sha2::Sha256::digest(client_secret.as_bytes());
    format!("sha256:{}", hex::encode(h))
}

/// Hex chars to show in get_token_delegation response (8 chars + ".." suffix).
const HASH_DISPLAY_HEX_LEN: usize = 8;

/// Truncates hash for display in get_token_delegation: algorithm-prefix:XXXXXXXX..
pub fn truncate_hash_for_display(full_hash: &str) -> String {
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
/// Only used when auth_method is ClientSecretBasic; for None the oneof is omitted.
pub fn stored_to_response_auth_config(
    auth_method: TokenDelegationAuthMethod,
    stored: Option<rpc_forge::ClientSecretBasic>,
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

#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub struct TokenDelegationValidationError(pub String);

/// Site policy for [`TokenDelegation`]: allowlist on `token_endpoint` URL host / domain name (same pattern language as trust-domain allowlist).
#[derive(Debug, Clone, Default)]
pub struct TokenDelegationValidationBounds {
    pub token_endpoint_domain_allowlist: Vec<String>,
}

impl TokenDelegation {
    /// Validates gRPC `TokenDelegation` and converts, including optional `token_endpoint` domain allowlist.
    /// When the allowlist is non-empty, `token_endpoint` must be an **`http://` or `https://` URL** with a DNS hostname (not an IP literal).
    pub fn try_from_proto(
        value: rpc_forge::TokenDelegation,
        bounds: &TokenDelegationValidationBounds,
    ) -> Result<Self, TokenDelegationValidationError> {
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
            let host =
                identity_config_policy::registered_host_for_token_endpoint(&value.token_endpoint)
                    .map_err(TokenDelegationValidationError)?;
            identity_config_policy::token_endpoint_domain_matches_allowlist(
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

    /// Returns (auth_method, config_json) for DB storage.
    pub fn to_db_format(&self) -> (TokenDelegationAuthMethod, String) {
        match &self.auth_method_config {
            TokenDelegationAuthMethodConfig::None => {
                (TokenDelegationAuthMethod::None, "{}".to_string())
            }
            TokenDelegationAuthMethodConfig::ClientSecretBasic {
                client_id,
                client_secret,
            } => {
                let stored = rpc_forge::ClientSecretBasic {
                    client_id: client_id.clone(),
                    client_secret: client_secret.clone(),
                };
                let config_json =
                    serde_json::to_string(&stored).unwrap_or_else(|_| "{}".to_string());
                (TokenDelegationAuthMethod::ClientSecretBasic, config_json)
            }
        }
    }
}

impl TryFrom<rpc_forge::TokenDelegation> for TokenDelegation {
    type Error = TokenDelegationValidationError;

    fn try_from(value: rpc_forge::TokenDelegation) -> Result<Self, Self::Error> {
        TokenDelegation::try_from_proto(value, &TokenDelegationValidationBounds::default())
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

        let stored: Option<rpc_forge::ClientSecretBasic> = value
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

pub struct TenantPublicKeyValidationRequest {
    pub instance_id: InstanceId,
    pub public_key: String,
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

impl TenantPublicKeyValidationRequest {
    pub fn validate_key(&self, keysets: Vec<TenantKeyset>) -> Result<(), TenantError> {
        // Validate with all available keysets
        for keyset in keysets {
            for key in keyset.keyset_content.public_keys {
                if key.public_key.key == self.public_key {
                    return Ok(());
                }
            }
        }

        Err(TenantError::PublickeyValidationFailed(
            self.instance_id,
            self.public_key.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use rpc::forge as rpc_forge;
    use rpc::forge::token_delegation_response::AuthMethodConfig;

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
        assert!(stored_to_response_auth_config(TokenDelegationAuthMethod::None, None).is_none());
    }

    #[test]
    fn test_stored_to_response_auth_config_client_secret_basic() {
        let stored = rpc_forge::ClientSecretBasic {
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
        let stored = rpc_forge::ClientSecretBasic {
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
        let stored = rpc_forge::ClientSecretBasic {
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
    fn parse_tenant_org() {
        // Valid cases
        for &valid in &["TenantA", "Tenant_B", "Tenant-C-_And_D_"] {
            let org = TenantOrganizationId::try_from(valid.to_string()).unwrap();
            assert_eq!(org.as_str(), valid);
            let org: TenantOrganizationId = valid.parse().unwrap();
            assert_eq!(org.as_str(), valid);
        }

        // Invalid cases
        for &invalid in &["", " Tenant_B", "Tenant_C ", "Tenant D", "Tenant!A"] {
            assert!(TenantOrganizationId::try_from(invalid.to_string()).is_err());
            assert!(invalid.parse::<TenantOrganizationId>().is_err());
        }
    }

    #[test]
    fn tenant_org_formatting() {
        let tenant = TenantOrganizationId::try_from("TenantA".to_string()).unwrap();
        assert_eq!(format!("{tenant}"), "TenantA");
        assert_eq!(format!("{tenant:?}"), "\"TenantA\"");
        assert_eq!(serde_json::to_string(&tenant).unwrap(), "\"TenantA\"");
    }

    #[test]
    fn public_key_formatting() {
        let pub_key = PublicKey {
            algo: Some("ssh-rsa".to_string()),
            key: "randomkey123".to_string(),
            comment: Some("test@myorg".to_string()),
        };

        assert_eq!("ssh-rsa randomkey123 test@myorg", pub_key.to_string());
    }

    #[test]
    fn public_key_formatting_no_comment() {
        let pub_key = PublicKey {
            algo: Some("ssh-rsa".to_string()),
            key: "randomkey123".to_string(),
            comment: None,
        };

        assert_eq!("ssh-rsa randomkey123", pub_key.to_string());
    }

    #[test]
    fn public_key_formatting_only_key() {
        let pub_key = PublicKey {
            algo: None,
            key: "randomkey123".to_string(),
            comment: None,
        };

        assert_eq!("randomkey123", pub_key.to_string());
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
        let stored: rpc_forge::ClientSecretBasic = serde_json::from_str(&config_json).unwrap();
        assert_eq!(stored.client_id, "client");
        assert_eq!(stored.client_secret, "secret");
        // Hash is computed on the fly when retrieving
        let hash = compute_client_secret_hash("secret");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64);
    }

    #[test]
    fn token_delegation_to_db_format_none() {
        let config = TokenDelegation {
            token_endpoint: "https://auth.example.com/token".to_string(),
            subject_token_audience: "https://api.example.com".to_string(),
            auth_method_config: TokenDelegationAuthMethodConfig::None,
        };
        let (auth_method, config_json) = config.to_db_format();
        assert_eq!(auth_method, TokenDelegationAuthMethod::None);
        assert_eq!(config_json, "{}");
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test-master".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let config = IdentityConfig::try_from_proto(proto, &bounds).unwrap();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test-master".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let config = IdentityConfig::try_from_proto(proto, &bounds).unwrap();
        assert_eq!(config.issuer.as_str(), "https://issuer.example.com/wl");
        assert_eq!(config.subject_prefix, "spiffe://issuer.example.com");
    }

    #[test]
    fn tenant_identity_signing_algorithm_from_str_rejects_unknown() {
        assert_eq!(
            "ES256"
                .parse::<identity_config::SigningAlgorithm>()
                .unwrap(),
            identity_config::SigningAlgorithm::Es256
        );
        assert!(
            "RS256"
                .parse::<identity_config::SigningAlgorithm>()
                .is_err()
        );
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let config = IdentityConfig::try_from_proto(proto, &bounds).unwrap();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let config = IdentityConfig::try_from_proto(proto, &bounds).unwrap();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec![],
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec!["login.example.com".to_string()],
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: vec!["**.login.example.com".to_string()],
        };
        let config = IdentityConfig::try_from_proto(proto, &bounds).unwrap();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: allowlist,
        };
        let config = IdentityConfig::try_from_proto(proto, &bounds).unwrap();
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
        };
        let bounds = IdentityConfigValidationBounds {
            token_ttl_min_sec: 60,
            token_ttl_max_sec: 86400,
            algorithm: identity_config::SigningAlgorithm::Es256,
            encryption_key_id: "test".parse().unwrap(),
            trust_domain_allowlist: allowlist,
        };
        let err = IdentityConfig::try_from_proto(proto, &bounds).unwrap_err();
        assert!(err.0.contains("allowlist"));
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

// simplified tenant keyset id struct with tenant_org_id and keyset_id both as string
// used in find_ids and find_by_ids
#[derive(Debug, Clone, FromRow)]
pub struct TenantKeysetId {
    pub organization_id: String,
    pub keyset_id: String,
}

impl From<TenantKeysetId> for rpc::forge::TenantKeysetIdentifier {
    fn from(src: TenantKeysetId) -> Self {
        Self {
            organization_id: src.organization_id,
            keyset_id: src.keyset_id,
        }
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for Tenant {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let organization_id: String = row.try_get("organization_id")?;
        let name: String = row.try_get("organization_name")?;
        let routing_profile_type: Option<String> = row.try_get("routing_profile_type")?;
        Ok(Self {
            routing_profile_type,
            organization_id: organization_id
                .try_into()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            metadata: Metadata {
                name,
                description: String::new(), // We're using metadata for consistency,
                labels: HashMap::new(), // but description and labels might never be used for Tenant
            },
            version: row.try_get("version")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for TenantKeyset {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let tenant_keyset_content: sqlx::types::Json<TenantKeysetContent> =
            row.try_get("content")?;

        let organization_id: String = row.try_get("organization_id")?;
        Ok(Self {
            version: row.try_get("version")?,
            keyset_content: tenant_keyset_content.0,
            keyset_identifier: TenantKeysetIdentifier {
                organization_id: organization_id
                    .try_into()
                    .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
                keyset_id: row.try_get("keyset_id")?,
            },
        })
    }
}
