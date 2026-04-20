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
use std::fmt::{self, Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// JWT `alg` for per-tenant signing keys. Only ES256 (ECDSA P-256) is implemented end-to-end.
pub const TENANT_IDENTITY_SIGNING_JWT_ALG: &str = "ES256";

/// Per-tenant JWT signing algorithm persisted in `tenant_identity_config.algorithm` and site config.
/// Only [`SigningAlgorithm::Es256`] is implemented end-to-end today; the enum leaves room for more JOSE `alg` values later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SigningAlgorithm {
    Es256,
}

impl Default for SigningAlgorithm {
    fn default() -> Self {
        Self::Es256
    }
}

impl SigningAlgorithm {
    #[must_use]
    pub const fn as_jwt_alg_str(self) -> &'static str {
        match self {
            Self::Es256 => TENANT_IDENTITY_SIGNING_JWT_ALG,
        }
    }
}

impl Display for SigningAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_jwt_alg_str())
    }
}

/// Unsupported or unknown `algorithm` string from config or the database.
#[derive(thiserror::Error, Debug)]
#[error(
    "unsupported tenant identity signing algorithm {0:?} (only {TENANT_IDENTITY_SIGNING_JWT_ALG} is implemented)"
)]
pub struct UnsupportedTenantSigningAlgorithm(pub String);

impl FromStr for SigningAlgorithm {
    type Err = UnsupportedTenantSigningAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            TENANT_IDENTITY_SIGNING_JWT_ALG => Ok(Self::Es256),
            other => Err(UnsupportedTenantSigningAlgorithm(other.to_string())),
        }
    }
}

impl sqlx::Type<sqlx::Postgres> for SigningAlgorithm {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("VARCHAR")
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for SigningAlgorithm {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer<'_>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <String as sqlx::Encode<'_, sqlx::Postgres>>::encode_by_ref(&self.to_string(), buf)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for SigningAlgorithm {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        s.parse()
            .map_err(|e: UnsupportedTenantSigningAlgorithm| sqlx::Error::Decode(Box::new(e)).into())
    }
}

// --- JWT issuer (`iss`) ---

/// Normalized JWT issuer URL or SPIFFE ID.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Issuer(String);

impl Issuer {
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Parse and normalize a raw issuer string. Returns the normalized issuer and the lowercase
    /// trust-domain token (registered host) used for SPIFFE and allowlist checks.
    pub fn parse(raw: &str) -> Result<(Self, String), InvalidIssuer> {
        let (normalized, trust_domain) =
            super::identity_config_policy::normalize_issuer_and_trust_domain(raw)
                .map_err(InvalidIssuer)?;
        Ok((Self(normalized), trust_domain))
    }

    /// Trust-domain token for this issuer (lowercase registered host), derived from the normalized
    /// `iss` string.
    pub fn trust_domain(&self) -> Result<String, InvalidIssuer> {
        super::identity_config_policy::normalize_issuer_and_trust_domain(self.as_str())
            .map(|(_, td)| td)
            .map_err(InvalidIssuer)
    }

    /// Whether this issuer's trust domain satisfies site [`super::identity_config_policy`] allowlist
    /// patterns (same semantics as [`super::identity_config_policy::trust_domain_matches_allowlist`]).
    /// Empty `allowlist` → `Ok`.
    pub fn trust_domain_matches_allowlist(&self, allowlist: &[String]) -> Result<(), String> {
        let td = self.trust_domain().map_err(|e| e.0)?;
        super::identity_config_policy::trust_domain_matches_allowlist(&td, allowlist)
    }

    /// Resolve optional proto `subject_prefix` against this issuer's trust domain (see
    /// [`super::identity_config_policy::resolve_subject_prefix`]).
    pub fn resolve_subject_prefix(&self, proto: Option<&str>) -> Result<String, String> {
        let td = self.trust_domain().map_err(|e| e.0)?;
        super::identity_config_policy::resolve_subject_prefix(&td, proto)
    }
}

impl AsRef<str> for Issuer {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Issuer").field(&self.0).finish()
    }
}

impl Serialize for Issuer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

/// Issuer string failed normalization or policy checks from [`super::identity_config_policy`].
#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub struct InvalidIssuer(pub String);

impl TryFrom<String> for Issuer {
    type Error = InvalidIssuer;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw).map(|(issuer, _)| issuer)
    }
}

impl FromStr for Issuer {
    type Err = InvalidIssuer;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).map(|(issuer, _)| issuer)
    }
}

impl sqlx::Type<sqlx::Postgres> for Issuer {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl sqlx::Encode<'_, sqlx::Postgres> for Issuer {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer<'_>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <String as sqlx::Encode<'_, sqlx::Postgres>>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Issuer {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Self::try_from(s).map_err(|e: InvalidIssuer| sqlx::Error::Decode(Box::new(e)).into())
    }
}

// --- Non-empty string newtype (shared) and machine-identity ciphertext types ---

/// Owned UTF-8 string that is not empty and not only whitespace (`trim()` non-empty).
/// `S` distinguishes usage sites at compile time.
#[derive(PartialEq, Eq, Hash)]
pub struct NonEmptyStr<S> {
    inner: String,
    _tag: PhantomData<S>,
}

impl<S> Clone for NonEmptyStr<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _tag: PhantomData,
        }
    }
}

impl<S> fmt::Debug for NonEmptyStr<S> {
    /// Redacts contents (length only): some markers protect ciphertext; avoid logging raw strings.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NonEmptyStr")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl<S> NonEmptyStr<S> {
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }
}

impl<S> AsRef<str> for NonEmptyStr<S> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Empty string was provided where a [`NonEmptyStr`] is required.
#[derive(thiserror::Error, Debug)]
#[error("non-empty string required")]
pub struct InvalidNonEmptyStr;

impl<S> TryFrom<String> for NonEmptyStr<S> {
    type Error = InvalidNonEmptyStr;

    fn try_from(inner: String) -> Result<Self, Self::Error> {
        if inner.trim().is_empty() {
            return Err(InvalidNonEmptyStr);
        }
        Ok(Self {
            inner,
            _tag: PhantomData,
        })
    }
}

impl<S> FromStr for NonEmptyStr<S> {
    type Err = InvalidNonEmptyStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

impl<S> sqlx::Type<sqlx::Postgres> for NonEmptyStr<S> {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

impl<S> sqlx::Encode<'_, sqlx::Postgres> for NonEmptyStr<S> {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer<'_>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <String as sqlx::Encode<'_, sqlx::Postgres>>::encode_by_ref(&self.inner, buf)
    }
}

impl<'r, S> sqlx::Decode<'r, sqlx::Postgres> for NonEmptyStr<S> {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Self::try_from(s).map_err(|e| sqlx::Error::Decode(Box::new(e)).into())
    }
}

/// Marker for [`NonEmptyStr`] used as `machine_identity.encryption_keys` id and envelope label.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct EncryptionKeyIdTag;

/// Selects the AES key under `machine_identity.encryption_keys` and labels encryption envelopes.
pub type EncryptionKeyId = NonEmptyStr<EncryptionKeyIdTag>;

/// Marker for JWT `kid` / `tenant_identity_config.key_id` (e.g. hex digest of public key material).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TenantIdentitySigningKeyIdTag;

/// Per-tenant signing key identifier stored in `key_id` (JWT `kid`); must be non-empty.
pub type KeyId = NonEmptyStr<TenantIdentitySigningKeyIdTag>;

/// Marker for `tenant_identity_config.signing_key_public` (SPKI PEM text).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TenantSigningPublicKeyPemTag;

/// ES256 public key in PEM form (`signing_key_public` column).
pub type SigningPublicKeyPem = NonEmptyStr<TenantSigningPublicKeyPemTag>;

/// Non-empty UTF-8 string holding a `key_encryption` JSON envelope (base64). `M` distinguishes
/// what plaintext the ciphertext wraps so distinct columns are not interchangeable.
pub type EnvelopeCiphertext<M> = NonEmptyStr<M>;

/// Marker for `tenant_identity_config.encrypted_signing_key` (encrypted ES256 private PEM).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TenantSigningPrivateKeyCiphertextTag;

/// Ciphertext for stored signing private key (`encrypted_signing_key`).
pub type EncryptedSigningPrivateKey = EnvelopeCiphertext<TenantSigningPrivateKeyCiphertextTag>;

/// Marker for token-delegation auth config ciphertext (`encrypted_auth_method_config`).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TokenDelegationEncryptedAuthConfigTag;

/// Ciphertext for `tenant_identity_config.encrypted_auth_method_config` (delegation client secret JSON).
pub type EncryptedTokenDelegationAuthConfig =
    EnvelopeCiphertext<TokenDelegationEncryptedAuthConfigTag>;
