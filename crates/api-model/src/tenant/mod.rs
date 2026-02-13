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
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use carbide_uuid::UuidConversionError;
use carbide_uuid::instance::InstanceId;
use config_version::ConfigVersion;
use itertools::Itertools;
use rpc::errors::RpcDataConversionError;
use rpc::forge as rpc_forge;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::metadata::Metadata;

#[derive(thiserror::Error, Debug)]
pub enum TenantError {
    #[error("Publickey validation fail for instance {0}, key {1}")]
    PublickeyValidationFailed(InstanceId, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub organization_id: TenantOrganizationId,
    pub routing_profile_type: Option<RoutingProfileType>,
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
            routing_profile_type: src
                .routing_profile_type
                .map(rpc_forge::RoutingProfileType::from)
                .map(|t| t.into()),
        })
    }
}

impl TryFrom<rpc::forge::Tenant> for Tenant {
    type Error = RpcDataConversionError;

    fn try_from(src: rpc::forge::Tenant) -> Result<Self, Self::Error> {
        let routing_profile_type = Some(src.routing_profile_type().try_into()?);
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
            routing_profile_type,
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
    use super::*;

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
            routing_profile_type: routing_profile_type
                .map(|p| p.parse::<RoutingProfileType>())
                .transpose()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
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

/* ********************************** */
/*                                    */
/*     Tenant Routing Profile Type    */
/*                                    */
/* ********************************** */

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd)]
pub enum RoutingProfileType {
    #[default]
    External,
    Internal,
    Maintenance,
    PrivilegedInternal,
    Admin,
}

/// A string is not a valid profile type
#[derive(thiserror::Error, Debug)]
#[error("{0} is not a valid RoutingProfileType")]
pub struct InvalidRoutingProfileType(String);

impl FromStr for RoutingProfileType {
    type Err = InvalidRoutingProfileType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "ADMIN" => RoutingProfileType::Admin,
            "INTERNAL" => RoutingProfileType::Internal,
            "PRIVILEGED_INTERNAL" => RoutingProfileType::PrivilegedInternal,
            "MAINTENANCE" => RoutingProfileType::Maintenance,
            "EXTERNAL" => RoutingProfileType::External,
            _ => return Err(InvalidRoutingProfileType(s.to_string())),
        })
    }
}

impl Display for RoutingProfileType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RoutingProfileType::Admin => write!(f, "ADMIN"),
            RoutingProfileType::Internal => write!(f, "INTERNAL"),
            RoutingProfileType::PrivilegedInternal => write!(f, "PRIVILEGED_INTERNAL"),
            RoutingProfileType::Maintenance => write!(f, "MAINTENANCE"),
            RoutingProfileType::External => write!(f, "EXTERNAL"),
        }
    }
}

impl From<RoutingProfileType> for rpc_forge::RoutingProfileType {
    fn from(t: RoutingProfileType) -> Self {
        match t {
            RoutingProfileType::Admin => rpc_forge::RoutingProfileType::Admin,
            RoutingProfileType::Internal => rpc_forge::RoutingProfileType::Internal,
            RoutingProfileType::PrivilegedInternal => {
                rpc_forge::RoutingProfileType::PrivilegedInternal
            }
            RoutingProfileType::Maintenance => rpc_forge::RoutingProfileType::Maintenance,
            RoutingProfileType::External => rpc_forge::RoutingProfileType::External,
        }
    }
}

impl TryFrom<rpc_forge::RoutingProfileType> for RoutingProfileType {
    type Error = RpcDataConversionError;

    fn try_from(t: rpc_forge::RoutingProfileType) -> Result<Self, Self::Error> {
        match t {
            rpc_forge::RoutingProfileType::Admin => Err(RpcDataConversionError::InvalidValue(
                "RoutingProfileType".to_string(),
                t.as_str_name().to_string(),
            )),
            rpc_forge::RoutingProfileType::Internal => Ok(RoutingProfileType::Internal),
            rpc_forge::RoutingProfileType::PrivilegedInternal => {
                Ok(RoutingProfileType::PrivilegedInternal)
            }
            rpc_forge::RoutingProfileType::Maintenance => Ok(RoutingProfileType::Maintenance),
            rpc_forge::RoutingProfileType::External => Ok(RoutingProfileType::External),
        }
    }
}
