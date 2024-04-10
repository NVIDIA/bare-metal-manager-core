/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::fmt::Display;
use std::str::FromStr;

use config_version::ConfigVersion;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::model::RpcDataConversionError;

#[derive(thiserror::Error, Debug)]
pub enum TenantError {
    #[error("Publickey validation fail for instance {0}, key {1}")]
    PublickeyValidationFailed(uuid::Uuid, String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub organization_id: TenantOrganizationId,
    pub version: ConfigVersion,
}

impl From<Tenant> for rpc::forge::Tenant {
    fn from(src: Tenant) -> Self {
        Self {
            tenant_content: Some(rpc::forge::TenantContent {}),
            organization_id: src.organization_id.to_string(),
            version: src.version.version_string(),
        }
    }
}

impl TryFrom<rpc::forge::Tenant> for Tenant {
    type Error = RpcDataConversionError;

    fn try_from(src: rpc::forge::Tenant) -> Result<Self, Self::Error> {
        let _tenant_content = src
            .tenant_content
            .ok_or(RpcDataConversionError::MissingArgument("tenant content"))?;
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
            version,
        })
    }
}

impl From<Tenant> for rpc::forge::CreateTenantResponse {
    fn from(value: Tenant) -> Self {
        rpc::forge::CreateTenantResponse {
            tenant: Some(rpc::forge::Tenant {
                organization_id: value.organization_id.0,
                tenant_content: None,
                version: value.version.to_string(),
            }),
        }
    }
}

impl From<Tenant> for rpc::forge::FindTenantResponse {
    fn from(value: Tenant) -> Self {
        rpc::forge::FindTenantResponse {
            tenant: Some(rpc::forge::Tenant {
                organization_id: value.organization_id.0,
                tenant_content: None,
                version: value.version.to_string(),
            }),
        }
    }
}

impl From<Tenant> for rpc::forge::UpdateTenantResponse {
    fn from(value: Tenant) -> Self {
        rpc::forge::UpdateTenantResponse {
            tenant: Some(rpc::forge::Tenant {
                organization_id: value.organization_id.0,
                tenant_content: None,
                version: value.version.to_string(),
            }),
        }
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
            format!("{} ", algo)
        } else {
            "".to_string()
        };

        let comment = if let Some(comment) = self.comment.as_ref() {
            format!(" {}", comment)
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub instance_id: uuid::Uuid,
    pub public_key: String,
}

impl TryFrom<rpc::forge::ValidateTenantPublicKeyRequest> for TenantPublicKeyValidationRequest {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::forge::ValidateTenantPublicKeyRequest) -> Result<Self, Self::Error> {
        let instance_id: uuid::Uuid = uuid::Uuid::parse_str(&value.instance_id).map_err(|_| {
            RpcDataConversionError::InvalidUuid(
                "Instance id is invalid in tenant public key validation",
            )
        })?;

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
        assert_eq!(format!("{}", tenant), "TenantA");
        assert_eq!(format!("{:?}", tenant), "\"TenantA\"");
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
