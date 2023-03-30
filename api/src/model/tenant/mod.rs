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
use std::convert::TryFrom;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::model::config_version::ConfigVersion;
use crate::model::RpcDataConversionError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub keyset_id: Option<String>,
    pub organization_id: TenantOrganizationId,
    pub version: ConfigVersion,
}

impl From<Tenant> for rpc::forge::Tenant {
    fn from(src: Tenant) -> Self {
        Self {
            tenant_content: Some(rpc::forge::TenantContent {
                keyset_id: src.keyset_id,
            }),
            organization_id: src.organization_id.to_string(),
            version: src.version.to_version_string(),
        }
    }
}

impl TryFrom<rpc::forge::Tenant> for Tenant {
    type Error = RpcDataConversionError;

    fn try_from(src: rpc::forge::Tenant) -> Result<Self, Self::Error> {
        let tenant_content = src
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
            keyset_id: tenant_content.keyset_id,
            organization_id,
            version,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeysetIdentifier {
    pub organization_id: TenantOrganizationId,
    pub keyset_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantPublicKey {
    pub public_key: String,
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
    pub version: ConfigVersion,
}

impl From<rpc::forge::TenantPublicKey> for TenantPublicKey {
    fn from(src: rpc::forge::TenantPublicKey) -> Self {
        Self {
            public_key: src.public_key,
            comment: src.comment,
        }
    }
}

impl From<TenantPublicKey> for rpc::forge::TenantPublicKey {
    fn from(src: TenantPublicKey) -> Self {
        Self {
            public_key: src.public_key,
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
        let version = src
            .version
            .parse::<ConfigVersion>()
            .map_err(|_| RpcDataConversionError::InvalidConfigVersion(src.version))?;

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
            version: src.version.to_version_string(),
        }
    }
}

/// Identifies a forge tenant
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantOrganizationId(String);

impl std::fmt::Debug for TenantOrganizationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
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
}
