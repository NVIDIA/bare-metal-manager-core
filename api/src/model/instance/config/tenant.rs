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

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::model::ConfigValidationError;

/// Identifies a forge tenant
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantOrg(String);

impl std::fmt::Debug for TenantOrg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Display for TenantOrg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TenantOrg {
    /// Returns a String representation of the Tenant Org
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A string is not a valid Tenant ID
#[derive(thiserror::Error, Debug)]
#[error("ID {0} is not a valid Tenant Organization ID")]
pub struct InvalidTenantOrg(String);

impl TryFrom<String> for TenantOrg {
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

impl FromStr for TenantOrg {
    type Err = InvalidTenantOrg;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Identifies the tenant that uses this instance
    pub tenant_org: TenantOrg,

    /// Custom iPXE script
    pub custom_ipxe: String,
    /// iPXE user data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

impl TenantConfig {
    /// Validates the tenant configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.custom_ipxe.trim().is_empty() {
            return Err(ConfigValidationError::invalid_value(
                "TenantConfig.custom_ipxe is empty",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tenant_org() {
        // Valid cases
        for &valid in &["TenantA", "Tenant_B", "Tenant-C-_And_D_"] {
            let org = TenantOrg::try_from(valid.to_string()).unwrap();
            assert_eq!(org.as_str(), valid);
            let org: TenantOrg = valid.parse().unwrap();
            assert_eq!(org.as_str(), valid);
        }

        // Invalid cases
        for &invalid in &["", " Tenant_B", "Tenant_C ", "Tenant D", "Tenant!A"] {
            assert!(TenantOrg::try_from(invalid.to_string()).is_err());
            assert!(invalid.parse::<TenantOrg>().is_err());
        }
    }

    #[test]
    fn tenant_org_formatting() {
        let tenant = TenantOrg::try_from("TenantA".to_string()).unwrap();
        assert_eq!(format!("{}", tenant), "TenantA");
        assert_eq!(format!("{:?}", tenant), "\"TenantA\"");
        assert_eq!(serde_json::to_string(&tenant).unwrap(), "\"TenantA\"");
    }

    #[test]
    fn serialize_tenant_config() {
        let mut config = TenantConfig {
            tenant_org: TenantOrg("TenantA".to_string()),
            custom_ipxe: "PXE".to_string(),
            user_data: Some("data".to_string()),
        };

        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_org\":\"TenantA\",\"custom_ipxe\":\"PXE\",\"user_data\":\"data\"}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );

        config.user_data = None;
        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_org\":\"TenantA\",\"custom_ipxe\":\"PXE\"}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );

        config.user_data = Some("".to_string());
        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_org\":\"TenantA\",\"custom_ipxe\":\"PXE\",\"user_data\":\"\"}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );
    }
}
