/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::model::tenant::TenantOrganizationId;
use crate::model::{ConfigValidationError, RpcDataConversionError};

const MAX_KEYSET_IDS: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Identifies the tenant that uses this instance
    pub tenant_organization_id: TenantOrganizationId,

    pub tenant_keyset_ids: Vec<String>,
}

impl TryFrom<rpc::TenantConfig> for TenantConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::TenantConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            tenant_organization_id: TenantOrganizationId::try_from(
                config.tenant_organization_id.clone(),
            )
            .map_err(|_| RpcDataConversionError::InvalidTenantOrg(config.tenant_organization_id))?,
            tenant_keyset_ids: config.tenant_keyset_ids,
        })
    }
}

impl TryFrom<TenantConfig> for rpc::TenantConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: TenantConfig) -> Result<rpc::TenantConfig, Self::Error> {
        Ok(Self {
            tenant_organization_id: config.tenant_organization_id.to_string(),
            custom_ipxe: String::new(),
            user_data: None,
            tenant_keyset_ids: config.tenant_keyset_ids,
            always_boot_with_custom_ipxe: false,
            phone_home_enabled: false,
        })
    }
}

impl TenantConfig {
    /// Validates the tenant configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        // Perform a check for duplicate keysets
        // and throw back an error to the caller if found.
        let mut unique_keyset_ids: HashSet<&String> = HashSet::new();
        for keyset_id in self.tenant_keyset_ids.iter() {
            if !unique_keyset_ids.insert(keyset_id) {
                return Err(ConfigValidationError::DuplicateTenantKeysetId(
                    keyset_id.into(),
                ));
            }
        }

        // check to see if we are over the max IDs or not
        if self.tenant_keyset_ids.len() > MAX_KEYSET_IDS {
            return Err(ConfigValidationError::TenantKeysetIdsOverMax(
                MAX_KEYSET_IDS,
            ));
        }

        Ok(())
    }

    pub fn verify_update_allowed_to(&self, new_config: &Self) -> Result<(), ConfigValidationError> {
        if self.tenant_organization_id != new_config.tenant_organization_id {
            return Err(ConfigValidationError::ConfigCanNotBeModified(
                "TenantConfig::tenant_organization_id".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_tenant_config() {
        let config = TenantConfig {
            tenant_organization_id: TenantOrganizationId::try_from("TenantA".to_string()).unwrap(),
            tenant_keyset_ids: vec![],
        };

        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_organization_id\":\"TenantA\",\"tenant_keyset_ids\":[]}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );
    }

    #[test]
    fn validate_tenant_config_duplicate_keysets() {
        let config = TenantConfig {
            tenant_organization_id: TenantOrganizationId::try_from("TenantA".to_string()).unwrap(),
            tenant_keyset_ids: vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "a".to_string(),
            ],
        };

        assert!(matches!(
            config.validate(),
            Err(ConfigValidationError::DuplicateTenantKeysetId(_))
        ))
    }

    #[test]
    fn validate_tenant_config_unique_keysets() {
        let config = TenantConfig {
            tenant_organization_id: TenantOrganizationId::try_from("TenantA".to_string()).unwrap(),
            tenant_keyset_ids: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        };

        config.validate().unwrap()
    }
}
