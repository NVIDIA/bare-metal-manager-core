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

use serde::{Deserialize, Serialize};

use crate::model::tenant::TenantOrganizationId;
use crate::model::{ConfigValidationError, RpcDataConversionError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Identifies the tenant that uses this instance
    pub tenant_organization_id: TenantOrganizationId,

    /// Custom iPXE script
    pub custom_ipxe: String,
    /// iPXE user data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,

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
            custom_ipxe: config.custom_ipxe,
            user_data: config.user_data,
            tenant_keyset_ids: config.tenant_keyset_ids,
        })
    }
}

impl TryFrom<TenantConfig> for rpc::TenantConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: TenantConfig) -> Result<rpc::TenantConfig, Self::Error> {
        Ok(Self {
            tenant_organization_id: config.tenant_organization_id.to_string(),
            custom_ipxe: config.custom_ipxe,
            user_data: config.user_data,
            tenant_keyset_ids: config.tenant_keyset_ids,
        })
    }
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
    fn serialize_tenant_config() {
        let mut config = TenantConfig {
            tenant_organization_id: TenantOrganizationId::try_from("TenantA".to_string()).unwrap(),
            custom_ipxe: "PXE".to_string(),
            user_data: Some("data".to_string()),
            tenant_keyset_ids: vec![],
        };

        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_organization_id\":\"TenantA\",\"custom_ipxe\":\"PXE\",\"user_data\":\"data\",\"tenant_keyset_ids\":[]}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );

        config.user_data = None;
        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_organization_id\":\"TenantA\",\"custom_ipxe\":\"PXE\",\"tenant_keyset_ids\":[]}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );

        config.user_data = Some("".to_string());
        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_organization_id\":\"TenantA\",\"custom_ipxe\":\"PXE\",\"user_data\":\"\",\"tenant_keyset_ids\":[]}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );
    }
}
