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

use serde::{Deserialize, Serialize};

use crate::model::ConfigValidationError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Identifies the tenant that uses this instance
    pub tenant_id: String,

    /// Custom iPXE script
    pub custom_ipxe: String,
    /// iPXE user data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

impl TenantConfig {
    /// Validates the tenant configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        // TODO: In the future we might also want a non-empty tenant-id

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
            tenant_id: "TenantA".to_string(),
            custom_ipxe: "PXE".to_string(),
            user_data: Some("data".to_string()),
        };

        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_id\":\"TenantA\",\"custom_ipxe\":\"PXE\",\"user_data\":\"data\"}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );

        config.user_data = None;
        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_id\":\"TenantA\",\"custom_ipxe\":\"PXE\"}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );

        config.user_data = Some("".to_string());
        let serialized = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serialized,
            "{\"tenant_id\":\"TenantA\",\"custom_ipxe\":\"PXE\",\"user_data\":\"\"}"
        );
        assert_eq!(
            serde_json::from_str::<TenantConfig>(&serialized).unwrap(),
            config
        );
    }
}
