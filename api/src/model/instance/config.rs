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

pub mod network;
pub mod tenant;

use serde::{Deserialize, Serialize};

use crate::model::{
    instance::config::{network::InstanceNetworkConfig, tenant::TenantConfig},
    ConfigValidationError,
};

/// Instance configuration
///
/// This represents the desired state of an Instance.
/// The instance might not yet be in that state, but work would be underway
/// to get the Instance into this state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceConfig {
    /// Tenant related configuation.
    /// This field can be absent if the instance has not yet been allocated by
    /// a tenant. On assignment, the config changes once. Due to the one-time
    /// change no version field is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<TenantConfig>,

    /// Configures instance networking
    #[serde(default)]
    pub network: InstanceNetworkConfig,
}

impl InstanceConfig {
    /// Validates the instances configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(tenant) = self.tenant.as_ref() {
            tenant.validate()?;
        }

        self.network.validate()
    }
}
