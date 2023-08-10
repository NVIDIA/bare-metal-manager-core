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

pub mod infiniband;
pub mod network;
pub mod tenant_config;

use rpc::forge as rpc;
use serde::{Deserialize, Serialize};

use crate::model::{
    instance::config::{
        infiniband::InstanceInfinibandConfig, network::InstanceNetworkConfig,
        tenant_config::TenantConfig,
    },
    ConfigValidationError, RpcDataConversionError,
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

    /// Configures instance infiniband
    pub infiniband: InstanceInfinibandConfig,
}

impl TryFrom<rpc::InstanceConfig> for InstanceConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceConfig) -> Result<Self, Self::Error> {
        let tenant = match config.tenant {
            Some(tenant) => Some(TenantConfig::try_from(tenant)?),
            None => None,
        };

        let network = InstanceNetworkConfig::try_from(config.network.ok_or(
            RpcDataConversionError::MissingArgument("InstanceConfig::network"),
        )?)?;

        let infiniband = config
            .infiniband
            .map(InstanceInfinibandConfig::try_from)
            .transpose()?
            .unwrap_or(InstanceInfinibandConfig::default());

        Ok(InstanceConfig {
            tenant,
            network,
            infiniband,
        })
    }
}

impl TryFrom<InstanceConfig> for rpc::InstanceConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: InstanceConfig) -> Result<rpc::InstanceConfig, Self::Error> {
        let tenant = match config.tenant {
            Some(tenant) => Some(rpc::TenantConfig::try_from(tenant)?),
            None => None,
        };

        let network = rpc::InstanceNetworkConfig::try_from(config.network)?;
        let infiniband = rpc::InstanceInfinibandConfig::try_from(config.infiniband)?;
        let infiniband = match infiniband.ib_interfaces.is_empty() {
            true => None,
            false => Some(infiniband),
        };

        Ok(rpc::InstanceConfig {
            tenant,
            network: Some(network),
            infiniband,
        })
    }
}

impl InstanceConfig {
    /// Validates the instances configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if let Some(tenant) = self.tenant.as_ref() {
            tenant.validate()?;
        }

        self.network.validate()?;

        self.infiniband.validate()?;

        Ok(())
    }
}
