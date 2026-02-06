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

pub mod extension_services;
pub mod infiniband;
pub mod network;
pub mod nvlink;
pub mod tenant_config;

use carbide_uuid::network_security_group::{
    NetworkSecurityGroupId, NetworkSecurityGroupIdParseError,
};
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};

use crate::ConfigValidationError;
use crate::instance::config::extension_services::{
    InstanceExtensionServiceConfig, InstanceExtensionServicesConfig,
};
use crate::instance::config::infiniband::InstanceInfinibandConfig;
use crate::instance::config::network::InstanceNetworkConfig;
use crate::instance::config::nvlink::InstanceNvLinkConfig;
use crate::instance::config::tenant_config::TenantConfig;
use crate::os::OperatingSystem;

/// Instance configuration
///
/// This represents the desired state of an Instance.
/// The instance might not yet be in that state, but work would be underway
/// to get the Instance into this state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceConfig {
    /// Tenant related configuation.
    pub tenant: TenantConfig,

    /// Operating system that is used by the instance
    pub os: OperatingSystem,

    /// Configures instance networking
    #[serde(default)]
    pub network: InstanceNetworkConfig,

    /// Configures instance infiniband
    pub infiniband: InstanceInfinibandConfig,

    /// Configures the security group
    pub network_security_group_id: Option<NetworkSecurityGroupId>,

    /// Configures instance extension services
    #[serde(default)]
    pub extension_services: InstanceExtensionServicesConfig,

    /// configure instance nvlink
    pub nvlink: InstanceNvLinkConfig,
}

impl TryFrom<rpc::InstanceConfig> for InstanceConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceConfig) -> Result<Self, Self::Error> {
        let os: OperatingSystem = OperatingSystem::try_from(config.os.ok_or(
            RpcDataConversionError::MissingArgument("InstanceConfig::os"),
        )?)?;

        let tenant = TenantConfig::try_from(config.tenant.ok_or(
            RpcDataConversionError::MissingArgument("InstanceConfig::tenant"),
        )?)?;

        // Network config is optional (for zero-dpu hosts).
        let network = config
            .network
            .map(InstanceNetworkConfig::try_from)
            .transpose()?
            .unwrap_or(InstanceNetworkConfig::default());

        // Infiniband config is optional
        let infiniband = config
            .infiniband
            .map(InstanceInfinibandConfig::try_from)
            .transpose()?
            .unwrap_or(InstanceInfinibandConfig::default());

        // Extension services config is optional
        let extension_services = config
            .dpu_extension_services
            .map(InstanceExtensionServicesConfig::try_from)
            .transpose()?
            .unwrap_or(InstanceExtensionServicesConfig::default());

        // NvLink config is optional
        let nvlink = config
            .nvlink
            .map(InstanceNvLinkConfig::try_from)
            .transpose()?
            .unwrap_or(InstanceNvLinkConfig::default());

        Ok(InstanceConfig {
            tenant,
            os,
            network,
            infiniband,
            network_security_group_id: config
                .network_security_group_id
                .map(|nsg| nsg.parse())
                .transpose()
                .map_err(|e: NetworkSecurityGroupIdParseError| {
                    RpcDataConversionError::InvalidNetworkSecurityGroupId(e.value())
                })?,
            extension_services,
            nvlink,
        })
    }
}

impl TryFrom<InstanceConfig> for rpc::InstanceConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: InstanceConfig) -> Result<rpc::InstanceConfig, Self::Error> {
        let tenant = rpc::forge::TenantConfig::try_from(config.tenant)?;
        let os = rpc::forge::OperatingSystem::try_from(config.os)?;
        let network = rpc::InstanceNetworkConfig::try_from(config.network)?;
        let infiniband = rpc::InstanceInfinibandConfig::try_from(config.infiniband)?;
        let infiniband = match infiniband.ib_interfaces.is_empty() {
            true => None,
            false => Some(infiniband),
        };
        let nvlink = rpc::forge::InstanceNvLinkConfig::try_from(config.nvlink)?;
        let nvlink = match nvlink.gpu_configs.is_empty() {
            true => None,
            false => Some(nvlink),
        };

        // We only show user active extension services, and track terminating services internally.
        let active_extension_services: Vec<InstanceExtensionServiceConfig> = config
            .extension_services
            .active_services()
            .into_iter()
            .cloned()
            .collect();
        let extension_services = match active_extension_services.is_empty() {
            true => None,
            false => Some(rpc::forge::InstanceDpuExtensionServicesConfig::try_from(
                InstanceExtensionServicesConfig {
                    service_configs: active_extension_services,
                },
            )?),
        };

        Ok(rpc::InstanceConfig {
            tenant: Some(tenant),
            os: Some(os),
            network: Some(network),
            infiniband,
            network_security_group_id: config.network_security_group_id.map(|i| i.to_string()),
            dpu_extension_services: extension_services,
            nvlink,
        })
    }
}

impl InstanceConfig {
    /// Validates the instances configuration
    pub fn validate(
        &self,
        validate_network: bool,
        allow_instance_vf: bool,
    ) -> Result<(), ConfigValidationError> {
        self.tenant.validate()?;

        self.os.validate()?;

        if validate_network {
            self.network.validate(allow_instance_vf)?;
        }

        self.infiniband.validate()?;

        self.nvlink.validate()?;

        Ok(())
    }

    /// Validates whether the configuration of a running instance (`self`) can be updated
    /// to a new configuration
    ///
    /// This check validates that certain unchangeable fields never change. These include
    /// - Tenant ID
    pub fn verify_update_allowed_to(
        &self,
        new_config: &InstanceConfig,
    ) -> Result<(), ConfigValidationError> {
        self.tenant.verify_update_allowed_to(&new_config.tenant)?;

        self.os.verify_update_allowed_to(&new_config.os)?;

        self.network.verify_update_allowed_to(&new_config.network)?;

        self.infiniband
            .verify_update_allowed_to(&new_config.infiniband)?;

        self.extension_services
            .verify_update_allowed_to(&new_config.extension_services)?;
        self.nvlink.verify_update_allowed_to(&new_config.nvlink)?;

        Ok(())
    }
}
