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
    os::{IpxeOperatingSystem, OperatingSystem, OperatingSystemVariant},
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
    pub tenant: TenantConfig,

    /// Operating system that is used by the instance
    pub os: OperatingSystem,

    /// Configures instance networking
    #[serde(default)]
    pub network: InstanceNetworkConfig,

    /// Configures instance infiniband
    pub infiniband: InstanceInfinibandConfig,
}

impl TryFrom<rpc::InstanceConfig> for InstanceConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceConfig) -> Result<Self, Self::Error> {
        let os: OperatingSystem = match config.os {
            Some(os) => OperatingSystem::try_from(os)?,
            None => {
                // Deprecated path: The OS is not specified in an extra field,
                // but in TenantConfig
                match &config.tenant {
                    Some(tenant) => OperatingSystem {
                        variant: OperatingSystemVariant::Ipxe(IpxeOperatingSystem {
                            ipxe_script: tenant.custom_ipxe.clone(),
                            user_data: tenant.user_data.clone(),
                        }),
                        run_provisioning_instructions_on_every_boot: tenant
                            .always_boot_with_custom_ipxe,
                        phone_home_enabled: tenant.phone_home_enabled,
                    },
                    None => {
                        return Err(RpcDataConversionError::MissingArgument(
                            "InstanceConfig::os or InstanceConfig::tenant",
                        ))
                    }
                }
            }
        };

        let tenant = TenantConfig::try_from(config.tenant.ok_or(
            RpcDataConversionError::MissingArgument("InstanceConfig::tenant"),
        )?)?;

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
            os,
            network,
            infiniband,
        })
    }
}

impl TryFrom<InstanceConfig> for rpc::InstanceConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: InstanceConfig) -> Result<rpc::InstanceConfig, Self::Error> {
        let mut tenant = rpc::TenantConfig::try_from(config.tenant)?;
        // Retrofit the OS details that are now stored in `os`
        // TODO: Deprecated this once nobody excepts OS details in TenantConfig anymore
        match &config.os.variant {
            crate::model::os::OperatingSystemVariant::Ipxe(ipxe) => {
                tenant.custom_ipxe = ipxe.ipxe_script.clone();
                tenant.user_data = ipxe.user_data.clone();
            }
        };
        tenant.always_boot_with_custom_ipxe = config.os.run_provisioning_instructions_on_every_boot;
        tenant.phone_home_enabled = config.os.phone_home_enabled;

        let os = rpc::OperatingSystem::try_from(config.os)?;
        let network = rpc::InstanceNetworkConfig::try_from(config.network)?;
        let infiniband = rpc::InstanceInfinibandConfig::try_from(config.infiniband)?;
        let infiniband = match infiniband.ib_interfaces.is_empty() {
            true => None,
            false => Some(infiniband),
        };

        Ok(rpc::InstanceConfig {
            tenant: Some(tenant),
            os: Some(os),
            network: Some(network),
            infiniband,
        })
    }
}

impl InstanceConfig {
    /// Validates the instances configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        self.tenant.validate()?;

        self.os.validate()?;

        self.network.validate()?;

        self.infiniband.validate()?;

        Ok(())
    }

    /// Validates whether the configuration of a running instance (`self`) can be updated
    /// to a new configuration
    ///
    /// This check validates that certain unchangeable fields never change. These include
    /// - Tenant ID
    /// - Ethernet network configuration
    /// - InfiniBand network configuration
    pub fn verify_update_allowed_to(
        &self,
        new_config: &InstanceConfig,
    ) -> Result<(), ConfigValidationError> {
        self.tenant.verify_update_allowed_to(&new_config.tenant)?;

        self.os.verify_update_allowed_to(&new_config.os)?;

        self.network.verify_update_allowed_to(&new_config.network)?;

        self.infiniband
            .verify_update_allowed_to(&new_config.infiniband)?;

        Ok(())
    }
}
