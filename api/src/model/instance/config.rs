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
pub mod storage;
pub mod tenant_config;

use forge_uuid::network_security_group::{
    NetworkSecurityGroupId, NetworkSecurityGroupIdParseError,
};
use serde::{Deserialize, Serialize};

use crate::model::{
    ConfigValidationError,
    instance::config::{
        infiniband::InstanceInfinibandConfig, network::InstanceNetworkConfig,
        storage::InstanceStorageConfig, tenant_config::TenantConfig,
    },
    os::{IpxeOperatingSystem, OperatingSystem, OperatingSystemVariant},
};
use ::rpc::errors::RpcDataConversionError;

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

    /// Configures instance storage
    pub storage: InstanceStorageConfig,

    /// Configures the security group
    pub network_security_group_id: Option<NetworkSecurityGroupId>,
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
                        }),
                        run_provisioning_instructions_on_every_boot: tenant
                            .always_boot_with_custom_ipxe,
                        phone_home_enabled: tenant.phone_home_enabled,
                        user_data: tenant.user_data.clone(),
                    },
                    None => {
                        return Err(RpcDataConversionError::MissingArgument(
                            "InstanceConfig::os or InstanceConfig::tenant",
                        ));
                    }
                }
            }
        };

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

        // Storage config is optional
        let storage = config
            .storage
            .map(InstanceStorageConfig::try_from)
            .transpose()?
            .unwrap_or(InstanceStorageConfig::default());

        Ok(InstanceConfig {
            tenant,
            os,
            network,
            infiniband,
            storage,
            network_security_group_id: config
                .network_security_group_id
                .map(|nsg| nsg.parse())
                .transpose()
                .map_err(|e: NetworkSecurityGroupIdParseError| {
                    RpcDataConversionError::InvalidNetworkSecurityGroupId(e.value())
                })?,
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
            }
            crate::model::os::OperatingSystemVariant::OsImage(_id) => {
                // tenant details are already in os images and not applicable here
            }
        };
        tenant.user_data = config.os.user_data.clone();
        tenant.always_boot_with_custom_ipxe = config.os.run_provisioning_instructions_on_every_boot;
        tenant.phone_home_enabled = config.os.phone_home_enabled;

        let os = rpc::forge::OperatingSystem::try_from(config.os)?;
        let network = rpc::InstanceNetworkConfig::try_from(config.network)?;
        let infiniband = rpc::InstanceInfinibandConfig::try_from(config.infiniband)?;
        let infiniband = match infiniband.ib_interfaces.is_empty() {
            true => None,
            false => Some(infiniband),
        };
        let storage = rpc::forge::InstanceStorageConfig::try_from(config.storage)?;
        let storage = match storage.volumes.is_empty() {
            true => None,
            false => Some(storage),
        };

        Ok(rpc::InstanceConfig {
            tenant: Some(tenant),
            os: Some(os),
            network: Some(network),
            infiniband,
            storage,
            network_security_group_id: config.network_security_group_id.map(|i| i.to_string()),
        })
    }
}

impl InstanceConfig {
    /// Validates the instances configuration
    pub fn validate(&self, validate_network: bool) -> Result<(), ConfigValidationError> {
        self.tenant.validate()?;

        self.os.validate()?;

        if validate_network {
            self.network.validate()?;
        }

        self.infiniband.validate()?;

        self.storage.validate()?;

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

        Ok(())
    }
}
