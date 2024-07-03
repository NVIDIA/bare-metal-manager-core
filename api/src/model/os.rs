/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::model::{ConfigValidationError, RpcDataConversionError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpxeOperatingSystem {
    /// The iPXE script which is booted into
    pub ipxe_script: String,

    /// Optional user-data that is associated with the iPXE script
    /// This can be a cloud-init script
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

impl TryFrom<rpc::forge::IpxeOperatingSystem> for IpxeOperatingSystem {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::forge::IpxeOperatingSystem) -> Result<Self, Self::Error> {
        Ok(Self {
            ipxe_script: config.ipxe_script,
            user_data: config.user_data,
        })
    }
}

impl TryFrom<IpxeOperatingSystem> for rpc::forge::IpxeOperatingSystem {
    type Error = RpcDataConversionError;

    fn try_from(
        config: IpxeOperatingSystem,
    ) -> Result<rpc::forge::IpxeOperatingSystem, Self::Error> {
        Ok(Self {
            ipxe_script: config.ipxe_script,
            user_data: config.user_data,
        })
    }
}

impl IpxeOperatingSystem {
    /// Validates the operating system
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.ipxe_script.trim().is_empty() {
            return Err(ConfigValidationError::invalid_value(
                "IpxeOperatingSystem::ipxe_script is empty",
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatingSystemVariant {
    /// An operating system that is booted into via iPXE
    Ipxe(IpxeOperatingSystem),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatingSystem {
    /// The specific OS variant
    pub variant: OperatingSystemVariant,

    /// If this flag is set to `true` the instance will not transition to a Ready state until
    /// InstancePhoneHomeLastContact is updated
    #[serde(default)]
    pub phone_home_enabled: bool,

    /// If this flag is set to `true`, the instance will run the provisioning instructions
    /// that are specified by the OS on every reboot attempt.
    /// Depending on the type of provisioning instructions, this might
    /// lead the instance to reinstall itself on every reboot.
    ///
    /// E.g. if the instance uses an iPXE script as OS and the iPXE scripts contains
    /// instructions for installing on a local disk, the installation would be repeated
    /// on the reboot.
    ///
    /// If the flag is set to `false` or not specified, Forge will only provide
    /// iPXE instructions that are defined by the OS definition on the first boot attempt.
    /// For every subsequent boot, the instance will use the default boot action - which
    /// is usually to boot from the hard drive.
    ///
    /// If the provisioning instructions should only be used on specific reboots
    /// in order to trigger reinstallation, tenants can use the `InvokeInstancePower`
    /// API to reboot instances with the `boot_with_custom_ipxe` parameter set to
    /// `true`.
    #[serde(default)]
    pub run_provisioning_instructions_on_every_boot: bool,
}

impl TryFrom<rpc::forge::OperatingSystem> for OperatingSystem {
    type Error = RpcDataConversionError;

    fn try_from(mut config: rpc::forge::OperatingSystem) -> Result<Self, Self::Error> {
        let variant = config
            .variant
            .take()
            .ok_or(RpcDataConversionError::MissingArgument(
                "OperatingSystem::variant",
            ))?;
        let variant = match variant {
            rpc::forge::operating_system::Variant::Ipxe(ipxe) => {
                OperatingSystemVariant::Ipxe(ipxe.try_into()?)
            }
        };

        Ok(Self {
            variant,
            phone_home_enabled: config.phone_home_enabled,
            run_provisioning_instructions_on_every_boot: config
                .run_provisioning_instructions_on_every_boot,
        })
    }
}

impl TryFrom<OperatingSystem> for rpc::forge::OperatingSystem {
    type Error = RpcDataConversionError;

    fn try_from(config: OperatingSystem) -> Result<rpc::forge::OperatingSystem, Self::Error> {
        let variant = match config.variant {
            OperatingSystemVariant::Ipxe(ipxe) => {
                rpc::forge::operating_system::Variant::Ipxe(ipxe.try_into()?)
            }
        };

        Ok(Self {
            variant: Some(variant),
            phone_home_enabled: config.phone_home_enabled,
            run_provisioning_instructions_on_every_boot: config
                .run_provisioning_instructions_on_every_boot,
        })
    }
}

impl OperatingSystem {
    /// Validates the operating system
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match &self.variant {
            OperatingSystemVariant::Ipxe(ipxe) => ipxe.validate(),
        }
    }

    pub fn verify_update_allowed_to(
        &self,
        _new_config: &Self,
    ) -> Result<(), ConfigValidationError> {
        Ok(())
    }
}
