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

use ::rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ConfigValidationError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InlineIpxe {
    /// The iPXE script which is booted into
    pub ipxe_script: String,
}

impl TryFrom<rpc::forge::InlineIpxe> for InlineIpxe {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::forge::InlineIpxe) -> Result<Self, Self::Error> {
        Ok(Self {
            ipxe_script: config.ipxe_script,
        })
    }
}

impl TryFrom<InlineIpxe> for rpc::forge::InlineIpxe {
    type Error = RpcDataConversionError;

    fn try_from(config: InlineIpxe) -> Result<rpc::forge::InlineIpxe, Self::Error> {
        Ok(Self {
            ipxe_script: config.ipxe_script,
            user_data: None,
        })
    }
}

impl InlineIpxe {
    /// Validates the operating system
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        if self.ipxe_script.trim().is_empty() {
            return Err(ConfigValidationError::invalid_value(
                "InlineIpxe::ipxe_script is empty",
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatingSystemVariant {
    /// An operating system that is booted into via iPXE
    Ipxe(InlineIpxe),
    OsImage(Uuid),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatingSystem {
    /// cloud-init user data for any OS variant, preferred
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
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
        let mut ipxe_user_data = None;
        let variant = match variant {
            rpc::forge::operating_system::Variant::Ipxe(ipxe) => {
                ipxe_user_data = ipxe.user_data.clone();
                OperatingSystemVariant::Ipxe(ipxe.try_into()?)
            }
            rpc::forge::operating_system::Variant::OsImageId(id) => {
                OperatingSystemVariant::OsImage(Uuid::try_from(id).map_err(|e| {
                    RpcDataConversionError::InvalidUuid("os_image_id: ", e.to_string())
                })?)
            }
        };

        Ok(Self {
            variant,
            phone_home_enabled: config.phone_home_enabled,
            run_provisioning_instructions_on_every_boot: config
                .run_provisioning_instructions_on_every_boot,
            user_data: config.user_data.or(ipxe_user_data),
        })
    }
}

impl TryFrom<OperatingSystem> for rpc::forge::OperatingSystem {
    type Error = RpcDataConversionError;

    fn try_from(config: OperatingSystem) -> Result<rpc::forge::OperatingSystem, Self::Error> {
        let variant = match config.variant {
            OperatingSystemVariant::Ipxe(ipxe) => {
                let mut ipxe: rpc::forge::InlineIpxe = ipxe.try_into()?;
                ipxe.user_data = config.user_data.clone();
                rpc::forge::operating_system::Variant::Ipxe(ipxe)
            }
            OperatingSystemVariant::OsImage(id) => {
                rpc::forge::operating_system::Variant::OsImageId(id.into())
            }
        };

        Ok(Self {
            variant: Some(variant),
            phone_home_enabled: config.phone_home_enabled,
            run_provisioning_instructions_on_every_boot: config
                .run_provisioning_instructions_on_every_boot,
            user_data: config.user_data.clone(),
        })
    }
}

impl OperatingSystem {
    /// Validates the operating system
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        match &self.variant {
            OperatingSystemVariant::Ipxe(ipxe) => ipxe.validate(),
            OperatingSystemVariant::OsImage(_id) => Ok(()),
        }
    }

    pub fn verify_update_allowed_to(
        &self,
        _new_config: &Self,
    ) -> Result<(), ConfigValidationError> {
        Ok(())
    }
}
