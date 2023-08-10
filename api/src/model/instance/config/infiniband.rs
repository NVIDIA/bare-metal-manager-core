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
use uuid::Uuid;

use rpc::forge as rpc;

// TODO(k82cn): It's better to move FunctionId/FunctionType to a standalone model.
use super::network::{InterfaceFunctionId, InterfaceFunctionType};
use crate::model::{ConfigValidationError, RpcDataConversionError};

/// Desired infiniband configuration for an instance
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInfinibandConfig {
    /// Configures how instance IB interfaces are set up
    pub ib_interfaces: Vec<InstanceIbInterfaceConfig>,
}

impl InstanceInfinibandConfig {
    /// Returns a infiniband configuration for a single physical interface
    pub fn for_ib_subnet_id(ib_subnet_id: Uuid) -> Self {
        Self {
            ib_interfaces: vec![InstanceIbInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                ib_subnet_id,
                guid: None,
            }],
        }
    }

    /// Validates the infiniband configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        Ok(())
    }
}

impl TryFrom<rpc::InstanceInfinibandConfig> for InstanceInfinibandConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceInfinibandConfig) -> Result<Self, Self::Error> {
        // try_from for ib_interfaces:
        let mut assigned_vfs: u8 = 0;
        let mut ib_interfaces = Vec::with_capacity(config.ib_interfaces.len());
        for iface in config.ib_interfaces.into_iter() {
            let iface_type = rpc::InterfaceFunctionType::from_i32(iface.function_type)
                .and_then(|ty| InterfaceFunctionType::try_from(ty).ok())
                .ok_or(RpcDataConversionError::InvalidInterfaceFunctionType(
                    iface.function_type,
                ))?;

            let function_id = match iface_type {
                InterfaceFunctionType::Physical => InterfaceFunctionId::Physical {},
                InterfaceFunctionType::Virtual => {
                    let id = assigned_vfs;
                    assigned_vfs = assigned_vfs.saturating_add(1);
                    InterfaceFunctionId::Virtual { id }
                }
            };

            let ib_subnet_id =
                iface
                    .ib_subnet_id
                    .ok_or(RpcDataConversionError::MissingArgument(
                        "InstanceIbInterfaceConfig::ib_subnet_id",
                    ))?;
            let ib_subnet_id = uuid::Uuid::try_from(ib_subnet_id).map_err(|_| {
                RpcDataConversionError::InvalidUuid("InstanceIbInterfaceConfig::ib_subnet_id")
            })?;

            ib_interfaces.push(InstanceIbInterfaceConfig {
                function_id,
                ib_subnet_id,
                guid: None,
            });
        }

        Ok(Self { ib_interfaces })
    }
}

impl TryFrom<InstanceInfinibandConfig> for rpc::InstanceInfinibandConfig {
    type Error = RpcDataConversionError;

    fn try_from(
        config: InstanceInfinibandConfig,
    ) -> Result<rpc::InstanceInfinibandConfig, Self::Error> {
        let mut ib_interfaces = Vec::with_capacity(config.ib_interfaces.len());
        for iface in config.ib_interfaces.into_iter() {
            let function_type = iface.function_id.function_type();

            ib_interfaces.push(rpc::InstanceIbInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::from(function_type) as i32,
                ib_subnet_id: Some(iface.ib_subnet_id.into()),
            });
        }

        Ok(rpc::InstanceInfinibandConfig { ib_interfaces })
    }
}

/// The configuration that a customer desires for an instances ib interface
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceIbInterfaceConfig {
    /// Uniquely identifies the ib interface on the instance
    pub function_id: InterfaceFunctionId,
    /// The ib subnet this ib interface is attached to
    pub ib_subnet_id: Uuid,
    /// The guid of this ib interface
    pub guid: Option<String>,
}
