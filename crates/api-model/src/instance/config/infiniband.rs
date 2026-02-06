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

use std::collections::HashSet;

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::infiniband::IBPartitionId;
use rpc::forge as rpc;
use serde::{Deserialize, Serialize};

// TODO(k82cn): It's better to move FunctionId/FunctionType to a standalone model.
use super::network::{InterfaceFunctionId, InterfaceFunctionType};
use crate::ConfigValidationError;

/// Desired infiniband configuration for an instance
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInfinibandConfig {
    /// Configures how instance IB interfaces are set up
    pub ib_interfaces: Vec<InstanceIbInterfaceConfig>,
}

impl InstanceInfinibandConfig {
    /// Validates the infiniband configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        #[derive(Hash, Eq, PartialEq)]
        struct IbDeviceKey {
            device: String,
            device_instance: u32,
        }

        let mut used_devices = HashSet::new();
        for iface in self.ib_interfaces.iter() {
            let ib_key = IbDeviceKey {
                device: iface.device.clone(),
                device_instance: iface.device_instance,
            };

            if !used_devices.insert(ib_key) {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "IB interface {} {} is configured more than once",
                    iface.device, iface.device_instance
                )));
            }
        }
        Ok(())
    }

    pub fn verify_update_allowed_to(
        &self,
        _new_config: &Self,
    ) -> Result<(), ConfigValidationError> {
        Ok(())
    }

    /// Returns whether the configuration has been modified by a tenant
    /// To get an accurate asessment, the values that are not assignable by the tenant
    /// are not included in the comparison.
    pub fn is_ib_config_update_requested(&self, new_config: &Self) -> bool {
        let mut current = self.clone();
        for iface in &mut current.ib_interfaces {
            iface.guid = None;
            iface.pf_guid = None;
        }

        current != *new_config
    }
}

impl TryFrom<rpc::InstanceInfinibandConfig> for InstanceInfinibandConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceInfinibandConfig) -> Result<Self, Self::Error> {
        // try_from for ib_interfaces:
        let mut assigned_vfs: u8 = 0;
        let mut ib_interfaces = Vec::with_capacity(config.ib_interfaces.len());
        for iface in config.ib_interfaces.into_iter() {
            let rpc_iface_type = rpc::InterfaceFunctionType::try_from(iface.function_type)
                .map_err(|_| {
                    RpcDataConversionError::InvalidInterfaceFunctionType(iface.function_type)
                })?;
            let iface_type = InterfaceFunctionType::try_from(rpc_iface_type).map_err(|_| {
                RpcDataConversionError::InvalidInterfaceFunctionType(iface.function_type)
            })?;

            let function_id = match iface_type {
                InterfaceFunctionType::Physical => InterfaceFunctionId::Physical {},
                InterfaceFunctionType::Virtual => {
                    let id = assigned_vfs;
                    assigned_vfs = assigned_vfs.saturating_add(1);
                    InterfaceFunctionId::Virtual { id }
                }
            };

            let ib_partition_id =
                iface
                    .ib_partition_id
                    .ok_or(RpcDataConversionError::MissingArgument(
                        "InstanceIbInterfaceConfig::ib_partition_id",
                    ))?;

            ib_interfaces.push(InstanceIbInterfaceConfig {
                function_id,
                ib_partition_id,
                pf_guid: None,
                guid: None,
                device: iface.device,
                vendor: iface.vendor,
                device_instance: iface.device_instance,
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
                virtual_function_id: None,
                ib_partition_id: Some(iface.ib_partition_id),
                device: iface.device,
                vendor: iface.vendor,
                device_instance: iface.device_instance,
            });
        }

        Ok(rpc::InstanceInfinibandConfig { ib_interfaces })
    }
}

/// The configuration that a customer desires for an instances ib interface
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceIbInterfaceConfig {
    // Uniquely identifies the ib interface on the instance
    pub function_id: InterfaceFunctionId,
    /// The IB partition this ib interface is attached to
    pub ib_partition_id: IBPartitionId,
    /// The GUID of the hardware device that this interface is attached to
    pub pf_guid: Option<String>,
    /// The GUID which has been assigned to this interface
    /// In case the interface is a PF interface, the GUID will be equivalent to
    /// `pf_guid` - which is the GUID that is stored on the hardware device.
    /// For a VF interface, this is a GUID that has been allocated by Forge in order
    /// be used for the VF.
    // Tenants have to configure the VF device on their instances to use this GUID.
    pub guid: Option<String>,
    /// The name of this device
    pub device: String,
    /// The device vendor
    pub vendor: Option<String>,
    /// If multiple devices with the same name - and connected to the same
    /// fabric - are available, this selects the device among these.
    /// `device_instance == 1` selects the 2nd device of a certain type.
    ///
    /// Forge will internally order devices of the same type by PCI slot in order
    /// to achieve deterministic device selection via `device_instance`.
    pub device_instance: u32,
}
