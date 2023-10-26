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
use std::collections::HashSet;
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
    pub fn for_ib_partition_id(ib_partition_id: Uuid) -> Self {
        Self {
            ib_interfaces: vec![InstanceIbInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                ib_partition_id,
                pf_guid: None,
                guid: None,
                device: "MT2910 Family [ConnectX-7]".to_string(), // only for test case
                vendor: None,
                device_instance: 0,
            }],
        }
    }

    /// Validates the infiniband configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        #[derive(Hash, Eq, PartialEq)]
        struct IbDeviceKey {
            device: String,
            device_instance: u32,
        }

        let mut used_segment_ids = HashSet::new();
        for iface in self.ib_interfaces.iter() {
            let ib_key = IbDeviceKey {
                device: iface.device.clone(),
                device_instance: iface.device_instance,
            };

            if !used_segment_ids.insert(ib_key) {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "IB interface {} {} is reused",
                    iface.device, iface.device_instance
                )));
            }
        }
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

            let ib_partition_id =
                iface
                    .ib_partition_id
                    .ok_or(RpcDataConversionError::MissingArgument(
                        "InstanceIbInterfaceConfig::ib_partition_id",
                    ))?;
            let ib_partition_id = uuid::Uuid::try_from(ib_partition_id).map_err(|_| {
                RpcDataConversionError::InvalidUuid("InstanceIbInterfaceConfig::ib_partition_id")
            })?;

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
                ib_partition_id: Some(iface.ib_partition_id.into()),
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
    pub ib_partition_id: Uuid,
    /// The GUID of the hardware device that this interface is attached to
    pub pf_guid: Option<String>,
    /// The GUID which has been assigned to this interface
    /// In case the interface is a PF interface, the GUID will be equvalent to
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
