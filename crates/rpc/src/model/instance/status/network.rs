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

use std::convert::Into;
use std::net::IpAddr;

use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use model::instance::config::network::InterfaceFunctionId;
use model::instance::status::network::{
    InstanceInterfaceStatus, InstanceInterfaceStatusObservation, InstanceNetworkStatus,
};

use crate as rpc;
use crate::errors::RpcDataConversionError;

impl TryFrom<InstanceNetworkStatus> for rpc::InstanceNetworkStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceNetworkStatus) -> Result<Self, Self::Error> {
        let mut interfaces = Vec::with_capacity(status.interfaces.len());
        for iface in status.interfaces {
            interfaces.push(rpc::InstanceInterfaceStatus::try_from(iface)?);
        }
        Ok(rpc::InstanceNetworkStatus {
            interfaces,
            configs_synced: rpc::SyncState::try_from(status.configs_synced)? as i32,
        })
    }
}

impl TryFrom<InstanceInterfaceStatus> for rpc::InstanceInterfaceStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceInterfaceStatus) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceInterfaceStatus {
            virtual_function_id: match status.function_id {
                InterfaceFunctionId::Physical {} => None,
                InterfaceFunctionId::Virtual { id } => Some(id as u32),
            },
            mac_address: status.mac_address.map(|mac| mac.to_string()),
            addresses: status
                .addresses
                .into_iter()
                .map(|ip| ip.to_string())
                .collect(),
            prefixes: status
                .prefixes
                .into_iter()
                .map(|ip_network| ip_network.to_string())
                .collect(),
            gateways: status
                .gateways
                .into_iter()
                .map(|ip| ip.to_string())
                .collect(),
            device: status.device,
            device_instance: status.device_instance as u32,
        })
    }
}

impl TryFrom<rpc::InstanceInterfaceStatusObservation> for InstanceInterfaceStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(observation: rpc::InstanceInterfaceStatusObservation) -> Result<Self, Self::Error> {
        let function_id = match observation.function_type() {
            rpc::forge::InterfaceFunctionType::Physical => InterfaceFunctionId::Physical {},
            rpc::forge::InterfaceFunctionType::Virtual => {
                InterfaceFunctionId::try_virtual_from(observation.virtual_function_id() as u8)
                    .map_err(|_| {
                        RpcDataConversionError::InvalidVirtualFunctionId(
                            observation.virtual_function_id() as usize,
                        )
                    })?
            }
        };

        let addresses = observation
            .addresses
            .iter()
            .map(|addr| {
                addr.parse::<IpAddr>()
                    .map_err(|_| RpcDataConversionError::InvalidIpAddress(addr.clone()))
            })
            .try_collect()?;

        let internal_uuid = if let Some(internal_uuid) = &observation.internal_uuid {
            Some(internal_uuid.try_into().map_err(|_| {
                RpcDataConversionError::InvalidUuid("internal_uuid", internal_uuid.to_string())
            })?)
        } else {
            None
        };

        Ok(Self {
            function_id,
            addresses,
            prefixes: observation
                .prefixes
                .iter()
                .map(|ip_network| {
                    IpNetwork::try_from(ip_network.as_str())
                        .map_err(|_| Self::Error::InvalidCidr(ip_network.to_string()))
                })
                .collect::<Result<Vec<IpNetwork>, Self::Error>>()?,
            gateways: observation
                .gateways
                .iter()
                .map(|gw| {
                    IpNetwork::try_from(gw.as_str())
                        .map_err(|_| Self::Error::InvalidCidr(gw.to_string()))
                })
                .collect::<Result<Vec<IpNetwork>, Self::Error>>()?,
            mac_address: observation
                .mac_address
                .map(|addr| {
                    addr.parse::<MacAddress>()
                        .map_err(|_| RpcDataConversionError::InvalidMacAddress(addr))
                })
                .transpose()?
                .map(Into::into),
            network_security_group: observation
                .network_security_group
                .map(|nsgo| nsgo.try_into())
                .transpose()?,
            internal_uuid,
        })
    }
}
