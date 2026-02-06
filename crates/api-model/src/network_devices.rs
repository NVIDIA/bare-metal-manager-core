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

use core::fmt;
use std::fmt::Display;
use std::net::IpAddr;

use carbide_uuid::machine::MachineId;
use itertools::Itertools;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

// When topology data is received,
//  -> If corresponding Switch entry does not exist, create one.
//  -> Create Switch <-> DPU association.

#[derive(thiserror::Error, Debug)]
pub enum LldpError {
    #[error("Missing port info: {0}")]
    MissingPort(String),
}

/// A NetworkDevice is identified with MGMT_MAC based unique ID.
/// NetworkDevice and Switches are words used interchangeably.
// TODO: Delete a switch when no DPU is connected to it.
#[derive(Debug, Clone)]
pub struct NetworkDevice {
    id: String,
    name: String,
    description: Option<String>,
    ip_addresses: Vec<IpAddr>,
    device_type: NetworkDeviceType,
    discovered_via: NetworkDeviceDiscoveredVia,

    pub dpus: Vec<DpuToNetworkDeviceMap>,
}

/// Network Device types
#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(type_name = "network_device_type")]
#[sqlx(rename_all = "lowercase")]
pub enum NetworkDeviceType {
    Ethernet,
}

/// Network Device types
#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(type_name = "network_device_discovered_via")]
#[sqlx(rename_all = "lowercase")]
pub enum NetworkDeviceDiscoveredVia {
    Lldp,
}

/// Currently only following 3 DPU ports are supported.
#[derive(Debug, Clone, sqlx::Type)]
#[sqlx(type_name = "dpu_local_ports")]
#[sqlx(rename_all = "lowercase")]
pub enum DpuLocalPorts {
    #[sqlx(rename = "oob_net0")]
    OobNet0,
    P0,
    P1,
}

impl Display for NetworkDeviceDiscoveredVia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

impl Display for NetworkDeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

impl Display for DpuLocalPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                DpuLocalPorts::OobNet0 => "oob_net0",
                DpuLocalPorts::P0 => "p0",
                DpuLocalPorts::P1 => "p1",
            }
        )
    }
}

impl<'r> FromRow<'r, PgRow> for NetworkDevice {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(NetworkDevice {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            ip_addresses: row.try_get("ip_addresses")?,
            device_type: row.try_get("device_type")?,
            discovered_via: row.try_get("discovered_via")?,
            dpus: vec![],
        })
    }
}

/// A entry represents connection between DPU and its port with a network device.
// TODO: Add switch port name also. It will be easy to find connecting port at switch and use it for
// debugging.
#[derive(Debug, Clone, FromRow)]
pub struct DpuToNetworkDeviceMap {
    dpu_id: MachineId,
    local_port: DpuLocalPorts,
    remote_port: String,
    network_device_id: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct NetworkTopologyData {
    pub network_devices: Vec<NetworkDevice>,
}

impl NetworkDevice {
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl From<NetworkTopologyData> for rpc::forge::NetworkTopologyData {
    fn from(value: NetworkTopologyData) -> Self {
        let mut network_devices = vec![];

        for network_device in value.network_devices {
            let devices = network_device.dpus.into_iter().map_into().collect_vec();

            network_devices.push(rpc::forge::NetworkDevice {
                id: network_device.id,
                name: network_device.name,
                description: network_device.description,
                mgmt_ip: network_device
                    .ip_addresses
                    .iter()
                    .map(|x| x.to_string())
                    .collect_vec(),
                devices,
                discovered_via: network_device.discovered_via.to_string(),
                device_type: network_device.device_type.to_string(),
            });
        }

        rpc::forge::NetworkTopologyData { network_devices }
    }
}

impl From<DpuToNetworkDeviceMap> for rpc::forge::ConnectedDevice {
    fn from(value: DpuToNetworkDeviceMap) -> Self {
        Self {
            id: value.dpu_id.into(),
            local_port: value.local_port.to_string(),
            remote_port: value.remote_port.clone(),
            network_device_id: Some(value.network_device_id),
        }
    }
}

impl From<NetworkDevice> for rpc::forge::NetworkDevice {
    fn from(value: NetworkDevice) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            description: value.description.clone(),
            mgmt_ip: value.ip_addresses.iter().map(|i| i.to_string()).collect(),
            discovered_via: value.discovered_via.to_string(),
            device_type: value.device_type.to_string(),
            devices: value.dpus.into_iter().map_into().collect(),
        }
    }
}
