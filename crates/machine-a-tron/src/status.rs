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
use bmc_mock::HostHardwareType;
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
pub struct MachineStatusConfig {
    pub redfish_reachable_port: u16,
    pub redfish_listen_port: u16,
}

impl MachineStatusConfig {
    pub fn new(redfish_listen_port: u16) -> Self {
        Self {
            redfish_reachable_port: 443,
            redfish_listen_port,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MachinesStatusResponse {
    pub machines: Vec<MachineStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachineStatus {
    pub mat_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_type: Option<HostHardwareType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mat_state: Option<String>,
    pub api_state: String,
    pub power_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_ip: Option<String>,
    pub bmc: BmcStatus,
    pub dpus: Vec<MachineStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BmcStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub redfish: EndpointStatus,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct EndpointStatus {
    pub reachable_port: u16,
    pub listen_port: u16,
}

impl EndpointStatus {
    pub fn redfish(config: &MachineStatusConfig) -> Self {
        Self {
            reachable_port: config.redfish_reachable_port,
            listen_port: config.redfish_listen_port,
        }
    }
}
