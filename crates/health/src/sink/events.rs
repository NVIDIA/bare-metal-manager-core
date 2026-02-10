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

use carbide_uuid::machine::MachineId;

use crate::endpoint::{BmcEndpoint, EndpointMetadata};
use crate::metrics::MetricLabel;

#[derive(Clone, Debug)]
pub struct EventContext {
    pub endpoint_key: String,
    pub endpoint_ip: String,
    pub endpoint_mac: String,
    pub collector_type: String,
    pub machine_id: Option<String>,
    pub switch_serial: Option<String>,
}

impl EventContext {
    pub fn from_endpoint(endpoint: &BmcEndpoint, collector_type: &str) -> Self {
        let (machine_id, switch_serial) = match &endpoint.metadata {
            Some(EndpointMetadata::Machine(machine)) => {
                (Some(machine.machine_id.to_string()), None)
            }
            Some(EndpointMetadata::Switch(switch)) => (None, Some(switch.serial.clone())),
            None => (None, None),
        };

        Self {
            endpoint_key: endpoint.addr.hash_key().to_string(),
            endpoint_ip: endpoint.addr.ip.to_string(),
            endpoint_mac: endpoint.addr.mac.clone(),
            collector_type: collector_type.to_string(),
            machine_id,
            switch_serial,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MetricSample {
    pub key: String,
    pub name: String,
    pub metric_type: String,
    pub unit: String,
    pub value: f64,
    pub labels: Vec<MetricLabel>,
}

#[derive(Clone, Debug)]
pub struct LogRecord {
    pub body: String,
    pub severity: String,
    pub attributes: Vec<MetricLabel>,
}

#[derive(Clone, Debug)]
pub struct FirmwareInfo {
    pub component: String,
    pub version: String,
    pub attributes: Vec<MetricLabel>,
}

#[derive(Clone, Debug)]
pub struct HealthOverride {
    pub machine_id: Option<MachineId>,
    pub report: health_report::HealthReport,
}

#[derive(Clone, Debug)]
pub enum CollectorEvent {
    MetricCollectionStart,
    Metric(MetricSample),
    MetricCollectionEnd,
    Log(LogRecord),
    Firmware(FirmwareInfo),
    HealthOverride(HealthOverride),
}
