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

use std::sync::Arc;

use carbide_uuid::machine::MachineId;

use crate::endpoint::{BmcAddr, BmcEndpoint, EndpointMetadata};
use crate::metrics::MetricLabel;

#[derive(Clone, Debug)]
pub struct EventContext {
    pub addr: BmcAddr,
    pub collector_type: &'static str,
    pub metadata: Option<EndpointMetadata>,
}

impl EventContext {
    pub fn from_endpoint(endpoint: &BmcEndpoint, collector_type: &'static str) -> Self {
        Self {
            addr: endpoint.addr.clone(),
            collector_type,
            metadata: endpoint.metadata.clone(),
        }
    }

    pub fn endpoint_key(&self) -> &str {
        self.addr.hash_key()
    }

    pub fn machine_id(&self) -> Option<MachineId> {
        match &self.metadata {
            Some(EndpointMetadata::Machine(machine)) => Some(machine.machine_id),
            _ => None,
        }
    }

    pub fn switch_serial(&self) -> Option<&str> {
        match &self.metadata {
            Some(EndpointMetadata::Switch(switch)) => Some(switch.serial.as_str()),
            _ => None,
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
    pub report: Arc<health_report::HealthReport>,
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
