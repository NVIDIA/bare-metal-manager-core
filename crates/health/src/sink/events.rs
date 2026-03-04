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

use std::borrow::Cow;

use carbide_uuid::machine::MachineId;
use nv_redfish::resource::Health as BmcHealth;

use crate::endpoint::{BmcAddr, BmcEndpoint, EndpointMetadata};
use crate::metrics::MetricLabel;

#[derive(Clone, Debug)]
pub struct EventContext {
    pub endpoint_key: String,
    pub addr: BmcAddr,
    pub collector_type: &'static str,
    pub metadata: Option<EndpointMetadata>,
}

impl EventContext {
    pub fn from_endpoint(endpoint: &BmcEndpoint, collector_type: &'static str) -> Self {
        Self {
            endpoint_key: endpoint.addr.hash_key().into_owned(),
            addr: endpoint.addr.clone(),
            collector_type,
            metadata: endpoint.metadata.clone(),
        }
    }

    pub fn endpoint_key(&self) -> &str {
        &self.endpoint_key
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
pub struct SensorHealthContext {
    pub entity_type: String,
    pub sensor_id: String,
    pub upper_critical: Option<f64>,
    pub lower_critical: Option<f64>,
    pub upper_caution: Option<f64>,
    pub lower_caution: Option<f64>,
    pub range_max: Option<f64>,
    pub range_min: Option<f64>,
    pub bmc_health: Option<BmcHealth>,
}

#[derive(Clone, Debug)]
pub struct SensorHealthData {
    pub key: String,
    pub name: String,
    pub metric_type: String,
    pub unit: String,
    pub value: f64,
    pub labels: Vec<MetricLabel>,
    pub health: Option<SensorHealthContext>,
}

impl SensorHealthData {
    pub fn from_metric_fields(
        key: String,
        name: String,
        metric_type: String,
        unit: String,
        value: f64,
        labels: Vec<MetricLabel>,
    ) -> Self {
        Self {
            key,
            name,
            metric_type,
            unit,
            value,
            labels,
            health: None,
        }
    }

    pub fn with_health_context(mut self, health: SensorHealthContext) -> Self {
        self.health = Some(health);
        self
    }

    pub fn set_label(
        &mut self,
        key: impl Into<Cow<'static, str>>,
        value: impl Into<String>,
    ) -> &mut Self {
        self.labels.push((key.into(), value.into()));
        self
    }
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
pub struct HealthReportSuccess {
    pub probe_id: String,
    pub target: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HealthReportAlert {
    pub probe_id: String,
    pub target: Option<String>,
    pub message: String,
    pub classifications: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct HealthReport {
    pub source: String,
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub successes: Vec<HealthReportSuccess>,
    pub alerts: Vec<HealthReportAlert>,
}

#[derive(Clone, Debug)]
pub enum CollectorEvent {
    MetricCollectionStart,
    Metric(SensorHealthData),
    MetricCollectionEnd,
    Log(LogRecord),
    Firmware(FirmwareInfo),
    HealthReport(HealthReport),
}
