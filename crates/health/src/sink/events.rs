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
use carbide_uuid::rack::RackId;
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthProbeSuccess,
    HealthReport as CarbideHealthReport, HealthReportConversionError,
};
use nv_redfish::resource::Health as BmcHealth;

use crate::endpoint::{BmcAddr, BmcEndpoint, EndpointMetadata};
use crate::metrics::MetricLabel;

#[derive(Clone, Debug)]
pub struct EventContext {
    pub endpoint_key: String,
    pub addr: BmcAddr,
    pub collector_type: &'static str,
    pub metadata: Option<EndpointMetadata>,
    pub rack_id: Option<RackId>,
}

impl EventContext {
    pub fn from_endpoint(endpoint: &BmcEndpoint, collector_type: &'static str) -> Self {
        Self {
            endpoint_key: endpoint.hash_key().into_owned(),
            addr: endpoint.addr.clone(),
            collector_type,
            metadata: endpoint.metadata.clone(),
            rack_id: endpoint.rack_id.clone(),
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

    pub fn serial_number(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .and_then(EndpointMetadata::serial_number)
    }

    pub fn rack_id(&self) -> Option<&RackId> {
        self.rack_id.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct SensorHealthContext {
    pub entity_type: String,
    pub sensor_id: String,
    pub upper_fatal: Option<f64>,
    pub lower_fatal: Option<f64>,
    pub upper_critical: Option<f64>,
    pub lower_critical: Option<f64>,
    pub upper_caution: Option<f64>,
    pub lower_caution: Option<f64>,
    pub range_max: Option<f64>,
    pub range_min: Option<f64>,
    pub bmc_health: BmcHealth,
}

#[derive(Clone, Debug)]
pub struct SensorHealthData {
    pub key: String,
    pub name: String,
    pub metric_type: String,
    pub unit: String,
    pub value: f64,
    pub labels: Vec<MetricLabel>,
    pub context: Option<SensorHealthContext>,
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
    pub probe_id: Probe,
    pub target: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HealthReportAlert {
    pub probe_id: Probe,
    pub target: Option<String>,
    pub message: String,
    pub classifications: Vec<Classification>,
}

#[derive(Clone, Debug)]
pub struct HealthReport {
    pub source: ReportSource,
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub successes: Vec<HealthReportSuccess>,
    pub alerts: Vec<HealthReportAlert>,
}

#[derive(Clone, Debug)]
pub enum CollectorEvent {
    MetricCollectionStart,
    Metric(Box<SensorHealthData>),
    MetricCollectionEnd,
    Log(Box<LogRecord>),
    Firmware(FirmwareInfo),
    HealthReport(Arc<HealthReport>),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ReportSource {
    BmcSensors,
    TrayLeakDetection,
    RackLeakDetection,
}

impl ReportSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BmcSensors => "bmc-sensors",
            Self::TrayLeakDetection => "tray-leak-detection",
            Self::RackLeakDetection => "rack-leak-detection",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Probe {
    Sensor,
    LeakDetection,
}

impl Probe {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sensor => "BmcSensor",
            Self::LeakDetection => "BmcLeakDetection",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Classification {
    SensorOk,
    SensorWarning,
    SensorCritical,
    SensorFatal,
    SensorFailure,
    Leak,
    LeakDetector,
}

impl Classification {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SensorOk => "SensorOk",
            Self::SensorWarning => "SensorWarning",
            Self::SensorCritical => "SensorCritical",
            Self::SensorFatal => "SensorFatal",
            Self::SensorFailure => "SensorFailure",
            Self::Leak => "Leak",
            Self::LeakDetector => "LeakDetector",
        }
    }
}

impl TryFrom<Probe> for HealthProbeId {
    type Error = HealthReportConversionError;

    fn try_from(value: Probe) -> Result<Self, Self::Error> {
        value.as_str().parse()
    }
}

impl TryFrom<Classification> for HealthAlertClassification {
    type Error = HealthReportConversionError;

    fn try_from(value: Classification) -> Result<Self, Self::Error> {
        value.as_str().parse()
    }
}

impl TryFrom<&HealthReportSuccess> for HealthProbeSuccess {
    type Error = HealthReportConversionError;

    fn try_from(value: &HealthReportSuccess) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.probe_id.try_into()?,
            target: value.target.clone(),
        })
    }
}

impl TryFrom<&HealthReportAlert> for HealthProbeAlert {
    type Error = HealthReportConversionError;

    fn try_from(value: &HealthReportAlert) -> Result<Self, Self::Error> {
        let classifications = value
            .classifications
            .iter()
            .copied()
            .map(TryInto::try_into)
            // Marks report as Hardware, used to filter all reports coming from health service.
            .chain(Some(Ok(HealthAlertClassification::hardware())))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            id: value.probe_id.try_into()?,
            target: value.target.clone(),
            in_alert_since: None,
            message: value.message.clone(),
            tenant_message: None,
            classifications,
        })
    }
}

impl TryFrom<&HealthReport> for CarbideHealthReport {
    type Error = HealthReportConversionError;

    fn try_from(value: &HealthReport) -> Result<Self, Self::Error> {
        let source = format!("hardware-health.{}", value.source.as_str());

        Ok(Self {
            source,
            triggered_by: None,
            observed_at: value.observed_at,
            successes: value
                .successes
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            alerts: value
                .alerts
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}
