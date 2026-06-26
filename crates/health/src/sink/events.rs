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
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use carbide_uuid::nvlink::NvLinkDomainId;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthProbeSuccess,
    HealthReport as CarbideHealthReport, HealthReportConversionError,
};
use nv_redfish::resource::Health as BmcHealth;
use serde::Serialize;

use crate::endpoint::{BmcAddr, BmcEndpoint, EndpointMetadata, SwitchEndpointRole};
use crate::metrics::MetricLabel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthReportTarget {
    Machine,
    PowerShelf,
    Rack,
    Switch,
}

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
            endpoint_key: endpoint.key(),
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

    pub fn slot_number(&self) -> Option<i32> {
        match &self.metadata {
            Some(EndpointMetadata::Machine(machine)) => machine.slot_number,
            _ => None,
        }
    }

    pub fn tray_index(&self) -> Option<i32> {
        match &self.metadata {
            Some(EndpointMetadata::Machine(machine)) => machine.tray_index,
            _ => None,
        }
    }

    pub fn nvlink_domain_uuid(&self) -> Option<NvLinkDomainId> {
        match &self.metadata {
            Some(EndpointMetadata::Machine(machine)) => machine.nvlink_domain_uuid,
            _ => None,
        }
    }

    pub fn switch_id(&self) -> Option<SwitchId> {
        match &self.metadata {
            Some(EndpointMetadata::Switch(switch)) => switch.id,
            _ => None,
        }
    }

    pub fn switch_serial(&self) -> Option<&str> {
        match &self.metadata {
            Some(EndpointMetadata::Switch(switch)) => Some(switch.serial.as_str()),
            _ => None,
        }
    }

    pub fn switch_endpoint_role(&self) -> Option<SwitchEndpointRole> {
        match &self.metadata {
            Some(EndpointMetadata::Switch(switch)) => Some(switch.endpoint_role),
            _ => None,
        }
    }

    pub fn switch_is_primary(&self) -> Option<bool> {
        match &self.metadata {
            Some(EndpointMetadata::Switch(switch)) => Some(switch.is_primary),
            _ => None,
        }
    }

    pub fn switch_slot_number(&self) -> Option<i32> {
        match &self.metadata {
            Some(EndpointMetadata::Switch(switch)) => switch.slot_number,
            _ => None,
        }
    }

    pub fn switch_tray_index(&self) -> Option<i32> {
        match &self.metadata {
            Some(EndpointMetadata::Switch(switch)) => switch.tray_index,
            _ => None,
        }
    }

    pub fn power_shelf_id(&self) -> Option<PowerShelfId> {
        match &self.metadata {
            Some(EndpointMetadata::PowerShelf(power_shelf)) => power_shelf.id,
            _ => None,
        }
    }

    pub fn health_report_target(&self) -> Option<HealthReportTarget> {
        match self.metadata {
            Some(EndpointMetadata::Machine(_)) => Some(HealthReportTarget::Machine),
            Some(EndpointMetadata::PowerShelf(_)) => Some(HealthReportTarget::PowerShelf),
            Some(EndpointMetadata::Switch(_)) => Some(HealthReportTarget::Switch),
            None => None,
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
pub struct SensorThresholdContext {
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
pub struct MetricSample {
    pub key: String,
    pub name: String,
    pub metric_type: String,
    pub unit: String,
    pub value: f64,
    pub labels: Vec<MetricLabel>,
    pub context: Option<SensorThresholdContext>,
}

/// Log event emitted by collectors and consumed by sinks.
#[derive(Clone, Debug)]
pub struct LogRecord {
    /// Human-readable log message or emitted structured body.
    pub body: String,

    /// Source-provided severity text.
    pub severity: String,

    /// Sink-visible metadata used for filtering, grouping, and correlation.
    pub attributes: Vec<MetricLabel>,

    /// Optional diagnostic payload carrier kept separate until a sink opts in.
    pub diagnostic_record: Option<DiagnosticLogRecord>,
}

impl LogRecord {
    /// Converts the collector-internal log record into the record a sink emits.
    ///
    /// Diagnostic payloads stay in a separate carrier until this boundary so
    /// sinks can drop them by default. When diagnostics are enabled, the
    /// opaque payload is embedded in the log body and diagnostic metadata is
    /// retained as attributes for filtering and correlation.
    /// Records without a diagnostic carrier are borrowed unchanged.
    pub(crate) fn emitted_log_record(&self, include_diagnostics: bool) -> Cow<'_, Self> {
        let Some(diagnostic_record) = &self.diagnostic_record else {
            return Cow::Borrowed(self);
        };

        /// Serializes parent and diagnostic fields into an emitted log body.
        fn diagnostic_body(
            message: &str,
            diagnostic_record: &DiagnosticLogRecord,
        ) -> Option<String> {
            let diagnostic_data = if diagnostic_record.body.is_empty() {
                None
            } else {
                Some(diagnostic_record.body.as_str())
            };

            let diagnostic_attributes = diagnostic_record
                .attributes
                .iter()
                .map(|(key, value)| DiagnosticLogBodyAttribute {
                    key: key.as_ref(),
                    value: value.as_str(),
                })
                .collect();

            let body = DiagnosticLogBody {
                message,
                diagnostic_data,
                diagnostic_attributes,
            };

            serde_json::to_string(&body).ok()
        }

        let mut body = self.body.clone();
        let mut attributes = self.attributes.clone();

        if include_diagnostics {
            if let Some(diagnostic_body) = diagnostic_body(self.body.as_str(), diagnostic_record) {
                body = diagnostic_body;
            }

            attributes.extend_from_slice(&diagnostic_record.attributes);
        }

        Cow::Owned(Self {
            body,
            severity: self.severity.clone(),
            attributes,
            diagnostic_record: None,
        })
    }
}

/// Diagnostic payload attached to a primary log record.
///
/// The payload body stays opaque. Sinks that opt in fold the parent message and
/// diagnostic payload into emitted log bodies, while retaining Redfish metadata
/// as attributes for filtering and correlation.
#[derive(Clone, Debug)]
pub struct DiagnosticLogRecord {
    /// Opaque diagnostic payload body, such as base64-encoded CPER text.
    pub body: String,

    /// Redfish diagnostic metadata and parent correlation attributes.
    pub attributes: Vec<MetricLabel>,
}

/// JSON body emitted when a sink folds diagnostics into a parent log record.
#[derive(Serialize)]
struct DiagnosticLogBody<'a> {
    message: &'a str,

    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic_data: Option<&'a str>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnostic_attributes: Vec<DiagnosticLogBodyAttribute<'a>>,
}

/// Diagnostic metadata entry embedded in an emitted diagnostic log body.
#[derive(Serialize)]
struct DiagnosticLogBodyAttribute<'a> {
    key: &'a str,
    value: &'a str,
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
    pub target: Option<HealthReportTarget>,
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub successes: Vec<HealthReportSuccess>,
    pub alerts: Vec<HealthReportAlert>,
}

impl HealthReport {
    pub fn is_empty(&self) -> bool {
        self.successes.is_empty() && self.alerts.is_empty()
    }
}

#[derive(Clone, Debug)]
pub enum CollectorEvent {
    MetricCollectionStart,
    Metric(Box<MetricSample>),
    MetricCollectionEnd,
    CollectorRemoved,
    Log(Box<LogRecord>),
    Firmware(FirmwareInfo),
    HealthReport(Arc<HealthReport>),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ReportSource {
    BmcSensors,
    BmcEvents,
    BmcLeakDetectors,
    TrayLeakDetection,
    RackLeakDetection,
}

impl ReportSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BmcSensors => "bmc-sensors",
            Self::BmcEvents => "bmc-events",
            Self::BmcLeakDetectors => "bmc-leak-detectors",
            Self::TrayLeakDetection => "tray-leak-detection",
            Self::RackLeakDetection => "rack-leak-detection",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Probe {
    Sensor,
    IntrusionSensorTriggered,
    LeakDetection,
}

impl Probe {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sensor => "BmcSensor",
            Self::IntrusionSensorTriggered => "IntrusionSensorTriggered",
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
    PreventAllocations,
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
            Self::PreventAllocations => "PreventAllocations",
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use carbide_test_support::value_scenarios;
    use carbide_uuid::machine::MachineId;
    use carbide_uuid::nvlink::NvLinkDomainId;
    use carbide_uuid::power_shelf::PowerShelfId;
    use carbide_uuid::rack::RackId;
    use carbide_uuid::switch::SwitchId;
    use chrono::{TimeZone, Utc};
    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::{MachineData, PowerShelfData, SwitchData};

    #[derive(Clone, Copy)]
    enum ContextKind {
        Empty,
        Machine,
        Switch,
        PowerShelf,
    }

    #[derive(Debug, PartialEq)]
    struct ContextSummary {
        endpoint_key: String,
        machine_id: Option<String>,
        slot_number: Option<i32>,
        tray_index: Option<i32>,
        nvlink_domain_uuid: Option<String>,
        switch_id: Option<String>,
        switch_serial: Option<String>,
        switch_endpoint_role: Option<SwitchEndpointRole>,
        switch_is_primary: Option<bool>,
        switch_slot_number: Option<i32>,
        switch_tray_index: Option<i32>,
        power_shelf_id: Option<String>,
        health_report_target: Option<HealthReportTarget>,
        serial_number: Option<String>,
        rack_id: Option<String>,
    }

    #[derive(Debug, PartialEq)]
    struct ProbeSummary {
        as_str: &'static str,
        health_report_id: String,
    }

    #[derive(Debug, PartialEq)]
    struct ClassificationSummary {
        as_str: &'static str,
        health_report_classification: String,
    }

    #[derive(Clone, Copy)]
    enum AlertCase {
        WithTarget,
        Intrusion,
        WithoutClassifications,
    }

    #[derive(Clone, Copy)]
    enum ReportCase {
        Rack,
        Untargeted,
    }

    #[derive(Debug, PartialEq)]
    struct AlertSummary {
        id: String,
        target: Option<String>,
        message: String,
        tenant_message: Option<String>,
        in_alert_since: bool,
        classifications: Vec<String>,
    }

    #[derive(Debug, PartialEq)]
    struct ConvertedReportSummary {
        source: String,
        triggered_by: Option<String>,
        observed_at: Option<chrono::DateTime<Utc>>,
        successes: Vec<(String, Option<String>)>,
        alerts: Vec<AlertSummary>,
    }

    fn machine_id() -> MachineId {
        MachineId::from_str("fm100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg")
            .expect("valid machine id")
    }

    fn switch_id() -> SwitchId {
        SwitchId::from_str("sw100nt038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg")
            .expect("valid switch id")
    }

    fn power_shelf_id() -> PowerShelfId {
        PowerShelfId::from_str("ps100ht038bg3qsho433vkg684heguv282qaggmrsh2ugn1qk096n2c6hcg")
            .expect("valid power shelf id")
    }

    fn nvlink_domain_id() -> NvLinkDomainId {
        NvLinkDomainId::from_str("00000000-0000-0000-0000-000000000000")
            .expect("valid NVLink domain id")
    }

    fn addr() -> BmcAddr {
        BmcAddr {
            ip: IpAddr::from_str("10.0.0.1").expect("valid IP"),
            port: Some(443),
            mac: MacAddress::from_str("00:11:22:33:44:55").expect("valid MAC"),
        }
    }

    fn context(kind: ContextKind) -> EventContext {
        let metadata = match kind {
            ContextKind::Empty => None,
            ContextKind::Machine => Some(EndpointMetadata::Machine(MachineData {
                machine_id: machine_id(),
                machine_serial: Some("MN-001".to_string()),
                slot_number: Some(7),
                tray_index: Some(3),
                nvlink_domain_uuid: Some(nvlink_domain_id()),
            })),
            ContextKind::Switch => Some(EndpointMetadata::Switch(SwitchData {
                id: Some(switch_id()),
                serial: "SW-001".to_string(),
                slot_number: Some(9),
                tray_index: Some(4),
                endpoint_role: SwitchEndpointRole::Host,
                is_primary: true,
                nmxt_enabled: true,
            })),
            ContextKind::PowerShelf => Some(EndpointMetadata::PowerShelf(PowerShelfData {
                id: Some(power_shelf_id()),
                serial: "PS-001".to_string(),
            })),
        };

        EventContext {
            endpoint_key: "00:11:22:33:44:55".to_string(),
            addr: addr(),
            collector_type: "unit-test",
            metadata,
            rack_id: Some(RackId::new("rack-1")),
        }
    }

    fn summarize_context(context: EventContext) -> ContextSummary {
        ContextSummary {
            endpoint_key: context.endpoint_key().to_string(),
            machine_id: context.machine_id().map(|id| id.to_string()),
            slot_number: context.slot_number(),
            tray_index: context.tray_index(),
            nvlink_domain_uuid: context.nvlink_domain_uuid().map(|id| id.to_string()),
            switch_id: context.switch_id().map(|id| id.to_string()),
            switch_serial: context.switch_serial().map(str::to_string),
            switch_endpoint_role: context.switch_endpoint_role(),
            switch_is_primary: context.switch_is_primary(),
            switch_slot_number: context.switch_slot_number(),
            switch_tray_index: context.switch_tray_index(),
            power_shelf_id: context.power_shelf_id().map(|id| id.to_string()),
            health_report_target: context.health_report_target(),
            serial_number: context.serial_number().map(str::to_string),
            rack_id: context.rack_id().map(|id| id.to_string()),
        }
    }

    fn summarize_alert(alert: HealthProbeAlert) -> AlertSummary {
        AlertSummary {
            id: alert.id.to_string(),
            target: alert.target,
            message: alert.message,
            tenant_message: alert.tenant_message,
            in_alert_since: alert.in_alert_since.is_some(),
            classifications: alert
                .classifications
                .into_iter()
                .map(|classification| classification.to_string())
                .collect(),
        }
    }

    fn convert_alert(case: AlertCase) -> AlertSummary {
        let alert = match case {
            AlertCase::WithTarget => HealthReportAlert {
                probe_id: Probe::Sensor,
                target: Some("fan0".to_string()),
                message: "fan warning".to_string(),
                classifications: vec![Classification::SensorWarning, Classification::SensorFailure],
            },
            AlertCase::Intrusion => HealthReportAlert {
                probe_id: Probe::IntrusionSensorTriggered,
                target: Some("HostBMC".to_string()),
                message: "Physical Chassis Intrusion Alert".to_string(),
                classifications: vec![
                    Classification::SensorCritical,
                    Classification::PreventAllocations,
                ],
            },
            AlertCase::WithoutClassifications => HealthReportAlert {
                probe_id: Probe::LeakDetection,
                target: None,
                message: "rack leak".to_string(),
                classifications: vec![],
            },
        };

        summarize_alert((&alert).try_into().expect("convert alert"))
    }

    fn convert_report(case: ReportCase) -> ConvertedReportSummary {
        let observed_at = Utc
            .with_ymd_and_hms(2026, 1, 2, 3, 4, 5)
            .single()
            .expect("valid timestamp");
        let report = HealthReport {
            source: ReportSource::RackLeakDetection,
            target: match case {
                ReportCase::Rack => Some(HealthReportTarget::Rack),
                ReportCase::Untargeted => None,
            },
            observed_at: Some(observed_at),
            successes: vec![HealthReportSuccess {
                probe_id: Probe::LeakDetection,
                target: Some("tray-1".to_string()),
            }],
            alerts: vec![HealthReportAlert {
                probe_id: Probe::Sensor,
                target: Some("temp0".to_string()),
                message: "temperature critical".to_string(),
                classifications: vec![Classification::SensorCritical],
            }],
        };
        let converted: CarbideHealthReport = (&report).try_into().expect("convert report");

        ConvertedReportSummary {
            source: converted.source,
            triggered_by: converted.triggered_by,
            observed_at: converted.observed_at,
            successes: converted
                .successes
                .into_iter()
                .map(|success| (success.id.to_string(), success.target))
                .collect(),
            alerts: converted.alerts.into_iter().map(summarize_alert).collect(),
        }
    }

    fn expected_converted_report() -> ConvertedReportSummary {
        ConvertedReportSummary {
            source: "hardware-health.rack-leak-detection".to_string(),
            triggered_by: None,
            observed_at: Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).single(),
            successes: vec![("BmcLeakDetection".to_string(), Some("tray-1".to_string()))],
            alerts: vec![AlertSummary {
                id: "BmcSensor".to_string(),
                target: Some("temp0".to_string()),
                message: "temperature critical".to_string(),
                tenant_message: None,
                in_alert_since: false,
                classifications: vec!["SensorCritical".to_string(), "Hardware".to_string()],
            }],
        }
    }

    #[test]
    fn report_source_strings() {
        value_scenarios!(
            run = ReportSource::as_str;
            "BMC sensors" {
                ReportSource::BmcSensors => "bmc-sensors",
            }

            "BMC events" {
                ReportSource::BmcEvents => "bmc-events",
            }

            "BMC leak detectors" {
                ReportSource::BmcLeakDetectors => "bmc-leak-detectors",
            }

            "tray leak detection" {
                ReportSource::TrayLeakDetection => "tray-leak-detection",
            }

            "rack leak detection" {
                ReportSource::RackLeakDetection => "rack-leak-detection",
            }
        );
    }

    #[test]
    fn probe_conversions() {
        value_scenarios!(
            run = |probe| {
                let id: HealthProbeId = probe.try_into().expect("convert probe id");
                ProbeSummary {
                    as_str: probe.as_str(),
                    health_report_id: id.to_string(),
                }
            };
            "sensor" {
                Probe::Sensor => ProbeSummary {
                    as_str: "BmcSensor",
                    health_report_id: "BmcSensor".to_string(),
                },
            }

            "intrusion sensor triggered" {
                Probe::IntrusionSensorTriggered => ProbeSummary {
                    as_str: "IntrusionSensorTriggered",
                    health_report_id: "IntrusionSensorTriggered".to_string(),
                },
            }

            "leak detection" {
                Probe::LeakDetection => ProbeSummary {
                    as_str: "BmcLeakDetection",
                    health_report_id: "BmcLeakDetection".to_string(),
                },
            }
        );
    }

    #[test]
    fn classification_conversions() {
        value_scenarios!(
            run = |classification| {
                let converted: HealthAlertClassification =
                    classification.try_into().expect("convert classification");
                ClassificationSummary {
                    as_str: classification.as_str(),
                    health_report_classification: converted.to_string(),
                }
            };
            "sensor ok" {
                Classification::SensorOk => ClassificationSummary {
                    as_str: "SensorOk",
                    health_report_classification: "SensorOk".to_string(),
                },
            }

            "sensor warning" {
                Classification::SensorWarning => ClassificationSummary {
                    as_str: "SensorWarning",
                    health_report_classification: "SensorWarning".to_string(),
                },
            }

            "sensor critical" {
                Classification::SensorCritical => ClassificationSummary {
                    as_str: "SensorCritical",
                    health_report_classification: "SensorCritical".to_string(),
                },
            }

            "sensor fatal" {
                Classification::SensorFatal => ClassificationSummary {
                    as_str: "SensorFatal",
                    health_report_classification: "SensorFatal".to_string(),
                },
            }

            "sensor failure" {
                Classification::SensorFailure => ClassificationSummary {
                    as_str: "SensorFailure",
                    health_report_classification: "SensorFailure".to_string(),
                },
            }

            "prevent allocations" {
                Classification::PreventAllocations => ClassificationSummary {
                    as_str: "PreventAllocations",
                    health_report_classification: "PreventAllocations".to_string(),
                },
            }

            "leak" {
                Classification::Leak => ClassificationSummary {
                    as_str: "Leak",
                    health_report_classification: "Leak".to_string(),
                },
            }

            "leak detector" {
                Classification::LeakDetector => ClassificationSummary {
                    as_str: "LeakDetector",
                    health_report_classification: "LeakDetector".to_string(),
                },
            }
        );
    }

    #[test]
    fn health_report_is_empty_cases() {
        value_scenarios!(
            run = |report| report.is_empty();
            "empty report" {
                HealthReport {
                    source: ReportSource::BmcSensors,
                    target: Some(HealthReportTarget::Machine),
                    observed_at: None,
                    successes: vec![],
                    alerts: vec![],
                } => true,
            }

            "success report" {
                HealthReport {
                    source: ReportSource::BmcSensors,
                    target: Some(HealthReportTarget::Machine),
                    observed_at: None,
                    successes: vec![HealthReportSuccess {
                        probe_id: Probe::Sensor,
                        target: None,
                    }],
                    alerts: vec![],
                } => false,
            }

            "alert report" {
                HealthReport {
                    source: ReportSource::BmcSensors,
                    target: Some(HealthReportTarget::Machine),
                    observed_at: None,
                    successes: vec![],
                    alerts: vec![HealthReportAlert {
                        probe_id: Probe::Sensor,
                        target: None,
                        message: "alert".to_string(),
                        classifications: vec![],
                    }],
                } => false,
            }
        );
    }

    #[test]
    fn health_report_success_conversion() {
        value_scenarios!(
            run = |success| {
                let converted: HealthProbeSuccess = (&success).try_into().expect("convert success");
                (converted.id.to_string(), converted.target)
            };
            "success with target" {
                HealthReportSuccess {
                    probe_id: Probe::Sensor,
                    target: Some("fan0".to_string()),
                } => ("BmcSensor".to_string(), Some("fan0".to_string())),
            }

            "success without target" {
                HealthReportSuccess {
                    probe_id: Probe::LeakDetection,
                    target: None,
                } => ("BmcLeakDetection".to_string(), None),
            }
        );
    }

    #[test]
    fn health_report_alert_conversion() {
        value_scenarios!(
            run = convert_alert;
            "alert with target" {
                AlertCase::WithTarget => AlertSummary {
                    id: "BmcSensor".to_string(),
                    target: Some("fan0".to_string()),
                    message: "fan warning".to_string(),
                    tenant_message: None,
                    in_alert_since: false,
                    classifications: vec![
                        "SensorWarning".to_string(),
                        "SensorFailure".to_string(),
                        "Hardware".to_string(),
                    ],
                },
            }

            "intrusion alert" {
                AlertCase::Intrusion => AlertSummary {
                    id: "IntrusionSensorTriggered".to_string(),
                    target: Some("HostBMC".to_string()),
                    message: "Physical Chassis Intrusion Alert".to_string(),
                    tenant_message: None,
                    in_alert_since: false,
                    classifications: vec![
                        "SensorCritical".to_string(),
                        "PreventAllocations".to_string(),
                        "Hardware".to_string(),
                    ],
                },
            }

            "alert without classifications" {
                AlertCase::WithoutClassifications => AlertSummary {
                    id: "BmcLeakDetection".to_string(),
                    target: None,
                    message: "rack leak".to_string(),
                    tenant_message: None,
                    in_alert_since: false,
                    classifications: vec!["Hardware".to_string()],
                },
            }
        );
    }

    #[test]
    fn health_report_conversion() {
        value_scenarios!(
            run = convert_report;
            "report with success, alert, and rack target" {
                ReportCase::Rack => expected_converted_report(),
            }

            "report with success and alert but no report target" {
                ReportCase::Untargeted => expected_converted_report(),
            }
        );
    }

    #[test]
    fn event_context_accessors() {
        value_scenarios!(
            run = |kind| summarize_context(context(kind));
            "empty metadata" {
                ContextKind::Empty => ContextSummary {
                    endpoint_key: "00:11:22:33:44:55".to_string(),
                    machine_id: None,
                    slot_number: None,
                    tray_index: None,
                    nvlink_domain_uuid: None,
                    switch_id: None,
                    switch_serial: None,
                    switch_endpoint_role: None,
                    switch_is_primary: None,
                    switch_slot_number: None,
                    switch_tray_index: None,
                    power_shelf_id: None,
                    health_report_target: None,
                    serial_number: None,
                    rack_id: Some("rack-1".to_string()),
                },
            }

            "machine metadata" {
                ContextKind::Machine => ContextSummary {
                    endpoint_key: "00:11:22:33:44:55".to_string(),
                    machine_id: Some(machine_id().to_string()),
                    slot_number: Some(7),
                    tray_index: Some(3),
                    nvlink_domain_uuid: Some(nvlink_domain_id().to_string()),
                    switch_id: None,
                    switch_serial: None,
                    switch_endpoint_role: None,
                    switch_is_primary: None,
                    switch_slot_number: None,
                    switch_tray_index: None,
                    power_shelf_id: None,
                    health_report_target: Some(HealthReportTarget::Machine),
                    serial_number: Some("MN-001".to_string()),
                    rack_id: Some("rack-1".to_string()),
                },
            }

            "switch metadata" {
                ContextKind::Switch => ContextSummary {
                    endpoint_key: "00:11:22:33:44:55".to_string(),
                    machine_id: None,
                    slot_number: None,
                    tray_index: None,
                    nvlink_domain_uuid: None,
                    switch_id: Some(switch_id().to_string()),
                    switch_serial: Some("SW-001".to_string()),
                    switch_endpoint_role: Some(SwitchEndpointRole::Host),
                    switch_is_primary: Some(true),
                    switch_slot_number: Some(9),
                    switch_tray_index: Some(4),
                    power_shelf_id: None,
                    health_report_target: Some(HealthReportTarget::Switch),
                    serial_number: Some("SW-001".to_string()),
                    rack_id: Some("rack-1".to_string()),
                },
            }

            "power shelf metadata" {
                ContextKind::PowerShelf => ContextSummary {
                    endpoint_key: "00:11:22:33:44:55".to_string(),
                    machine_id: None,
                    slot_number: None,
                    tray_index: None,
                    nvlink_domain_uuid: None,
                    switch_id: None,
                    switch_serial: None,
                    switch_endpoint_role: None,
                    switch_is_primary: None,
                    switch_slot_number: None,
                    switch_tray_index: None,
                    power_shelf_id: Some(power_shelf_id().to_string()),
                    health_report_target: Some(HealthReportTarget::PowerShelf),
                    serial_number: Some("PS-001".to_string()),
                    rack_id: Some("rack-1".to_string()),
                },
            }
        );
    }
}
