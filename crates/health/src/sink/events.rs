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
use carbide_uuid::nvlink::NvLinkDomainId;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthProbeSuccess,
    HealthReport as CarbideHealthReport, HealthReportConversionError,
};
use nv_redfish::resource::Health as BmcHealth;

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
    BmcLeakDetectors,
    TrayLeakDetection,
    RackLeakDetection,
}

impl ReportSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BmcSensors => "bmc-sensors",
            Self::BmcLeakDetectors => "bmc-leak-detectors",
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use carbide_test_support::{Check, check_values};
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
        check_values(
            [
                Check {
                    scenario: "BMC sensors",
                    input: ReportSource::BmcSensors,
                    expect: "bmc-sensors",
                },
                Check {
                    scenario: "BMC leak detectors",
                    input: ReportSource::BmcLeakDetectors,
                    expect: "bmc-leak-detectors",
                },
                Check {
                    scenario: "tray leak detection",
                    input: ReportSource::TrayLeakDetection,
                    expect: "tray-leak-detection",
                },
                Check {
                    scenario: "rack leak detection",
                    input: ReportSource::RackLeakDetection,
                    expect: "rack-leak-detection",
                },
            ],
            ReportSource::as_str,
        );
    }

    #[test]
    fn probe_conversions() {
        check_values(
            [
                Check {
                    scenario: "sensor",
                    input: Probe::Sensor,
                    expect: ProbeSummary {
                        as_str: "BmcSensor",
                        health_report_id: "BmcSensor".to_string(),
                    },
                },
                Check {
                    scenario: "leak detection",
                    input: Probe::LeakDetection,
                    expect: ProbeSummary {
                        as_str: "BmcLeakDetection",
                        health_report_id: "BmcLeakDetection".to_string(),
                    },
                },
            ],
            |probe| {
                let id: HealthProbeId = probe.try_into().expect("convert probe id");
                ProbeSummary {
                    as_str: probe.as_str(),
                    health_report_id: id.to_string(),
                }
            },
        );
    }

    #[test]
    fn classification_conversions() {
        check_values(
            [
                Check {
                    scenario: "sensor ok",
                    input: Classification::SensorOk,
                    expect: ClassificationSummary {
                        as_str: "SensorOk",
                        health_report_classification: "SensorOk".to_string(),
                    },
                },
                Check {
                    scenario: "sensor warning",
                    input: Classification::SensorWarning,
                    expect: ClassificationSummary {
                        as_str: "SensorWarning",
                        health_report_classification: "SensorWarning".to_string(),
                    },
                },
                Check {
                    scenario: "sensor critical",
                    input: Classification::SensorCritical,
                    expect: ClassificationSummary {
                        as_str: "SensorCritical",
                        health_report_classification: "SensorCritical".to_string(),
                    },
                },
                Check {
                    scenario: "sensor fatal",
                    input: Classification::SensorFatal,
                    expect: ClassificationSummary {
                        as_str: "SensorFatal",
                        health_report_classification: "SensorFatal".to_string(),
                    },
                },
                Check {
                    scenario: "sensor failure",
                    input: Classification::SensorFailure,
                    expect: ClassificationSummary {
                        as_str: "SensorFailure",
                        health_report_classification: "SensorFailure".to_string(),
                    },
                },
                Check {
                    scenario: "leak",
                    input: Classification::Leak,
                    expect: ClassificationSummary {
                        as_str: "Leak",
                        health_report_classification: "Leak".to_string(),
                    },
                },
                Check {
                    scenario: "leak detector",
                    input: Classification::LeakDetector,
                    expect: ClassificationSummary {
                        as_str: "LeakDetector",
                        health_report_classification: "LeakDetector".to_string(),
                    },
                },
            ],
            |classification| {
                let converted: HealthAlertClassification =
                    classification.try_into().expect("convert classification");
                ClassificationSummary {
                    as_str: classification.as_str(),
                    health_report_classification: converted.to_string(),
                }
            },
        );
    }

    #[test]
    fn health_report_is_empty_cases() {
        check_values(
            [
                Check {
                    scenario: "empty report",
                    input: HealthReport {
                        source: ReportSource::BmcSensors,
                        target: Some(HealthReportTarget::Machine),
                        observed_at: None,
                        successes: vec![],
                        alerts: vec![],
                    },
                    expect: true,
                },
                Check {
                    scenario: "success report",
                    input: HealthReport {
                        source: ReportSource::BmcSensors,
                        target: Some(HealthReportTarget::Machine),
                        observed_at: None,
                        successes: vec![HealthReportSuccess {
                            probe_id: Probe::Sensor,
                            target: None,
                        }],
                        alerts: vec![],
                    },
                    expect: false,
                },
                Check {
                    scenario: "alert report",
                    input: HealthReport {
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
                    },
                    expect: false,
                },
            ],
            |report| report.is_empty(),
        );
    }

    #[test]
    fn health_report_success_conversion() {
        check_values(
            [
                Check {
                    scenario: "success with target",
                    input: HealthReportSuccess {
                        probe_id: Probe::Sensor,
                        target: Some("fan0".to_string()),
                    },
                    expect: ("BmcSensor".to_string(), Some("fan0".to_string())),
                },
                Check {
                    scenario: "success without target",
                    input: HealthReportSuccess {
                        probe_id: Probe::LeakDetection,
                        target: None,
                    },
                    expect: ("BmcLeakDetection".to_string(), None),
                },
            ],
            |success| {
                let converted: HealthProbeSuccess = (&success).try_into().expect("convert success");
                (converted.id.to_string(), converted.target)
            },
        );
    }

    #[test]
    fn health_report_alert_conversion() {
        check_values(
            [
                Check {
                    scenario: "alert with target",
                    input: AlertCase::WithTarget,
                    expect: AlertSummary {
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
                },
                Check {
                    scenario: "alert without classifications",
                    input: AlertCase::WithoutClassifications,
                    expect: AlertSummary {
                        id: "BmcLeakDetection".to_string(),
                        target: None,
                        message: "rack leak".to_string(),
                        tenant_message: None,
                        in_alert_since: false,
                        classifications: vec!["Hardware".to_string()],
                    },
                },
            ],
            convert_alert,
        );
    }

    #[test]
    fn health_report_conversion() {
        check_values(
            [
                Check {
                    scenario: "report with success, alert, and rack target",
                    input: ReportCase::Rack,
                    expect: expected_converted_report(),
                },
                Check {
                    scenario: "report with success and alert but no report target",
                    input: ReportCase::Untargeted,
                    expect: expected_converted_report(),
                },
            ],
            convert_report,
        );
    }

    #[test]
    fn event_context_accessors() {
        check_values(
            [
                Check {
                    scenario: "empty metadata",
                    input: ContextKind::Empty,
                    expect: ContextSummary {
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
                },
                Check {
                    scenario: "machine metadata",
                    input: ContextKind::Machine,
                    expect: ContextSummary {
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
                },
                Check {
                    scenario: "switch metadata",
                    input: ContextKind::Switch,
                    expect: ContextSummary {
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
                },
                Check {
                    scenario: "power shelf metadata",
                    input: ContextKind::PowerShelf,
                    expect: ContextSummary {
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
                },
            ],
            |kind| summarize_context(context(kind)),
        );
    }
}
