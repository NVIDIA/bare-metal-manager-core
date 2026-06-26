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

use std::collections::HashMap;
use std::time::SystemTime;

use super::collector_logs::ExportLogsServiceRequest;
use super::collector_metrics::ExportMetricsServiceRequest;
use super::common::{AnyValue, KeyValue, any_value};
use super::logs::{LogRecord as OtlpLogRecord, ResourceLogs, ScopeLogs, SeverityNumber};
use super::metrics::{
    Gauge as OtlpGauge, Metric as OtlpMetric, NumberDataPoint, ResourceMetrics, ScopeMetrics,
    metric, number_data_point,
};
use super::resource::Resource;
use crate::endpoint::SwitchEndpointRole;
use crate::sink::{CollectorEvent, EventContext, MetricSample};

fn severity_text_to_number(severity: &str) -> i32 {
    match severity.to_uppercase().as_str() {
        "TRACE" => SeverityNumber::Trace as i32,
        "DEBUG" => SeverityNumber::Debug as i32,
        "INFO" | "INFORMATIONAL" | "OK" => SeverityNumber::Info as i32,
        "WARN" | "WARNING" => SeverityNumber::Warn as i32,
        "ERROR" | "ERR" => SeverityNumber::Error as i32,
        "FATAL" | "CRITICAL" => SeverityNumber::Fatal as i32,
        _ => SeverityNumber::Unspecified as i32,
    }
}

fn string_value(s: String) -> Option<AnyValue> {
    Some(AnyValue {
        value: Some(any_value::Value::StringValue(s)),
    })
}

fn int_value(value: i64) -> Option<AnyValue> {
    Some(AnyValue {
        value: Some(any_value::Value::IntValue(value)),
    })
}

fn kv(key: &str, val: String) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: string_value(val),
    }
}

fn int_kv(key: &str, value: i64) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: int_value(value),
    }
}

fn resource_group_key(context: &EventContext) -> String {
    format!("{}|{}", context.endpoint_key, context.collector_type)
}

fn resource_attributes(context: &EventContext) -> Vec<KeyValue> {
    let mut attrs = Vec::new();
    match context.switch_endpoint_role() {
        Some(SwitchEndpointRole::Host) => {
            attrs.push(kv("switch.endpoint", context.endpoint_key.clone()));
            attrs.push(kv("switch.ip", context.addr.ip.to_string()));
        }
        _ => {
            attrs.push(kv("bmc.endpoint", context.endpoint_key.clone()));
            attrs.push(kv("bmc.ip", context.addr.ip.to_string()));
        }
    }
    attrs.push(kv("collector.type", context.collector_type.to_string()));
    if let Some(machine_id) = context.machine_id() {
        attrs.push(kv("machine.id", machine_id.to_string()));
    }
    if let Some(switch_id) = context.switch_id() {
        attrs.push(kv("switch.id", switch_id.to_string()));
    }
    if let Some(serial) = context.switch_serial() {
        attrs.push(kv("switch.serial", serial.to_string()));
    }
    if let Some(role) = context.switch_endpoint_role() {
        let endpoint_role = match role {
            SwitchEndpointRole::Bmc => "bmc",
            SwitchEndpointRole::Host => "host",
        };
        attrs.push(kv("switch.endpoint_role", endpoint_role.to_string()));
    }
    if let Some(is_primary) = context.switch_is_primary() {
        attrs.push(KeyValue {
            key: "switch.is_primary".to_string(),
            value: Some(AnyValue {
                value: Some(any_value::Value::BoolValue(is_primary)),
            }),
        });
    }
    if let Some(rack_id) = context.rack_id() {
        attrs.push(kv("rack.id", rack_id.to_string()));
    }
    if let Some(slot) = context.slot_number() {
        attrs.push(int_kv("machine.slot_number", i64::from(slot)));
    }
    if let Some(tray) = context.tray_index() {
        attrs.push(int_kv("machine.tray_index", i64::from(tray)));
    }
    if let Some(domain) = context.nvlink_domain_uuid() {
        attrs.push(kv("nvlink.domain.uuid", domain.to_string()));
    }
    if let Some(slot) = context.switch_slot_number() {
        attrs.push(int_kv("switch.slot_number", i64::from(slot)));
    }
    if let Some(tray) = context.switch_tray_index() {
        attrs.push(int_kv("switch.tray_index", i64::from(tray)));
    }
    attrs
}

fn convert_log(log: &crate::sink::LogRecord, observed_nanos: u64) -> OtlpLogRecord {
    let attributes = log
        .attributes
        .iter()
        .map(|(k, v)| kv(k, v.clone()))
        .collect();

    OtlpLogRecord {
        time_unix_nano: observed_nanos,
        observed_time_unix_nano: observed_nanos,
        severity_number: severity_text_to_number(&log.severity),
        severity_text: log.severity.clone(),
        body: string_value(log.body.clone()),
        attributes,
        ..Default::default()
    }
}

fn convert_event(event: &CollectorEvent, observed_nanos: u64) -> Option<OtlpLogRecord> {
    match event {
        CollectorEvent::Log(log) => Some(convert_log(log, observed_nanos)),
        CollectorEvent::HealthReport(report) => {
            let body = format!(
                "health report: {} alerts, {} ok (source: {:?})",
                report.alerts.len(),
                report.successes.len(),
                report.source,
            );
            let severity = if report.alerts.is_empty() {
                "INFO"
            } else {
                "WARN"
            };
            Some(OtlpLogRecord {
                time_unix_nano: observed_nanos,
                observed_time_unix_nano: observed_nanos,
                severity_number: severity_text_to_number(severity),
                severity_text: severity.to_string(),
                body: string_value(body),
                attributes: vec![kv("event.type", "health_report".to_string())],
                ..Default::default()
            })
        }
        CollectorEvent::Firmware(info) => {
            let body = format!("{}: {}", info.component, info.version);
            Some(OtlpLogRecord {
                time_unix_nano: observed_nanos,
                observed_time_unix_nano: observed_nanos,
                severity_number: SeverityNumber::Info as i32,
                severity_text: "INFO".to_string(),
                body: string_value(body),
                attributes: vec![kv("event.type", "firmware".to_string())],
                ..Default::default()
            })
        }
        CollectorEvent::Metric(_)
        | CollectorEvent::MetricCollectionStart
        | CollectorEvent::MetricCollectionEnd
        | CollectorEvent::CollectorRemoved => None,
    }
}

/// Builds an OTLP log export request grouped by endpoint.
pub fn build_export_request(batch: &[(EventContext, CollectorEvent)]) -> ExportLogsServiceRequest {
    let observed_nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let mut by_endpoint: HashMap<String, (Vec<KeyValue>, Vec<OtlpLogRecord>)> = HashMap::new();

    for (context, event) in batch {
        let Some(record) = convert_event(event, observed_nanos) else {
            continue;
        };
        by_endpoint
            .entry(resource_group_key(context))
            .or_insert_with(|| (resource_attributes(context), Vec::new()))
            .1
            .push(record);
    }

    let resource_logs = by_endpoint
        .into_values()
        .map(|(attrs, records)| ResourceLogs {
            resource: Some(Resource {
                attributes: attrs,
                dropped_attributes_count: 0,
            }),
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: records,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        })
        .collect();

    ExportLogsServiceRequest { resource_logs }
}

/// Builds an OTLP metric export request grouped by endpoint.
///
/// Every sample maps to an OTLP `Gauge` point; Sum and Histogram mapping can
/// be added when the health metric model exposes those temporality choices.
pub fn build_metrics_export_request(
    batch: &[(EventContext, MetricSample)],
) -> ExportMetricsServiceRequest {
    let observed_nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let mut by_endpoint: HashMap<String, (Vec<KeyValue>, Vec<OtlpMetric>)> = HashMap::new();

    for (context, sample) in batch {
        let data_point = NumberDataPoint {
            attributes: sample
                .labels
                .iter()
                .map(|(k, v)| kv(k, v.clone()))
                .collect(),
            time_unix_nano: observed_nanos,
            value: Some(number_data_point::Value::AsDouble(sample.value)),
            ..Default::default()
        };

        let otlp_metric = OtlpMetric {
            name: sample.metric_type.clone(),
            description: String::new(),
            unit: sample.unit.clone(),
            data: Some(metric::Data::Gauge(OtlpGauge {
                data_points: vec![data_point],
            })),
            ..Default::default()
        };

        by_endpoint
            .entry(resource_group_key(context))
            .or_insert_with(|| (resource_attributes(context), Vec::new()))
            .1
            .push(otlp_metric);
    }

    let resource_metrics = by_endpoint
        .into_values()
        .map(|(attrs, metrics)| ResourceMetrics {
            resource: Some(Resource {
                attributes: attrs,
                dropped_attributes_count: 0,
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: None,
                metrics,
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        })
        .collect();

    ExportMetricsServiceRequest { resource_metrics }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use carbide_uuid::nvlink::NvLinkDomainId;
    use carbide_uuid::rack::RackId;
    use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::{BmcAddr, EndpointMetadata, MachineData, SwitchData, SwitchEndpointRole};
    use crate::sink::{
        Classification, HealthReport, HealthReportAlert, LogRecord, Probe, ReportSource,
    };

    fn test_context() -> EventContext {
        EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").expect("valid mac"),
            },
            collector_type: "test",
            metadata: None,
            rack_id: None,
        }
    }

    fn test_switch_id(label: &str) -> SwitchId {
        let mut hash = [0u8; 32];
        let bytes = label.as_bytes();
        hash[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        SwitchId::new(SwitchIdSource::Tpm, hash, SwitchType::NvLink)
    }

    fn attr_value<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a str> {
        attrs
            .iter()
            .find(|attr| attr.key == key)
            .and_then(|attr| attr.value.as_ref())
            .and_then(|value| match value.value.as_ref()? {
                any_value::Value::StringValue(value) => Some(value.as_str()),
                _ => None,
            })
    }

    fn attr_int_value(attrs: &[KeyValue], key: &str) -> Option<i64> {
        attrs
            .iter()
            .find(|attr| attr.key == key)
            .and_then(|attr| attr.value.as_ref())
            .and_then(|value| match value.value.as_ref()? {
                any_value::Value::IntValue(value) => Some(*value),
                _ => None,
            })
    }

    fn attr_bool_value(attrs: &[KeyValue], key: &str) -> Option<bool> {
        attrs
            .iter()
            .find(|attr| attr.key == key)
            .and_then(|attr| attr.value.as_ref())
            .and_then(|value| match value.value.as_ref()? {
                any_value::Value::BoolValue(value) => Some(*value),
                _ => None,
            })
    }

    #[test]
    fn resource_attributes_include_machine_metadata_when_present() {
        let domain_uuid = NvLinkDomainId::nil();
        let context = EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").expect("valid mac"),
            },
            collector_type: "test",
            metadata: Some(EndpointMetadata::Machine(MachineData {
                machine_id: "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0"
                    .parse()
                    .expect("valid machine id"),
                machine_serial: None,
                slot_number: Some(15),
                tray_index: Some(5),
                nvlink_domain_uuid: Some(domain_uuid),
            })),
            rack_id: Some(RackId::new("RACK_1")),
        };

        let attrs = resource_attributes(&context);

        assert_eq!(attr_value(&attrs, "rack.id"), Some("RACK_1"));
        assert_eq!(attr_int_value(&attrs, "machine.slot_number"), Some(15));
        assert_eq!(attr_int_value(&attrs, "machine.tray_index"), Some(5));
        assert_eq!(
            attr_value(&attrs, "nvlink.domain.uuid"),
            Some("00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn resource_attributes_include_switch_placement_metadata_when_present() {
        let switch_id = test_switch_id("switch-a");
        let switch_id_attr = switch_id.to_string();
        let context = EventContext {
            endpoint_key: "11:22:33:44:55:66".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
                port: Some(443),
                mac: MacAddress::from_str("11:22:33:44:55:66").expect("valid mac"),
            },
            collector_type: "test",
            metadata: Some(EndpointMetadata::Switch(SwitchData {
                id: Some(switch_id),
                serial: "SN-SWITCH-001".to_string(),
                slot_number: Some(7),
                tray_index: Some(3),
                endpoint_role: SwitchEndpointRole::Host,
                is_primary: false,
                nmxt_enabled: false,
            })),
            rack_id: Some(RackId::new("RACK_2")),
        };

        let attrs = resource_attributes(&context);

        assert_eq!(
            attr_value(&attrs, "switch.id"),
            Some(switch_id_attr.as_str())
        );
        assert_eq!(attr_value(&attrs, "rack.id"), Some("RACK_2"));
        assert_eq!(attr_int_value(&attrs, "switch.slot_number"), Some(7));
        assert_eq!(attr_int_value(&attrs, "switch.tray_index"), Some(3));
    }

    #[test]
    fn switch_host_resource_uses_switch_endpoint_identity() {
        let switch_id = test_switch_id("switch-host");
        let switch_id_attr = switch_id.to_string();
        let context = EventContext {
            endpoint_key: "11:22:33:44:55:66".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
                port: Some(443),
                mac: MacAddress::from_str("11:22:33:44:55:66").expect("valid mac"),
            },
            collector_type: "nvue_gnmi",
            metadata: Some(EndpointMetadata::Switch(SwitchData {
                id: Some(switch_id),
                serial: "SN-SWITCH-001".to_string(),
                slot_number: Some(7),
                tray_index: Some(3),
                endpoint_role: SwitchEndpointRole::Host,
                is_primary: true,
                nmxt_enabled: true,
            })),
            rack_id: Some(RackId::new("RACK_2")),
        };

        let attrs = resource_attributes(&context);

        assert_eq!(attr_value(&attrs, "bmc.endpoint"), None);
        assert_eq!(attr_value(&attrs, "bmc.ip"), None);
        assert_eq!(
            attr_value(&attrs, "switch.endpoint"),
            Some("11:22:33:44:55:66")
        );
        assert_eq!(attr_value(&attrs, "switch.ip"), Some("10.0.1.1"));
        assert_eq!(
            attr_value(&attrs, "switch.id"),
            Some(switch_id_attr.as_str())
        );
        assert_eq!(attr_value(&attrs, "switch.serial"), Some("SN-SWITCH-001"));
        assert_eq!(attr_value(&attrs, "switch.endpoint_role"), Some("host"));
        assert_eq!(attr_bool_value(&attrs, "switch.is_primary"), Some(true));
        assert_eq!(attr_int_value(&attrs, "switch.slot_number"), Some(7));
        assert_eq!(attr_int_value(&attrs, "switch.tray_index"), Some(3));
        assert_eq!(attr_value(&attrs, "nvlink.domain.uuid"), None);
        assert_eq!(attr_value(&attrs, "rack.id"), Some("RACK_2"));
        assert_eq!(attr_value(&attrs, "collector.type"), Some("nvue_gnmi"));
    }

    #[test]
    fn switch_bmc_resource_keeps_bmc_endpoint_identity_and_switch_metadata() {
        let switch_id = test_switch_id("switch-bmc");
        let switch_id_attr = switch_id.to_string();
        let context = EventContext {
            endpoint_key: "22:33:44:55:66:77".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)),
                port: Some(443),
                mac: MacAddress::from_str("22:33:44:55:66:77").expect("valid mac"),
            },
            collector_type: "sensor_collector",
            metadata: Some(EndpointMetadata::Switch(SwitchData {
                id: Some(switch_id),
                serial: "SN-SWITCH-BMC-001".to_string(),
                slot_number: Some(8),
                tray_index: Some(4),
                endpoint_role: SwitchEndpointRole::Bmc,
                is_primary: false,
                nmxt_enabled: false,
            })),
            rack_id: Some(RackId::new("RACK_3")),
        };

        let attrs = resource_attributes(&context);

        assert_eq!(
            attr_value(&attrs, "bmc.endpoint"),
            Some("22:33:44:55:66:77")
        );
        assert_eq!(attr_value(&attrs, "bmc.ip"), Some("10.0.2.1"));
        assert_eq!(attr_value(&attrs, "switch.endpoint"), None);
        assert_eq!(attr_value(&attrs, "switch.ip"), None);
        assert_eq!(
            attr_value(&attrs, "switch.id"),
            Some(switch_id_attr.as_str())
        );
        assert_eq!(
            attr_value(&attrs, "switch.serial"),
            Some("SN-SWITCH-BMC-001")
        );
        assert_eq!(attr_value(&attrs, "switch.endpoint_role"), Some("bmc"));
        assert_eq!(attr_bool_value(&attrs, "switch.is_primary"), Some(false));
        assert_eq!(attr_value(&attrs, "nvlink.domain.uuid"), None);
    }

    #[test]
    fn log_event_converts_to_otlp_record() {
        let ctx = test_context();
        let log = CollectorEvent::Log(Box::new(LogRecord {
            body: "something happened".to_string(),
            severity: "WARNING".to_string(),
            attributes: vec![(Cow::Borrowed("entry_id"), "42".to_string())],
            diagnostic_record: None,
        }));

        let request = build_export_request(&[(ctx, log)]);
        assert_eq!(request.resource_logs.len(), 1);

        let records = &request.resource_logs[0].scope_logs[0].log_records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].severity_text, "WARNING");
        assert_eq!(records[0].severity_number, SeverityNumber::Warn as i32);
    }

    /// Verifies OTLP conversion preserves an already-emitted diagnostic log.
    #[test]
    fn diagnostic_log_event_preserves_diagnostic_body_and_attributes() {
        let ctx = test_context();
        let body = concat!(
            r#"{"message":"parent message","#,
            r#""diagnostic_data":"opaque-base64-payload","#,
            r#""diagnostic_attributes":["#,
            r#"{"key":"redfish.diagnostic_data.type","value":"cper"},"#,
            r#"{"key":"redfish.parent.log_entry_id","value":"42"}]}"#
        );

        let log = CollectorEvent::Log(Box::new(LogRecord {
            body: body.to_string(),
            severity: "WARN".to_string(),
            attributes: vec![
                (
                    Cow::Borrowed("redfish.diagnostic_data.type"),
                    "cper".to_string(),
                ),
                (
                    Cow::Borrowed("redfish.parent.log_entry_id"),
                    "42".to_string(),
                ),
            ],
            diagnostic_record: None,
        }));

        let request = build_export_request(&[(ctx, log)]);

        let records = &request.resource_logs[0].scope_logs[0].log_records;
        let record = &records[0];

        assert_eq!(
            record.body.as_ref().and_then(|body| body.value.as_ref()),
            Some(&any_value::Value::StringValue(body.to_string()))
        );
        assert_eq!(
            attr_value(&record.attributes, "redfish.diagnostic_data.type"),
            Some("cper")
        );
        assert_eq!(
            attr_value(&record.attributes, "redfish.parent.log_entry_id"),
            Some("42")
        );
    }

    #[test]
    fn metric_events_are_filtered_out() {
        let ctx = test_context();
        let batch = vec![
            (ctx.clone(), CollectorEvent::MetricCollectionStart),
            (ctx, CollectorEvent::MetricCollectionEnd),
        ];
        let request = build_export_request(&batch);
        assert!(request.resource_logs.is_empty());
    }

    #[test]
    fn health_report_converts_with_alert_severity() {
        let ctx = test_context();
        let report = CollectorEvent::HealthReport(
            HealthReport {
                source: ReportSource::BmcSensors,
                target: None,
                observed_at: None,
                successes: vec![],
                alerts: vec![HealthReportAlert {
                    probe_id: Probe::Sensor,
                    target: Some("Temp1".to_string()),
                    message: "critical".to_string(),
                    classifications: vec![Classification::SensorCritical],
                }],
            }
            .into(),
        );

        let request = build_export_request(&[(ctx, report)]);
        let records = &request.resource_logs[0].scope_logs[0].log_records;
        assert_eq!(records[0].severity_text, "WARN");
    }

    #[test]
    fn events_grouped_by_endpoint() {
        let ctx1 = EventContext {
            endpoint_key: "endpoint-a".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").expect("valid mac"),
            },
            collector_type: "test",
            metadata: None,
            rack_id: None,
        };
        let ctx2 = EventContext {
            endpoint_key: "endpoint-b".to_string(),
            ..ctx1.clone()
        };

        let log = |ctx| {
            (
                ctx,
                CollectorEvent::Log(Box::new(LogRecord {
                    body: "x".to_string(),
                    severity: "INFO".to_string(),
                    attributes: vec![],
                    diagnostic_record: None,
                })),
            )
        };

        let batch = vec![log(ctx1.clone()), log(ctx2), log(ctx1)];
        let request = build_export_request(&batch);

        assert_eq!(request.resource_logs.len(), 2);
        let total_records: usize = request
            .resource_logs
            .iter()
            .flat_map(|rl| &rl.scope_logs)
            .map(|sl| sl.log_records.len())
            .sum();
        assert_eq!(total_records, 3);
    }

    #[test]
    fn metric_resources_are_grouped_by_endpoint_and_collector() {
        let base_ctx = test_context();
        let rest_ctx = EventContext {
            collector_type: "nvue_rest",
            ..base_ctx.clone()
        };
        let gnmi_ctx = EventContext {
            collector_type: "nvue_gnmi",
            ..base_ctx
        };
        let sample = |name: &str| MetricSample {
            key: "status:swp1".to_string(),
            name: name.to_string(),
            metric_type: "interface_oper_status".to_string(),
            unit: "state".to_string(),
            value: 1.0,
            labels: vec![(Cow::Borrowed("interface_name"), "swp1".to_string())],
            context: None,
        };

        let request = build_metrics_export_request(&[
            (rest_ctx, sample("nvue_rest")),
            (gnmi_ctx, sample("nvue_gnmi")),
        ]);

        let collector_types: std::collections::HashSet<_> = request
            .resource_metrics
            .iter()
            .filter_map(|resource_metrics| resource_metrics.resource.as_ref())
            .filter_map(|resource| attr_value(&resource.attributes, "collector.type"))
            .collect();

        assert_eq!(request.resource_metrics.len(), 2);
        assert!(collector_types.contains("nvue_rest"));
        assert!(collector_types.contains("nvue_gnmi"));
    }

    #[test]
    fn metric_export_name_uses_metric_type() {
        let ctx = test_context();
        let sample = MetricSample {
            key: "asic0/oper_status".to_string(),
            name: "nvue_gnmi".to_string(),
            metric_type: "interface_oper_status".to_string(),
            unit: "state".to_string(),
            value: 1.0,
            labels: vec![(Cow::Borrowed("path"), "/system/state".to_string())],
            context: None,
        };

        let request = build_metrics_export_request(&[(ctx, sample)]);
        let metrics = &request.resource_metrics[0].scope_metrics[0].metrics;

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].name, "interface_oper_status");
        assert_eq!(metrics[0].unit, "state");
    }
}
