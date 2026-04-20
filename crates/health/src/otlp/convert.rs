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
use super::common::{AnyValue, KeyValue, any_value};
use super::logs::{LogRecord as OtlpLogRecord, ResourceLogs, ScopeLogs, SeverityNumber};
use super::resource::Resource;
use crate::sink::{CollectorEvent, EventContext};

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

fn kv(key: &str, val: String) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: string_value(val),
    }
}

fn resource_attributes(context: &EventContext) -> Vec<KeyValue> {
    let mut attrs = vec![
        kv("bmc.endpoint", context.endpoint_key.clone()),
        kv("bmc.ip", context.addr.ip.to_string()),
        kv("collector.type", context.collector_type.to_string()),
    ];
    if let Some(machine_id) = context.machine_id() {
        attrs.push(kv("machine.id", machine_id.to_string()));
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
        | CollectorEvent::MetricCollectionEnd => None,
    }
}

/// groups a batch of events by endpoint and builds an ExportLogsServiceRequest with only logs
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
            .entry(context.endpoint_key.clone())
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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::BmcAddr;
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

    #[test]
    fn log_event_converts_to_otlp_record() {
        let ctx = test_context();
        let log = CollectorEvent::Log(Box::new(LogRecord {
            body: "something happened".to_string(),
            severity: "WARNING".to_string(),
            attributes: vec![(Cow::Borrowed("entry_id"), "42".to_string())],
        }));

        let request = build_export_request(&[(ctx, log)]);
        assert_eq!(request.resource_logs.len(), 1);

        let records = &request.resource_logs[0].scope_logs[0].log_records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].severity_text, "WARNING");
        assert_eq!(records[0].severity_number, SeverityNumber::Warn as i32);
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
}
