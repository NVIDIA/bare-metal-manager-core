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

//! Redfish TelemetryService MetricReport collection.

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

use futures::{StreamExt, stream};
use nv_redfish::ServiceRoot;
use nv_redfish::core::{Bmc, EntityTypeRef};
use nv_redfish::schema::metric_report::{MetricReport, MetricValue};

use crate::HealthError;
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::config::TelemetryServiceCollectorConfig as TelemetryServiceCollectorOptions;
use crate::endpoint::BmcEndpoint;
use crate::metrics::MetricLabel;
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample};

pub struct TelemetryServiceCollectorConfig {
    pub data_sink: Option<Arc<dyn DataSink>>,
    pub options: TelemetryServiceCollectorOptions,
}

pub struct TelemetryServiceCollector<B: Bmc> {
    bmc: Arc<B>,
    event_context: EventContext,
    data_sink: Option<Arc<dyn DataSink>>,
    metric_report_ids: HashSet<String>,
    fetch_concurrency: usize,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for TelemetryServiceCollector<B> {
    type Config = TelemetryServiceCollectorConfig;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        Ok(Self {
            bmc,
            event_context: EventContext::from_endpoint(
                endpoint.as_ref(),
                "redfish_telemetry_service",
            ),
            data_sink: config.data_sink,
            metric_report_ids: config.options.metric_report_ids.into_iter().collect(),
            fetch_concurrency: config.options.fetch_concurrency.max(1),
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        self.collect_metric_reports().await
    }

    fn collector_type(&self) -> &'static str {
        "redfish_telemetry_service"
    }

    async fn stop(&mut self) {
        self.emit_event(CollectorEvent::CollectorRemoved);
    }
}

impl<B: Bmc + 'static> TelemetryServiceCollector<B> {
    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    async fn collect_metric_reports(&self) -> Result<IterationResult, HealthError> {
        let root = ServiceRoot::new(self.bmc.clone())
            .await
            .map_err(|error| HealthError::BmcError(Box::new(error)))?;

        let Some(telemetry_service) = root
            .telemetry_service()
            .await
            .map_err(|error| HealthError::BmcError(Box::new(error)))?
        else {
            tracing::debug!("BMC endpoint does not expose Redfish TelemetryService");
            return Ok(IterationResult {
                refresh_triggered: true,
                entity_count: Some(0),
                fetch_failures: 0,
            });
        };

        let Some(metric_report_links) = telemetry_service
            .metric_report_links()
            .await
            .map_err(|error| HealthError::BmcError(Box::new(error)))?
        else {
            tracing::debug!("Redfish TelemetryService has no MetricReports collection");
            return Ok(IterationResult {
                refresh_triggered: true,
                entity_count: Some(0),
                fetch_failures: 0,
            });
        };

        let requested_ids = &self.metric_report_ids;
        let fetch_concurrency = self.fetch_concurrency;
        let reports = stream::iter(metric_report_links)
            .filter(|link| {
                let include = requested_ids.is_empty()
                    || link
                        .odata_id()
                        .last_segment()
                        .is_some_and(|id| requested_ids.contains(id));
                async move { include }
            })
            .map(|link| async move {
                let report_id = link.odata_id().to_string();
                link.fetch().await.map(|report| (report_id, report))
            })
            .buffer_unordered(fetch_concurrency)
            .collect::<Vec<_>>()
            .await;

        self.emit_event(CollectorEvent::MetricCollectionStart);

        let mut sample_count = 0;
        let mut fetch_failures = 0;
        for result in reports {
            match result {
                Ok((report_uri, report)) => {
                    for sample in metric_samples_from_report(&report, &report_uri) {
                        sample_count += 1;
                        self.emit_event(CollectorEvent::Metric(sample.into()));
                    }
                }
                Err(error) => {
                    fetch_failures += 1;
                    tracing::warn!(?error, "failed to fetch Redfish MetricReport");
                }
            }
        }

        self.emit_event(CollectorEvent::MetricCollectionEnd);

        Ok(IterationResult {
            refresh_triggered: true,
            entity_count: Some(sample_count),
            fetch_failures,
        })
    }
}

fn metric_samples_from_report(report: &MetricReport, report_uri: &str) -> Vec<MetricSample> {
    let report_id = report.base.id.as_str();
    let report_definition = report
        .metric_report_definition
        .as_ref()
        .map(|reference| reference.odata_id().to_string());

    report
        .metric_values
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|metric| {
            metric_sample_from_value(report_id, report_uri, report_definition.as_deref(), metric)
        })
        .collect()
}

fn metric_sample_from_value(
    report_id: &str,
    report_uri: &str,
    report_definition: Option<&str>,
    metric: &MetricValue,
) -> Option<MetricSample> {
    let raw_value = nested_optional_str(&metric.metric_value)?;
    let metric_id = nested_optional_str(&metric.metric_id);
    let metric_property = nested_optional_str(&metric.metric_property);
    let (value, unit) = metric_value_to_f64(raw_value)?;
    let metric_identity = metric_identity(metric_id, metric_property).or_else(|| {
        tracing::warn!(
            report_id,
            report_uri,
            "Skipping Redfish MetricReport value without MetricId or MetricProperty"
        );
        None
    })?;
    let metric_type = metric_type(metric_id, metric_property)?;

    let mut labels: Vec<MetricLabel> = vec![
        (Cow::Borrowed("report_id"), report_id.to_string()),
        (Cow::Borrowed("report_uri"), report_uri.to_string()),
    ];
    if let Some(metric_id) = metric_id {
        labels.push((Cow::Borrowed("metric_id"), metric_id.to_string()));
    }
    if let Some(metric_property) = metric_property {
        labels.push((
            Cow::Borrowed("metric_property"),
            metric_property.to_string(),
        ));
    }
    if let Some(report_definition) = report_definition {
        labels.push((
            Cow::Borrowed("metric_report_definition"),
            report_definition.to_string(),
        ));
    }
    labels.push((Cow::Borrowed("metric_identity"), metric_identity));
    let key = metric_sample_key(report_id, metric_id, metric_property)?;
    Some(MetricSample {
        key,
        name: "redfish_telemetry_service".to_string(),
        metric_type,
        unit,
        value,
        labels,
        context: None,
    })
}

fn nested_optional_str(value: &Option<Option<String>>) -> Option<&str> {
    value.as_ref().and_then(|inner| inner.as_deref())
}

fn metric_value_to_f64(raw: &str) -> Option<(f64, String)> {
    if raw.eq_ignore_ascii_case("true") {
        return Some((1.0, "state".to_string()));
    }
    if raw.eq_ignore_ascii_case("false") {
        return Some((0.0, "state".to_string()));
    }
    if let Ok(value) = raw.parse::<f64>() {
        return value.is_finite().then_some((value, "value".to_string()));
    }

    Some((1.0, "info".to_string()))
}

fn metric_identity(metric_id: Option<&str>, metric_property: Option<&str>) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(metric_id) = metric_id.and_then(non_empty) {
        let token = sanitize_metric_token(metric_id);
        if !token.is_empty() {
            parts.push(format!("metric_id:{token}"));
        }
    }
    if let Some(metric_property) = metric_property.and_then(non_empty) {
        let token = sanitize_metric_token(metric_property);
        if !token.is_empty() {
            parts.push(format!("metric_property:{token}"));
        }
    }
    (!parts.is_empty()).then(|| parts.join(":"))
}

fn metric_sample_key(
    report_id: &str,
    metric_id: Option<&str>,
    metric_property: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(metric_id) = metric_id.and_then(non_empty) {
        parts.push(format!(
            "metric_id={}",
            escape_metric_key_component(metric_id)
        ));
    }
    if let Some(metric_property) = metric_property.and_then(non_empty) {
        parts.push(format!(
            "metric_property={}",
            escape_metric_key_component(metric_property)
        ));
    }

    (!parts.is_empty()).then(|| format!("{report_id}:{}", parts.join(":")))
}

fn escape_metric_key_component(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                escaped.push(byte as char);
            }
            _ => {
                escaped.push('%');
                escaped.push(hex_digit(byte >> 4));
                escaped.push(hex_digit(byte & 0x0f));
            }
        }
    }
    escaped
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + nibble - 10) as char,
        _ => unreachable!("hex nibble is always <= 15"),
    }
}

fn metric_type(metric_id: Option<&str>, metric_property: Option<&str>) -> Option<String> {
    metric_id
        .and_then(non_empty)
        .or_else(|| metric_property.and_then(last_path_segment))
        .map(sanitize_metric_token)
        .filter(|token| !token.is_empty())
}

fn non_empty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn last_path_segment(value: &str) -> Option<&str> {
    let pointer = value
        .split_once('#')
        .map(|(_, pointer)| pointer)
        .filter(|pointer| !pointer.is_empty());
    let path = pointer.unwrap_or(value).trim_end_matches('/');
    path.rsplit('/').find(|segment| !segment.is_empty())
}

fn sanitize_metric_token(value: &str) -> String {
    let mut token = String::with_capacity(value.len());
    let mut previous_was_separator = false;
    let chars = value.chars().collect::<Vec<_>>();
    for (index, ch) in chars.iter().copied().enumerate() {
        if ch.is_ascii_alphanumeric() {
            let previous = index.checked_sub(1).and_then(|i| chars.get(i)).copied();
            let next = chars.get(index + 1).copied();
            let starts_word = ch.is_ascii_uppercase()
                && !previous_was_separator
                && previous.is_some_and(|prev| prev.is_ascii_alphanumeric())
                && (previous
                    .is_some_and(|prev| prev.is_ascii_lowercase() || prev.is_ascii_digit())
                    || next.is_some_and(|next| next.is_ascii_lowercase()));
            if starts_word {
                token.push('_');
            }
            token.push(ch.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            token.push('_');
            previous_was_separator = true;
        }
    }
    token.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_report_values_emit_numeric_and_info_samples() {
        let report: MetricReport = serde_json::from_value(serde_json::json!({
            "@odata.id": "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
            "@odata.type": "#MetricReport.v1_3_0.MetricReport",
            "Id": "NvidiaNMMetrics_0",
            "Name": "NVIDIA NVSwitch metrics",
            "MetricReportDefinition": {
                "@odata.id": "/redfish/v1/TelemetryService/MetricReportDefinitions/NvidiaNMMetrics"
            },
            "MetricValues": [
                {
                    "MetricId": "PortMalformedPacketErrors",
                    "MetricValue": "17",
                    "MetricProperty": "/redfish/v1/Fabrics/NVLink/Switches/0/Ports/1/Metrics#/Oem/Nvidia/MalformedPackets"
                },
                {
                    "MetricId": "SwitchFirmwareVersion",
                    "MetricValue": "1.2.3"
                },
                {
                    "MetricId": "LinkHealthy",
                    "MetricValue": "true"
                }
            ]
        }))
        .expect("MetricReport JSON should parse");

        let samples = metric_samples_from_report(
            &report,
            "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
        );

        assert_eq!(samples.len(), 3);
        assert_eq!(samples[0].name, "redfish_telemetry_service");
        assert_eq!(samples[0].metric_type, "port_malformed_packet_errors");
        assert_eq!(samples[0].unit, "value");
        assert_eq!(samples[0].value, 17.0);
        assert!(
            samples[0].key.starts_with(
                "NvidiaNMMetrics_0:metric_id=PortMalformedPacketErrors:metric_property="
            )
        );
        assert_eq!(samples[1].metric_type, "switch_firmware_version");
        assert_eq!(samples[1].unit, "info");
        assert_eq!(samples[1].value, 1.0);
        assert!(
            samples[1]
                .labels
                .iter()
                .all(|(key, _)| key.as_ref() != "metric_value")
        );
        assert_eq!(samples[2].metric_type, "link_healthy");
        assert_eq!(samples[2].unit, "state");
        assert_eq!(samples[2].value, 1.0);
    }

    #[test]
    fn metric_report_keys_use_stable_metric_identity_instead_of_array_index() {
        let report: MetricReport = serde_json::from_value(serde_json::json!({
            "@odata.id": "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
            "@odata.type": "#MetricReport.v1_3_0.MetricReport",
            "Id": "NvidiaNMMetrics_0",
            "Name": "NVIDIA NVSwitch metrics",
            "MetricValues": [
                {
                    "MetricId": "PortRcvErrors",
                    "MetricValue": "1",
                    "MetricProperty": "/redfish/v1/Fabrics/NVLink/Switches/0/Ports/1/Metrics#/RXErrors"
                },
                {
                    "MetricId": "PortRcvErrors",
                    "MetricValue": "2",
                    "MetricProperty": "/redfish/v1/Fabrics/NVLink/Switches/0/Ports/2/Metrics#/RXErrors"
                }
            ]
        }))
        .expect("MetricReport JSON should parse");
        let reversed: MetricReport = serde_json::from_value(serde_json::json!({
            "@odata.id": "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
            "@odata.type": "#MetricReport.v1_3_0.MetricReport",
            "Id": "NvidiaNMMetrics_0",
            "Name": "NVIDIA NVSwitch metrics",
            "MetricValues": [
                {
                    "MetricId": "PortRcvErrors",
                    "MetricValue": "2",
                    "MetricProperty": "/redfish/v1/Fabrics/NVLink/Switches/0/Ports/2/Metrics#/RXErrors"
                },
                {
                    "MetricId": "PortRcvErrors",
                    "MetricValue": "1",
                    "MetricProperty": "/redfish/v1/Fabrics/NVLink/Switches/0/Ports/1/Metrics#/RXErrors"
                }
            ]
        }))
        .expect("MetricReport JSON should parse");

        let original_keys = metric_samples_from_report(
            &report,
            "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
        )
        .into_iter()
        .map(|sample| sample.key)
        .collect::<std::collections::HashSet<_>>();
        let reversed_keys = metric_samples_from_report(
            &reversed,
            "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
        )
        .into_iter()
        .map(|sample| sample.key)
        .collect::<std::collections::HashSet<_>>();

        assert_eq!(original_keys, reversed_keys);
        assert_eq!(original_keys.len(), 2);
        assert!(
            original_keys
                .iter()
                .all(|key| !key.ends_with(":0") && !key.ends_with(":1"))
        );
    }

    #[test]
    fn metric_report_keys_preserve_raw_identity_after_sanitized_aliasing() {
        let report: MetricReport = serde_json::from_value(serde_json::json!({
            "@odata.id": "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
            "@odata.type": "#MetricReport.v1_3_0.MetricReport",
            "Id": "NvidiaNMMetrics_0",
            "Name": "NVIDIA NVSwitch metrics",
            "MetricValues": [
                {
                    "MetricId": "Port-RcvErrors",
                    "MetricValue": "1"
                },
                {
                    "MetricId": "Port_RcvErrors",
                    "MetricValue": "2"
                }
            ]
        }))
        .expect("MetricReport JSON should parse");

        let samples = metric_samples_from_report(
            &report,
            "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
        );

        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].metric_type, samples[1].metric_type);
        assert_ne!(samples[0].key, samples[1].key);
        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.key.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            2
        );
    }

    #[test]
    fn metric_report_value_without_source_identity_is_skipped() {
        let report: MetricReport = serde_json::from_value(serde_json::json!({
            "@odata.id": "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0",
            "@odata.type": "#MetricReport.v1_3_0.MetricReport",
            "Id": "NvidiaNMMetrics_0",
            "Name": "NVIDIA NVSwitch metrics",
            "MetricValues": [{ "MetricValue": "3" }]
        }))
        .expect("MetricReport JSON should parse");

        assert!(
            metric_samples_from_report(
                &report,
                "/redfish/v1/TelemetryService/MetricReports/NvidiaNMMetrics_0"
            )
            .is_empty()
        );
    }

    #[test]
    fn metric_type_falls_back_to_metric_property_last_segment() {
        assert_eq!(
            metric_type(
                None,
                Some("/redfish/v1/Fabrics/NVLink/Switches/0/Ports/1/Metrics#/RXErrors"),
            )
            .as_deref(),
            Some("rx_errors")
        );
        assert_eq!(metric_type(None, None), None);
    }
}
