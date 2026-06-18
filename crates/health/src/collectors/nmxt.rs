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

//! This module collects metrics from NMX-T telemetry endpoints on NVLink switches if the service is enabled.
//! Scrapes HTTP on 9352 (default for NMX-T) - NOT A Redfish collector!
//! Known switch metrics are emitted with existing canonical names; all other
//! numeric Prometheus samples are preserved as source-qualified NMX-T metrics.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use nv_redfish::core::Bmc;

use crate::HealthError;
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::config::NmxtCollectorConfig as NmxtCollectorOptions;
use crate::endpoint::{BmcEndpoint, EndpointMetadata};
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample};

/// default NMX-T port
const NMXT_PORT: u16 = 9352;

/// NMX-T endpoint
const NMXT_ENDPOINT: &str = "/xcset/nvlink_domain_telemetry";

/// Prometheus text -> NmxtMetricSample
#[derive(Debug, Clone)]
struct NmxtMetricSample {
    name: String,
    labels: HashMap<String, String>,
    value: f64,
}

/// Parse Prometheus text format metrics from NMX-T endpoint
fn parse_prometheus_metrics(body: &str) -> Vec<NmxtMetricSample> {
    let mut samples = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(sample) = parse_prometheus_line(line) {
            samples.push(sample);
        }
    }

    samples
}

/// Parse a single text line
fn parse_prometheus_line(line: &str) -> Option<NmxtMetricSample> {
    // find labels
    let (name_part, rest) = if let Some(brace_pos) = line.find('{') {
        let name = &line[..brace_pos];
        let rest = &line[brace_pos..];
        (name, rest)
    } else {
        // no labels
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0];
            let value = parts[1].parse::<f64>().ok()?;
            return Some(NmxtMetricSample {
                name: name.to_string(),
                labels: HashMap::new(),
                value,
            });
        }
        return None;
    };

    let close_brace = rest.find('}')?;
    let labels_str = &rest[1..close_brace];
    let value_part = rest[close_brace + 1..].trim();
    let value_str = value_part.split_whitespace().next()?;
    let value = value_str.parse::<f64>().ok()?;

    let mut labels = HashMap::new();
    for label_pair in labels_str.split(',') {
        let label_pair = label_pair.trim();
        if let Some(eq_pos) = label_pair.find('=') {
            let key = label_pair[..eq_pos].trim();
            let val = label_pair[eq_pos + 1..].trim().trim_matches('"');
            labels.insert(key.to_string(), val.to_string());
        }
    }

    Some(NmxtMetricSample {
        name: name_part.to_string(),
        labels,
        value,
    })
}

/// scrape nmxt metrics from a single switch
async fn scrape_switch_nmxt_metrics(
    http_client: &reqwest::Client,
    switch_ip: &str,
) -> Result<Vec<NmxtMetricSample>, HealthError> {
    let url = format!("http://{}:{}{}", switch_ip, NMXT_PORT, NMXT_ENDPOINT);

    let response = http_client.get(&url).send().await.map_err(|e| {
        HealthError::GenericError(format!("HTTP request failed for {}: {}", switch_ip, e))
    })?;

    if !response.status().is_success() {
        return Err(HealthError::GenericError(format!(
            "HTTP request to {} returned status {}",
            url,
            response.status()
        )));
    }

    let body = response.text().await.map_err(|e| {
        HealthError::GenericError(format!(
            "Failed to read response body from {}: {}",
            switch_ip, e
        ))
    })?;

    Ok(parse_prometheus_metrics(&body))
}

pub struct NmxtCollectorConfig {
    pub nmxt_config: NmxtCollectorOptions,
    pub data_sink: Option<Arc<dyn DataSink>>,
}

/// NMX-T collector for a single switch/endpoint
pub struct NmxtCollector {
    endpoint: Arc<BmcEndpoint>,
    switch_id: String,
    http_client: reqwest::Client,
    event_context: EventContext,
    data_sink: Option<Arc<dyn DataSink>>,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for NmxtCollector {
    type Config = NmxtCollectorConfig;

    fn new_runner(
        _bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let switch_id = match &endpoint.metadata {
            Some(EndpointMetadata::Switch(s)) => s.serial.clone(),
            _ => endpoint.addr.mac.to_string(),
        };
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), "nmxt");
        let request_timeout = config.nmxt_config.request_timeout;

        let http_client = reqwest::Client::builder()
            .timeout(request_timeout)
            .build()
            .map_err(|e| {
                HealthError::GenericError(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            endpoint,
            switch_id,
            http_client,
            event_context,
            data_sink: config.data_sink,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        self.scrape_iteration().await?;
        Ok(IterationResult {
            refresh_triggered: true,
            entity_count: None,
            fetch_failures: 0,
        })
    }

    fn collector_type(&self) -> &'static str {
        "nmxt"
    }

    async fn stop(&mut self) {
        self.emit_event(CollectorEvent::CollectorRemoved);
    }
}

impl NmxtCollector {
    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    async fn scrape_iteration(&self) -> Result<(), HealthError> {
        let switch_ip = self.endpoint.addr.ip.to_string();

        let metrics = scrape_switch_nmxt_metrics(&self.http_client, &switch_ip).await?;

        self.emit_event(CollectorEvent::MetricCollectionStart);

        for sample in metrics {
            let NmxtMetricSample {
                name,
                labels: mut sample_labels,
                value,
            } = sample;
            let port_num = sample_labels.remove("Port_Number").unwrap_or_default();
            let node_guid = sample_labels.remove("Node_GUID").unwrap_or_default();

            let known_legacy_metric = matches!(
                name.as_str(),
                "Effective_BER" | "Symbol_Errors" | "Link_Down"
            );
            let metric_type = match name.as_str() {
                "Effective_BER" => "effective_ber".to_string(),
                "Symbol_Errors" => "symbol_errors".to_string(),
                "Link_Down" => "link_down".to_string(),
                _ => sanitize_metric_token(&name),
            };

            let metric_key = if known_legacy_metric {
                legacy_metric_key(&metric_type, &port_num)
            } else {
                generic_metric_key(&metric_type, &name, &port_num, &node_guid, &sample_labels)
            };

            let mut labels = vec![
                (Cow::Borrowed("switch_id"), self.switch_id.clone()),
                (Cow::Borrowed("switch_ip"), switch_ip.clone()),
                (Cow::Borrowed("node_guid"), node_guid),
                (Cow::Borrowed("port_num"), port_num),
            ];
            if !known_legacy_metric {
                labels.push((Cow::Borrowed("source_metric"), name));
            }
            for (label_name, label_value) in sample_labels {
                labels.push((Cow::Owned(sanitize_label_name(&label_name)), label_value));
            }

            self.emit_event(CollectorEvent::Metric(
                MetricSample {
                    key: metric_key,
                    name: "switch_nmxt".to_string(),
                    metric_type,
                    unit: "count".to_string(),
                    value,
                    labels,
                    context: None,
                }
                .into(),
            ));
        }

        self.emit_event(CollectorEvent::MetricCollectionEnd);

        Ok(())
    }
}

fn legacy_metric_key(metric_type: &str, port_num: &str) -> String {
    let mut metric_key = String::with_capacity(metric_type.len() + 1 + port_num.len());
    metric_key.push_str(metric_type);
    metric_key.push(':');
    metric_key.push_str(port_num);
    metric_key
}

fn generic_metric_key(
    metric_type: &str,
    source_metric: &str,
    port_num: &str,
    node_guid: &str,
    sample_labels: &HashMap<String, String>,
) -> String {
    let mut metric_key = metric_type.to_string();

    append_metric_key_identity(&mut metric_key, "port_num", port_num);
    append_metric_key_identity(&mut metric_key, "source_metric", source_metric);
    append_metric_key_identity(&mut metric_key, "node_guid", node_guid);

    let mut identity_labels = sample_labels
        .iter()
        .map(|(label_name, label_value)| (sanitize_label_name(label_name), label_name, label_value))
        .collect::<Vec<_>>();
    identity_labels.sort_by(
        |(left_sanitized, left_name, left_value), (right_sanitized, right_name, right_value)| {
            left_sanitized
                .cmp(right_sanitized)
                .then_with(|| left_name.cmp(right_name))
                .then_with(|| left_value.cmp(right_value))
        },
    );

    for (_, label_name, label_value) in identity_labels {
        append_metric_key_identity(&mut metric_key, "label_name", label_name);
        append_metric_key_identity(&mut metric_key, "label_value", label_value);
    }

    metric_key
}

fn append_metric_key_identity(
    metric_key: &mut String,
    component_name: &str,
    component_value: &str,
) {
    if component_value.is_empty() {
        return;
    }
    metric_key.push(':');
    metric_key.push_str(&escape_metric_key_component(component_name));
    metric_key.push('=');
    metric_key.push_str(&escape_metric_key_component(component_value));
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

fn sanitize_label_name(value: &str) -> String {
    let mut label = sanitize_metric_token(value);
    if label.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        label.insert(0, '_');
    }
    label
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prometheus_line_with_labels() {
        let line = r#"Effective_BER{Port_Number="2", Node_GUID="0x8e2161c8803caf64"} 1.5e-254"#;
        let sample = parse_prometheus_line(line).unwrap();

        assert_eq!(sample.name, "Effective_BER");
        assert_eq!(sample.labels.get("Port_Number"), Some(&"2".to_string()));
        assert_eq!(
            sample.labels.get("Node_GUID"),
            Some(&"0x8e2161c8803caf64".to_string())
        );
        assert_eq!(sample.value, 1.5e-254);
    }

    #[test]
    fn test_parse_prometheus_line_no_labels() {
        let line = "simple_metric 42.5 1234567890";
        let sample = parse_prometheus_line(line).unwrap();

        assert_eq!(sample.name, "simple_metric");
        assert!(sample.labels.is_empty());
        assert_eq!(sample.value, 42.5);
    }

    #[test]
    fn test_parse_prometheus_metrics() {
        let body = r#"
# HELP Effective_BER Effective bit error rate
# TYPE Effective_BER gauge
Effective_BER{Port_Number="1"} 0
Effective_BER{Port_Number="2"} 1e-10
Symbol_Errors{Port_Number="1"} 0
Link_Down{Port_Number="1"} 5
"#;

        let samples = parse_prometheus_metrics(body);
        assert_eq!(samples.len(), 4);
    }

    #[test]
    fn unknown_nmxt_metric_names_are_sanitized_instead_of_dropped() {
        assert_eq!(
            sanitize_metric_token("PortMalformedPacketErrors"),
            "port_malformed_packet_errors"
        );
        assert_eq!(sanitize_label_name("Lane-Number"), "lane_number");
        assert_eq!(sanitize_label_name("8b10b"), "_8b10b");
    }

    #[test]
    fn generic_metric_key_includes_sorted_extra_label_identity() {
        let labels = HashMap::from([
            ("Lane-Number".to_string(), "3".to_string()),
            ("Device".to_string(), "nvswitch0".to_string()),
        ]);

        assert_eq!(
            generic_metric_key(
                "port_malformed_packet_errors",
                "PortMalformedPacketErrors",
                "4",
                "0x8e2161c8803caf64",
                &labels,
            ),
            "port_malformed_packet_errors:port_num=4:source_metric=PortMalformedPacketErrors:node_guid=0x8e2161c8803caf64:label_name=Device:label_value=nvswitch0:label_name=Lane-Number:label_value=3"
        );
    }

    #[test]
    fn generic_metric_key_includes_raw_source_metric_to_avoid_sanitized_name_aliasing() {
        let labels = HashMap::new();

        assert_ne!(
            generic_metric_key("rx_errors", "RxErrors", "1", "", &labels),
            generic_metric_key("rx_errors", "rx-errors", "1", "", &labels),
        );
    }

    #[test]
    fn generic_metric_key_escapes_identity_delimiters_to_avoid_aliasing() {
        let labels_with_delimiter_value = HashMap::from([("b".to_string(), "c:d=e".to_string())]);
        let labels_split_by_delimiters = HashMap::from([
            ("b".to_string(), "c".to_string()),
            ("d".to_string(), "e".to_string()),
        ]);

        assert_ne!(
            generic_metric_key(
                "rx_errors",
                "RxErrors",
                "1",
                "",
                &labels_with_delimiter_value
            ),
            generic_metric_key(
                "rx_errors",
                "RxErrors",
                "1",
                "",
                &labels_split_by_delimiters
            )
        );

        assert_ne!(
            generic_metric_key(
                "rx_errors",
                "RxErrors:node_guid=x",
                "1",
                "",
                &HashMap::new()
            ),
            generic_metric_key("rx_errors", "RxErrors", "1", "x", &HashMap::new())
        );
    }

    #[test]
    fn generic_metric_key_distinguishes_same_port_samples_by_extra_labels() {
        let first = HashMap::from([("Lane".to_string(), "0".to_string())]);
        let second = HashMap::from([("Lane".to_string(), "1".to_string())]);

        assert_ne!(
            generic_metric_key("rx_errors", "RxErrors", "1", "", &first),
            generic_metric_key("rx_errors", "RxErrors", "1", "", &second)
        );
    }
}
