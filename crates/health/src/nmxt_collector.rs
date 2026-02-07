/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! This module collects metrics from NMX-T telemetry endpoints on NVLink switches if the service is enabled.
//! Scrapes HTTP on 9352 (default for NMX-T) - NOT A Redfish collector!
//! Currently scraping for Effective BER, Symbol Errors and Link Down counter.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use nv_redfish_core::Bmc;
use prometheus::{GaugeVec, Opts};

use crate::HealthError;
use crate::api_client::{BmcEndpoint, EndpointMetadata};
use crate::collector::{IterationResult, PeriodicCollector};
use crate::config::NmxtCollectorConfig as NmxtCollectorOptions;
use crate::metrics::CollectorRegistry;

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

    let response = http_client
        .get(&url)
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| {
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
    pub collector_registry: Arc<CollectorRegistry>,
}

/// NMX-T collector for a single switch/endpoint
pub struct NmxtCollector {
    endpoint: Arc<BmcEndpoint>,
    http_client: reqwest::Client,
    switch_id: String,
    effective_ber_gauge: GaugeVec,
    symbol_error_gauge: GaugeVec,
    link_down_gauge: GaugeVec,
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
            _ => endpoint.addr.mac.clone(),
        };

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| {
                HealthError::GenericError(format!("Failed to create HTTP client: {}", e))
            })?;

        let registry = config.collector_registry.registry();
        let prefix = config.collector_registry.prefix();

        let effective_ber_gauge = GaugeVec::new(
            Opts::new(
                format!("{prefix}_switch_effective_ber"),
                "Effective BER from NMX-T telemetry",
            ),
            &["switch_id", "switch_ip", "node_guid", "port_num"],
        )?;
        registry.register(Box::new(effective_ber_gauge.clone()))?;

        let symbol_error_gauge = GaugeVec::new(
            Opts::new(
                format!("{prefix}_switch_symbol_error_counter"),
                "Symbol error counter from NMX-T telemetry",
            ),
            &["switch_id", "switch_ip", "node_guid", "port_num"],
        )?;
        registry.register(Box::new(symbol_error_gauge.clone()))?;

        let link_down_gauge = GaugeVec::new(
            Opts::new(
                format!("{prefix}_switch_link_down_counter"),
                "Link down counter from NMX-T telemetry",
            ),
            &["switch_id", "switch_ip", "node_guid", "port_num"],
        )?;
        registry.register(Box::new(link_down_gauge.clone()))?;

        Ok(Self {
            endpoint,
            http_client,
            switch_id,
            effective_ber_gauge,
            symbol_error_gauge,
            link_down_gauge,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        self.scrape_iteration().await?;
        Ok(IterationResult {
            refresh_triggered: true,
            entity_count: None,
        })
    }

    fn collector_type(&self) -> &'static str {
        "nmxt"
    }
}

impl NmxtCollector {
    async fn scrape_iteration(&self) -> Result<(), HealthError> {
        let switch_ip = self.endpoint.addr.ip.to_string();

        let metrics = scrape_switch_nmxt_metrics(&self.http_client, &switch_ip).await?;

        for sample in metrics {
            let port_num = sample
                .labels
                .get("Port_Number")
                .cloned()
                .unwrap_or_default();

            let node_guid = sample.labels.get("Node_GUID").cloned().unwrap_or_default();

            let labels = [self.switch_id.as_str(), &switch_ip, &node_guid, &port_num];

            match sample.name.as_str() {
                "Effective_BER" => {
                    self.effective_ber_gauge
                        .with_label_values(&labels)
                        .set(sample.value);
                }
                "Symbol_Errors" => {
                    self.symbol_error_gauge
                        .with_label_values(&labels)
                        .set(sample.value);
                }
                "Link_Down" => {
                    self.link_down_gauge
                        .with_label_values(&labels)
                        .set(sample.value);
                }
                _ => {}
            }
        }

        Ok(())
    }
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
}
