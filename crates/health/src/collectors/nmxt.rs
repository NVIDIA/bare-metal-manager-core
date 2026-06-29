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
//! Scrapes HTTP on 9352 (default for NMX-T)
//!
//! Mapping is an EXPLICIT, catalog-row allowlist over the live NMX-T Prometheus scrape (see
//! `NMXT_METRIC_MAP` and `NMXT_LABEL_MAP`). Each NMX-T source name is either:
//!   * a numeric **family** -> emitted as one canonical `switch_nmxt` series (`NMXT_METRIC_MAP`), or
//!   * an identity/inventory **label dimension** carried on every series -> re-exported as a
//!     canonical label, never as a standalone metric (`NMXT_LABEL_MAP`).
//!
//! Source names not on either allowlist are skipped and counted only (never sanitized into telemetry).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nv_redfish::core::Bmc;

use crate::HealthError;
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::config::NmxtCollectorConfig as NmxtCollectorOptions;
use crate::endpoint::BmcEndpoint;
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample};

/// default NMX-T port
const NMXT_PORT: u16 = 9352;

/// NMX-T endpoint
const NMXT_ENDPOINT: &str = "/xcset/nvlink_domain_telemetry";

/// MetricSample name for NMX-T metrics
const NMXT_METRIC_NAME: &str = "switch_nmxt";

#[derive(Debug, PartialEq)]
struct NmxtMetric {
    source: &'static str,
    metric_type: &'static str,
    unit: &'static str,
}

#[derive(Debug, PartialEq)]
struct NmxtLabel {
    source: &'static str,
    canonical: &'static str,
}

const NMXT_METRIC_MAP: &[NmxtMetric] = &[
    NmxtMetric {
        source: "Effective_BER",
        metric_type: "effective_ber",
        unit: "ratio",
    },
    NmxtMetric {
        source: "Symbol_Errors",
        metric_type: "symbol_errors",
        unit: "count",
    }, // PHY-SYMBOL-ERRORS
    NmxtMetric {
        source: "Link_Down",
        metric_type: "link_down",
        unit: "count",
    },
    NmxtMetric {
        source: "lid",
        metric_type: "lid",
        unit: "id",
    }, // LID
    NmxtMetric {
        source: "device_hw_rev",
        metric_type: "device_hw_rev",
        unit: "id",
    }, // DEVICE-HARDWARE-REVISION
    NmxtMetric {
        source: "Advanced_Status_Opcode",
        metric_type: "status_opcode",
        unit: "code",
    }, // STATUS-OPCODE
    NmxtMetric {
        source: "remote_reason_opcode",
        metric_type: "remote_reason_opcode",
        unit: "code",
    }, // REMOTE-REASON-OPCODE
    NmxtMetric {
        source: "time_to_link_up_ext_msec",
        metric_type: "time_to_link_up",
        unit: "milliseconds",
    }, // TIME-TO-LINKS-UP
    NmxtMetric {
        source: "cable_technology",
        metric_type: "cable_transmitter_technology",
        unit: "code",
    }, // CABLE-TRANSMITTER-TECHNOLOGY
    NmxtMetric {
        source: "rx_power_lane_0",
        metric_type: "cable_rx_power_lane0",
        unit: "milliwatts",
    }, // CABLE-RX-POWER-LANE0
    NmxtMetric {
        source: "rx_power_lane_1",
        metric_type: "cable_rx_power_lane1",
        unit: "milliwatts",
    }, // CABLE-RX-POWER-LANE1
    NmxtMetric {
        source: "Module_Voltage",
        metric_type: "cable_diag_supply_voltage",
        unit: "volts",
    }, // CABLE-DIAG-SUPPLY-VOLTAGE
    NmxtMetric {
        source: "link_partner_lid",
        metric_type: "link_partner_lid",
        unit: "id",
    }, // LINK-PARTNER-LID
    NmxtMetric {
        source: "successful_recovery_events",
        metric_type: "link_recovery_success_cnt",
        unit: "count",
    }, // LINK-RECOVERY-SUCCESS-CNT
    NmxtMetric {
        source: "total_successful_recovery_events",
        metric_type: "total_link_recovery_success_cnt",
        unit: "count",
    }, // TOTAL-LINK-RECOVERY-SUCCESS-CNT
    NmxtMetric {
        source: "time_since_last_recovery",
        metric_type: "time_since_last_recovery",
        unit: "seconds",
    }, // TIME-SINCE-LAST-RECOVERY
    NmxtMetric {
        source: "time_between_last_2_recoveries",
        metric_type: "time_btwn_two_recoveries",
        unit: "seconds",
    }, // TIME-BTWN-TWO-RECOVERIES
    NmxtMetric {
        source: "last_host_logical_recovery_attempts_count",
        metric_type: "recovery_attempts_l1_cnt",
        unit: "count",
    }, // RECOVERY-ATTEMPTS-L1-CNT
    NmxtMetric {
        source: "last_host_serdes_feq_attempts_count",
        metric_type: "recovery_attempts_l2_cnt",
        unit: "count",
    }, // RECOVERY-ATTEMPTS-L2-CNT
    NmxtMetric {
        source: "time_in_last_host_logical_recovery",
        metric_type: "recovery_cycle_duration",
        unit: "seconds",
    }, // RECOVERY-CYCLE-DURATION
    NmxtMetric {
        source: "time_in_last_host_serdes_feq_recovery",
        metric_type: "serdes_recovery_cycle_duration",
        unit: "seconds",
    }, // SERDES-RECOVERY-CYCLE-DURATION
    NmxtMetric {
        source: "contain_n_drain_xmit_discards",
        metric_type: "contain_drain_xmit_discard",
        unit: "count",
    }, // CONTAIN-DRAIN-XMIT-DISCARD
    NmxtMetric {
        source: "contain_n_drain_rcv_discards",
        metric_type: "contain_drain_rcv_discard",
        unit: "count",
    }, // CONTAIN-DRAIN-RCV-DISCARD
    NmxtMetric {
        source: "Raw_Errors_Lane_2",
        metric_type: "raw_err_lane_2",
        unit: "count",
    }, // RAW-ERR-LANE-2
    NmxtMetric {
        source: "Raw_Errors_Lane_3",
        metric_type: "raw_err_lane_3",
        unit: "count",
    }, // RAW-ERR-LANE-3
    NmxtMetric {
        source: "tx_cdr_lol",
        metric_type: "cable_tx_cdr_lol",
        unit: "state",
    }, // CABLE-TX-CDR-LOL
    NmxtMetric {
        source: "rx_cdr_lol",
        metric_type: "cable_rx_cdr_lol",
        unit: "state",
    }, // CABLE-RX-CDR-LOL
    NmxtMetric {
        source: "tx_los",
        metric_type: "cable_tx_los",
        unit: "state",
    }, // CABLE-TX-LOS
    NmxtMetric {
        source: "rx_los",
        metric_type: "cable_rx_los",
        unit: "state",
    }, // CABLE-RX-LOS
];

const NMXT_LABEL_MAP: &[NmxtLabel] = &[
    NmxtLabel {
        source: "FW_Version",
        canonical: "net_fw_ver",
    }, // NET-FW-VER
    NmxtLabel {
        source: "sw_serial_number",
        canonical: "serial",
    }, // SERIAL
    NmxtLabel {
        source: "Node_GUID",
        canonical: "node_guid",
    }, // NODE-GUID
    NmxtLabel {
        source: "port_guid",
        canonical: "port_guid",
    }, // PORT-GUID
    NmxtLabel {
        source: "Port_Number",
        canonical: "port_num",
    }, // PORT-NUMBER
    NmxtLabel {
        source: "port_label",
        canonical: "port_label",
    }, // PORT-LABEL
    NmxtLabel {
        source: "sw_revision",
        canonical: "revision",
    }, // REVISION
    NmxtLabel {
        source: "Active_FEC",
        canonical: "fec_mode_active",
    }, // FEC-MODE-ACTIVE
    NmxtLabel {
        source: "Device_ID",
        canonical: "device_id",
    }, // DEVICE-ID
    NmxtLabel {
        source: "local_reason_opcode",
        canonical: "local_reason_opcode",
    }, // LOCAL-REASON-OPCODE
    NmxtLabel {
        source: "Cable_PN",
        canonical: "cable_part_number",
    }, // CABLE-PART-NUMBER
    NmxtLabel {
        source: "Cable_SN",
        canonical: "cable_serial_number",
    }, // CABLE-SERIAL-NUMBER
    NmxtLabel {
        source: "cable_type",
        canonical: "cable_type",
    }, // CABLE-TYPE
    NmxtLabel {
        source: "cable_vendor",
        canonical: "cable_vendor",
    }, // CABLE-VENDOR
    NmxtLabel {
        source: "cable_length",
        canonical: "cable_length",
    }, // CABLE-LENGTH
    NmxtLabel {
        source: "cable_identifier",
        canonical: "cable_identifier",
    }, // CABLE-IDENTIFIER
    NmxtLabel {
        source: "vendor_rev",
        canonical: "cable_rev",
    }, // CABLE-REV
    NmxtLabel {
        source: "cable_fw_version",
        canonical: "cable_fw_version",
    }, // CABLE-FW-VERSION
    NmxtLabel {
        source: "link_partner_description",
        canonical: "link_partner_description",
    }, // LINK-PARTNER-DESCRIPTION
    NmxtLabel {
        source: "link_partner_node_guid",
        canonical: "link_partner_node_guid",
    }, // LINK-PARTNER-NODE-GUID
    NmxtLabel {
        source: "link_partner_port_num",
        canonical: "link_partner_port_num",
    }, // LINK-PARTNER-PORT-NUM
    NmxtLabel {
        source: "device_num_on_tray",
        canonical: "device_num",
    }, // DEVICE-NUM
    NmxtLabel {
        source: "board_type",
        canonical: "board_type",
    }, // BOARD-TYPE
    NmxtLabel {
        source: "chassis_slot_index",
        canonical: "chassis_slot_idx",
    }, // CHASSIS-SLOT-IDX
    NmxtLabel {
        source: "tray_index",
        canonical: "tray_idx",
    }, // TRAY-IDX
    NmxtLabel {
        source: "topology_id",
        canonical: "topology_id",
    }, // TOPOLOGY-ID
    NmxtLabel {
        source: "chassis_id",
        canonical: "chassis_id",
    }, // CHASSIS-ID
];

fn lookup_nmxt_metric(name: &str) -> Option<&'static NmxtMetric> {
    NMXT_METRIC_MAP.iter().find(|m| m.source == name)
}

/// Parse `Module_Temperature` as a label value (e.g. `"0C"`), never its own numeric
/// line and emit as a gauge with either numeric or `None
fn cable_temp_to_celsius(raw: &str) -> Option<f64> {
    let trimmed = raw.trim();
    let digits = trimmed.strip_suffix(['C', 'c']).unwrap_or(trimmed).trim();
    digits.parse::<f64>().ok()
}

/// Enum for `down_blame`, emitted as a StateSet (one 0/1 series per state).
const DOWN_BLAME_STATES: &[&str] = &["unknown", "local_phy", "remote_phy"];

/// Maps a raw `down_blame` value to its canonical state, case-insensitively; unknown/empty -> "unknown".
fn down_blame_to_state(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "local_phy" => "local_phy",
        "remote_phy" => "remote_phy",
        _ => "unknown",
    }
}

fn required_port_num(sample_labels: &HashMap<String, String>) -> Option<&str> {
    sample_labels
        .get("Port_Number")
        .map(String::as_str)
        .filter(|port_num| !port_num.is_empty())
}

#[cfg(test)]
fn lookup_nmxt_label(key: &str) -> Option<&'static NmxtLabel> {
    NMXT_LABEL_MAP.iter().find(|l| l.source == key)
}

#[derive(Debug, Clone)]
struct NmxtMetricSample {
    name: String,
    labels: HashMap<String, String>,
    value: f64,
}

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

fn parse_prometheus_line(line: &str) -> Option<NmxtMetricSample> {
    let (name_part, rest) = if let Some(brace_pos) = line.find('{') {
        let name = &line[..brace_pos];
        let rest = &line[brace_pos..];
        (name, rest)
    } else {
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

pub struct NmxtCollector {
    endpoint: Arc<BmcEndpoint>,
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
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), "nmxt");
        let request_timeout = config.nmxt_config.request_timeout;

        let mut http_client_builder = reqwest::Client::builder().timeout(request_timeout);
        if config.nmxt_config.dangerously_skip_tls_verification {
            http_client_builder = http_client_builder.danger_accept_invalid_certs(true);
        }
        let http_client = http_client_builder.build().map_err(|e| {
            HealthError::GenericError(format!("Failed to create HTTP client: {}", e))
        })?;

        Ok(Self {
            endpoint,
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

    /// Builds label set for one `switch_nmxt` series
    fn build_labels(
        &self,
        sample_labels: &HashMap<String, String>,
    ) -> Vec<(Cow<'static, str>, String)> {
        let mut labels: Vec<(Cow<'static, str>, String)> = Vec::with_capacity(NMXT_LABEL_MAP.len());

        for label in NMXT_LABEL_MAP {
            if let Some(value) = sample_labels.get(label.source) {
                labels.push((Cow::Borrowed(label.canonical), value.clone()));
            }
        }

        labels
    }

    async fn scrape_iteration(&self) -> Result<(), HealthError> {
        let switch_ip = self.endpoint.addr.ip.to_string();

        let metrics = scrape_switch_nmxt_metrics(&self.http_client, &switch_ip).await?;

        self.emit_event(CollectorEvent::MetricCollectionStart);

        // Ports already emitted a cable temperature this iteration (one series per port).
        let mut cable_temp_ports: HashSet<String> = HashSet::new();
        // Ports already emitted a down_blame StateSet this iteration (one set per port).
        let mut down_blame_ports: HashSet<String> = HashSet::new();

        for sample in metrics {
            let NmxtMetricSample {
                name,
                labels: sample_labels,
                value,
            } = sample;

            // `Module_Temperature` rides as a label on lines whose map entry may not be
            // collected. Emit before the map check, once per port.
            if let Some(celsius) = sample_labels
                .get("Module_Temperature")
                .and_then(|raw| cable_temp_to_celsius(raw))
            {
                let Some(port_num) = required_port_num(&sample_labels) else {
                    continue;
                };
                if cable_temp_ports.insert(port_num.to_string()) {
                    let labels = self.build_labels(&sample_labels);
                    self.emit_event(CollectorEvent::Metric(
                        MetricSample {
                            key: format!("cable_temperature_celsius:{}", port_num),
                            name: NMXT_METRIC_NAME.to_string(),
                            metric_type: "cable_temperature_celsius".to_string(),
                            unit: "celsius".to_string(),
                            value: celsius,
                            labels,
                            context: None,
                        }
                        .into(),
                    ));
                }
            }

            // `down_blame` is an enum riding as a label; emit per port as a StateSet
            if let Some(raw) = sample_labels.get("down_blame") {
                let Some(port_num) = required_port_num(&sample_labels) else {
                    continue;
                };
                if down_blame_ports.insert(port_num.to_string()) {
                    let current = down_blame_to_state(raw);
                    let base_labels = self.build_labels(&sample_labels);
                    for state in DOWN_BLAME_STATES {
                        let mut labels = base_labels.clone();
                        labels.push((Cow::Borrowed("state"), (*state).to_string()));
                        self.emit_event(CollectorEvent::Metric(
                            MetricSample {
                                key: format!("down_blame:{}:{}", port_num, state),
                                name: NMXT_METRIC_NAME.to_string(),
                                metric_type: "down_blame".to_string(),
                                unit: "state".to_string(),
                                value: if *state == current { 1.0 } else { 0.0 },
                                labels,
                                context: None,
                            }
                            .into(),
                        ));
                    }
                }
            }

            let Some(metric) = lookup_nmxt_metric(&name) else {
                continue;
            };
            let (metric_type, unit) = (metric.metric_type, metric.unit);

            // Port number anchors the per-series key.
            let Some(port_num) = required_port_num(&sample_labels) else {
                continue;
            };

            let mut metric_key = String::with_capacity(metric_type.len() + 1 + port_num.len());
            metric_key.push_str(metric_type);
            metric_key.push(':');
            metric_key.push_str(port_num);

            let labels = self.build_labels(&sample_labels);

            self.emit_event(CollectorEvent::Metric(
                MetricSample {
                    key: metric_key,
                    name: NMXT_METRIC_NAME.to_string(),
                    metric_type: metric_type.to_string(),
                    unit: unit.to_string(),
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
    fn test_required_port_num_requires_present_non_empty_label() {
        let missing = HashMap::new();
        assert_eq!(required_port_num(&missing), None);

        let mut empty = HashMap::new();
        empty.insert("Port_Number".to_string(), String::new());
        assert_eq!(required_port_num(&empty), None);

        let mut present = HashMap::new();
        present.insert("Port_Number".to_string(), "11".to_string());
        assert_eq!(required_port_num(&present), Some("11"));
    }

    /// Live NMX-T `lid` series from the Stage-0 GB200 scrape (`nmxt-prometheus.txt`).
    const SAMPLE_LID_LINE: &str = r#"lid{Device_ID="GB100", port_label="GPUP10", logical_state="ACT", device_num_on_tray="2", board_type="3", chassis_slot_index="27", tray_index="17", topology_id="128", chassis_id="1820325172739", Active_FEC="Int_KP4_FEC_PLR", link_partner_description="MF0;sw06:N5400_LD/U1", link_partner_node_guid="0x2c5eab0300b6a900", link_partner_port_num="71", cable_vendor="Other", down_blame="Unknown", local_reason_opcode="No_link_down_indication", Node_GUID="0xe1d04a69816f16bc", node_description="GB100 Nvidia Technologies", Port_Number="11", FW_Version="36.2014.1866", Cable_PN="NA", Cable_SN="NA", cable_type="850 nm VCSEL", cable_length="NA", cable_identifier="Backplane", vendor_rev="NA", cable_fw_version="N/A", Module_Temperature="0C", Status_Message="No issue was observed", port_guid="0xe1d04a69816f16c6", sw_serial_number="MT123", sw_revision="A1", remote_reason_opcode="4"}  3093 1781993954087"#;

    #[test]
    fn test_nmxt_metric_map_locks_type_and_unit() {
        let expected: &[(&str, &str, &str)] = &[
            ("Effective_BER", "effective_ber", "ratio"),
            ("Symbol_Errors", "symbol_errors", "count"),
            ("Link_Down", "link_down", "count"),
            ("lid", "lid", "id"),
            ("device_hw_rev", "device_hw_rev", "id"),
            ("Advanced_Status_Opcode", "status_opcode", "code"),
            ("remote_reason_opcode", "remote_reason_opcode", "code"),
            (
                "time_to_link_up_ext_msec",
                "time_to_link_up",
                "milliseconds",
            ),
            ("cable_technology", "cable_transmitter_technology", "code"),
            ("rx_power_lane_0", "cable_rx_power_lane0", "milliwatts"),
            ("rx_power_lane_1", "cable_rx_power_lane1", "milliwatts"),
            ("Module_Voltage", "cable_diag_supply_voltage", "volts"),
            ("link_partner_lid", "link_partner_lid", "id"),
            (
                "successful_recovery_events",
                "link_recovery_success_cnt",
                "count",
            ),
            (
                "total_successful_recovery_events",
                "total_link_recovery_success_cnt",
                "count",
            ),
            (
                "time_since_last_recovery",
                "time_since_last_recovery",
                "seconds",
            ),
            (
                "time_between_last_2_recoveries",
                "time_btwn_two_recoveries",
                "seconds",
            ),
            (
                "last_host_logical_recovery_attempts_count",
                "recovery_attempts_l1_cnt",
                "count",
            ),
            (
                "last_host_serdes_feq_attempts_count",
                "recovery_attempts_l2_cnt",
                "count",
            ),
            (
                "time_in_last_host_logical_recovery",
                "recovery_cycle_duration",
                "seconds",
            ),
            (
                "time_in_last_host_serdes_feq_recovery",
                "serdes_recovery_cycle_duration",
                "seconds",
            ),
            (
                "contain_n_drain_xmit_discards",
                "contain_drain_xmit_discard",
                "count",
            ),
            (
                "contain_n_drain_rcv_discards",
                "contain_drain_rcv_discard",
                "count",
            ),
            ("Raw_Errors_Lane_2", "raw_err_lane_2", "count"),
            ("Raw_Errors_Lane_3", "raw_err_lane_3", "count"),
            ("tx_cdr_lol", "cable_tx_cdr_lol", "state"),
            ("rx_cdr_lol", "cable_rx_cdr_lol", "state"),
            ("tx_los", "cable_tx_los", "state"),
            ("rx_los", "cable_rx_los", "state"),
        ];

        for (source, metric_type, unit) in expected {
            let m = lookup_nmxt_metric(source)
                .unwrap_or_else(|| panic!("family `{source}` must be allowlisted"));
            assert_eq!(
                (m.metric_type, m.unit),
                (*metric_type, *unit),
                "family `{source}` must map to ({metric_type}, {unit})"
            );
        }
        // The allowlist must contain exactly these explicit families (no extras, no generic).
        assert_eq!(NMXT_METRIC_MAP.len(), expected.len());
    }

    #[test]
    fn test_nmxt_label_map_locks_canonical_names() {
        let expected: &[(&str, &str)] = &[
            ("FW_Version", "net_fw_ver"),
            ("sw_serial_number", "serial"),
            ("Node_GUID", "node_guid"),
            ("port_guid", "port_guid"),
            ("Port_Number", "port_num"),
            ("port_label", "port_label"),
            ("sw_revision", "revision"),
            ("Active_FEC", "fec_mode_active"),
            ("Device_ID", "device_id"),
            ("local_reason_opcode", "local_reason_opcode"),
            ("Cable_PN", "cable_part_number"),
            ("Cable_SN", "cable_serial_number"),
            ("cable_type", "cable_type"),
            ("cable_vendor", "cable_vendor"),
            ("cable_length", "cable_length"),
            ("cable_identifier", "cable_identifier"),
            ("vendor_rev", "cable_rev"),
            ("cable_fw_version", "cable_fw_version"),
            ("link_partner_description", "link_partner_description"),
            ("link_partner_node_guid", "link_partner_node_guid"),
            ("link_partner_port_num", "link_partner_port_num"),
            ("device_num_on_tray", "device_num"),
            ("board_type", "board_type"),
            ("chassis_slot_index", "chassis_slot_idx"),
            ("tray_index", "tray_idx"),
            ("topology_id", "topology_id"),
            ("chassis_id", "chassis_id"),
        ];

        for (key, canonical) in expected {
            assert_eq!(
                lookup_nmxt_label(key).map(|l| l.canonical),
                Some(*canonical),
                "label `{key}` must map to canonical `{canonical}`"
            );
        }
        assert_eq!(NMXT_LABEL_MAP.len(), expected.len());
    }

    // Unknown NMX-T source names are not on either allowlist (never sanitized into telemetry).
    #[test]
    fn test_unknown_nmxt_sources_not_allowlisted() {
        // Live-but-blocked families and arbitrary unknowns: all must be rejected.
        for unknown in [
            "HiRetransmissionRate", // row 931, not live
            "rq_num_wrfe",          // row 1706, not live
            "rq_num_lle",           // row 1707, not live
            "sq_num_wrfe",          // row 1708, not live
            "Chip_Temp",            // threshold blocker, not an NMX-T explicit mapping
            "totally_made_up_metric",
        ] {
            assert!(
                lookup_nmxt_metric(unknown).is_none(),
                "`{unknown}` must not be an allowlisted family"
            );
            assert!(
                lookup_nmxt_label(unknown).is_none(),
                "`{unknown}` must not be an allowlisted label"
            );
        }
    }

    // End-to-end: a live family line yields one canonical key and re-exported allowlisted labels.
    #[test]
    fn test_label_map_reexports_identity_dims_from_live_series() {
        let sample = parse_prometheus_line(SAMPLE_LID_LINE).expect("parse lid line");
        assert_eq!(sample.name, "lid");

        // Resolve canonical labels exactly as build_labels would (allowlist-gated).
        let mut canonical = HashMap::new();
        for label in NMXT_LABEL_MAP {
            if let Some(value) = sample.labels.get(label.source) {
                canonical.insert(label.canonical, value.clone());
            }
        }

        assert_eq!(
            canonical.get("node_guid"),
            Some(&"0xe1d04a69816f16bc".to_string())
        );
        assert_eq!(
            canonical.get("port_guid"),
            Some(&"0xe1d04a69816f16c6".to_string())
        );
        assert_eq!(canonical.get("port_num"), Some(&"11".to_string()));
        assert_eq!(canonical.get("port_label"), Some(&"GPUP10".to_string()));
        assert_eq!(
            canonical.get("net_fw_ver"),
            Some(&"36.2014.1866".to_string())
        );
        assert_eq!(canonical.get("serial"), Some(&"MT123".to_string()));
        assert_eq!(canonical.get("revision"), Some(&"A1".to_string()));
        assert_eq!(canonical.get("device_id"), Some(&"GB100".to_string()));
        assert_eq!(
            canonical.get("fec_mode_active"),
            Some(&"Int_KP4_FEC_PLR".to_string())
        );
        assert_eq!(canonical.get("cable_part_number"), Some(&"NA".to_string()));
        // Module_Temperature is no longer a re-exported label; it becomes a numeric metric.
        assert!(!canonical.contains_key("cable_temp"));
        assert_eq!(
            sample
                .labels
                .get("Module_Temperature")
                .and_then(|raw| cable_temp_to_celsius(raw)),
            Some(0.0)
        );
        assert_eq!(
            canonical.get("chassis_id"),
            Some(&"1820325172739".to_string())
        );
        assert_eq!(
            canonical.get("link_partner_node_guid"),
            Some(&"0x2c5eab0300b6a900".to_string())
        );

        // node_description is present on the series but NOT allowlisted -> not re-exported.
        assert!(!canonical.contains_key("node_description"));
    }

    #[test]
    fn test_down_blame_to_state() {
        assert_eq!(down_blame_to_state("Unknown"), "unknown");
        assert_eq!(down_blame_to_state("Local_phy"), "local_phy");
        assert_eq!(down_blame_to_state("Remote_phy"), "remote_phy");
        // Case-insensitive.
        assert_eq!(down_blame_to_state("LOCAL_PHY"), "local_phy");
        assert_eq!(down_blame_to_state("remote_PHY"), "remote_phy");
        // Unrecognized / empty -> "unknown".
        assert_eq!(down_blame_to_state("garbage"), "unknown");
        assert_eq!(down_blame_to_state(""), "unknown");
    }

    // Two scraped lines for the same port both carry down_blame="Remote_phy": exactly three
    // down_blame series (one per state) are emitted for that port, remote_phy=1 the rest=0,
    // unit "state", and down_blame is NOT a plain identity label on the emitted series.
    #[test]
    fn test_down_blame_state_set_once_per_port() {
        use std::sync::Mutex as StdMutex;

        use crate::endpoint::test_support::{mac, test_endpoint};

        struct CapturingSink {
            samples: StdMutex<Vec<MetricSample>>,
        }

        impl DataSink for CapturingSink {
            fn sink_type(&self) -> &'static str {
                "capturing_sink"
            }

            fn handle_event(&self, _context: &EventContext, event: &CollectorEvent) {
                if let CollectorEvent::Metric(sample) = event {
                    self.samples.lock().unwrap().push((**sample).clone());
                }
            }
        }

        let endpoint = Arc::new(test_endpoint(mac("00:11:22:33:44:55")));
        let sink = Arc::new(CapturingSink {
            samples: StdMutex::new(Vec::new()),
        });
        let collector = NmxtCollector {
            endpoint: endpoint.clone(),
            http_client: reqwest::Client::new(),
            event_context: EventContext::from_endpoint(endpoint.as_ref(), "nmxt"),
            data_sink: Some(sink.clone()),
        };

        // Two distinct families on the SAME port, both carrying down_blame.
        let lines = [
            r#"lid{Port_Number="11", down_blame="Remote_phy"} 3093"#,
            r#"Effective_BER{Port_Number="11", down_blame="Remote_phy"} 0"#,
        ];
        let mut down_blame_ports: HashSet<String> = HashSet::new();
        for line in lines {
            let sample = parse_prometheus_line(line).expect("parse line");
            if let Some(raw) = sample.labels.get("down_blame") {
                let Some(port_num) = required_port_num(&sample.labels) else {
                    continue;
                };
                if down_blame_ports.insert(port_num.to_string()) {
                    let current = down_blame_to_state(raw);
                    for state in DOWN_BLAME_STATES {
                        let mut labels = collector.build_labels(&sample.labels);
                        labels.push((Cow::Borrowed("state"), (*state).to_string()));
                        collector.emit_event(CollectorEvent::Metric(
                            MetricSample {
                                key: format!("down_blame:{}:{}", port_num, state),
                                name: NMXT_METRIC_NAME.to_string(),
                                metric_type: "down_blame".to_string(),
                                unit: "state".to_string(),
                                value: if *state == current { 1.0 } else { 0.0 },
                                labels,
                                context: None,
                            }
                            .into(),
                        ));
                    }
                }
            }
        }

        let samples = sink.samples.lock().unwrap();
        let blame_series: Vec<&MetricSample> = samples
            .iter()
            .filter(|s| s.metric_type == "down_blame")
            .collect();
        assert_eq!(
            blame_series.len(),
            3,
            "exactly one series per state per port per scrape"
        );

        for s in &blame_series {
            assert_eq!(s.name, "switch_nmxt");
            assert_eq!(s.unit, "state");
            let state = s
                .labels
                .iter()
                .find(|(k, _)| k == "state")
                .map(|(_, v)| v.as_str())
                .expect("state label present");
            let expected = if state == "remote_phy" { 1.0 } else { 0.0 };
            assert_eq!(s.value, expected, "state `{state}` value");
            // down_blame must not survive as a plain identity label.
            assert!(
                !s.labels.iter().any(|(k, _)| k == "down_blame"),
                "down_blame must not be a re-exported identity label"
            );
        }
    }

    #[test]
    fn test_cable_temp_to_celsius() {
        assert_eq!(cable_temp_to_celsius("0C"), Some(0.0));
        assert_eq!(cable_temp_to_celsius("37C"), Some(37.0));
        assert_eq!(cable_temp_to_celsius("37.5C"), Some(37.5));
        assert_eq!(cable_temp_to_celsius("N/A"), None);
        assert_eq!(cable_temp_to_celsius(""), None);
        assert_eq!(cable_temp_to_celsius("NA"), None);
    }

    // Two scraped lines for the same port both carry Module_Temperature: exactly one
    // cable_temperature_celsius series is emitted, with the parsed value and no cable_temp label.
    #[test]
    fn test_cable_temperature_emit_once_per_port() {
        use std::sync::Mutex as StdMutex;

        use crate::endpoint::test_support::{mac, test_endpoint};

        struct CapturingSink {
            samples: StdMutex<Vec<MetricSample>>,
        }

        impl DataSink for CapturingSink {
            fn sink_type(&self) -> &'static str {
                "capturing_sink"
            }

            fn handle_event(&self, _context: &EventContext, event: &CollectorEvent) {
                if let CollectorEvent::Metric(sample) = event {
                    self.samples.lock().unwrap().push((**sample).clone());
                }
            }
        }

        let endpoint = Arc::new(test_endpoint(mac("00:11:22:33:44:55")));
        let sink = Arc::new(CapturingSink {
            samples: StdMutex::new(Vec::new()),
        });
        let collector = NmxtCollector {
            endpoint: endpoint.clone(),
            http_client: reqwest::Client::new(),
            event_context: EventContext::from_endpoint(endpoint.as_ref(), "nmxt"),
            data_sink: Some(sink.clone()),
        };

        // Two distinct families on the SAME port, both carrying Module_Temperature.
        let lines = [
            r#"lid{Port_Number="11", Module_Temperature="37.5C"} 3093"#,
            r#"Effective_BER{Port_Number="11", Module_Temperature="37.5C"} 0"#,
        ];
        let mut cable_temp_ports: HashSet<String> = HashSet::new();
        for line in lines {
            let sample = parse_prometheus_line(line).expect("parse line");
            if let Some(celsius) = sample
                .labels
                .get("Module_Temperature")
                .and_then(|raw| cable_temp_to_celsius(raw))
            {
                let Some(port_num) = required_port_num(&sample.labels) else {
                    continue;
                };
                if cable_temp_ports.insert(port_num.to_string()) {
                    let labels = collector.build_labels(&sample.labels);
                    collector.emit_event(CollectorEvent::Metric(
                        MetricSample {
                            key: format!("cable_temperature_celsius:{}", port_num),
                            name: NMXT_METRIC_NAME.to_string(),
                            metric_type: "cable_temperature_celsius".to_string(),
                            unit: "celsius".to_string(),
                            value: celsius,
                            labels,
                            context: None,
                        }
                        .into(),
                    ));
                }
            }
        }

        let samples = sink.samples.lock().unwrap();
        let temp_series: Vec<&MetricSample> = samples
            .iter()
            .filter(|s| s.metric_type == "cable_temperature_celsius")
            .collect();
        assert_eq!(
            temp_series.len(),
            1,
            "exactly one series per port per scrape"
        );

        let series = temp_series[0];
        assert_eq!(series.name, "switch_nmxt");
        assert_eq!(series.unit, "celsius");
        assert_eq!(series.value, 37.5);
        assert_eq!(series.key, "cable_temperature_celsius:11");
        assert!(
            !series.labels.iter().any(|(k, _)| k == "cable_temp"),
            "identity labels must no longer include cable_temp"
        );
        assert!(
            series
                .labels
                .iter()
                .any(|(k, v)| k == "port_num" && v == "11"),
            "identity labels still carry port_num"
        );
    }
}
