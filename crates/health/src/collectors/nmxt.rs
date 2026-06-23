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
//!
//! Mapping is an EXPLICIT, catalog-row allowlist over the live NMX-T Prometheus scrape (see
//! `NMXT_METRIC_MAP` and `NMXT_LABEL_MAP`). Each NMX-T source name is either:
//!   * a numeric **family** -> emitted as one canonical `switch_nmxt` series (`NMXT_METRIC_MAP`), or
//!   * an identity/inventory **label dimension** carried on every series -> re-exported as a
//!     canonical label, never as a standalone metric (`NMXT_LABEL_MAP`).
//!
//! Source names not on either allowlist are skipped and counted only (never sanitized into telemetry).

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

/// Producer name for every emitted NMX-T series. Preserved across all mappings so the
/// downstream sink keeps a single `switch_nmxt` family.
const NMXT_PRODUCER: &str = "switch_nmxt";

/// Explicit allowlist: live NMX-T Prometheus **family** (numeric series) -> canonical mapping.
///
/// Tuple is `(nmxt_source_name, metric_type, unit)`. One canonical series per catalog row; the
/// source name is matched verbatim against the scraped line name. Names absent from this table
/// (and from [`NMXT_LABEL_MAP`]) are never exported. Each entry was confirmed live in the GB200
/// NMX-T scrape (Stage 0). Catalog rows are noted for traceability.
const NMXT_METRIC_MAP: &[(&str, &str, &str)] = &[
    // BER / error counters (existing mappings, retained)
    ("Effective_BER", "effective_ber", "ratio"),
    ("Symbol_Errors", "symbol_errors", "count"), // row 908 PHY-SYMBOL-ERRORS
    ("Link_Down", "link_down", "count"),
    // Identity / inventory numeric families
    ("lid", "lid", "id"),                       // row 865 LID
    ("device_hw_rev", "device_hw_rev", "id"),   // row 869 DEVICE-HARDWARE-REVISION
    // Status / link-down attribution
    ("Advanced_Status_Opcode", "status_opcode", "code"), // row 945 STATUS-OPCODE
    ("remote_reason_opcode", "remote_reason_opcode", "code"), // row 949 REMOTE-REASON-OPCODE
    ("time_to_link_up_ext_msec", "time_to_link_up", "milliseconds"), // row 944 TIME-TO-LINKS-UP
    // Cable optics (numeric families)
    ("cable_technology", "cable_transmitter_technology", "code"), // row 970 CABLE-TRANSMITTER-TECHNOLOGY
    ("rx_power_lane_0", "cable_rx_power_lane0", "milliwatts"), // row 977 CABLE-RX-POWER-LANE0
    ("rx_power_lane_1", "cable_rx_power_lane1", "milliwatts"), // row 978 CABLE-RX-POWER-LANE1
    ("Module_Voltage", "cable_diag_supply_voltage", "volts"), // row 979 CABLE-DIAG-SUPPLY-VOLTAGE
    // Link partner
    ("link_partner_lid", "link_partner_lid", "id"), // row 989 LINK-PARTNER-LID
    // Recovery counters / timers
    ("successful_recovery_events", "link_recovery_success_cnt", "count"), // row 1688 LINK-RECOVERY-SUCCESS-CNT
    ("total_successful_recovery_events", "total_link_recovery_success_cnt", "count"), // row 1689 TOTAL-LINK-RECOVERY-SUCCESS-CNT
    ("time_since_last_recovery", "time_since_last_recovery", "seconds"), // row 1690 TIME-SINCE-LAST-RECOVERY
    ("time_between_last_2_recoveries", "time_btwn_two_recoveries", "seconds"), // row 1691 TIME-BTWN-TWO-RECOVERIES
    ("last_host_logical_recovery_attempts_count", "recovery_attempts_l1_cnt", "count"), // row 1692 RECOVERY-ATTEMPTS-L1-CNT
    ("last_host_serdes_feq_attempts_count", "recovery_attempts_l2_cnt", "count"), // row 1693 RECOVERY-ATTEMPTS-L2-CNT
    ("time_in_last_host_logical_recovery", "recovery_cycle_duration", "seconds"), // row 1694 RECOVERY-CYCLE-DURATION
    ("time_in_last_host_serdes_feq_recovery", "serdes_recovery_cycle_duration", "seconds"), // row 1695 SERDES-RECOVERY-CYCLE-DURATION
    // Contain-and-drain discards
    ("contain_n_drain_xmit_discards", "contain_drain_xmit_discard", "count"), // row 1696 CONTAIN-DRAIN-XMIT-DISCARD
    ("contain_n_drain_rcv_discards", "contain_drain_rcv_discard", "count"), // row 1697 CONTAIN-DRAIN-RCV-DISCARD
    // Raw error lanes
    ("Raw_Errors_Lane_2", "raw_err_lane_2", "count"), // row 1704 RAW-ERR-LANE-2
    ("Raw_Errors_Lane_3", "raw_err_lane_3", "count"), // row 1705 RAW-ERR-LANE-3
];

/// Explicit allowlist: live NMX-T Prometheus **label** key -> canonical label name.
///
/// These catalog rows are identity/inventory dimensions, not standalone metrics. NMX-T carries
/// them as labels on every series, so they are re-exported as canonical labels on each emitted
/// `switch_nmxt` sample (consistent with the existing `node_guid` / `port_num` handling). They are
/// never emitted as their own metric family. Tuple is `(nmxt_label_key, canonical_label_name)`.
/// Catalog rows are noted for traceability.
const NMXT_LABEL_MAP: &[(&str, &str)] = &[
    ("FW_Version", "net_fw_ver"),                 // row 763 NET-FW-VER
    ("sw_serial_number", "serial"),               // row 804 SERIAL
    ("Node_GUID", "node_guid"),                   // row 806 NODE-GUID
    ("port_guid", "port_guid"),                   // row 807 PORT-GUID
    ("Port_Number", "port_num"),                  // row 866 PORT-NUMBER
    ("port_label", "port_label"),                 // row 867 PORT-LABEL
    ("sw_revision", "revision"),                  // row 868 REVISION
    ("Active_FEC", "fec_mode_active"),            // row 898 FEC-MODE-ACTIVE
    ("Device_ID", "device_id"),                   // row 910 DEVICE-ID
    ("Status_Message", "status_message"),         // row 946 STATUS-MESSAGE
    ("down_blame", "down_blame"),                 // row 947 DOWN-BLAME
    ("local_reason_opcode", "local_reason_opcode"), // row 948 LOCAL-REASON-OPCODE
    ("Cable_PN", "cable_part_number"),            // row 968 CABLE-PART-NUMBER
    ("Cable_SN", "cable_serial_number"),          // row 969 CABLE-SERIAL-NUMBER
    ("cable_type", "cable_type"),                 // row 971 CABLE-TYPE
    ("cable_vendor", "cable_vendor"),             // row 972 CABLE-VENDOR
    ("cable_length", "cable_length"),             // row 973 CABLE-LENGTH
    ("cable_identifier", "cable_identifier"),     // row 974 CABLE-IDENTIFIER
    ("vendor_rev", "cable_rev"),                  // row 975 CABLE-REV
    ("cable_fw_version", "cable_fw_version"),     // row 976 CABLE-FW-VERSION
    ("Module_Temperature", "cable_temp"),         // row 980 CABLE-TEMP
    ("link_partner_description", "link_partner_description"), // row 987 LINK-PARTNER-DESCRIPTION
    ("link_partner_node_guid", "link_partner_node_guid"), // row 988 LINK-PARTNER-NODE-GUID
    ("link_partner_port_num", "link_partner_port_num"), // row 990 LINK-PARTNER-PORT-NUM
    ("device_num_on_tray", "device_num"),         // row 1698 DEVICE-NUM
    ("board_type", "board_type"),                 // row 1699 BOARD-TYPE
    ("chassis_slot_index", "chassis_slot_idx"),   // row 1700 CHASSIS-SLOT-IDX
    ("tray_index", "tray_idx"),                   // row 1701 TRAY-IDX
    ("topology_id", "topology_id"),               // row 1702 TOPOLOGY-ID
    ("chassis_id", "chassis_id"),                 // row 1703 CHASSIS-ID
];

/// Look up a live NMX-T family name in the explicit allowlist, returning `(metric_type, unit)`.
fn lookup_nmxt_metric(name: &str) -> Option<(&'static str, &'static str)> {
    NMXT_METRIC_MAP
        .iter()
        .find(|(source, _, _)| *source == name)
        .map(|(_, metric_type, unit)| (*metric_type, *unit))
}

/// Look up a live NMX-T label key in the explicit allowlist, returning the canonical label name.
/// Test-only helper; production re-exports labels by iterating `NMXT_LABEL_MAP` directly in `build_labels`.
#[cfg(test)]
fn lookup_nmxt_label(key: &str) -> Option<&'static str> {
    NMXT_LABEL_MAP
        .iter()
        .find(|(source, _)| *source == key)
        .map(|(_, canonical)| *canonical)
}

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

    /// Build the canonical label set for one emitted `switch_nmxt` series.
    ///
    /// Always carries `switch_id` / `switch_ip`. Identity and inventory dimensions are re-exported
    /// from the scraped sample only when their NMX-T label key is on the explicit
    /// [`NMXT_LABEL_MAP`] allowlist; their canonical names come from that map. Label keys not on
    /// the allowlist are dropped (never sanitized into exported labels).
    fn build_labels(
        &self,
        switch_ip: &str,
        sample_labels: &HashMap<String, String>,
    ) -> Vec<(Cow<'static, str>, String)> {
        let mut labels: Vec<(Cow<'static, str>, String)> = Vec::with_capacity(2 + NMXT_LABEL_MAP.len());
        labels.push((Cow::Borrowed("switch_id"), self.switch_id.clone()));
        labels.push((Cow::Borrowed("switch_ip"), switch_ip.to_string()));

        for (source_key, canonical) in NMXT_LABEL_MAP {
            if let Some(value) = sample_labels.get(*source_key) {
                labels.push((Cow::Borrowed(*canonical), value.clone()));
            }
        }

        labels
    }

    async fn scrape_iteration(&self) -> Result<(), HealthError> {
        let switch_ip = self.endpoint.addr.ip.to_string();

        let metrics = scrape_switch_nmxt_metrics(&self.http_client, &switch_ip).await?;

        self.emit_event(CollectorEvent::MetricCollectionStart);

        // Count of scraped families not on the explicit allowlist. These are skipped (never
        // sanitized into telemetry) and only reported diagnostically.
        let mut unmapped_families = 0u64;

        for sample in metrics {
            let NmxtMetricSample {
                name,
                labels: sample_labels,
                value,
            } = sample;

            // Explicit family allowlist: an unknown source name is dropped and counted only.
            let Some((metric_type, unit)) = lookup_nmxt_metric(&name) else {
                unmapped_families += 1;
                continue;
            };

            // Port number anchors the per-series key; sourced from the explicit label dimension.
            let port_num = sample_labels
                .get("Port_Number")
                .cloned()
                .unwrap_or_default();

            let mut metric_key = String::with_capacity(metric_type.len() + 1 + port_num.len());
            metric_key.push_str(metric_type);
            metric_key.push(':');
            metric_key.push_str(&port_num);

            let labels = self.build_labels(&switch_ip, &sample_labels);

            self.emit_event(CollectorEvent::Metric(
                MetricSample {
                    key: metric_key,
                    name: NMXT_PRODUCER.to_string(),
                    metric_type: metric_type.to_string(),
                    unit: unit.to_string(),
                    value,
                    labels,
                    context: None,
                }
                .into(),
            ));
        }

        if unmapped_families > 0 {
            tracing::debug!(
                switch_id = %self.switch_id,
                count = unmapped_families,
                "skipped NMX-T families not on explicit allowlist"
            );
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

    /// Representative live NMX-T `lid` series carrying the full identity/inventory label set.
    /// Mirrors the Stage-0 GB200 scrape (`nmxt-prometheus.txt`).
    const SAMPLE_LID_LINE: &str = r#"lid{Device_ID="GB100", port_label="GPUP10", logical_state="ACT", device_num_on_tray="2", board_type="3", chassis_slot_index="27", tray_index="17", topology_id="128", chassis_id="1820325172739", Active_FEC="Int_KP4_FEC_PLR", link_partner_description="MF0;sw06:N5400_LD/U1", link_partner_node_guid="0x2c5eab0300b6a900", link_partner_port_num="71", cable_vendor="Other", down_blame="Unknown", local_reason_opcode="No_link_down_indication", Node_GUID="0xe1d04a69816f16bc", node_description="GB100 Nvidia Technologies", Port_Number="11", FW_Version="36.2014.1866", Cable_PN="NA", Cable_SN="NA", cable_type="850 nm VCSEL", cable_length="NA", cable_identifier="Backplane", vendor_rev="NA", cable_fw_version="N/A", Module_Temperature="0C", Status_Message="No issue was observed", port_guid="0xe1d04a69816f16c6", sw_serial_number="MT123", sw_revision="A1", remote_reason_opcode="4"}  3093 1781993954087"#;

    // Catalog row -> NMX-T family -> (metric_type, unit). One row per explicit family mapping.
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
            ("time_to_link_up_ext_msec", "time_to_link_up", "milliseconds"),
            ("cable_technology", "cable_transmitter_technology", "code"),
            ("rx_power_lane_0", "cable_rx_power_lane0", "milliwatts"),
            ("rx_power_lane_1", "cable_rx_power_lane1", "milliwatts"),
            ("Module_Voltage", "cable_diag_supply_voltage", "volts"),
            ("link_partner_lid", "link_partner_lid", "id"),
            ("successful_recovery_events", "link_recovery_success_cnt", "count"),
            (
                "total_successful_recovery_events",
                "total_link_recovery_success_cnt",
                "count",
            ),
            ("time_since_last_recovery", "time_since_last_recovery", "seconds"),
            ("time_between_last_2_recoveries", "time_btwn_two_recoveries", "seconds"),
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
            ("time_in_last_host_logical_recovery", "recovery_cycle_duration", "seconds"),
            (
                "time_in_last_host_serdes_feq_recovery",
                "serdes_recovery_cycle_duration",
                "seconds",
            ),
            ("contain_n_drain_xmit_discards", "contain_drain_xmit_discard", "count"),
            ("contain_n_drain_rcv_discards", "contain_drain_rcv_discard", "count"),
            ("Raw_Errors_Lane_2", "raw_err_lane_2", "count"),
            ("Raw_Errors_Lane_3", "raw_err_lane_3", "count"),
        ];

        for (source, metric_type, unit) in expected {
            assert_eq!(
                lookup_nmxt_metric(source),
                Some((*metric_type, *unit)),
                "family `{source}` must map to ({metric_type}, {unit})"
            );
        }
        // The allowlist must contain exactly these explicit families (no extras, no generic).
        assert_eq!(NMXT_METRIC_MAP.len(), expected.len());
    }

    // Catalog identity/inventory row -> NMX-T label key -> canonical label name.
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
            ("Status_Message", "status_message"),
            ("down_blame", "down_blame"),
            ("local_reason_opcode", "local_reason_opcode"),
            ("Cable_PN", "cable_part_number"),
            ("Cable_SN", "cable_serial_number"),
            ("cable_type", "cable_type"),
            ("cable_vendor", "cable_vendor"),
            ("cable_length", "cable_length"),
            ("cable_identifier", "cable_identifier"),
            ("vendor_rev", "cable_rev"),
            ("cable_fw_version", "cable_fw_version"),
            ("Module_Temperature", "cable_temp"),
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
                lookup_nmxt_label(key),
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
        for (source_key, canonical_name) in NMXT_LABEL_MAP {
            if let Some(value) = sample.labels.get(*source_key) {
                canonical.insert(*canonical_name, value.clone());
            }
        }

        // Identity/inventory rows are present as labels with their canonical names.
        assert_eq!(canonical.get("node_guid"), Some(&"0xe1d04a69816f16bc".to_string())); // 806
        assert_eq!(canonical.get("port_guid"), Some(&"0xe1d04a69816f16c6".to_string())); // 807
        assert_eq!(canonical.get("port_num"), Some(&"11".to_string())); // 866
        assert_eq!(canonical.get("port_label"), Some(&"GPUP10".to_string())); // 867
        assert_eq!(canonical.get("net_fw_ver"), Some(&"36.2014.1866".to_string())); // 763
        assert_eq!(canonical.get("serial"), Some(&"MT123".to_string())); // 804
        assert_eq!(canonical.get("revision"), Some(&"A1".to_string())); // 868
        assert_eq!(canonical.get("device_id"), Some(&"GB100".to_string())); // 910
        assert_eq!(canonical.get("fec_mode_active"), Some(&"Int_KP4_FEC_PLR".to_string())); // 898
        assert_eq!(canonical.get("cable_part_number"), Some(&"NA".to_string())); // 968
        assert_eq!(canonical.get("cable_temp"), Some(&"0C".to_string())); // 980
        assert_eq!(canonical.get("chassis_id"), Some(&"1820325172739".to_string())); // 1703
        assert_eq!(
            canonical.get("link_partner_node_guid"),
            Some(&"0x2c5eab0300b6a900".to_string())
        ); // 988

        // node_description is present on the series but NOT allowlisted -> not re-exported.
        assert!(!canonical.contains_key("node_description"));
    }
}
