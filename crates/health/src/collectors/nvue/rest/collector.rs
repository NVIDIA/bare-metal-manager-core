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

use super::client::{RestClient, UsernamePassword};
use crate::HealthError;
use crate::bmc::{CREDENTIAL_REFRESH_TIMEOUT, CredentialProvider, is_auth_error};
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::config::NvueRestConfig;
use crate::endpoint::{BmcAddr, BmcCredentials, BmcEndpoint, EndpointMetadata};
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample};

const COLLECTOR_NAME: &str = "nvue_rest";

const SYSTEM_HEALTH_STATES: &[&str] = &["ok", "not_ok", "unknown"];

fn system_health_to_state(status: Option<&str>) -> &'static str {
    match status {
        Some("OK") => "ok",
        Some("Not OK") => "not_ok",
        _ => "unknown",
    }
}

const PARTITION_HEALTH_STATES: &[&str] = &[
    "healthy",
    "degraded_bandwidth",
    "degraded",
    "unhealthy",
    "unknown",
];

fn partition_health_to_state(status: Option<&str>) -> &'static str {
    match status {
        Some("healthy") => "healthy",
        Some("degraded_bandwidth") => "degraded_bandwidth",
        Some("degraded") => "degraded",
        Some("unhealthy") => "unhealthy",
        _ => "unknown",
    }
}

const APP_STATUS_STATES: &[&str] = &["ok", "not_ok", "unknown"];

fn app_status_to_state(status: Option<&str>) -> &'static str {
    match status {
        Some("ok") => "ok",
        Some("not ok") => "not_ok",
        _ => "unknown",
    }
}

/// "0" -> no issue. Any other opcode indicates a problem
fn diagnostic_opcode_to_f64(code: &str) -> f64 {
    match code {
        "0" => 0.0,
        _ => 1.0,
    }
}

/// NVUE reports fan max-speed as a string (e.g. "33000"). Parse it to RPM.
/// Returns None when the field is absent or unparseable.
fn fan_max_speed_to_f64(max_speed: Option<&str>) -> Option<f64> {
    max_speed
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
}

/// NVUE reports temps (current/max/crit) as Celsius strings (e.g. "105.00").
/// Parse to f64. Returns None when the field is absent or unparseable.
fn temp_to_f64(value: Option<&str>) -> Option<f64> {
    value.and_then(|s| s.trim().parse::<f64>().ok())
}

const TEMP_STATE_STATES: &[&str] = &["ok", "not_ok"];

/// Sensor `state` -> StateSet: "ok" (case-insensitive) => "ok", other present
/// => "not_ok", absent => None.
fn temp_state_to_state(state: Option<&str>) -> Option<&'static str> {
    state.map(|s| {
        if s.trim().eq_ignore_ascii_case("ok") {
            "ok"
        } else {
            "not_ok"
        }
    })
}

const FAN_LED_STATES: &[&str] = &["ok", "not_ok"];

/// `FAN_STATUS` LED -> StateSet: "green"/"ok" (case-insensitive) => "ok",
/// other non-empty => "not_ok", absent/empty => None.
fn fan_led_to_state(state: Option<&str>) -> Option<&'static str> {
    let s = state?.trim();
    if s.is_empty() {
        return None;
    }
    if s.eq_ignore_ascii_case("green") || s.eq_ignore_ascii_case("ok") {
        Some("ok")
    } else {
        Some("not_ok")
    }
}

pub struct NvueRestCollectorConfig {
    pub rest_config: NvueRestConfig,
    pub data_sink: Option<Arc<dyn DataSink>>,
    pub credential_provider: Arc<dyn CredentialProvider>,
}

pub struct NvueRestCollector {
    client: RestClient,
    switch_id: String,
    event_context: EventContext,
    data_sink: Option<Arc<dyn DataSink>>,
    addr: BmcAddr,
    provider: Arc<dyn CredentialProvider>,
}

impl PeriodicCollector<crate::bmc::BmcClient> for NvueRestCollector {
    type Config = NvueRestCollectorConfig;

    fn new_runner(
        _bmc: Arc<crate::bmc::BmcClient>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let switch_id = match &endpoint.metadata {
            Some(EndpointMetadata::Switch(s)) => s.serial.clone(),
            _ => endpoint.addr.mac.to_string(),
        };
        let switch_ip = endpoint.addr.ip.to_string();
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), COLLECTOR_NAME);

        let rest_cfg = &config.rest_config;
        // self_signed_tls is always true -- TLS cert provisioning on switches is not yet implemented
        let client = RestClient::new(
            switch_id.clone(),
            &switch_ip,
            rest_cfg.request_timeout,
            true,
            rest_cfg.paths.clone(),
        )?;

        Ok(Self {
            client,
            switch_id,
            event_context,
            data_sink: config.data_sink,
            addr: endpoint.addr.clone(),
            provider: config.credential_provider,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        if !self.client.has_credentials()
            && let Err(error) = self.refresh_rest_credentials().await
        {
            tracing::warn!(
                ?error,
                switch_id = %self.switch_id,
                "nvue_rest: skipping iteration — credential fetch failed"
            );
            return Ok(IterationResult {
                refresh_triggered: false,
                entity_count: Some(0),
                fetch_failures: 1,
            });
        }

        self.emit_event(CollectorEvent::MetricCollectionStart);
        let mut entity_count = 0usize;
        let mut fetch_failures = 0usize;
        let mut saw_auth_failure = false;

        match self.client.get_system_health().await {
            Ok(Some(health)) => {
                let current = system_health_to_state(health.status.as_deref());
                self.emit_state_set("system_health", None, current, SYSTEM_HEALTH_STATES, vec![]);
                entity_count += 1;
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect system health"
                );
            }
        }

        match self.client.get_cluster_apps().await {
            Ok(Some(apps)) => {
                for (name, app) in &apps {
                    let current = app_status_to_state(app.status.as_deref());
                    self.emit_state_set(
                        "cluster_app",
                        Some(name),
                        current,
                        APP_STATUS_STATES,
                        vec![(Cow::Borrowed("app_name"), name.clone())],
                    );
                    entity_count += 1;
                }
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect cluster apps"
                );
            }
        }

        match self.client.get_sdn_partitions().await {
            Ok(Some(partitions)) => {
                for (part_id, partition) in &partitions {
                    let part_name = partition.name.as_deref().unwrap_or(part_id);
                    let health_state = partition_health_to_state(partition.health.as_deref());
                    let gpu_count = partition.num_gpus.unwrap_or(0) as f64;

                    let partition_labels = vec![
                        (Cow::Borrowed("partition_id"), part_id.clone()),
                        (Cow::Borrowed("partition_name"), part_name.to_string()),
                    ];
                    self.emit_state_set(
                        "partition_health",
                        Some(part_id),
                        health_state,
                        PARTITION_HEALTH_STATES,
                        partition_labels.clone(),
                    );
                    self.emit_metric(
                        "partition_gpu",
                        Some(part_id),
                        gpu_count,
                        "count",
                        partition_labels,
                    );
                    entity_count += 1;
                }
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect SDN partitions"
                );
            }
        }

        match self.client.get_link_diagnostics().await {
            Ok(diagnostics) => {
                for diag in &diagnostics {
                    let value = diagnostic_opcode_to_f64(&diag.code);
                    self.emit_metric(
                        "link_diagnostic",
                        Some(&format!("{}:{}", diag.interface, diag.code)),
                        value,
                        "state",
                        vec![
                            (Cow::Borrowed("interface_name"), diag.interface.clone()),
                            (Cow::Borrowed("opcode"), diag.code.clone()),
                            (Cow::Borrowed("diagnostic_status"), diag.status.clone()),
                        ],
                    );
                    entity_count += 1;
                }
            }
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect link diagnostics"
                );
            }
        }

        match self.client.get_platform_environment_fan().await {
            Ok(Some(fans)) => {
                for (fan_name, fan) in &fans {
                    // Only emit when max-speed parses. Absent or garbage emits nothing.
                    if let Some(value) = fan_max_speed_to_f64(fan.max_speed.as_deref()) {
                        self.emit_metric(
                            "fan_max_speed",
                            Some(fan_name),
                            value,
                            "rpm",
                            vec![(Cow::Borrowed("fan_name"), fan_name.clone())],
                        );
                        entity_count += 1;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect platform environment fan"
                );
            }
        }

        match self.client.get_platform_environment_temperature().await {
            Ok(Some(temps)) => {
                for (sensor_name, temp) in &temps {
                    // Each field is optional. Emit only those present and parseable.
                    let sensor_label = || vec![(Cow::Borrowed("sensor"), sensor_name.clone())];

                    if let Some(value) = temp_to_f64(temp.current.as_deref()) {
                        self.emit_metric(
                            "platform_temperature",
                            Some(sensor_name),
                            value,
                            "celsius",
                            sensor_label(),
                        );
                        entity_count += 1;
                    }
                    if let Some(value) = temp_to_f64(temp.max.as_deref()) {
                        self.emit_metric(
                            "platform_temperature_max",
                            Some(sensor_name),
                            value,
                            "celsius",
                            sensor_label(),
                        );
                        entity_count += 1;
                    }
                    if let Some(value) = temp_to_f64(temp.crit.as_deref()) {
                        self.emit_metric(
                            "platform_temperature_critical",
                            Some(sensor_name),
                            value,
                            "celsius",
                            sensor_label(),
                        );
                        entity_count += 1;
                    }
                    // Absent state emits nothing. Present state emits one 0/1 series per state.
                    if let Some(current) = temp_state_to_state(temp.state.as_deref()) {
                        self.emit_state_set(
                            "platform_temperature_state",
                            Some(sensor_name),
                            current,
                            TEMP_STATE_STATES,
                            sensor_label(),
                        );
                        entity_count += 1;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect platform environment temperature"
                );
            }
        }

        match self.client.get_platform_environment().await {
            Ok(Some(env)) => {
                // Switch-level FAN_STATUS LED. Emit only when present and mappable.
                if let Some(current) = env
                    .get("FAN_STATUS")
                    .and_then(|s| fan_led_to_state(s.state.as_deref()))
                {
                    self.emit_state_set("fan_led", None, current, FAN_LED_STATES, vec![]);
                    entity_count += 1;
                }
            }
            Ok(None) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect platform environment status"
                );
            }
        }

        if saw_auth_failure {
            tracing::warn!(
                switch_id = %self.switch_id,
                "nvue_rest: auth failure observed, clearing cached credentials"
            );
            self.client.clear_credentials();
        }

        self.emit_event(CollectorEvent::MetricCollectionEnd);

        tracing::debug!(
            switch_id = %self.switch_id,
            entity_count,
            "nvue_rest: collection iteration complete"
        );

        Ok(IterationResult {
            refresh_triggered: true,
            entity_count: Some(entity_count),
            fetch_failures,
        })
    }

    fn collector_type(&self) -> &'static str {
        COLLECTOR_NAME
    }

    async fn stop(&mut self) {
        self.emit_event(CollectorEvent::CollectorRemoved);
    }
}

impl NvueRestCollector {
    async fn refresh_rest_credentials(&self) -> Result<(), HealthError> {
        let creds = tokio::time::timeout(
            CREDENTIAL_REFRESH_TIMEOUT,
            self.provider.fetch_credentials(&self.addr),
        )
        .await
        .map_err(|_elapsed| {
            HealthError::GenericError(format!(
                "Timed out after {}s fetching NVUE REST credentials",
                CREDENTIAL_REFRESH_TIMEOUT.as_secs(),
            ))
        })??;
        match creds {
            BmcCredentials::UsernamePassword { username, password } => {
                self.client
                    .set_credentials(UsernamePassword { username, password });
                Ok(())
            }
            _ => Err(HealthError::GenericError(
                "NVUE REST collector requires username/password credentials".to_string(),
            )),
        }
    }

    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    fn emit_metric(
        &self,
        metric_type: &str,
        entity_qualifier: Option<&str>,
        value: f64,
        unit: &str,
        labels: Vec<(Cow<'static, str>, String)>,
    ) {
        let key = match entity_qualifier {
            Some(q) => {
                let mut k = String::with_capacity(metric_type.len() + 1 + q.len());
                k.push_str(metric_type);
                k.push(':');
                k.push_str(q);
                k
            }
            None => metric_type.to_string(),
        };

        self.emit_event(CollectorEvent::Metric(
            MetricSample {
                key,
                name: COLLECTOR_NAME.to_string(),
                metric_type: metric_type.to_string(),
                unit: unit.to_string(),
                value,
                labels,
                context: None,
            }
            .into(),
        ));
    }

    /// Emit an OpenMetrics StateSet: one 0/1 series per state (current => 1.0),
    /// each carrying `labels` plus a `state` label. `key_base` is suffixed with
    /// the state name for a unique per-series key. Unit is always "state".
    fn emit_state_set(
        &self,
        metric_type: &str,
        key_base: Option<&str>,
        current_state: &str,
        all_states: &[&str],
        labels: Vec<(Cow<'static, str>, String)>,
    ) {
        for state in all_states {
            let mut series_labels = labels.clone();
            series_labels.push((Cow::Borrowed("state"), state.to_string()));

            // suffix state onto the qualifier for a unique per-series key
            // (switch-level series use the state name alone).
            let qualifier = match key_base {
                Some(base) => format!("{base}:{state}"),
                None => (*state).to_string(),
            };

            self.emit_metric(
                metric_type,
                Some(&qualifier),
                if *state == current_state { 1.0 } else { 0.0 },
                "state",
                series_labels,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use mac_address::MacAddress;

    use super::*;
    use crate::bmc::BoxFuture;
    use crate::config::NvueRestPaths;

    /// Assert StateSet semantics: one 0/1 series per state (current => 1.0),
    /// each with unit "state" and a `state` label. `entity` (if set) is present
    /// on every series.
    fn assert_state_set(
        samples: &[MetricSample],
        metric_type: &str,
        entity: Option<(&str, &str)>,
        all_states: &[&str],
        current: &str,
    ) {
        let series: Vec<&MetricSample> = samples
            .iter()
            .filter(|s| s.metric_type == metric_type)
            .collect();
        assert_eq!(
            series.len(),
            all_states.len(),
            "{metric_type}: expected one series per state"
        );
        for state in all_states {
            let sample = series
                .iter()
                .find(|s| s.labels.iter().any(|(k, v)| k == "state" && v == state))
                .unwrap_or_else(|| panic!("{metric_type}: missing series for state {state}"));
            assert_eq!(sample.unit, "state", "state {state}");
            assert_eq!(
                sample.value,
                if *state == current { 1.0 } else { 0.0 },
                "{metric_type} state {state}: value (current={current})"
            );
            if let Some((label, value)) = entity {
                assert!(
                    sample.labels.iter().any(|(k, v)| k == label && v == value),
                    "{metric_type} state {state}: missing entity label {label}={value}"
                );
            }
        }
    }

    #[test]
    fn test_system_health_mapping() {
        assert_eq!(system_health_to_state(Some("OK")), "ok");
        assert_eq!(system_health_to_state(Some("Not OK")), "not_ok");
        assert_eq!(system_health_to_state(None), "unknown");
        assert_eq!(system_health_to_state(Some("unknown_value")), "unknown");
    }

    #[test]
    fn test_partition_health_mapping() {
        assert_eq!(partition_health_to_state(Some("unknown")), "unknown");
        assert_eq!(partition_health_to_state(Some("healthy")), "healthy");
        assert_eq!(
            partition_health_to_state(Some("degraded_bandwidth")),
            "degraded_bandwidth"
        );
        assert_eq!(partition_health_to_state(Some("degraded")), "degraded");
        assert_eq!(partition_health_to_state(Some("unhealthy")), "unhealthy");
        assert_eq!(partition_health_to_state(None), "unknown");
    }

    #[test]
    fn test_app_status_mapping() {
        assert_eq!(app_status_to_state(Some("ok")), "ok");
        assert_eq!(app_status_to_state(Some("not ok")), "not_ok");
        assert_eq!(app_status_to_state(None), "unknown");
        assert_eq!(app_status_to_state(Some("other")), "unknown");
    }

    #[test]
    fn test_diagnostic_opcode_mapping() {
        assert_eq!(diagnostic_opcode_to_f64("0"), 0.0);
        assert_eq!(diagnostic_opcode_to_f64("2"), 1.0);
        assert_eq!(diagnostic_opcode_to_f64("1024"), 1.0);
        assert_eq!(diagnostic_opcode_to_f64("57"), 1.0);
    }

    #[test]
    fn test_fan_max_speed_parsing() {
        assert_eq!(fan_max_speed_to_f64(Some("33000")), Some(33000.0));
        assert_eq!(fan_max_speed_to_f64(Some(" 33000 ")), Some(33000.0));
        assert_eq!(fan_max_speed_to_f64(Some("6000")), Some(6000.0));
        assert_eq!(fan_max_speed_to_f64(Some("NaN")), None);
        assert_eq!(fan_max_speed_to_f64(Some("inf")), None);
        assert_eq!(fan_max_speed_to_f64(Some("-1")), None);
        assert_eq!(fan_max_speed_to_f64(Some("not-a-number")), None);
        assert_eq!(fan_max_speed_to_f64(Some("")), None);
        assert_eq!(fan_max_speed_to_f64(None), None);
    }

    #[test]
    fn test_temp_to_f64_parsing() {
        assert_eq!(temp_to_f64(Some("105.00")), Some(105.0));
        assert_eq!(temp_to_f64(Some(" 43 ")), Some(43.0));
        assert_eq!(temp_to_f64(Some("120.00")), Some(120.0));
        assert_eq!(temp_to_f64(Some("x")), None);
        assert_eq!(temp_to_f64(Some("")), None);
        assert_eq!(temp_to_f64(None), None);
    }

    #[test]
    fn test_temp_state_to_state_mapping() {
        assert_eq!(temp_state_to_state(Some("ok")), Some("ok"));
        assert_eq!(temp_state_to_state(Some("OK")), Some("ok"));
        assert_eq!(temp_state_to_state(Some(" ok ")), Some("ok"));
        assert_eq!(temp_state_to_state(Some("warning")), Some("not_ok"));
        assert_eq!(temp_state_to_state(Some("")), Some("not_ok"));
        // absent => None (emit nothing, never fabricate)
        assert_eq!(temp_state_to_state(None), None);
    }

    #[test]
    fn test_fan_led_to_state_mapping() {
        // green/ok (case-insensitive) => "ok"
        assert_eq!(fan_led_to_state(Some("green")), Some("ok"));
        assert_eq!(fan_led_to_state(Some("GREEN")), Some("ok"));
        assert_eq!(fan_led_to_state(Some(" green ")), Some("ok"));
        assert_eq!(fan_led_to_state(Some("ok")), Some("ok"));
        assert_eq!(fan_led_to_state(Some("OK")), Some("ok"));
        // any other non-empty value => "not_ok"
        assert_eq!(fan_led_to_state(Some("amber")), Some("not_ok"));
        assert_eq!(fan_led_to_state(Some("red")), Some("not_ok"));
        // absent/empty => None (emit nothing)
        assert_eq!(fan_led_to_state(Some("")), None);
        assert_eq!(fan_led_to_state(Some("   ")), None);
        assert_eq!(fan_led_to_state(None), None);
    }

    /// Drives run_iteration's fan parse + emit logic against a captured sink,
    /// asserting max-speed sample shape. Table-driven.
    #[test]
    fn test_fan_max_speed_emit() {
        use crate::collectors::nvue::rest::client::FanEnvironmentResponse;

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

        struct Case {
            name: &'static str,
            json: &'static str,
            // (fan_name, expected_value) pairs that MUST be emitted.
            expected: &'static [(&'static str, f64)],
            // Fan names that MUST NOT produce a sample.
            absent: &'static [&'static str],
        }

        let cases = [
            Case {
                name: "two healthy fans emit max-speed",
                json: r#"{
                    "FAN1/1": {"current-speed": "10096", "direction": "F2B", "max-speed": "33000", "min-speed": "6000", "state": "ok"},
                    "FAN1/2": {"current-speed": "9800", "direction": "F2B", "max-speed": "33000", "min-speed": "6000", "state": "ok"}
                }"#,
                expected: &[("FAN1/1", 33000.0), ("FAN1/2", 33000.0)],
                absent: &[],
            },
            Case {
                name: "missing max-speed emits nothing",
                json: r#"{
                    "FAN1/1": {"current-speed": "10096", "min-speed": "6000", "state": "ok"}
                }"#,
                expected: &[],
                absent: &["FAN1/1"],
            },
            Case {
                name: "garbage max-speed emits nothing",
                json: r#"{
                    "FAN1/1": {"max-speed": "bogus", "state": "ok"}
                }"#,
                expected: &[],
                absent: &["FAN1/1"],
            },
        ];

        for case in cases {
            let sink = Arc::new(CapturingSink {
                samples: StdMutex::new(Vec::new()),
            });
            let mut collector = collector_with_provider(ScriptedProvider::new(vec![]));
            collector.data_sink = Some(sink.clone());

            let fans: FanEnvironmentResponse =
                serde_json::from_str(case.json).expect("fan json parses");
            // Mirror run_iteration's emit loop exactly.
            for (fan_name, fan) in &fans {
                if let Some(value) = fan_max_speed_to_f64(fan.max_speed.as_deref()) {
                    collector.emit_metric(
                        "fan_max_speed",
                        Some(fan_name),
                        value,
                        "rpm",
                        vec![(Cow::Borrowed("fan_name"), fan_name.clone())],
                    );
                }
            }

            let samples = sink.samples.lock().unwrap();
            assert_eq!(
                samples.len(),
                case.expected.len(),
                "case '{}': unexpected emitted sample count",
                case.name
            );

            for (fan_name, expected_value) in case.expected {
                let sample = samples
                    .iter()
                    .find(|s| {
                        s.labels
                            .iter()
                            .any(|(k, v)| k == "fan_name" && v == fan_name)
                    })
                    .unwrap_or_else(|| {
                        panic!("case '{}': no sample for fan {fan_name}", case.name)
                    });

                assert_eq!(sample.name, COLLECTOR_NAME, "case '{}'", case.name);
                assert_eq!(sample.metric_type, "fan_max_speed", "case '{}'", case.name);
                assert_eq!(sample.unit, "rpm", "case '{}'", case.name);
                assert_eq!(sample.value, *expected_value, "case '{}'", case.name);
                assert_eq!(
                    sample.key,
                    format!("fan_max_speed:{fan_name}"),
                    "case '{}'",
                    case.name
                );
                assert_eq!(sample.labels.len(), 1, "case '{}'", case.name);
                assert_eq!(sample.labels[0].0, "fan_name", "case '{}'", case.name);
                assert_eq!(sample.labels[0].1, *fan_name, "case '{}'", case.name);
            }

            for fan_name in case.absent {
                assert!(
                    !samples.iter().any(|s| s
                        .labels
                        .iter()
                        .any(|(k, v)| k == "fan_name" && v == fan_name)),
                    "case '{}': fan {fan_name} should not emit a sample",
                    case.name
                );
            }
        }
    }

    /// Drives run_iteration's temperature parse + emit logic against a captured
    /// sink. A full sensor (ASIC1) emits all four series. A sparse sensor
    /// (current + state only) emits two and must NOT fabricate absent max/crit.
    #[test]
    fn test_platform_temperature_emit() {
        use crate::collectors::nvue::rest::client::TemperatureEnvironmentResponse;

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

        let json = r#"{
            "ASIC1": {"crit": "120.00", "current": "43.00", "max": "105.00", "state": "ok"},
            "Ambient-MNG-Temp": {"current": "27.00", "state": "ok"}
        }"#;

        let sink = Arc::new(CapturingSink {
            samples: StdMutex::new(Vec::new()),
        });
        let mut collector = collector_with_provider(ScriptedProvider::new(vec![]));
        collector.data_sink = Some(sink.clone());

        let temps: TemperatureEnvironmentResponse =
            serde_json::from_str(json).expect("temperature json parses");
        // Mirror run_iteration's emit loop exactly.
        for (sensor_name, temp) in &temps {
            let sensor_label = || vec![(Cow::Borrowed("sensor"), sensor_name.clone())];
            if let Some(value) = temp_to_f64(temp.current.as_deref()) {
                collector.emit_metric(
                    "platform_temperature",
                    Some(sensor_name),
                    value,
                    "celsius",
                    sensor_label(),
                );
            }
            if let Some(value) = temp_to_f64(temp.max.as_deref()) {
                collector.emit_metric(
                    "platform_temperature_max",
                    Some(sensor_name),
                    value,
                    "celsius",
                    sensor_label(),
                );
            }
            if let Some(value) = temp_to_f64(temp.crit.as_deref()) {
                collector.emit_metric(
                    "platform_temperature_critical",
                    Some(sensor_name),
                    value,
                    "celsius",
                    sensor_label(),
                );
            }
            if let Some(current) = temp_state_to_state(temp.state.as_deref()) {
                collector.emit_state_set(
                    "platform_temperature_state",
                    Some(sensor_name),
                    current,
                    TEMP_STATE_STATES,
                    sensor_label(),
                );
            }
        }

        let samples = sink.samples.lock().unwrap();
        // ASIC1: current + max + crit (3) + state StateSet (2) = 5.
        // Ambient-MNG-Temp: current (1) + state StateSet (2) = 3. Total 8.
        assert_eq!(samples.len(), 8, "unexpected emitted sample count");

        // Helper: find a sample by metric_type + sensor label.
        let find = |metric_type: &str, sensor: &str| {
            samples.iter().find(|s| {
                s.metric_type == metric_type
                    && s.labels.iter().any(|(k, v)| k == "sensor" && v == sensor)
            })
        };

        // ASIC1: the three scalar temperature series present with correct
        // name/unit/value/label/key.
        let expected_asic1: &[(&str, &str, f64)] = &[
            ("platform_temperature", "celsius", 43.0),
            ("platform_temperature_max", "celsius", 105.0),
            ("platform_temperature_critical", "celsius", 120.0),
        ];
        for (metric_type, unit, value) in expected_asic1 {
            let sample = find(metric_type, "ASIC1")
                .unwrap_or_else(|| panic!("no ASIC1 sample for {metric_type}"));
            assert_eq!(sample.name, COLLECTOR_NAME);
            assert_eq!(&sample.metric_type, metric_type);
            assert_eq!(&sample.unit, unit);
            assert_eq!(sample.value, *value, "value for {metric_type}");
            assert_eq!(sample.key, format!("{metric_type}:ASIC1"));
            assert_eq!(sample.labels.len(), 1);
            assert_eq!(sample.labels[0].0, "sensor");
            assert_eq!(sample.labels[0].1, "ASIC1");
        }

        // ASIC1 state="ok" => StateSet: ok=1, not_ok=0. Sensor label preserved.
        let asic1_state: Vec<MetricSample> = samples
            .iter()
            .filter(|s| {
                s.metric_type == "platform_temperature_state"
                    && s.labels.iter().any(|(k, v)| k == "sensor" && v == "ASIC1")
            })
            .cloned()
            .collect();
        assert_state_set(
            &asic1_state,
            "platform_temperature_state",
            Some(("sensor", "ASIC1")),
            TEMP_STATE_STATES,
            "ok",
        );

        // Ambient-MNG-Temp: only current + state StateSet emitted.
        let ambient_current =
            find("platform_temperature", "Ambient-MNG-Temp").expect("ambient current sample");
        assert_eq!(ambient_current.value, 27.0);
        assert_eq!(ambient_current.unit, "celsius");
        let ambient_state: Vec<MetricSample> = samples
            .iter()
            .filter(|s| {
                s.metric_type == "platform_temperature_state"
                    && s.labels
                        .iter()
                        .any(|(k, v)| k == "sensor" && v == "Ambient-MNG-Temp")
            })
            .cloned()
            .collect();
        assert_state_set(
            &ambient_state,
            "platform_temperature_state",
            Some(("sensor", "Ambient-MNG-Temp")),
            TEMP_STATE_STATES,
            "ok",
        );

        // A sensor missing max/crit must NOT emit those series.
        assert!(
            find("platform_temperature_max", "Ambient-MNG-Temp").is_none(),
            "ambient sensor without max must not emit platform_temperature_max"
        );
        assert!(
            find("platform_temperature_critical", "Ambient-MNG-Temp").is_none(),
            "ambient sensor without crit must not emit platform_temperature_critical"
        );
    }

    /// Drives run_iteration's fan_led parse + emit logic against a captured sink.
    /// "green"/"ok" => 1.0, "amber" => 0.0, absent FAN_STATUS emits nothing.
    #[test]
    fn test_fan_led_emit() {
        use crate::collectors::nvue::rest::client::PlatformEnvironmentResponse;

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

        struct Case {
            name: &'static str,
            json: &'static str,
            // expected current StateSet state, or None when nothing must emit.
            expected: Option<&'static str>,
        }

        let cases = [
            Case {
                name: "green LED => ok",
                json: r#"{"FAN_STATUS": {"state": "green", "type": "led"}}"#,
                expected: Some("ok"),
            },
            Case {
                name: "ok LED => ok",
                json: r#"{"FAN_STATUS": {"state": "ok", "type": "led"}}"#,
                expected: Some("ok"),
            },
            Case {
                name: "amber LED => not_ok",
                json: r#"{"FAN_STATUS": {"state": "amber", "type": "led"}}"#,
                expected: Some("not_ok"),
            },
            Case {
                name: "absent FAN_STATUS emits nothing",
                json: r#"{"PSU_STATUS": {"state": "green", "type": "led"}}"#,
                expected: None,
            },
        ];

        for case in cases {
            let sink = Arc::new(CapturingSink {
                samples: StdMutex::new(Vec::new()),
            });
            let mut collector = collector_with_provider(ScriptedProvider::new(vec![]));
            collector.data_sink = Some(sink.clone());

            let env: PlatformEnvironmentResponse =
                serde_json::from_str(case.json).expect("env json parses");
            // Mirror run_iteration's emit logic exactly.
            if let Some(current) = env
                .get("FAN_STATUS")
                .and_then(|s| fan_led_to_state(s.state.as_deref()))
            {
                collector.emit_state_set("fan_led", None, current, FAN_LED_STATES, vec![]);
            }

            let samples = sink.samples.lock().unwrap();
            match case.expected {
                Some(current) => {
                    // switch-level StateSet: no per-entity label, but a `state`
                    // label per series. Series keys are unique per state.
                    assert_state_set(&samples, "fan_led", None, FAN_LED_STATES, current);
                    for sample in samples.iter() {
                        assert_eq!(sample.name, COLLECTOR_NAME, "case '{}'", case.name);
                        let state = sample
                            .labels
                            .iter()
                            .find(|(k, _)| k == "state")
                            .map(|(_, v)| v.clone())
                            .expect("state label present");
                        assert_eq!(
                            sample.key,
                            format!("fan_led:{state}"),
                            "case '{}'",
                            case.name
                        );
                        // switch-level: the only label is `state`.
                        assert_eq!(
                            sample.labels.len(),
                            1,
                            "case '{}': fan_led is switch-level (only the state label)",
                            case.name
                        );
                    }
                }
                None => assert_eq!(
                    samples.len(),
                    0,
                    "case '{}': absent FAN_STATUS must not emit a sample",
                    case.name
                ),
            }
        }
    }

    struct ScriptedProvider {
        calls: AtomicUsize,
        // Each call pops the front. An empty queue yields an error. HealthError
        // isn't Clone, so we consume by value.
        responses: StdMutex<std::collections::VecDeque<Result<BmcCredentials, HealthError>>>,
    }

    impl ScriptedProvider {
        fn new(responses: Vec<Result<BmcCredentials, HealthError>>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                responses: StdMutex::new(responses.into_iter().collect()),
            })
        }
    }

    impl CredentialProvider for ScriptedProvider {
        fn fetch_credentials<'a>(
            &'a self,
            _endpoint: &'a BmcAddr,
        ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| {
                    Err(HealthError::GenericError(
                        "scripted provider exhausted".to_string(),
                    ))
                });
            Box::pin(async move { response })
        }
    }

    fn test_addr() -> BmcAddr {
        BmcAddr {
            ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: Some(443),
            mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
        }
    }

    fn paths_all_disabled() -> NvueRestPaths {
        NvueRestPaths {
            system_health_enabled: false,
            cluster_apps_enabled: false,
            sdn_partitions_enabled: false,
            interfaces_enabled: false,
            platform_environment_fan_enabled: false,
            platform_environment_temperature_enabled: false,
            platform_environment_status_enabled: false,
        }
    }

    fn collector_with_provider(provider: Arc<dyn CredentialProvider>) -> NvueRestCollector {
        let addr = test_addr();
        let client = RestClient::new(
            "test-switch".to_string(),
            &addr.ip.to_string(),
            Duration::from_millis(10),
            true,
            paths_all_disabled(),
        )
        .expect("rest client builds");

        let event_context = EventContext {
            endpoint_key: "test-switch".to_string(),
            addr: addr.clone(),
            collector_type: COLLECTOR_NAME,
            metadata: None,
            rack_id: None,
        };

        NvueRestCollector {
            client,
            switch_id: "test-switch".to_string(),
            event_context,
            data_sink: None,
            addr,
            provider,
        }
    }

    #[tokio::test]
    async fn first_iteration_lazy_fetches_credentials_then_runs() {
        let provider = ScriptedProvider::new(vec![Ok(BmcCredentials::UsernamePassword {
            username: "admin".to_string(),
            password: Some("hunter2".to_string()),
        })]);
        let mut collector = collector_with_provider(provider.clone());

        assert!(
            !collector.client.has_credentials(),
            "client must start credential-less so sharded-out endpoints never trigger a fetch"
        );

        let result = collector
            .run_iteration()
            .await
            .expect("iteration returns Ok even when all paths are disabled");

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        assert!(collector.client.has_credentials());
        assert_eq!(
            result.fetch_failures, 0,
            "all paths disabled → no HTTP, no failures"
        );
        // Subsequent iterations reuse the already-installed credentials.
        collector
            .run_iteration()
            .await
            .expect("second iteration ok");
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            1,
            "credential provider must not be re-hit while creds are still valid"
        );
    }

    #[tokio::test]
    async fn iteration_is_skipped_when_credential_fetch_fails_and_recovers_next_time() {
        let provider = ScriptedProvider::new(vec![
            Err(HealthError::GenericError("forge unavailable".to_string())),
            Ok(BmcCredentials::UsernamePassword {
                username: "admin".to_string(),
                password: None,
            }),
        ]);
        let mut collector = collector_with_provider(provider.clone());

        let first = collector.run_iteration().await.expect("first iteration ok");
        assert_eq!(first.fetch_failures, 1, "credential fetch failure surfaces");
        assert!(!first.refresh_triggered);
        assert!(
            !collector.client.has_credentials(),
            "failed fetch must NOT install bogus credentials"
        );

        let second = collector
            .run_iteration()
            .await
            .expect("second iteration ok");
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert!(collector.client.has_credentials());
        assert_eq!(
            second.fetch_failures, 0,
            "second iteration recovers — credentials now present, no GETs to fail"
        );
    }

    #[tokio::test]
    async fn refresh_rejects_session_token_credentials() {
        let provider = ScriptedProvider::new(vec![Ok(BmcCredentials::SessionToken {
            token: "irrelevant".to_string(),
        })]);
        let collector = collector_with_provider(provider);

        let error = collector
            .refresh_rest_credentials()
            .await
            .expect_err("session-token credentials are not usable for NVUE basic auth");
        match error {
            HealthError::GenericError(msg) => assert!(
                msg.contains("requires username/password"),
                "expected explicit message, got: {msg}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_rest_credentials_respects_timeout() {
        // Mirrors the `BmcClient::refresh_credentials_respects_timeout`
        // contract on the NVUE REST side: a hung Forge call must not block
        // the collector's iteration loop past `CREDENTIAL_REFRESH_TIMEOUT`.
        struct HangingProvider;
        impl CredentialProvider for HangingProvider {
            fn fetch_credentials<'a>(
                &'a self,
                _endpoint: &'a BmcAddr,
            ) -> BoxFuture<'a, Result<BmcCredentials, HealthError>> {
                Box::pin(std::future::pending())
            }
        }

        let collector = Arc::new(collector_with_provider(Arc::new(HangingProvider)));
        let refresh_collector = collector.clone();
        let refresh =
            tokio::spawn(async move { refresh_collector.refresh_rest_credentials().await });

        // Sleep just past the timeout so the tokio timer fires.
        tokio::time::advance(CREDENTIAL_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
        let result = refresh.await.expect("task joined");
        let error = result.expect_err("hanging provider must surface as timeout");
        match error {
            HealthError::GenericError(msg) => assert!(
                msg.contains("Timed out"),
                "expected timeout message, got: {msg}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn debug_redacts_password() {
        let creds = UsernamePassword {
            username: "admin".to_string(),
            password: Some("hunter2".to_string()),
        };
        let rendered = format!("{creds:?}");
        assert!(
            !rendered.contains("hunter2"),
            "Debug must not leak the password; got: {rendered}"
        );
        assert!(rendered.contains("admin"));
        assert!(rendered.contains("<redacted>"));

        let no_password = UsernamePassword {
            username: "admin".to_string(),
            password: None,
        };
        let rendered = format!("{no_password:?}");
        assert!(
            !rendered.contains("<redacted>"),
            "missing password must not show as redacted; got: {rendered}"
        );
    }
}
