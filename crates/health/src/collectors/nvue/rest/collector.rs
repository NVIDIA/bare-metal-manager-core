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

use super::client::{
    LeakageEnvironmentResponse, LeakageSensorData, OptionalNvueResponse, RebootReasonResponse,
    RestClient, UsernamePassword,
};
use crate::HealthError;
use crate::bmc::{CREDENTIAL_REFRESH_TIMEOUT, CredentialProvider, is_auth_error};
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::config::NvueRestConfig;
use crate::endpoint::{BmcAddr, BmcCredentials, BmcEndpoint, EndpointMetadata};
use crate::sink::{
    Classification, CollectorEvent, DataSink, EventContext, HealthReport, HealthReportAlert,
    HealthReportSuccess, HealthReportTarget, MetricSample, Probe, ReportSource,
};

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

const LEAKAGE_STATES: &[&str] = &["ok", "leak", "unknown"];

/// Maps NVUE leakage sensor strings to the emitted StateSet domain.
///
/// NVUE OpenAPI defines populated leakage sensor states as `ok` or `leak`.
/// `unknown` is an emitted fallback for per-sensor `null`, absent state, or an
/// unrecognized value; the health report classifies that fallback as a sensor
/// failure.
fn leakage_state_to_state(state: Option<&str>) -> &'static str {
    match state.map(str::trim) {
        Some(s) if s.eq_ignore_ascii_case("ok") => "ok",
        Some(s) if s.eq_ignore_ascii_case("leak") => "leak",
        _ => "unknown",
    }
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

        match self.client.get_system_reboot_reason().await {
            Ok(OptionalNvueResponse::Present(reason)) => {
                self.emit_reboot_reason_data(&reason);

                entity_count += 1;
            }
            Ok(OptionalNvueResponse::Null | OptionalNvueResponse::Disabled) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect system reboot reason"
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

        match self.client.get_platform_environment_leakage().await {
            Ok(OptionalNvueResponse::Present(leakage)) => {
                entity_count += self.emit_leakage_data(&leakage);
            }
            Ok(OptionalNvueResponse::Null) => {
                self.emit_leakage_unavailable();
            }
            Ok(OptionalNvueResponse::Disabled) => {}
            Err(e) => {
                fetch_failures += 1;
                saw_auth_failure |= is_auth_error(&e);
                tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect platform environment leakage"
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

    /// Emits reboot-reason metadata as an info metric.
    ///
    /// `reason` is intentionally kept as the Prometheus grouping label because
    /// the metric is not useful without it. `gentime` and `user` are excluded
    /// from labels because they churn per event and can expose operator data.
    fn emit_reboot_reason_data(&self, reason: &RebootReasonResponse) {
        let reason_text = reason.reason.as_deref().unwrap_or("unknown");
        let gentime = reason.gentime.as_deref().unwrap_or("unknown");
        let user = reason.user.as_deref().unwrap_or("unknown");

        tracing::info!(
            switch_id = %self.switch_id,
            reason = reason_text,
            gentime,
            user,
            "nvue_rest: collected system reboot reason"
        );

        self.emit_metric(
            "reboot_reason_info",
            None,
            1.0,
            "info",
            vec![(Cow::Borrowed("reason"), reason_text.to_string())],
        );
    }

    fn emit_leakage_data(&self, leakage: &LeakageEnvironmentResponse) -> usize {
        let mut sensors = leakage.iter().collect::<Vec<_>>();
        sensors.sort_by(|left, right| left.0.cmp(right.0));

        for &(sensor_name, sensor) in &sensors {
            let current =
                leakage_state_to_state(sensor.as_ref().and_then(|sensor| sensor.state.as_deref()));

            self.emit_state_set(
                "leakage_state",
                Some(sensor_name.as_str()),
                current,
                LEAKAGE_STATES,
                vec![(Cow::Borrowed("sensor"), sensor_name.clone())],
            );
        }

        let report = self.build_leakage_report(sensors.as_slice());
        self.emit_event(CollectorEvent::HealthReport(Arc::new(report)));

        sensors.len()
    }

    /// Emits a switch-level alert when the leakage endpoint returns top-level
    /// JSON `null`.
    ///
    /// A concrete empty map means "no sensors reported" and is a source success;
    /// top-level `null` means the switch did not provide leakage data, so the
    /// previous leakage state must not be cleared as healthy.
    fn emit_leakage_unavailable(&self) {
        let report = HealthReport {
            source: ReportSource::NvueLeakage,
            target: Some(HealthReportTarget::Switch),
            observed_at: Some(chrono::Utc::now()),
            successes: Vec::new(),
            alerts: vec![HealthReportAlert {
                probe_id: Probe::NvueLeakage,
                target: None,
                message: "NVUE leakage data is unavailable".to_string(),
                classifications: vec![Classification::SensorFailure],
            }],
        };

        self.emit_event(CollectorEvent::HealthReport(Arc::new(report)));
    }

    /// Builds the switch-level health report for NVUE leakage sensors.
    ///
    /// Empty leakage data means the endpoint was reachable and no sensors were
    /// reported, so the source is healthy. Per-sensor `null` or unrecognized
    /// states alert as sensor failures; explicit `leak` states alert as leaks.
    fn build_leakage_report(
        &self,
        sensors: &[(&String, &Option<LeakageSensorData>)],
    ) -> HealthReport {
        let mut successes = Vec::new();
        let mut alerts = Vec::new();

        if sensors.is_empty() {
            successes.push(HealthReportSuccess {
                probe_id: Probe::NvueLeakage,
                target: None,
            });
        }

        for (sensor_name, sensor) in sensors {
            match leakage_state_to_state(sensor.as_ref().and_then(|sensor| sensor.state.as_deref()))
            {
                "ok" => successes.push(HealthReportSuccess {
                    probe_id: Probe::NvueLeakage,
                    target: Some((*sensor_name).clone()),
                }),
                "leak" => alerts.push(HealthReportAlert {
                    probe_id: Probe::NvueLeakage,
                    target: Some((*sensor_name).clone()),
                    message: format!("NVUE leakage sensor {sensor_name} reports leak"),
                    classifications: vec![Classification::Leak],
                }),
                _ => alerts.push(HealthReportAlert {
                    probe_id: Probe::NvueLeakage,
                    target: Some((*sensor_name).clone()),
                    message: format!("NVUE leakage sensor {sensor_name} state is unknown"),
                    classifications: vec![Classification::SensorFailure],
                }),
            }
        }

        HealthReport {
            source: ReportSource::NvueLeakage,
            target: Some(HealthReportTarget::Switch),
            observed_at: Some(chrono::Utc::now()),
            successes,
            alerts,
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
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread::JoinHandle;
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

    #[derive(Default)]
    struct CapturingSink {
        samples: StdMutex<Vec<MetricSample>>,
        reports: StdMutex<Vec<HealthReport>>,
    }

    impl DataSink for CapturingSink {
        fn sink_type(&self) -> &'static str {
            "capturing_sink"
        }

        fn try_handle_event(
            &self,
            _context: &EventContext,
            event: &CollectorEvent,
        ) -> Result<(), crate::HealthError> {
            match event {
                CollectorEvent::Metric(sample) => {
                    self.samples.lock().unwrap().push((**sample).clone());
                }
                CollectorEvent::HealthReport(report) => {
                    self.reports.lock().unwrap().push((**report).clone());
                }
                CollectorEvent::MetricCollectionStart
                | CollectorEvent::MetricCollectionEnd
                | CollectorEvent::CollectorRemoved
                | CollectorEvent::Log(_)
                | CollectorEvent::Firmware(_) => {}
            }
            Ok(())
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
    fn test_leakage_state_mapping() {
        assert_eq!(leakage_state_to_state(Some("ok")), "ok");
        assert_eq!(leakage_state_to_state(Some("OK")), "ok");
        assert_eq!(leakage_state_to_state(Some(" ok ")), "ok");
        assert_eq!(leakage_state_to_state(Some("leak")), "leak");
        assert_eq!(leakage_state_to_state(Some("LEAK")), "leak");
        assert_eq!(leakage_state_to_state(Some(" leak ")), "leak");
        assert_eq!(leakage_state_to_state(Some("missing")), "unknown");
        assert_eq!(leakage_state_to_state(Some("   ")), "unknown");
        assert_eq!(leakage_state_to_state(None), "unknown");
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

            fn try_handle_event(
                &self,
                _context: &EventContext,
                event: &CollectorEvent,
            ) -> Result<(), crate::HealthError> {
                if let CollectorEvent::Metric(sample) = event {
                    self.samples.lock().unwrap().push((**sample).clone());
                }
                Ok(())
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

            fn try_handle_event(
                &self,
                _context: &EventContext,
                event: &CollectorEvent,
            ) -> Result<(), crate::HealthError> {
                if let CollectorEvent::Metric(sample) = event {
                    self.samples.lock().unwrap().push((**sample).clone());
                }
                Ok(())
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

            fn try_handle_event(
                &self,
                _context: &EventContext,
                event: &CollectorEvent,
            ) -> Result<(), crate::HealthError> {
                if let CollectorEvent::Metric(sample) = event {
                    self.samples.lock().unwrap().push((**sample).clone());
                }
                Ok(())
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

    #[test]
    fn test_reboot_reason_emits_reason_label_without_user_or_gentime() {
        let sink = Arc::new(CapturingSink::default());
        let mut collector = collector_with_provider(ScriptedProvider::new(vec![]));
        collector.data_sink = Some(sink.clone());

        let reason = RebootReasonResponse {
            reason: Some("package upgrade".to_string()),
            gentime: Some("2026-07-05 12:34:56".to_string()),
            user: Some("admin".to_string()),
        };

        collector.emit_reboot_reason_data(&reason);

        let samples = sink.samples.lock().unwrap();
        let reports = sink.reports.lock().unwrap();
        let sample = samples.first().expect("reboot reason emits one sample");

        assert_eq!(samples.len(), 1);
        assert!(reports.is_empty());
        assert_eq!(sample.name, COLLECTOR_NAME);
        assert_eq!(sample.key, "reboot_reason_info");
        assert_eq!(sample.metric_type, "reboot_reason_info");
        assert_eq!(sample.unit, "info");
        assert_eq!(sample.value, 1.0);

        assert_eq!(
            sample.labels,
            vec![(Cow::Borrowed("reason"), "package upgrade".to_string())]
        );
    }

    #[test]
    fn test_leakage_emits_metrics_and_health_report() {
        let sink = Arc::new(CapturingSink::default());
        let mut collector = collector_with_provider(ScriptedProvider::new(vec![]));
        collector.data_sink = Some(sink.clone());

        let leakage: LeakageEnvironmentResponse = serde_json::from_str(
            r#"{
                "LEAK1":{"state":"ok"},
                "LEAK2":{"state":"leak"},
                "LEAK3":{"state":"unknown"},
                "LEAK4": null
            }"#,
        )
        .expect("leakage json parses");

        let entity_count = collector.emit_leakage_data(&leakage);

        let samples = sink.samples.lock().unwrap();

        assert_eq!(entity_count, 4);
        assert_eq!(samples.len(), 12);

        let leak2_samples = samples
            .iter()
            .filter(|sample| {
                sample.metric_type == "leakage_state"
                    && sample
                        .labels
                        .iter()
                        .any(|(key, value)| key == "sensor" && value == "LEAK2")
            })
            .cloned()
            .collect::<Vec<_>>();

        assert_state_set(
            &leak2_samples,
            "leakage_state",
            Some(("sensor", "LEAK2")),
            LEAKAGE_STATES,
            "leak",
        );

        let reports = sink.reports.lock().unwrap();

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].source, ReportSource::NvueLeakage);
        assert_eq!(reports[0].target, Some(HealthReportTarget::Switch));
        assert_eq!(reports[0].successes.len(), 1);
        assert_eq!(reports[0].alerts.len(), 3);

        assert!(
            reports[0]
                .alerts
                .iter()
                .any(|alert| alert.classifications.contains(&Classification::Leak))
        );

        assert!(reports[0].alerts.iter().any(|alert| {
            alert
                .classifications
                .contains(&Classification::SensorFailure)
        }));
    }

    #[test]
    fn test_empty_leakage_emits_source_success_report() {
        let sink = Arc::new(CapturingSink::default());
        let mut collector = collector_with_provider(ScriptedProvider::new(vec![]));
        collector.data_sink = Some(sink.clone());

        let leakage: LeakageEnvironmentResponse =
            serde_json::from_str("{}").expect("empty leakage json parses");

        let entity_count = collector.emit_leakage_data(&leakage);

        let samples = sink.samples.lock().unwrap();

        assert_eq!(entity_count, 0);
        assert!(samples.is_empty());

        let reports = sink.reports.lock().unwrap();

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].source, ReportSource::NvueLeakage);
        assert_eq!(reports[0].target, Some(HealthReportTarget::Switch));
        assert_eq!(reports[0].successes.len(), 1);
        assert_eq!(reports[0].successes[0].probe_id, Probe::NvueLeakage);
        assert_eq!(reports[0].successes[0].target, None);
        assert!(reports[0].alerts.is_empty());
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
            system_reboot_reason_enabled: false,
            cluster_apps_enabled: false,
            sdn_partitions_enabled: false,
            interfaces_enabled: false,
            platform_environment_fan_enabled: false,
            platform_environment_temperature_enabled: false,
            platform_environment_leakage_enabled: false,
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

    fn spawn_json_response_server(body: &'static str) -> (url::Url, JoinHandle<()>) {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("test server binds local port");

        let addr = listener.local_addr().expect("test server local addr");
        let base_url = url::Url::parse(&format!("http://{addr}")).expect("test server url parses");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("test server accepts request");
            let mut buffer = [0_u8; 2048];
            let _bytes_read = stream.read(&mut buffer).expect("test server reads request");

            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );

            stream
                .write_all(response.as_bytes())
                .expect("test server writes response");
        });

        (base_url, handle)
    }

    fn collector_with_json_response(
        paths: NvueRestPaths,
        body: &'static str,
    ) -> (NvueRestCollector, Arc<CapturingSink>, JoinHandle<()>) {
        let (base_url, server) = spawn_json_response_server(body);

        let client = RestClient::new_with_base_url_for_test(
            "test-switch".to_string(),
            base_url,
            Duration::from_secs(1),
            paths,
        )
        .expect("test rest client builds");

        client.set_credentials(UsernamePassword {
            username: "admin".to_string(),
            password: None,
        });

        let sink = Arc::new(CapturingSink::default());
        let mut collector = collector_with_provider(ScriptedProvider::new(vec![]));
        collector.client = client;
        collector.data_sink = Some(sink.clone());

        (collector, sink, server)
    }

    async fn collect_response(
        paths: NvueRestPaths,
        body: &'static str,
    ) -> (IterationResult, Vec<MetricSample>, Vec<HealthReport>) {
        let (mut collector, sink, server) = collector_with_json_response(paths, body);

        let result = collector
            .run_iteration()
            .await
            .expect("response iteration succeeds");

        server.join().expect("test server exits cleanly");

        let samples = sink.samples.lock().unwrap().clone();
        let reports = sink.reports.lock().unwrap().clone();

        (result, samples, reports)
    }

    async fn collect_null_response(
        paths: NvueRestPaths,
    ) -> (IterationResult, Vec<MetricSample>, Vec<HealthReport>) {
        collect_response(paths, "null").await
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

    #[tokio::test]
    async fn run_iteration_reboot_reason_null_is_unavailable_metadata() {
        let mut paths = paths_all_disabled();
        paths.system_reboot_reason_enabled = true;

        let (result, samples, reports) = collect_null_response(paths).await;

        assert_eq!(result.fetch_failures, 0);
        assert_eq!(result.entity_count, Some(0));
        assert!(samples.is_empty());
        assert!(reports.is_empty());
    }

    #[tokio::test]
    async fn run_iteration_metric_path_null_counts_fetch_failure() {
        let mut paths = paths_all_disabled();
        paths.cluster_apps_enabled = true;

        let (result, samples, reports) = collect_null_response(paths).await;

        assert_eq!(result.fetch_failures, 1);
        assert_eq!(result.entity_count, Some(0));
        assert!(samples.is_empty());
        assert!(reports.is_empty());
    }

    #[tokio::test]
    async fn run_iteration_leakage_null_emits_unavailable_alert_report() {
        let mut paths = paths_all_disabled();
        paths.platform_environment_leakage_enabled = true;

        let (result, samples, reports) = collect_null_response(paths).await;

        assert_eq!(result.fetch_failures, 0);
        assert_eq!(result.entity_count, Some(0));
        assert!(samples.is_empty());

        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].source, ReportSource::NvueLeakage);
        assert_eq!(reports[0].target, Some(HealthReportTarget::Switch));
        assert!(reports[0].successes.is_empty());
        assert_eq!(reports[0].alerts.len(), 1);
        assert_eq!(reports[0].alerts[0].probe_id, Probe::NvueLeakage);
        assert_eq!(reports[0].alerts[0].target, None);

        assert_eq!(
            reports[0].alerts[0].classifications,
            vec![Classification::SensorFailure]
        );

        assert_eq!(
            reports[0].alerts[0].message,
            "NVUE leakage data is unavailable"
        );
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
