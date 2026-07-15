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

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use carbide_rack::firmware_update::{build_new_node_info, load_switch_firmware_device_info};
use carbide_rack::rms_node_type::switch_node_type_for_profile;
use carbide_secrets::credentials::CredentialManager;
use carbide_utils::metrics::SharedMetricsHolder;
use carbide_utils::periodic_timer::PeriodicTimer;
use carbide_uuid::rack::{RackId, RackProfileId};
use carbide_uuid::switch::SwitchId;
use chrono::Utc;
use db::db_read::PgPoolReader;
use db::work_lock_manager::WorkLockManagerHandle;
use librms::protos::rack_manager as rms;
use model::rack_type::RackProfileConfig;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Histogram, Meter};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::NvLinkConfig;
use crate::errors::{NvLinkManagerError, NvLinkManagerResult};
use crate::nmx_c_endpoint;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CertificateInfo {
    fingerprint_sha256: String,
    not_after_timestamp: i64,
}

#[derive(Clone, Debug)]
struct SwitchCertificateMonitorTarget {
    switch_id: SwitchId,
    rack_id: RackId,
    rack_profile_id: Option<RackProfileId>,
    endpoint_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwitchCertApplyStatus {
    NotNeeded,
    Pending,
    Applied,
    Error,
    Skipped,
}

impl SwitchCertApplyStatus {
    fn as_metric_label(self) -> &'static str {
        match self {
            Self::NotNeeded => "not_needed",
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Error => "error",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Debug)]
struct ObservedSwitchCertMetrics {
    desired_cert: Option<CertificateInfo>,
    desired_cert_error: String,
    probe_success: bool,
    fingerprint_matches: bool,
    expires_within_warning_window: bool,
    observed_cert: Option<CertificateInfo>,
    error: String,
    apply_status: SwitchCertApplyStatus,
    apply_error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SwitchCertMonitorErrorKind {
    Timeout,
    Connection,
    Tls,
    CertificateFile,
    CertificateParse,
    EndpointConfig,
    ServerCertificate,
    Configuration,
    Rms,
    Other,
}

impl SwitchCertMonitorErrorKind {
    fn as_metric_label(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Connection => "connection",
            Self::Tls => "tls",
            Self::CertificateFile => "certificate_file",
            Self::CertificateParse => "certificate_parse",
            Self::EndpointConfig => "endpoint_config",
            Self::ServerCertificate => "server_certificate",
            Self::Configuration => "configuration",
            Self::Rms => "rms",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug)]
struct SwitchCertMonitorMetrics {
    recording_started_at: std::time::Instant,
    observed_certs: Vec<ObservedSwitchCertMetrics>,
}

impl SwitchCertMonitorMetrics {
    fn new() -> Self {
        Self {
            recording_started_at: std::time::Instant::now(),
            observed_certs: Vec::new(),
        }
    }
}

impl fmt::Display for SwitchCertMonitorMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let successful_probes = self
            .observed_certs
            .iter()
            .filter(|cert| cert.probe_success)
            .count();
        let matching_fingerprints = self
            .observed_certs
            .iter()
            .filter(|cert| cert.fingerprint_matches)
            .count();
        let desired_cert_errors = self
            .observed_certs
            .iter()
            .filter(|cert| !cert.desired_cert_error.is_empty())
            .count();
        let applied_updates = self
            .observed_certs
            .iter()
            .filter(|cert| cert.apply_status == SwitchCertApplyStatus::Applied)
            .count();
        let pending_updates = self
            .observed_certs
            .iter()
            .filter(|cert| cert.apply_status == SwitchCertApplyStatus::Pending)
            .count();
        write!(
            f,
            "{{ observed_endpoints: {}, desired_cert_errors: {}, successful_probes: {}, matching_fingerprints: {}, applied_updates: {}, pending_updates: {}, duration: {} }}",
            self.observed_certs.len(),
            desired_cert_errors,
            successful_probes,
            matching_fingerprints,
            applied_updates,
            pending_updates,
            self.recording_started_at.elapsed().as_millis(),
        )
    }
}

struct SwitchCertMonitorInstruments {
    iteration_latency: Histogram<f64>,
}

impl SwitchCertMonitorInstruments {
    fn new(meter: Meter, shared_metrics: SharedMetricsHolder<SwitchCertMonitorMetrics>) -> Self {
        let iteration_latency = meter
            .f64_histogram("carbide_nvlink_switch_cert_monitor_iteration_latency")
            .with_description("Time consumed for one NMX-C switch certificate monitor iteration")
            .with_unit("ms")
            .build();

        {
            let metrics = shared_metrics.clone();
            meter
                .i64_observable_gauge(
                    "carbide_nvlink_switch_cert_monitor_desired_cert_expiration_time",
                )
                .with_description(
                    "Earliest expiration time (epoch seconds) for desired NMX-C server certificates",
                )
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        let earliest_desired_expiration = metrics
                            .observed_certs
                            .iter()
                            .filter_map(|cert| cert.desired_cert.as_ref())
                            .map(|cert| cert.not_after_timestamp)
                            .min();
                        if let Some(not_after) = earliest_desired_expiration {
                            observer.observe(
                                not_after,
                                &metric_attrs(attrs, &[KeyValue::new("status", "ok")]),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_switch_cert_monitor_desired_cert_error_count")
                .with_description(
                    "Number of desired NMX-C server certificate read failures by error kind",
                )
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        let error_counts = count_errors_by_kind(
                            metrics
                                .observed_certs
                                .iter()
                                .map(|cert| cert.desired_cert_error.as_str()),
                        );
                        for (error_kind, count) in error_counts {
                            observer.observe(
                                count,
                                &metric_attrs(
                                    attrs,
                                    &[
                                        KeyValue::new("status", "error"),
                                        KeyValue::new("error_kind", error_kind.as_metric_label()),
                                    ],
                                ),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .i64_observable_gauge(
                    "carbide_nvlink_switch_cert_monitor_observed_cert_expiration_time",
                )
                .with_description(
                    "Earliest expiration time (epoch seconds) for certificates served by NMX-C, by status",
                )
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        let mut expirations_by_status = BTreeMap::new();
                        for cert in &metrics.observed_certs {
                            if let Some(observed_cert) = &cert.observed_cert {
                                let entry = expirations_by_status
                                    .entry(expiry_status(cert))
                                    .or_insert(observed_cert.not_after_timestamp);
                                *entry = (*entry).min(observed_cert.not_after_timestamp);
                            }
                        }

                        for (status, not_after) in expirations_by_status {
                            observer.observe(
                                not_after,
                                &metric_attrs(attrs, &[KeyValue::new("status", status)]),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_switch_cert_monitor_probe_success")
                .with_description("Number of NMX-C TLS certificate probes by status")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (status, count) in
                            count_by_status(&metrics.observed_certs, probe_status)
                        {
                            observer.observe(
                                count,
                                &metric_attrs(attrs, &[KeyValue::new("status", status)]),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_switch_cert_monitor_fingerprint_match")
                .with_description("Number of NMX-C certificates by fingerprint match status")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (status, count) in
                            count_by_status(&metrics.observed_certs, fingerprint_status)
                        {
                            observer.observe(
                                count,
                                &metric_attrs(attrs, &[KeyValue::new("status", status)]),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_switch_cert_monitor_expiring_soon")
                .with_description("Number of NMX-C certificates by expiration warning status")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (status, count) in
                            count_by_status(&metrics.observed_certs, expiry_status)
                        {
                            observer.observe(
                                count,
                                &metric_attrs(attrs, &[KeyValue::new("status", status)]),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_switch_cert_monitor_apply_status")
                .with_description("Number of NMX-C switch certificate apply outcomes by status")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (status, count) in
                            count_by_status(&metrics.observed_certs, apply_status)
                        {
                            observer.observe(
                                count,
                                &metric_attrs(attrs, &[KeyValue::new("status", status)]),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_switch_cert_monitor_apply_error_count")
                .with_description("Number of NMX-C switch certificate apply failures by error kind")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        let error_counts = count_errors_by_kind(
                            metrics
                                .observed_certs
                                .iter()
                                .map(|cert| cert.apply_error.as_str()),
                        );
                        for (error_kind, count) in error_counts {
                            observer.observe(
                                count,
                                &metric_attrs(
                                    attrs,
                                    &[
                                        KeyValue::new("status", "error"),
                                        KeyValue::new("error_kind", error_kind.as_metric_label()),
                                    ],
                                ),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics;
            meter
                .u64_observable_gauge("carbide_nvlink_switch_cert_monitor_probe_error_count")
                .with_description("Number of NMX-C endpoint probe failures by error kind")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        let error_counts = count_errors_by_kind(
                            metrics
                                .observed_certs
                                .iter()
                                .map(|cert| cert.error.as_str()),
                        );
                        for (error_kind, count) in error_counts {
                            observer.observe(
                                count,
                                &metric_attrs(
                                    attrs,
                                    &[
                                        KeyValue::new("status", "error"),
                                        KeyValue::new("error_kind", error_kind.as_metric_label()),
                                    ],
                                ),
                            );
                        }
                    })
                })
                .build();
        }

        Self { iteration_latency }
    }

    fn emit_counters_and_histograms(&self, metrics: &SwitchCertMonitorMetrics) {
        self.iteration_latency.record(
            metrics.recording_started_at.elapsed().as_millis() as f64,
            &[],
        );
    }
}

pub struct MetricHolder {
    instruments: SwitchCertMonitorInstruments,
    last_iteration_metrics: SharedMetricsHolder<SwitchCertMonitorMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: Duration) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        let instruments = SwitchCertMonitorInstruments::new(meter, last_iteration_metrics.clone());
        Self {
            instruments,
            last_iteration_metrics,
        }
    }

    fn update_metrics(&self, metrics: SwitchCertMonitorMetrics) {
        self.instruments.emit_counters_and_histograms(&metrics);
        self.last_iteration_metrics.update(metrics);
    }
}

pub struct SwitchCertificateMonitor {
    db_pool: PgPool,
    config: NvLinkConfig,
    rms_client: Option<Arc<dyn librms::RmsApi>>,
    credential_manager: Arc<dyn CredentialManager>,
    rack_profiles: RackProfileConfig,
    metric_holder: Arc<MetricHolder>,
    work_lock_manager_handle: WorkLockManagerHandle,
    in_flight_certificate_jobs: Mutex<BTreeMap<SwitchCertJobKey, InFlightSwitchCertJob>>,
}

#[derive(Clone, Debug)]
struct InFlightSwitchCertJob {
    job_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SwitchCertJobKey {
    switch_id: String,
    rack_id: String,
}

impl SwitchCertJobKey {
    fn from_target(target: &SwitchCertificateMonitorTarget) -> Self {
        Self {
            switch_id: target.switch_id.to_string(),
            rack_id: target.rack_id.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RmsSwitchCertJobState {
    Pending(String),
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchCertificateMonitorIterationResult {
    pub observed_endpoints: usize,
    pub successful_probes: usize,
    pub fingerprint_mismatches: usize,
    pub desired_cert_errors: usize,
    pub probe_errors: usize,
    pub applied_updates: usize,
    pub pending_updates: usize,
    pub apply_errors: usize,
}

impl SwitchCertificateMonitorIterationResult {
    fn from_metrics(metrics: &SwitchCertMonitorMetrics) -> Self {
        Self {
            observed_endpoints: metrics.observed_certs.len(),
            successful_probes: metrics
                .observed_certs
                .iter()
                .filter(|cert| cert.probe_success)
                .count(),
            fingerprint_mismatches: metrics
                .observed_certs
                .iter()
                .filter(|cert| cert.probe_success && !cert.fingerprint_matches)
                .count(),
            desired_cert_errors: metrics
                .observed_certs
                .iter()
                .filter(|cert| !cert.desired_cert_error.is_empty())
                .count(),
            probe_errors: metrics
                .observed_certs
                .iter()
                .filter(|cert| !cert.error.is_empty())
                .count(),
            applied_updates: metrics
                .observed_certs
                .iter()
                .filter(|cert| cert.apply_status == SwitchCertApplyStatus::Applied)
                .count(),
            pending_updates: metrics
                .observed_certs
                .iter()
                .filter(|cert| cert.apply_status == SwitchCertApplyStatus::Pending)
                .count(),
            apply_errors: metrics
                .observed_certs
                .iter()
                .filter(|cert| !cert.apply_error.is_empty())
                .count(),
        }
    }
}

impl SwitchCertificateMonitor {
    const ITERATION_WORK_KEY: &'static str = "SwitchCertificateMonitor::run_single_iteration";
    const PROBE_CANCELLED_ERROR: &'static str = "NMX-C server certificate probe cancelled";
    const APPLY_CANCELLED_ERROR: &'static str = "NMX-C server certificate apply cancelled";

    pub fn new(
        db_pool: PgPool,
        meter: Meter,
        config: NvLinkConfig,
        rms_client: Option<Arc<dyn librms::RmsApi>>,
        credential_manager: Arc<dyn CredentialManager>,
        rack_profiles: RackProfileConfig,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        let hold_period = config
            .nmx_c_certificate_rotation
            .run_interval
            .saturating_add(std::time::Duration::from_secs(60));
        let metric_holder = Arc::new(MetricHolder::new(meter, hold_period));
        Self {
            db_pool,
            config,
            rms_client,
            credential_manager,
            rack_profiles,
            metric_holder,
            work_lock_manager_handle,
            in_flight_certificate_jobs: Mutex::new(BTreeMap::new()),
        }
    }

    pub async fn run(&self, cancel_token: CancellationToken) {
        let timer = PeriodicTimer::new(self.config.nmx_c_certificate_rotation.run_interval);
        loop {
            let tick = timer.tick();
            if let Err(e) = self.run_single_iteration(&cancel_token).await {
                tracing::warn!(
                    error = %e,
                    "Switch certificate monitor error",
                );
            }

            tokio::select! {
                _ = tick.sleep() => {},
                _ = cancel_token.cancelled() => {
                    tracing::info!("SwitchCertificateMonitor stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(
        &self,
        cancel_token: &CancellationToken,
    ) -> NvLinkManagerResult<SwitchCertificateMonitorIterationResult> {
        let mut metrics = SwitchCertMonitorMetrics::new();
        let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));
        let switch_cert_monitor_span = tracing::span!(
            parent: None,
            tracing::Level::INFO,
            "nmx_c_switch_cert_monitor",
            span_id,
            otel.status_code = tracing::field::Empty,
            otel.status_message = tracing::field::Empty,
            metrics = tracing::field::Empty,
        );
        let result = self
            .run_single_iteration_inner(&mut metrics, cancel_token)
            .instrument(switch_cert_monitor_span.clone())
            .await;
        switch_cert_monitor_span.record(
            "otel.status_code",
            if result.is_ok() { "ok" } else { "error" },
        );
        if let Err(ref e) = result {
            switch_cert_monitor_span.record("otel.status_message", format!("{e:?}"));
        }
        switch_cert_monitor_span.record("metrics", metrics.to_string());
        let iteration_result = SwitchCertificateMonitorIterationResult::from_metrics(&metrics);
        self.metric_holder.update_metrics(metrics);
        result.map(|_| iteration_result)
    }

    async fn run_single_iteration_inner(
        &self,
        metrics: &mut SwitchCertMonitorMetrics,
        cancel_token: &CancellationToken,
    ) -> NvLinkManagerResult<()> {
        let _lock = match self
            .work_lock_manager_handle
            .try_acquire_lock(Self::ITERATION_WORK_KEY.into())
            .await
        {
            Ok(lock) => lock,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "SwitchCertificateMonitor failed to acquire work lock: Another instance of carbide running?",
                );
                return Ok(());
            }
        };

        let targets = self.load_switch_certificate_monitor_targets().await?;

        for target in targets {
            let rack_id_label = target.rack_id.to_string();

            let desired_cert_path = desired_server_cert_path(&self.config, &target.rack_id);
            let desired_cert = match desired_cert_path {
                Ok(desired_cert_path) => {
                    match read_leaf_cert_info_from_pem_file(&desired_cert_path).await {
                        Ok(cert) => {
                            if cert_expires_within(
                                &cert,
                                self.config.nmx_c_certificate_rotation.expiry_warning_window,
                            ) {
                                tracing::warn!(
                                    switch_id = %target.switch_id,
                                    rack_id = %rack_id_label,
                                    endpoint = %target.endpoint_url,
                                    path = %desired_cert_path,
                                    not_after = cert.not_after_timestamp,
                                    "Desired NMX-C server certificate expires within the warning window"
                                );
                            }
                            Ok(cert)
                        }
                        Err(error) => {
                            tracing::warn!(
                                switch_id = %target.switch_id,
                                rack_id = %rack_id_label,
                                endpoint = %target.endpoint_url,
                                path = %desired_cert_path,
                                error = %error,
                                "Failed to read desired NMX-C server certificate"
                            );
                            Err(error)
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        switch_id = %target.switch_id,
                        rack_id = %rack_id_label,
                        endpoint = %target.endpoint_url,
                        error = %error,
                        "Failed to resolve desired NMX-C server certificate path"
                    );
                    Err(error)
                }
            };

            let desired_cert = match desired_cert {
                Ok(desired_cert) => desired_cert,
                Err(error) => {
                    metrics.observed_certs.push(ObservedSwitchCertMetrics {
                        desired_cert: None,
                        desired_cert_error: error,
                        probe_success: false,
                        fingerprint_matches: false,
                        expires_within_warning_window: false,
                        observed_cert: None,
                        error: String::new(),
                        apply_status: SwitchCertApplyStatus::Skipped,
                        apply_error: String::new(),
                    });
                    continue;
                }
            };

            let observed_cert = tokio::select! {
                _ = cancel_token.cancelled() => {
                    tracing::info!("SwitchCertificateMonitor stop was requested");
                    return Ok(());
                }
                observed_cert = self.probe_endpoint_certificate(&target.endpoint_url, cancel_token) => {
                    observed_cert
                }
            };

            let observed = match observed_cert {
                Ok(observed_cert) => {
                    let fingerprint_matches =
                        observed_cert.fingerprint_sha256 == desired_cert.fingerprint_sha256;
                    let expires_within_warning_window = cert_expires_within(
                        &observed_cert,
                        self.config.nmx_c_certificate_rotation.expiry_warning_window,
                    );

                    if !fingerprint_matches {
                        tracing::warn!(
                            switch_id = %target.switch_id,
                            rack_id = %rack_id_label,
                            endpoint = %target.endpoint_url,
                            desired_fingerprint = %desired_cert.fingerprint_sha256,
                            observed_fingerprint = %observed_cert.fingerprint_sha256,
                            "NMX-C is not serving the desired server certificate"
                        );
                    }

                    let (apply_status, apply_error) = if fingerprint_matches {
                        (SwitchCertApplyStatus::NotNeeded, String::new())
                    } else {
                        match self
                            .reconcile_desired_certificate_apply(&target, cancel_token)
                            .await
                        {
                            Ok(apply_status) => (apply_status, String::new()),
                            Err(error) if error == Self::APPLY_CANCELLED_ERROR => {
                                tracing::info!("SwitchCertificateMonitor stop was requested");
                                return Ok(());
                            }
                            Err(error) => {
                                tracing::warn!(
                                    switch_id = %target.switch_id,
                                    rack_id = %rack_id_label,
                                    endpoint = %target.endpoint_url,
                                    error = %error,
                                    "Failed to request RMS NMX-C switch certificate configuration"
                                );
                                (SwitchCertApplyStatus::Error, error)
                            }
                        }
                    };

                    if expires_within_warning_window {
                        tracing::warn!(
                            switch_id = %target.switch_id,
                            rack_id = %rack_id_label,
                            endpoint = %target.endpoint_url,
                            not_after = observed_cert.not_after_timestamp,
                            "NMX-C server certificate expires within the warning window"
                        );
                    }

                    tracing::debug!(
                        switch_id = %target.switch_id,
                        rack_id = %rack_id_label,
                        endpoint = %target.endpoint_url,
                        desired_not_after = desired_cert.not_after_timestamp,
                        observed_not_after = observed_cert.not_after_timestamp,
                        fingerprint_matches,
                        expires_within_warning_window,
                        "Observed NMX-C server certificate"
                    );

                    ObservedSwitchCertMetrics {
                        desired_cert: Some(desired_cert),
                        desired_cert_error: String::new(),
                        probe_success: true,
                        fingerprint_matches,
                        expires_within_warning_window,
                        observed_cert: Some(observed_cert),
                        error: String::new(),
                        apply_status,
                        apply_error,
                    }
                }
                Err(error) if error == Self::PROBE_CANCELLED_ERROR => {
                    tracing::info!("SwitchCertificateMonitor stop was requested");
                    return Ok(());
                }
                Err(error) => {
                    tracing::warn!(
                        switch_id = %target.switch_id,
                        rack_id = %rack_id_label,
                        endpoint = %target.endpoint_url,
                        error = %error,
                        "Failed to probe NMX-C server certificate"
                    );
                    ObservedSwitchCertMetrics {
                        desired_cert: Some(desired_cert),
                        desired_cert_error: String::new(),
                        probe_success: false,
                        fingerprint_matches: false,
                        expires_within_warning_window: false,
                        observed_cert: None,
                        error,
                        apply_status: SwitchCertApplyStatus::Skipped,
                        apply_error: String::new(),
                    }
                }
            };
            metrics.observed_certs.push(observed);
        }

        Ok(())
    }

    async fn reconcile_desired_certificate_apply(
        &self,
        target: &SwitchCertificateMonitorTarget,
        cancel_token: &CancellationToken,
    ) -> Result<SwitchCertApplyStatus, String> {
        let key = SwitchCertJobKey::from_target(target);
        let in_flight_job = self
            .in_flight_certificate_jobs
            .lock()
            .await
            .get(&key)
            .cloned();

        if let Some(in_flight_job) = in_flight_job {
            let job_state = self
                .get_in_flight_certificate_job_state(&in_flight_job.job_id, cancel_token)
                .await?;
            match job_state {
                RmsSwitchCertJobState::Pending(state) => {
                    tracing::info!(
                        switch_id = %target.switch_id,
                        rack_id = %target.rack_id,
                        endpoint = %target.endpoint_url,
                        job_id = %in_flight_job.job_id,
                        job_state = %state,
                        "RMS NMX-C switch certificate configuration job is still in progress"
                    );
                    Ok(SwitchCertApplyStatus::Pending)
                }
                RmsSwitchCertJobState::Completed => {
                    self.in_flight_certificate_jobs.lock().await.remove(&key);
                    tracing::info!(
                        switch_id = %target.switch_id,
                        rack_id = %target.rack_id,
                        endpoint = %target.endpoint_url,
                        job_id = %in_flight_job.job_id,
                        "RMS NMX-C switch certificate configuration job completed"
                    );
                    Ok(SwitchCertApplyStatus::Applied)
                }
                RmsSwitchCertJobState::Failed(error) => {
                    self.in_flight_certificate_jobs.lock().await.remove(&key);
                    Err(format!(
                        "RMS NMX-C switch certificate configuration job {} failed: {}",
                        in_flight_job.job_id, error
                    ))
                }
            }
        } else {
            let job_id = self
                .apply_desired_certificate_with_rms(target, cancel_token)
                .await?;
            self.in_flight_certificate_jobs
                .lock()
                .await
                .insert(key, InFlightSwitchCertJob { job_id });
            Ok(SwitchCertApplyStatus::Pending)
        }
    }

    async fn load_switch_certificate_monitor_targets(
        &self,
    ) -> NvLinkManagerResult<Vec<SwitchCertificateMonitorTarget>> {
        let mut db_reader = PgPoolReader::from(self.db_pool.clone());
        let endpoint_rows =
            db::switch::find_ready_control_plane_configured_switch_endpoints(&mut db_reader)
                .await
                .map_err(NvLinkManagerError::from)?;

        Ok(endpoint_rows
            .into_iter()
            .map(|row| SwitchCertificateMonitorTarget {
                switch_id: row.switch_id,
                rack_id: row.rack_id,
                rack_profile_id: row.rack_profile_id,
                endpoint_url: nmx_c_endpoint::nmx_c_endpoint_url_from_nvos_ip(
                    &row.nvos_ip,
                    None,
                    &self.config,
                ),
            })
            .collect())
    }

    async fn apply_desired_certificate_with_rms(
        &self,
        target: &SwitchCertificateMonitorTarget,
        cancel_token: &CancellationToken,
    ) -> Result<String, String> {
        let rms_client = self.rms_client.as_ref().ok_or_else(|| {
            "RMS client is not configured, so NMX-C switch certificate cannot be applied"
                .to_string()
        })?;

        let rack_profile_id = target.rack_profile_id.as_ref().ok_or_else(|| {
            format!(
                "rack {} has no rack_profile_id, so RMS switch node type and topology cannot be resolved",
                target.rack_id
            )
        })?;
        let profile = self
            .rack_profiles
            .get(rack_profile_id.as_ref())
            .ok_or_else(|| {
                format!(
                    "rack profile {} is not configured, so RMS switch node type and topology cannot be resolved",
                    rack_profile_id
                )
            })?;
        let switch_node_type = switch_node_type_for_profile(profile)
            .map_err(|error| format!("failed to resolve RMS switch node type: {error}"))?;

        let switch = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(Self::APPLY_CANCELLED_ERROR.to_string());
            }
            switch = load_switch_firmware_device_info(
                &self.db_pool,
                self.credential_manager.as_ref(),
                &target.switch_id,
            ) => switch
                .map_err(|error| {
                    format!(
                        "failed to load switch endpoint info for RMS certificate apply: {error}"
                    )
                })?,
        };

        validate_switch_for_rms_certificate_apply(&switch)?;

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(Self::APPLY_CANCELLED_ERROR.to_string());
            }
            response = rms_client.configure_switch_certificate(
                rms::ConfigureSwitchCertificateRequest {
                    nodes: Some(rms::NodeSet {
                        nodes: vec![build_new_node_info(
                            &target.rack_id,
                            &switch,
                            switch_node_type,
                        )],
                    }),
                    services: vec![rms::SwitchService::ScaleUpFabricManager as i32],
                    test_hello: true,
                    domain: Some(target.rack_id.to_string()),
                }
            ) => response.map_err(|error| {
                format!("RMS ConfigureSwitchCertificate failed: {error}")
            })?,
        };

        let batch_response = response.response.ok_or_else(|| {
            "RMS ConfigureSwitchCertificate response did not include a batch response".to_string()
        })?;
        if batch_response.status != rms::ReturnCode::Success as i32 {
            let message = if batch_response.message.trim().is_empty() {
                "no error details provided".to_string()
            } else {
                batch_response.message
            };
            return Err(format!(
                "RMS ConfigureSwitchCertificate returned status {}: {}",
                batch_response.status, message
            ));
        }

        let switch_id = target.switch_id.to_string();
        let child_job_id = response
            .jobs
            .iter()
            .find(|job| job.node_id == switch_id)
            .map(|job| job.job_id.trim())
            .filter(|job_id| !job_id.is_empty());
        let job_id = child_job_id
            .or_else(|| {
                let parent_job_id = batch_response.job_id.trim();
                if parent_job_id.is_empty() {
                    None
                } else {
                    Some(parent_job_id)
                }
            })
            .ok_or_else(|| {
                "RMS ConfigureSwitchCertificate response did not include a job id".to_string()
            })?
            .to_string();

        tracing::info!(
            switch_id = %target.switch_id,
            rack_id = %target.rack_id,
            job_id = %job_id,
            "Submitted RMS switch certificate configuration"
        );

        Ok(job_id)
    }

    async fn get_in_flight_certificate_job_state(
        &self,
        job_id: &str,
        cancel_token: &CancellationToken,
    ) -> Result<RmsSwitchCertJobState, String> {
        let rms_client = self.rms_client.as_ref().ok_or_else(|| {
            "RMS client is not configured, so NMX-C switch certificate job status cannot be checked"
                .to_string()
        })?;

        let response = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(Self::APPLY_CANCELLED_ERROR.to_string());
            }
            response = rms_client.get_configure_switch_certificate_job_status(
                rms::GetConfigureSwitchCertificateJobStatusRequest {
                    job_id: job_id.to_string(),
                },
            ) => response.map_err(|error| {
                format!("RMS GetConfigureSwitchCertificateJobStatus failed: {error}")
            })?,
        };

        if response.status != rms::ReturnCode::Success as i32 {
            return Ok(RmsSwitchCertJobState::Failed(format!(
                "RMS GetConfigureSwitchCertificateJobStatus returned status {}: {}",
                response.status,
                non_empty_or(response.error_message.as_str(), response.message.as_str())
            )));
        }

        let state = response.state.trim().to_ascii_lowercase();
        match state.as_str() {
            "completed" | "complete" | "succeeded" | "success" => {
                Ok(RmsSwitchCertJobState::Completed)
            }
            "failed" | "failure" | "error" => Ok(RmsSwitchCertJobState::Failed(non_empty_or(
                response.error_message.as_str(),
                response.message.as_str(),
            ))),
            "queued" | "running" | "pending" | "active" | "in_progress" => {
                Ok(RmsSwitchCertJobState::Pending(state))
            }
            "" => Ok(RmsSwitchCertJobState::Pending("unknown".to_string())),
            _ => {
                tracing::warn!(
                    job_id = %job_id,
                    job_state = %response.state,
                    "RMS returned unknown NMX-C switch certificate job state; treating as pending"
                );
                Ok(RmsSwitchCertJobState::Pending(response.state))
            }
        }
    }

    async fn probe_endpoint_certificate(
        &self,
        endpoint_url: &str,
        cancel_token: &CancellationToken,
    ) -> Result<CertificateInfo, String> {
        let uri = endpoint_url
            .parse::<http::Uri>()
            .map_err(|error| format!("invalid NMX-C endpoint URI {endpoint_url}: {error}"))?;

        let scheme = uri.scheme_str().unwrap_or("http");
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(format!(
                "NMX-C endpoint {endpoint_url} is not HTTPS, so no server certificate can be probed"
            ));
        }

        let host = uri
            .host()
            .ok_or_else(|| format!("NMX-C endpoint {endpoint_url} has no host"))?
            .to_string();
        let port = uri.port_u16().unwrap_or(443);
        let tls_authority = self
            .config
            .nmx_c_tls_authority
            .clone()
            .unwrap_or_else(|| host.clone());
        let server_name = ServerName::try_from(tls_authority.clone())
            .map_err(|error| format!("invalid NMX-C TLS authority {tls_authority}: {error}"))?;

        let probe_timeout = self.config.nmx_c_certificate_rotation.probe_timeout;
        let client_config = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(Self::PROBE_CANCELLED_ERROR.to_string());
            }
            client_config = build_tls_client_config(&self.config) => client_config?,
        };
        let connector = TlsConnector::from(Arc::new(client_config));
        let tcp_stream = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(Self::PROBE_CANCELLED_ERROR.to_string());
            }
            tcp_stream = tokio::time::timeout(
                probe_timeout,
                TcpStream::connect((host.as_str(), port)),
            ) => tcp_stream
                .map_err(|_| {
                    format!("connection to {host}:{port} timed out after {probe_timeout:?}")
                })?
                .map_err(|error| format!("failed to connect to {host}:{port}: {error}"))?,
        };
        let tls_stream = tokio::select! {
            _ = cancel_token.cancelled() => {
                return Err(Self::PROBE_CANCELLED_ERROR.to_string());
            }
            tls_stream = tokio::time::timeout(
                probe_timeout,
                connector.connect(server_name, tcp_stream),
            ) => tls_stream
                .map_err(|_| {
                    format!("TLS handshake timed out for {endpoint_url} after {probe_timeout:?}")
                })?
                .map_err(|error| format!("TLS handshake failed for {endpoint_url}: {error}"))?,
        };

        let peer_certs =
            tls_stream.get_ref().1.peer_certificates().ok_or_else(|| {
                format!("NMX-C endpoint {endpoint_url} did not serve a certificate")
            })?;
        let leaf_cert = peer_certs.first().ok_or_else(|| {
            format!("NMX-C endpoint {endpoint_url} served an empty certificate chain")
        })?;
        certificate_info_from_der(leaf_cert.as_ref())
    }
}

fn desired_server_cert_path(config: &NvLinkConfig, rack_id: &RackId) -> Result<String, String> {
    if let Some(path_template) = &config.nmx_c_certificate_rotation.server_cert_path_template {
        return Ok(path_template.replace("{rack_id}", rack_id.as_ref()));
    }

    config
        .nmx_c_certificate_rotation
        .server_cert_path
        .clone()
        .ok_or_else(|| {
            "nmx_c_certificate_rotation.server_cert_path or server_cert_path_template is not configured"
                .to_string()
        })
}

fn validate_switch_for_rms_certificate_apply(
    switch: &model::rack::FirmwareUpgradeDeviceInfo,
) -> Result<(), String> {
    if switch.os_ip.as_deref().unwrap_or_default().is_empty() {
        return Err(format!(
            "switch {} is missing an NVOS IP address for RMS certificate apply",
            switch.node_id
        ));
    }
    if switch.os_username.as_deref().unwrap_or_default().is_empty()
        || switch.os_password.as_deref().unwrap_or_default().is_empty()
    {
        return Err(format!(
            "switch {} is missing NVOS credentials for RMS certificate apply",
            switch.node_id
        ));
    }

    Ok(())
}

async fn build_tls_client_config(config: &NvLinkConfig) -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    let ca_cert_path = config
        .nmx_c_tls_ca_cert_path
        .as_ref()
        .ok_or_else(|| "nmx_c_tls_ca_cert_path is required to probe NMX-C TLS".to_string())?;
    let ca_certs = read_certs_from_pem_file(ca_cert_path).await?;
    let (added, ignored) = roots.add_parsable_certificates(ca_certs);
    if added == 0 {
        return Err(format!(
            "no CA certificates from {ca_cert_path} could be added to the NMX-C TLS root store; ignored {ignored}"
        ));
    }

    let builder = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("failed to build rustls client config: {error}"))?
    .with_root_certificates(roots);

    match (
        &config.nmx_c_tls_client_cert_path,
        &config.nmx_c_tls_client_key_path,
    ) {
        (Some(client_cert_path), Some(client_key_path)) => {
            let certs = read_certs_from_pem_file(client_cert_path).await?;
            let key = read_private_key_from_pem_file(client_key_path).await?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|error| format!("invalid NMX-C client certificate config: {error}"))
        }
        (None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(
            "nmx_c_tls_client_cert_path and nmx_c_tls_client_key_path must be configured together"
                .to_string(),
        ),
    }
}

async fn read_leaf_cert_info_from_pem_file(path: &str) -> Result<CertificateInfo, String> {
    let certs = read_certs_from_pem_file(path).await?;
    let leaf_cert = certs
        .first()
        .ok_or_else(|| format!("no certificates found in {path}"))?;
    certificate_info_from_der(leaf_cert.as_ref())
}

async fn read_certs_from_pem_file(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = tokio::fs::read(path)
        .await
        .map_err(|error| format!("failed to read {path}: {error}"))?;
    let mut cursor = io::Cursor::new(pem);
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse certificates from {path}: {error}"))
}

async fn read_private_key_from_pem_file(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let pem = tokio::fs::read(path)
        .await
        .map_err(|error| format!("failed to read {path}: {error}"))?;
    let mut cursor = io::Cursor::new(pem);
    rustls_pemfile::private_key(&mut cursor)
        .map_err(|error| format!("failed to parse private key from {path}: {error}"))?
        .ok_or_else(|| format!("no private key found in {path}"))
}

fn certificate_info_from_der(der: &[u8]) -> Result<CertificateInfo, String> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|error| format!("failed to parse X.509 certificate: {error}"))?;
    let fingerprint_sha256 = hex::encode_upper(Sha256::digest(der));
    Ok(CertificateInfo {
        fingerprint_sha256,
        not_after_timestamp: cert.validity.not_after.timestamp(),
    })
}

fn cert_expires_within(cert: &CertificateInfo, window: Duration) -> bool {
    let Some(not_after) = chrono::DateTime::from_timestamp(cert.not_after_timestamp, 0) else {
        return true;
    };
    let Ok(window) = chrono::Duration::from_std(window) else {
        return true;
    };
    let Some(warning_threshold) = Utc::now().checked_add_signed(window) else {
        return true;
    };
    not_after <= warning_threshold
}

fn non_empty_or(primary: &str, fallback: &str) -> String {
    if primary.trim().is_empty() {
        fallback.trim().to_string()
    } else {
        primary.trim().to_string()
    }
}

fn metric_attrs(base_attrs: &[KeyValue], extra_attrs: &[KeyValue]) -> Vec<KeyValue> {
    [base_attrs, extra_attrs].concat()
}

fn count_by_status(
    certs: &[ObservedSwitchCertMetrics],
    status_for_cert: impl Fn(&ObservedSwitchCertMetrics) -> &'static str,
) -> BTreeMap<&'static str, u64> {
    let mut counts = BTreeMap::new();
    for cert in certs {
        *counts.entry(status_for_cert(cert)).or_insert(0) += 1;
    }
    counts
}

fn count_errors_by_kind<'a>(
    errors: impl Iterator<Item = &'a str>,
) -> BTreeMap<SwitchCertMonitorErrorKind, u64> {
    let mut counts = BTreeMap::new();
    for error in errors {
        if !error.is_empty() {
            *counts
                .entry(switch_cert_monitor_error_kind(error))
                .or_insert(0) += 1;
        }
    }
    counts
}

fn probe_status(cert: &ObservedSwitchCertMetrics) -> &'static str {
    if cert.probe_success { "ok" } else { "error" }
}

fn fingerprint_status(cert: &ObservedSwitchCertMetrics) -> &'static str {
    if !cert.probe_success {
        "unknown"
    } else if cert.fingerprint_matches {
        "match"
    } else {
        "mismatch"
    }
}

fn expiry_status(cert: &ObservedSwitchCertMetrics) -> &'static str {
    if cert.observed_cert.is_none() {
        "unknown"
    } else if cert.expires_within_warning_window {
        "expiring_soon"
    } else {
        "ok"
    }
}

fn apply_status(cert: &ObservedSwitchCertMetrics) -> &'static str {
    cert.apply_status.as_metric_label()
}

fn switch_cert_monitor_error_kind(error: &str) -> SwitchCertMonitorErrorKind {
    let error = error.to_ascii_lowercase();
    if error.contains("timed out") {
        SwitchCertMonitorErrorKind::Timeout
    } else if error.contains("failed to connect") || error.contains("connection to") {
        SwitchCertMonitorErrorKind::Connection
    } else if error.contains("tls")
        || error.contains("client certificate")
        || error.contains("root store")
    {
        SwitchCertMonitorErrorKind::Tls
    } else if error.contains("failed to read") || error.contains("no certificates found") {
        SwitchCertMonitorErrorKind::CertificateFile
    } else if error.contains("parse") || error.contains("x.509") {
        SwitchCertMonitorErrorKind::CertificateParse
    } else if error.contains("not https")
        || error.contains("invalid nmx-c endpoint uri")
        || error.contains("has no host")
    {
        SwitchCertMonitorErrorKind::EndpointConfig
    } else if error.contains("did not serve") || error.contains("empty certificate chain") {
        SwitchCertMonitorErrorKind::ServerCertificate
    } else if error.contains("not configured")
        || error.contains("required")
        || error.contains("rack profile")
        || error.contains("missing")
    {
        SwitchCertMonitorErrorKind::Configuration
    } else if error.contains("rms ") || error.contains("configurescaleupfabricmanager") {
        SwitchCertMonitorErrorKind::Rms
    } else {
        SwitchCertMonitorErrorKind::Other
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use super::*;
    use crate::config::NmxCCertificateRotationConfig;

    #[test]
    fn desired_server_cert_path_uses_single_path_fallback() {
        let config = NvLinkConfig {
            nmx_c_certificate_rotation: NmxCCertificateRotationConfig {
                server_cert_path: Some("/var/run/nmxc/site/tls.crt".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let actual = desired_server_cert_path(&config, &RackId::new("rack-1")).unwrap();

        assert_eq!(actual, "/var/run/nmxc/site/tls.crt");
    }

    #[test]
    fn desired_server_cert_path_expands_rack_template() {
        let config = NvLinkConfig {
            nmx_c_certificate_rotation: NmxCCertificateRotationConfig {
                server_cert_path: Some("/var/run/nmxc/site/tls.crt".to_string()),
                server_cert_path_template: Some("/var/run/nmxc/{rack_id}/tls.crt".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let actual = desired_server_cert_path(&config, &RackId::new("rack-42")).unwrap();

        assert_eq!(actual, "/var/run/nmxc/rack-42/tls.crt");
    }

    #[test]
    fn desired_server_cert_path_requires_some_cert_path_config() {
        let config = NvLinkConfig::default();

        let error = desired_server_cert_path(&config, &RackId::new("rack-42")).unwrap_err();

        assert_eq!(
            error,
            "nmx_c_certificate_rotation.server_cert_path or server_cert_path_template is not configured"
        );
    }

    #[tokio::test]
    async fn read_leaf_cert_info_from_pem_file_returns_fingerprint_and_expiry() {
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec!["nmxc.example.test".to_string()]).unwrap();
        let expected_fingerprint = hex::encode_upper(Sha256::digest(cert.der().as_ref()));

        let cert_file = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(cert_file.path(), cert.pem())
            .await
            .unwrap();

        let actual = read_leaf_cert_info_from_pem_file(&cert_file.path().to_string_lossy())
            .await
            .unwrap();

        assert_eq!(actual.fingerprint_sha256, expected_fingerprint);
        assert!(actual.not_after_timestamp > Utc::now().timestamp());
    }
}
