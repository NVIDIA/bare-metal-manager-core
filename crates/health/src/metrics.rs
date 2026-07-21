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
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use http::Response;
use http::header::CONTENT_TYPE;
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use prometheus::core::{Collector, Desc};
use prometheus::proto::LabelPair;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Registry, TextEncoder, proto,
};
use tokio::net::TcpListener;

use crate::HealthError;

pub type MetricLabel = (Cow<'static, str>, String);
type BoxedErr = Box<dyn std::error::Error + Send + Sync + 'static>;

pub fn operation_duration_buckets_seconds() -> Vec<f64> {
    vec![
        1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 30.0, 45.0, 60.0, 90.0, 120.0, 180.0, 240.0, 300.0,
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentKind {
    Collector,
    Processor,
    Sink,
}

impl ComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collector => "collector",
            Self::Processor => "processor",
            Self::Sink => "sink",
        }
    }
}

#[derive(Clone)]
pub struct ComponentMetrics {
    failures_total: IntCounterVec,
    duration_seconds: HistogramVec,
}

impl ComponentMetrics {
    pub fn new(registry: &Registry, prefix: &str) -> Result<Self, prometheus::Error> {
        let failures_total = IntCounterVec::new(
            prometheus::Opts::new(
                format!("{prefix}_component_failures_total"),
                "Number of component operation failures",
            ),
            &["component_kind", "component_name"],
        )?;
        registry.register(Box::new(failures_total.clone()))?;

        let duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                format!("{prefix}_component_duration_seconds"),
                "Duration of component operations",
            )
            .buckets(operation_duration_buckets_seconds()),
            &["component_kind", "component_name"],
        )?;
        registry.register(Box::new(duration_seconds.clone()))?;

        Ok(Self {
            failures_total,
            duration_seconds,
        })
    }

    pub fn record_operation(
        &self,
        kind: ComponentKind,
        name: &str,
        duration: std::time::Duration,
        success: bool,
    ) {
        let labels = [kind.as_str(), name];
        self.duration_seconds
            .with_label_values(&labels)
            .observe(duration.as_secs_f64());
        if !success {
            self.failures_total.with_label_values(&labels).inc();
        }
    }
}

pub struct MetricsManager {
    global_registry: Registry,
    telemetry_registry: Registry,
    component_metrics: Arc<ComponentMetrics>,
    /// The instrumentation framework's registry, exposed through the same
    /// /metrics response so its events are scrapeable without migrating this
    /// server off its raw prometheus pipeline. Set once at startup.
    framework_registry: std::sync::OnceLock<Registry>,
}

impl MetricsManager {
    pub fn new(prefix: &str) -> Result<Self, prometheus::Error> {
        let global_registry = Registry::new();
        let telemetry_registry = Registry::new();
        let component_metrics = Arc::new(ComponentMetrics::new(&global_registry, prefix)?);

        Ok(Self {
            global_registry,
            telemetry_registry,
            component_metrics,
            framework_registry: std::sync::OnceLock::new(),
        })
    }

    pub fn global_registry(&self) -> &Registry {
        &self.global_registry
    }

    pub fn component_metrics(&self) -> Arc<ComponentMetrics> {
        self.component_metrics.clone()
    }

    pub fn create_collector_registry(
        &self,
        id: String,
        prefix: impl Into<String>,
    ) -> Result<CollectorRegistry, HealthError> {
        CollectorRegistry::new(id, self.global_registry.clone(), prefix)
    }

    pub fn create_telemetry_collector_registry(
        &self,
        id: String,
        prefix: impl Into<String>,
    ) -> Result<CollectorRegistry, HealthError> {
        CollectorRegistry::new(id, self.telemetry_registry.clone(), prefix)
    }

    /// Makes the instrumentation framework's registry part of every
    /// subsequent /metrics response. A second call is ignored.
    pub fn expose_framework_registry(&self, registry: Registry) {
        let _ = self.framework_registry.set(registry);
    }

    pub fn export_metrics(&self) -> Result<String, HealthError> {
        let mut exposition = export_registry(&self.global_registry)?;
        if let Some(framework) = self.framework_registry.get() {
            exposition.push_str(&export_registry(framework)?);
        }
        Ok(exposition)
    }

    pub fn export_telemetry(&self) -> Result<String, HealthError> {
        export_registry(&self.telemetry_registry)
    }
}

fn export_registry(registry: &Registry) -> Result<String, HealthError> {
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    String::from_utf8(buffer).map_err(|e| {
        HealthError::GenericError(format!(
            "MetricManager encoutered IO error while export is called: {e:?}"
        ))
    })
}

pub struct CollectorRegistry {
    prefix: String,
    registry: Box<SubRegistry>,
    parent: Registry,
}

impl CollectorRegistry {
    fn new(id: String, parent: Registry, prefix: impl Into<String>) -> Result<Self, HealthError> {
        let fq_id = id.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
        let desc = Desc::new(fq_id, id, Vec::new(), HashMap::new())?;

        let registry = Box::new(SubRegistry {
            registry: Registry::new(),
            desc,
        });

        parent.register(registry.clone())?;

        Ok(Self {
            prefix: prefix.into(),
            registry,
            parent,
        })
    }

    pub fn create_gauge_metrics(
        &self,
        id: String,
        help: impl Into<String>,
        static_labels: Vec<MetricLabel>,
    ) -> Result<Arc<GaugeMetrics>, prometheus::Error> {
        let metrics = Arc::new(GaugeMetrics::new(
            id,
            &self.registry.registry,
            self.prefix.clone(),
            help,
            static_labels,
        )?);

        Ok(metrics)
    }

    pub fn unregister_gauge_metrics(
        &self,
        metrics: &GaugeMetrics,
    ) -> Result<(), prometheus::Error> {
        self.registry
            .registry
            .unregister(Box::new(metrics.clone()))
            .map(|_| ())
    }

    pub fn registry(&self) -> &Registry {
        &self.registry.registry
    }

    pub fn prefix(&self) -> &String {
        &self.prefix
    }
}

#[derive(Clone)]
struct SubRegistry {
    registry: Registry,
    desc: Desc,
}

impl Collector for SubRegistry {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        self.registry.gather()
    }
}

impl Drop for CollectorRegistry {
    fn drop(&mut self) {
        if let Err(e) = self.parent.unregister(self.registry.clone()) {
            tracing::error!(
                error = ?e,
                collector_prefix = self.prefix().as_str(),
                "Could not properly drop registry for collector"
            )
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct GaugeKey(String);

impl From<String> for GaugeKey {
    fn from(s: String) -> Self {
        GaugeKey(s)
    }
}

impl From<&str> for GaugeKey {
    fn from(s: &str) -> Self {
        GaugeKey(s.to_string())
    }
}

pub struct GaugeReading {
    pub key: GaugeKey,
    pub name: String,
    pub metric_type: String,
    pub unit: String,
    pub value: f64,
    pub labels: Vec<MetricLabel>,
}

impl GaugeReading {
    pub fn new(
        key: impl Into<GaugeKey>,
        name: impl Into<String>,
        metric_type: impl Into<String>,
        unit: impl Into<String>,
        value: f64,
    ) -> Self {
        Self {
            key: key.into(),
            name: name.into(),
            metric_type: metric_type.into(),
            unit: unit.into(),
            value,
            labels: Vec::new(),
        }
    }

    pub fn with_labels(mut self, labels: Vec<MetricLabel>) -> Self {
        self.labels.extend(labels);
        self
    }
}

struct GaugeData {
    name: String,
    metric_type: String,
    unit: String,
    value: f64,
    labels: Vec<MetricLabel>,
    generation: u64,
}

#[derive(Clone)]
pub struct GaugeMetrics {
    gauges: Arc<DashMap<GaugeKey, GaugeData>>,
    current_generation: Arc<AtomicU64>,
    metric_name_prefix: String,
    metric_help: String,
    static_labels: Vec<proto::LabelPair>,
    desc: Desc,
}

impl GaugeMetrics {
    pub fn new(
        id: String,
        registry: &Registry,
        metric_name_prefix: impl Into<String>,
        metric_help: impl Into<String>,
        static_labels: Vec<(impl Into<String>, impl Into<String>)>,
    ) -> Result<Self, prometheus::Error> {
        let desc = Desc::new(id.clone(), id, Vec::new(), HashMap::new())?;
        let metrics = Self {
            gauges: Arc::new(DashMap::new()),
            current_generation: Arc::new(AtomicU64::new(0)),
            metric_name_prefix: metric_name_prefix.into(),
            metric_help: metric_help.into(),
            static_labels: static_labels
                .into_iter()
                .map(|(name, value)| {
                    let mut label = LabelPair::new();
                    label.set_name(name.into());
                    label.set_value(value.into());
                    label
                })
                .collect(),
            desc,
        };

        registry.register(Box::new(metrics.clone()))?;
        Ok(metrics)
    }

    pub fn begin_update(&self) {
        self.current_generation.fetch_add(1, Ordering::Release);
    }

    pub fn record(&self, reading: GaugeReading) {
        let generation = self.current_generation.load(Ordering::Acquire);

        self.gauges.insert(
            reading.key,
            GaugeData {
                name: reading.name,
                metric_type: reading.metric_type,
                unit: reading.unit,
                value: reading.value,
                labels: reading.labels,
                generation,
            },
        );
    }

    pub fn sweep_stale(&self) {
        let current_gen = self.current_generation.load(Ordering::Acquire);
        self.gauges.retain(|_, data| data.generation == current_gen);
    }

    pub fn clear(&self) {
        self.gauges.clear();
    }
}

impl Collector for GaugeMetrics {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        let mut families: HashMap<(String, String, String), proto::MetricFamily> = HashMap::new();

        for gauge_ref in self.gauges.iter() {
            let data = gauge_ref.value();
            let family_key = (
                data.name.clone(),
                data.metric_type.clone(),
                data.unit.clone(),
            );

            let family = families.entry(family_key.clone()).or_insert_with(|| {
                let metric_name = format!(
                    "{}_{}_{}_{}",
                    self.metric_name_prefix, family_key.0, family_key.1, family_key.2
                );
                let mut mf = proto::MetricFamily::default();
                mf.set_name(metric_name);
                mf.set_help(self.metric_help.clone());
                mf.set_field_type(proto::MetricType::GAUGE);
                mf
            });

            let mut labels: Vec<proto::LabelPair> = self.static_labels.clone();

            for (name, value) in &data.labels {
                let mut label = proto::LabelPair::new();
                label.set_name(name.as_ref().to_owned());
                label.set_value(value.clone());
                labels.push(label);
            }

            let mut gauge = proto::Gauge::new();
            gauge.set_value(data.value);

            let mut metric = proto::Metric::new();
            metric.set_label(labels);
            metric.set_gauge(gauge);

            family.mut_metric().push(metric);
        }

        families.into_values().collect()
    }
}

pub async fn run_metrics_server(
    metrics_endpoint: std::net::SocketAddr,
    metrics_manager: Arc<MetricsManager>,
) -> Result<(), BoxedErr> {
    let listener = TcpListener::bind(metrics_endpoint)
        .await
        .map_err(|e| Box::new(e) as BoxedErr)?;

    tracing::info!(
        %metrics_endpoint,
        "Metrics server listening (paths: /metrics, /telemetry, /livez)"
    );

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| Box::new(e) as BoxedErr)?;

        let io = TokioIo::new(stream);
        let metrics_manager = metrics_manager.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let metrics_manager = metrics_manager.clone();
                async move { serve_request(req, metrics_manager) }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                tracing::error!(error=?e, "metrics server connection error");
            }
        });
    }
}

fn serve_request(
    req: Request<Incoming>,
    metrics_manager: Arc<MetricsManager>,
) -> Result<Response<String>, hyper::Error> {
    match req.uri().path() {
        "/livez" => Ok(Response::builder()
            .status(http::StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body("ok".to_string())
            .expect("BUG: Response::builder error")),
        "/metrics" => serve_prometheus(metrics_manager.export_metrics(), "service metrics"),
        "/telemetry" => serve_prometheus(metrics_manager.export_telemetry(), "telemetry metrics"),
        _ => Ok(Response::builder()
            .status(http::StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body("not found; use /metrics, /telemetry, or /livez".to_string())
            .expect("BUG: Response::builder error")),
    }
}

fn serve_prometheus(
    export_result: Result<String, HealthError>,
    export_name: &'static str,
) -> Result<Response<String>, hyper::Error> {
    let encoder = TextEncoder::new();
    let body = match export_result {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error=?e, export_name, "error exporting prometheus metrics");
            return Ok(Response::builder()
                .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(format!("error exporting {export_name}, see logs"))
                .expect("BUG: Response::builder error"));
        }
    };

    Ok(Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(body)
        .expect("BUG: Response::builder error"))
}

pub fn sanitize_unit(unit: &str) -> String {
    match unit.to_lowercase().as_str() {
        "%" => "percent".to_string(),
        "°c" | "c" | "cel" => "celsius".to_string(),
        "°f" | "f" => "fahrenheit".to_string(),
        "v" => "volts".to_string(),
        "a" | "amps" => "amperes".to_string(),
        "w" => "watts".to_string(),
        "hz" => "hertz".to_string(),
        _ => unit
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_registry_sanitizes_descriptor_fq_name() {
        for (id, expected_fq_name) in [
            (
                "sensor_collector_10.0.0.1:443",
                "sensor_collector_10_0_0_1_443",
            ),
            (
                "log_collector_bmc-01.example.com",
                "log_collector_bmc_01_example_com",
            ),
            (
                "collector with spaces/slashes",
                "collector_with_spaces_slashes",
            ),
        ] {
            let registry = CollectorRegistry::new(id.to_string(), Registry::new(), "test_prefix")
                .expect("collector registry should accept sanitized id");

            assert_eq!(registry.registry.desc.fq_name, expected_fq_name);
            assert_eq!(registry.registry.desc.help, id);
        }
    }
}
