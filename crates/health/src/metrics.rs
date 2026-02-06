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
use prometheus::{Encoder, Registry, TextEncoder, proto};
use tokio::net::TcpListener;

use crate::HealthError;

pub type MetricLabel = (String, String);
type BoxedErr = Box<dyn std::error::Error + Send + Sync + 'static>;

pub struct MetricsManager {
    global_registry: Registry,
}

impl Default for MetricsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsManager {
    pub fn new() -> Self {
        Self {
            global_registry: Registry::new(),
        }
    }

    pub fn global_registry(&self) -> &Registry {
        &self.global_registry
    }

    pub fn create_collector_registry(
        &self,
        id: String,
        prefix: impl Into<String>,
    ) -> Result<CollectorRegistry, HealthError> {
        CollectorRegistry::new(id, self.global_registry.clone(), prefix)
    }

    pub fn export_all(&self) -> Result<String, HealthError> {
        let encoder = TextEncoder::new();
        let metric_families = self.global_registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        String::from_utf8(buffer).map_err(|e| {
            HealthError::GenericError(format!(
                "MetricManager encoutered IO error while export is called: {e:?}"
            ))
        })
    }
}

pub struct CollectorRegistry {
    prefix: String,
    registry: Box<SubRegistry>,
    parent: Registry,
}

impl CollectorRegistry {
    fn new(id: String, parent: Registry, prefix: impl Into<String>) -> Result<Self, HealthError> {
        let desc = Desc::new(id.clone(), id, Vec::new(), HashMap::new())?;

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
            tracing::error!(e=?e, "Could not properly drop registry for collector {}", self.prefix())
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
                label.set_name(name.clone());
                label.set_value(value.clone());
                labels.push(label);
            }

            let mut gauge = proto::Gauge::new();
            gauge.set_value(data.value);

            let mut metric = proto::Metric::new();
            metric.set_label(labels.into());
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

    tracing::info!("Metrics server listening on {}", metrics_endpoint);

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
                async move { serve_metrics(req, metrics_manager) }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                tracing::error!(error=?e, "metrics server connection error");
            }
        });
    }
}

fn serve_metrics(
    _req: Request<Incoming>,
    metrics_manager: Arc<MetricsManager>,
) -> Result<Response<String>, hyper::Error> {
    let encoder = TextEncoder::new();
    let body = match metrics_manager.export_all() {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error=?e, "error exporting metrics");
            return Ok(Response::builder()
                .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body("error exporting metrics, see logs".to_string())
                .expect("BUG: Response::builder error"));
        }
    };

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(body)
        .expect("BUG: Response::builder error");
    Ok(response)
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
