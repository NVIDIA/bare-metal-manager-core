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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::routing::get;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use prometheus::{Encoder, TextEncoder};
use tonic::service::AxumBody;
use tower::ServiceBuilder;
use tracing::Span;

pub mod config;
use carbide_uuid::machine::MachineId;
pub use config::{get_dpu_agent_meter, get_prometheus_registry};

pub struct AgentMetricsState {
    meter: Meter,
    http_counter: Counter<u64>,
    http_req_latency_histogram: Histogram<f64>,
}

impl AgentMetricsState {
    // Record the boot time of the machine we're running on as a Unix timestamp.
    // This only needs to be called once per lifetime of the Meter (which is
    // probably the same as the process lifetime).
    pub fn record_machine_boot_time(&self, timestamp: u64) {
        self.meter
            .u64_observable_gauge("machine_boot_time_seconds")
            .with_description("Timestamp of this machine's last boot")
            .with_callback(move |machine_boot_time| {
                machine_boot_time.observe(timestamp, &[]);
            })
            .build();
    }

    // Record the agent process's start time as a Unix timestamp. This only
    // needs to be called once per lifetime of the Meter (which is probably the
    // same as the process lifetime).
    pub fn record_agent_start_time(&self, timestamp: u64) {
        self.meter
            .u64_observable_gauge("agent_start_time_seconds")
            .with_description("Timestamp of the agent process's last start")
            .with_callback(move |agent_start_time| {
                agent_start_time.observe(timestamp, &[]);
            })
            .build();
    }
}

pub fn create_metrics(meter: Meter) -> Arc<AgentMetricsState> {
    let http_counter = meter
        .u64_counter("http_requests")
        .with_description("Total number of HTTP requests made.")
        .build();
    let http_req_latency_histogram: Histogram<f64> = meter
        .f64_histogram("request_latency")
        .with_description("HTTP request latency")
        .with_unit("ms")
        .build();

    Arc::new(AgentMetricsState {
        meter,
        http_counter,
        http_req_latency_histogram,
    })
}

pub struct NetworkMonitorMetricsState {
    // Metrics for network monitoring
    network_latency: Histogram<f64>,
    network_loss_percent: Histogram<f64>,
    network_monitor_error: Counter<u64>,
    network_communication_error: Counter<u64>,

    // Fields used for network_reachable observations
    network_reachable_map: NetworkReachableMap,
}

type NetworkReachableMap = Arc<Mutex<Option<HashMap<MachineId, bool>>>>;

impl NetworkMonitorMetricsState {
    pub fn initialize(meter: Meter, machine_id: MachineId) -> Arc<Self> {
        let network_reachable_map = NetworkReachableMap::default();

        {
            let network_reachable_map = network_reachable_map.clone();
            meter
                .u64_observable_gauge("forge_dpu_agent_network_reachable")
                .with_description(
                    "Network reachability status (1 for reachable, 0 for unreachable)",
                )
                .with_callback(move |observer| {
                    let network_reachable_map = network_reachable_map.lock().unwrap();
                    if let Some(map) = network_reachable_map.as_ref() {
                        // Export reachability metrics from the map
                        for (dpu_id, reachable) in map.iter() {
                            let reachability = if *reachable { 1 } else { 0 };
                            observer.observe(
                                reachability,
                                &[
                                    KeyValue::new("source_dpu_id", machine_id.to_string()),
                                    KeyValue::new("dest_dpu_id", dpu_id.to_string()),
                                ],
                            );
                        }
                    }
                })
                .build();
        }

        let network_latency = meter
            .f64_histogram("forge_dpu_agent_network_latency")
            .with_unit("ms")
            .build();
        let network_loss_percent = meter
            .f64_histogram("forge_dpu_agent_network_loss_percentage")
            .with_description("Percentage of failed pings out of total 5 pings")
            .build();
        let network_monitor_error = meter
            .u64_counter("forge_dpu_agent_network_monitor_error")
            .with_description("Network monitor errors which are unrelated to network connectivity")
            .build();
        let network_communication_error = meter
            .u64_counter("forge_dpu_agent_network_communication_error")
            .with_description("Network monitor errors related to ping dpu")
            .build();

        Arc::new(Self {
            network_latency,
            network_loss_percent,
            network_monitor_error,
            network_communication_error,
            network_reachable_map,
        })
    }

    /// Records network latency between two DPUs as milliseconds.
    ///
    /// # Parameters
    /// - `latency`: Network latency between the two DPUs.
    /// - `source_dpu_id`: The ID of source DPU.
    /// - `dest_dpu_id`: The ID of destination DPU.
    pub fn record_network_latency(
        &self,
        latency: Duration,
        source_dpu_id: MachineId,
        dest_dpu_id: MachineId,
    ) {
        let attributes = [
            KeyValue::new("source_dpu_id", source_dpu_id.to_string()),
            KeyValue::new("dest_dpu_id", dest_dpu_id.to_string()),
        ];
        self.network_latency
            .record(latency.as_secs_f64() * 1000.0, &attributes);
    }

    /// Record network loss percent out of total number of pings sent during one network check.
    ///
    /// # Parameters
    /// - `loss_percent`: Percentage of loss out of total pings sent.
    /// - `source_dpu_id`: The ID of source DPU.
    /// - `dest_dpu_id`: The ID of destination DPU.
    pub fn record_network_loss_percent(
        &self,
        loss_percent: f64,
        source_dpu_id: MachineId,
        dest_dpu_id: MachineId,
    ) {
        let attributes = [
            KeyValue::new("source_dpu_id", source_dpu_id.to_string()),
            KeyValue::new("dest_dpu_id", dest_dpu_id.to_string()),
        ];
        self.network_loss_percent.record(loss_percent, &attributes);
    }

    /// Overwrites the network reachable map with a new map.
    ///
    /// # Parameters
    /// - `new_reachable_map`: Records reachability between DPUs where the key is ID of destination DPU
    ///   and value is reachability as bool
    pub fn update_network_reachable_map(&self, new_reachable_map: HashMap<MachineId, bool>) {
        *self.network_reachable_map.lock().unwrap() = Some(new_reachable_map);
    }

    /// Records an error related to network communication with a DPU.
    ///
    /// # Parameters
    /// - `source_dpu_id`: The ID of this DPU, which starts the communication.
    /// - `dest_dpu_id`: The destination DPU id to which communication error happened.
    /// - `error_type`: A string describing the type of communication error.
    pub fn record_communication_error(
        &self,
        source_dpu_id: MachineId,
        dest_dpu_id: MachineId,
        error_type: String,
    ) {
        let attributes = [
            KeyValue::new("source_dpu_id", source_dpu_id.to_string()),
            KeyValue::new("dest_dpu_id", dest_dpu_id.to_string()),
            KeyValue::new("error_type", error_type),
        ];
        self.network_communication_error.add(1, &attributes);
    }

    /// Records an error related to network monitoring that is unrelated to connectivity.
    ///
    /// # Parameters
    /// - `machine_id`: The ID of this machine
    /// - `error_type`: A string describing the type of network monitor error.
    pub fn record_monitor_error(&self, machine_id: MachineId, error_type: String) {
        let attributes = [
            KeyValue::new("dpu_id", machine_id.to_string()),
            KeyValue::new("error_type", error_type),
        ];
        self.network_monitor_error.add(1, &attributes);
    }
}

pub fn get_metrics_router(registry: prometheus::Registry) -> Router {
    Router::new()
        .route("/", get(export_metrics))
        .with_state(registry)
}

#[axum::debug_handler]
async fn export_metrics(State(registry): State<prometheus::Registry>) -> Response<Full<Bytes>> {
    tokio::task::spawn_blocking(move || {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        Response::builder()
            .status(200)
            .header(CONTENT_TYPE, encoder.format_type())
            .header(CONTENT_LENGTH, buffer.len())
            .body(buffer.into())
            .unwrap()
    })
    .await
    .unwrap()
}
pub trait WithTracingLayer {
    fn with_tracing_layer(self, metrics: Arc<AgentMetricsState>) -> Router;
}

impl WithTracingLayer for Router {
    fn with_tracing_layer(self, metrics: Arc<AgentMetricsState>) -> Router {
        let metrics_copy = metrics.clone();
        let layer = tower_http::trace::TraceLayer::new_for_http()
            .on_request(move |request: &Request<AxumBody>, _span: &Span| {
                metrics.http_counter.add(1, &[]);
                tracing::info!("started {} {}", request.method(), request.uri().path())
            })
            .on_response(
                move |_response: &Response<AxumBody>, latency: Duration, _span: &Span| {
                    // TODO revisit time units
                    metrics_copy
                        .http_req_latency_histogram
                        .record(latency.as_secs_f64() * 1000.0, &[]);

                    tracing::info!("response generated in {:?}", latency)
                },
            );

        self.layer(ServiceBuilder::new().layer(layer))
    }
}
