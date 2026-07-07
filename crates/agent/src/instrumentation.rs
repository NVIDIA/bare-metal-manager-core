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

    // Every sample this agent records is for the same source DPU, so the
    // label sets are rendered once here instead of once per recorded sample.
    source_attributes: [KeyValue; 1],
    dpu_id_attribute: KeyValue,

    // Reachability results from the latest network check, the input for the
    // reachable/unreachable peer-count gauges.
    network_reachable_map: NetworkReachableMap,
}

type NetworkReachableMap = Arc<Mutex<Option<HashMap<MachineId, bool>>>>;

impl NetworkMonitorMetricsState {
    pub fn initialize(meter: Meter, machine_id: MachineId) -> Arc<Self> {
        let network_reachable_map = NetworkReachableMap::default();
        let machine_id_label = machine_id.to_string();
        let source_attributes = [KeyValue::new("source_dpu_id", machine_id_label.clone())];
        let dpu_id_attribute = KeyValue::new("dpu_id", machine_id_label);

        // Peer reachability is exported as two per-source counts rather than
        // one 0/1 series per (source, dest) pair: every agent probes every
        // other DPU, so per-pair series multiply into O(N^2) fleet-wide
        // cardinality. Per-peer detail is logged on reachability transitions
        // instead (see `update_network_reachable_map`).
        {
            let network_reachable_map = network_reachable_map.clone();
            let attributes = source_attributes.clone();
            meter
                .u64_observable_gauge("forge_dpu_agent_network_reachable_peers_count")
                .with_description(
                    "Number of peer DPUs this DPU could reach in its latest network check",
                )
                .with_callback(move |observer| {
                    let network_reachable_map = network_reachable_map.lock().unwrap();
                    if let Some(map) = network_reachable_map.as_ref() {
                        let reachable_peers =
                            map.values().filter(|reachable| **reachable).count() as u64;
                        observer.observe(reachable_peers, &attributes);
                    }
                })
                .build();
        }
        {
            let network_reachable_map = network_reachable_map.clone();
            let attributes = source_attributes.clone();
            meter
                .u64_observable_gauge("forge_dpu_agent_network_unreachable_peers_count")
                .with_description(
                    "Number of peer DPUs this DPU could not reach in its latest network check",
                )
                .with_callback(move |observer| {
                    let network_reachable_map = network_reachable_map.lock().unwrap();
                    if let Some(map) = network_reachable_map.as_ref() {
                        let unreachable_peers =
                            map.values().filter(|reachable| !**reachable).count() as u64;
                        observer.observe(unreachable_peers, &attributes);
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
            source_attributes,
            dpu_id_attribute,
            network_reachable_map,
        })
    }

    /// Records one peer probe's network latency in milliseconds.
    ///
    /// The sample lands in this DPU's single per-source histogram, which
    /// aggregates the latency distribution across all probed peers.
    pub fn record_network_latency(&self, latency: Duration) {
        self.network_latency
            .record(latency.as_secs_f64() * 1000.0, &self.source_attributes);
    }

    /// Records one peer probe's loss percentage out of the total number of
    /// pings sent during one network check.
    ///
    /// The sample lands in this DPU's single per-source histogram, which
    /// aggregates the loss distribution across all probed peers.
    pub fn record_network_loss_percent(&self, loss_percent: f64) {
        self.network_loss_percent
            .record(loss_percent, &self.source_attributes);
    }

    /// Replaces the reachability results of the latest network check.
    ///
    /// Peers whose reachability changed since the previous check are logged
    /// here, so per-peer detail stays available in the logs while the
    /// exported metrics stay per-source counts.
    ///
    /// # Parameters
    /// - `new_reachable_map`: Reachability keyed by the ID of the probed peer
    ///   DPU, with reachability as the bool value
    pub fn update_network_reachable_map(&self, new_reachable_map: HashMap<MachineId, bool>) {
        let mut network_reachable_map = self.network_reachable_map.lock().unwrap();
        log_peer_reachability_transitions(network_reachable_map.as_ref(), &new_reachable_map);
        *network_reachable_map = Some(new_reachable_map);
    }

    /// Records an error related to network communication with a peer DPU.
    ///
    /// # Parameters
    /// - `error_type`: A string describing the type of communication error.
    pub fn record_communication_error(&self, error_type: String) {
        let attributes = [
            self.source_attributes[0].clone(),
            KeyValue::new("error_type", error_type),
        ];
        self.network_communication_error.add(1, &attributes);
    }

    /// Records an error related to network monitoring that is unrelated to connectivity.
    ///
    /// # Parameters
    /// - `error_type`: A string describing the type of network monitor error.
    pub fn record_monitor_error(&self, error_type: String) {
        let attributes = [
            self.dpu_id_attribute.clone(),
            KeyValue::new("error_type", error_type),
        ];
        self.network_monitor_error.add(1, &attributes);
    }
}

/// Logs every peer whose reachability changed between the previous network
/// check and the current one. Steady-state results (a peer that stayed
/// reachable or stayed unreachable, or a newly discovered reachable peer) are
/// not logged, so a stable fleet produces no output here.
fn log_peer_reachability_transitions(
    previous: Option<&HashMap<MachineId, bool>>,
    current: &HashMap<MachineId, bool>,
) {
    for (peer_dpu_id, reachable) in current {
        let previously_reachable = previous.and_then(|map| map.get(peer_dpu_id)).copied();
        match (previously_reachable, *reachable) {
            (Some(true), false) => {
                tracing::warn!(%peer_dpu_id, "Peer DPU became unreachable");
            }
            (Some(false), true) => {
                tracing::info!(%peer_dpu_id, "Peer DPU became reachable");
            }
            (None, false) => {
                tracing::warn!(%peer_dpu_id, "Peer DPU is unreachable at its first network check");
            }
            _ => {}
        }
    }

    if let Some(previous) = previous {
        for peer_dpu_id in previous.keys() {
            if !current.contains_key(peer_dpu_id) {
                tracing::debug!(%peer_dpu_id, "Peer DPU is no longer in the monitored set");
            }
        }
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
