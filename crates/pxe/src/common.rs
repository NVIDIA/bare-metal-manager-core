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
use std::net::IpAddr;

use axum_template::engine::Engine;
use metrics_exporter_prometheus::PrometheusHandle;
use rpc::forge::CloudInitInstructions;
use serde::{Deserialize, Serialize};
use tera::Tera;

use crate::config::RuntimeConfig;
use crate::extractors::machine_architecture;
// use crate::middleware::metrics::RequestMetrics;

#[derive(Debug)]
pub(crate) struct Machine {
    pub instructions: CloudInitInstructions,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MachineInterface {
    pub architecture: Option<machine_architecture::MachineArchitecture>,
    /// IP carbide-pxe observed for the booting machine: Does not support `X-Forwarded-For` for
    /// proxying, it is the real IP of the connecting client.
    pub client_ip: IpAddr,
    pub platform: Option<String>,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub asset: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct AppState {
    pub engine: Engine<Tera>,
    // pub request_metrics: RequestMetrics,
    pub runtime_config: RuntimeConfig,
    pub prometheus_handle: PrometheusHandle,
    /// The registry behind the global OTel meter, where the instrumentation
    /// framework's events record; `/metrics` renders it alongside the
    /// `metrics-exporter-prometheus` recorder above.
    pub otel_registry: prometheus::Registry,
}

/// An [`AppState`] for handler tests: an empty template engine, a local
/// (uninstalled) recorder, and a fresh OTel registry.
#[cfg(test)]
pub(crate) fn test_app_state() -> AppState {
    use metrics_exporter_prometheus::PrometheusBuilder;

    AppState {
        engine: Engine::from(Tera::default()),
        runtime_config: RuntimeConfig {
            internal_api_url: "https://carbide-api.forge-system.svc.cluster.local:1079".to_string(),
            client_facing_api_url: "https://carbide-api.forge".to_string(),
            pxe_url: "http://carbide-pxe.forge".to_string(),
            static_pxe_url: "http://carbide-pxe.forge".to_string(),
            forge_root_ca_path: String::new(),
            server_cert_path: String::new(),
            server_key_path: String::new(),
            bind_address: "0.0.0.0".parse().unwrap(),
            bind_port: 8080,
            template_directory: String::new(),
        },
        prometheus_handle: PrometheusBuilder::new().build_recorder().handle(),
        otel_registry: prometheus::Registry::new(),
    }
}
