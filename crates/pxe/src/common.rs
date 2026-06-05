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
    /// IP carbide-pxe observed for the booting machine: `X-Forwarded-For`
    /// when fronted by a proxy that injects it, TCP socket peer otherwise.
    /// Forwarded to carbide-api which resolves it via `find_by_ip` to
    /// fetch the machine_interface_id.
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
}
