/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use axum_template::engine::Engine;
use carbide_uuid::machine::MachineInterfaceId;
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
    pub interface_id: MachineInterfaceId,
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
