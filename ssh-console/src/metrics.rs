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

use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;

pub struct MetricsState {
    pub meter: Meter,
    pub registry: prometheus::Registry,
    _meter_provider: SdkMeterProvider,
}

impl Default for MetricsState {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsState {
    pub fn new() -> Self {
        let registry = prometheus::Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .without_scope_info()
            .without_target_info()
            .build()
            .expect("BUG: could not build default metrics state");
        let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(exporter)
            .build();
        let meter = meter_provider.meter("ssh-console");

        Self {
            meter,
            registry,
            _meter_provider: meter_provider,
        }
    }
}
