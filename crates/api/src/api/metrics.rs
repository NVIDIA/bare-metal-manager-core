/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use model::machine::MachineLastRebootRequestedMode;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Histogram, Meter};
use opentelemetry_sdk::metrics::{Aggregation, Instrument, InstrumentKind, Stream, View};

/// Metric name for machine restart time histogram
pub const MACHINE_RESTART_TIME_METRIC_NAME: &str = "forge_machine_restart_time_seconds";

/// Holds all metrics related to the API service
pub struct ApiMetrics {
    pub machine_restart_time_histogram: Histogram<u64>,
}

impl ApiMetrics {
    /// Creates a new ApiMetrics instance with all metrics initialized
    pub fn new(meter: &Meter) -> Self {
        let machine_restart_time_histogram = meter
            .u64_histogram(MACHINE_RESTART_TIME_METRIC_NAME)
            .with_description("Time taken for machine/host to restart in seconds")
            .with_unit("s")
            .build();

        Self {
            machine_restart_time_histogram,
        }
    }

    /// Creates histogram bucket configuration for machine restart time
    ///
    /// Machine restarts typically take 5-20 minutes (300-1200 seconds).
    /// Buckets are optimized for this range with additional buckets for faster/slower restarts.
    ///
    /// Boundaries in seconds: 1min, 2min, 3min, 5min, 7min, 10min, 15min, 20min, 30min, 45min, 60min
    pub fn machine_restart_time_view()
    -> Result<Box<dyn View>, opentelemetry_sdk::metrics::MetricError> {
        let mut criteria = Instrument::new().name(MACHINE_RESTART_TIME_METRIC_NAME.to_string());
        criteria.kind = Some(InstrumentKind::Histogram);
        let mask = Stream::new().aggregation(Aggregation::ExplicitBucketHistogram {
            boundaries: vec![
                60.0, 120.0, 180.0, 300.0, 420.0, 600.0, 900.0, 1200.0, 1800.0, 2700.0, 3600.0,
            ],
            record_min_max: true,
        });
        opentelemetry_sdk::metrics::new_view(criteria, mask)
    }

    /// Records the machine restart time metric with product information
    pub fn record_restart_time_metric(&self, machine: &model::machine::Machine) {
        let Some(last_reboot_requested) = &machine.last_reboot_requested else {
            return;
        };

        // Skip recording metrics for PowerOff requests
        if matches!(
            last_reboot_requested.mode,
            MachineLastRebootRequestedMode::PowerOff
        ) {
            return;
        }

        let restart_duration_secs = (chrono::Utc::now() - last_reboot_requested.time).num_seconds();

        // Only record positive durations (in case of clock skew)
        if restart_duration_secs <= 0 {
            return;
        }

        // Extract product serial and name from hardware info
        let product_serial = machine
            .hardware_info
            .as_ref()
            .and_then(|hi| hi.dmi_data.as_ref())
            .map(|dmi| dmi.product_serial.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let product_name = machine
            .hardware_info
            .as_ref()
            .and_then(|hi| hi.dmi_data.as_ref())
            .map(|dmi| dmi.product_name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        // Record histogram with product serial, name, and request mode as attributes
        let attributes = [
            KeyValue::new("product_serial", product_serial),
            KeyValue::new("product_name", product_name),
            KeyValue::new("reboot_mode", last_reboot_requested.mode.to_string()),
        ];

        self.machine_restart_time_histogram
            .record(restart_duration_secs as u64, &attributes);
    }
}
