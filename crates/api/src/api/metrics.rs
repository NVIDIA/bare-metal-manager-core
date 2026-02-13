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

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Histogram, Meter};
use opentelemetry_sdk::metrics::{Aggregation, Instrument, InstrumentKind, Stream, View};

/// Metric name for machine reboot duration histogram
const MACHINE_REBOOT_DURATION_METRIC_NAME: &str = "carbide_machine_reboot_duration";

/// Holds all metrics related to the API service
pub struct ApiMetricsEmitter {
    machine_reboot_duration_histogram: Histogram<u64>,
}

impl ApiMetricsEmitter {
    pub fn new(meter: &Meter) -> Self {
        let machine_reboot_duration_histogram = meter
            .u64_histogram(MACHINE_REBOOT_DURATION_METRIC_NAME)
            .with_description("Time taken for machine/host to reboot in seconds")
            .with_unit("s")
            .build();

        Self {
            machine_reboot_duration_histogram,
        }
    }

    /// Creates histogram bucket configuration for machine reboot duration
    ///
    /// Machine reboots typically take 5-20 minutes (300-1200 seconds).
    /// Buckets are optimized for this range with additional buckets for faster/slower reboots.
    ///
    /// Boundaries in seconds: 3min, 5min, 10min, 15min, 30min, 60min
    pub fn machine_reboot_duration_view()
    -> Result<Box<dyn View>, opentelemetry_sdk::metrics::MetricError> {
        let mut criteria = Instrument::new().name(MACHINE_REBOOT_DURATION_METRIC_NAME.to_string());
        criteria.kind = Some(InstrumentKind::Histogram);
        let mask = Stream::new().aggregation(Aggregation::ExplicitBucketHistogram {
            boundaries: vec![180.0, 300.0, 600.0, 900.0, 1800.0, 3600.0],
            record_min_max: true,
        });
        opentelemetry_sdk::metrics::new_view(criteria, mask)
    }

    /// Records machine reboot duration with product information
    pub fn record_machine_reboot_duration(
        &self,
        duration_secs: u64,
        product_name: String,
        vendor: String,
        reboot_mode: String,
    ) {
        let attributes = [
            KeyValue::new("product_name", product_name),
            KeyValue::new("vendor", vendor),
            KeyValue::new("reboot_mode", reboot_mode),
        ];

        self.machine_reboot_duration_histogram
            .record(duration_secs, &attributes);
    }
}
