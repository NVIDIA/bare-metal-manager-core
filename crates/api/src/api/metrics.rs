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
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry_sdk::metrics::{Aggregation, Instrument, InstrumentKind, Stream, View};

/// Metric name for machine reboot duration histogram
const MACHINE_REBOOT_DURATION_METRIC_NAME: &str = "carbide_machine_reboot_duration";
const STATIC_IP_MANAGEMENT_FAILURES_METRIC_NAME: &str = "carbide_static_ip_management_failures";

/// Holds all metrics related to the API service
pub struct ApiMetricsEmitter {
    machine_reboot_duration_histogram: Histogram<u64>,
    static_ip_management_failures_counter: Counter<u64>,
}

impl ApiMetricsEmitter {
    pub fn new(meter: &Meter) -> Self {
        let machine_reboot_duration_histogram = meter
            .u64_histogram(MACHINE_REBOOT_DURATION_METRIC_NAME)
            .with_description("Time taken for machine/host to reboot in seconds")
            .with_unit("s")
            .build();

        let static_ip_management_failures_counter = meter
            .u64_counter(STATIC_IP_MANAGEMENT_FAILURES_METRIC_NAME)
            .with_description(
                "Total number of failures while managing static IP reservations and assignments",
            )
            .build();

        Self {
            machine_reboot_duration_histogram,
            static_ip_management_failures_counter,
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

    /// Records a failure in static IP reservation/assignment management.
    pub fn record_static_ip_management_failure(
        &self,
        operation: &'static str,
        reason: &'static str,
    ) {
        self.static_ip_management_failures_counter.add(
            1,
            &[
                KeyValue::new("operation", operation),
                KeyValue::new("reason", reason),
            ],
        );
    }
}
