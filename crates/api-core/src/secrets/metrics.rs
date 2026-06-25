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

use std::time::Instant;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter};

/// Request, outcome, and duration instruments for the Postgres secrets
/// backend, under `carbide-api.secrets.*` with an `operation` label
/// (get/set/create/delete).
#[derive(Clone)]
pub struct SecretsMetrics {
    requests: Counter<u64>,
    successes: Counter<u64>,
    failures: Counter<u64>,
    duration: Histogram<u64>,
}

impl SecretsMetrics {
    /// Create the instruments from an OpenTelemetry meter.
    pub fn new(meter: &Meter) -> Self {
        Self {
            requests: meter
                .u64_counter("carbide-api.secrets.requests")
                .with_description("Total number of Postgres secrets operations attempted.")
                .build(),
            successes: meter
                .u64_counter("carbide-api.secrets.requests.succeeded")
                .with_description("Number of Postgres secrets operations that succeeded.")
                .build(),
            failures: meter
                .u64_counter("carbide-api.secrets.requests.failed")
                .with_description("Number of Postgres secrets operations that failed.")
                .build(),
            duration: meter
                .u64_histogram("carbide-api.secrets.request_duration")
                .with_description("Duration of Postgres secrets operations, in milliseconds.")
                .with_unit("ms")
                .build(),
        }
    }
}

/// Times one secrets operation and records its outcome exactly once: call
/// [`OperationTimer::succeed`] on the success path, and any other way out
/// of scope -- early `?` returns included -- records a failure on drop. No
/// instruments are touched when metrics are disabled.
pub struct OperationTimer {
    metrics: Option<SecretsMetrics>,
    operation: &'static str,
    started: Instant,
    completed: bool,
}

impl OperationTimer {
    /// Start timing an operation, counting the request immediately. Pass
    /// None to make every recording call a no-op.
    pub fn start(metrics: Option<SecretsMetrics>, operation: &'static str) -> Self {
        if let Some(m) = &metrics {
            m.requests.add(1, &[KeyValue::new("operation", operation)]);
        }
        Self {
            metrics,
            operation,
            started: Instant::now(),
            completed: false,
        }
    }

    /// Record a successful operation and its duration.
    pub fn succeed(mut self) {
        self.completed = true;
        if let Some(m) = &self.metrics {
            let elapsed = self.started.elapsed().as_millis() as u64;
            let attrs = [KeyValue::new("operation", self.operation)];
            m.successes.add(1, &attrs);
            m.duration.record(elapsed, &attrs);
        }
    }
}

impl Drop for OperationTimer {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Some(m) = &self.metrics {
            let elapsed = self.started.elapsed().as_millis() as u64;
            let attrs = [KeyValue::new("operation", self.operation)];
            m.failures.add(1, &attrs);
            m.duration.record(elapsed, &attrs);
        }
    }
}
