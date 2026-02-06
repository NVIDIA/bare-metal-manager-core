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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use opentelemetry::metrics::Meter;

pub struct MachineUpdateManagerMetrics {
    pub machines_in_maintenance: Arc<AtomicU64>,
    pub machine_updates_started: Arc<AtomicU64>,
    pub concurrent_machine_updates_available: Arc<AtomicU64>,
}

impl MachineUpdateManagerMetrics {
    pub fn new() -> Self {
        MachineUpdateManagerMetrics {
            machines_in_maintenance: Arc::new(AtomicU64::new(0)),
            machine_updates_started: Arc::new(AtomicU64::new(0)),
            concurrent_machine_updates_available: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn register_callbacks(&mut self, meter: &Meter) {
        let machines_in_maintenance = self.machines_in_maintenance.clone();
        let machine_updates_started = self.machine_updates_started.clone();
        let concurrent_machine_updates_available =
            self.concurrent_machine_updates_available.clone();
        meter
            .u64_observable_gauge("carbide_machines_in_maintenance_count")
            .with_description("The total number of machines in the system that are in maintenance.")
            .with_callback(move |observer| {
                observer.observe(machines_in_maintenance.load(Ordering::Relaxed), &[])
            })
            .build();
        meter
            .u64_observable_gauge("carbide_machine_updates_started_count")
            .with_description(
                "The number of machines in the system that in the process of updating.",
            )
            .with_callback(move |observer| {
                observer.observe(machine_updates_started.load(Ordering::Relaxed), &[])
            })
            .build();
        meter
            .u64_observable_gauge("carbide_concurrent_machine_updates_available")
            .with_description(
                "The number of machines in the system that we will update concurrently.",
            )
            .with_callback(move |observer| {
                observer.observe(
                    concurrent_machine_updates_available.load(Ordering::Relaxed),
                    &[],
                )
            })
            .build();
    }
}
