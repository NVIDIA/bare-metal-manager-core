/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
