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
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;

use opentelemetry::metrics::Meter;

pub struct DpuNicFirmwareUpdateMetrics {
    pub pending_firmware_updates: Arc<AtomicU64>,
    pub unavailable_dpu_updates: Arc<AtomicU64>,
    pub running_dpu_updates: Arc<AtomicU64>,
}

impl Default for DpuNicFirmwareUpdateMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DpuNicFirmwareUpdateMetrics {
    pub fn new() -> Self {
        DpuNicFirmwareUpdateMetrics {
            pending_firmware_updates: Arc::new(AtomicU64::new(0)),
            unavailable_dpu_updates: Arc::new(AtomicU64::new(0)),
            running_dpu_updates: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn register_callbacks(&mut self, meter: &Meter) {
        let pending_firmware_updates = self.pending_firmware_updates.clone();
        let unavailable_dpu_updates = self.unavailable_dpu_updates.clone();
        let running_dpu_updates = self.running_dpu_updates.clone();
        meter
            .u64_observable_gauge("carbide_pending_dpu_nic_firmware_update_count")
            .with_description("The number of machines in the system that need a firmware update.")
            .with_callback(move |observer| {
                observer.observe(pending_firmware_updates.load(Relaxed), &[]);
            })
            .build();

        meter
            .u64_observable_gauge("carbide_unavailable_dpu_nic_firmware_update_count")
            .with_description(
                "The number of machines in the system that need a firmware update but are unavailble for update.",
            )
            .with_callback(move |observer| {
                observer.observe(unavailable_dpu_updates.load(Relaxed), &[]);
            })
            .build();

        meter
            .u64_observable_gauge("carbide_running_dpu_updates_count")
            .with_description(
                "The number of machines in the system that running a firmware update.",
            )
            .with_callback(move |observer| {
                observer.observe(running_dpu_updates.load(Relaxed), &[]);
            })
            .build();
    }
}
