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
            .u64_observable_gauge("forge_pending_dpu_nic_firmware_update_count")
            .with_description("The number of machines in the system that need a firmware update.")
            .with_callback(move |observer| {
                observer.observe(pending_firmware_updates.load(Relaxed), &[]);
            })
            .build();

        meter
            .u64_observable_gauge("forge_unavailable_dpu_nic_firmware_update_count")
            .with_description(
                "The number of machines in the system that need a firmware update but are unavailble for update.",
            )
            .with_callback(move |observer| {
                observer.observe(unavailable_dpu_updates.load(Relaxed), &[]);
            })
            .build();

        meter
            .u64_observable_gauge("forge_running_dpu_updates_count")
            .with_description(
                "The number of machines in the system that running a firmware update.",
            )
            .with_callback(move |observer| {
                observer.observe(running_dpu_updates.load(Relaxed), &[]);
            })
            .build();
    }
}
