use std::{any::Any, sync::Arc};

use opentelemetry_api::metrics::{ObservableGauge, Observer};

pub struct DpuNicFirmwareUpdateMetrics {
    pub pending_firmware_updates: usize,
    pub unavailable_dpu_updates: usize,
    pub running_dpu_updates: usize,

    pub pending_firmware_updates_gauge: ObservableGauge<u64>,
    pub unavailable_dpu_updates_gauge: ObservableGauge<u64>,
    pub running_dpu_updates_guage: ObservableGauge<u64>,
}

impl DpuNicFirmwareUpdateMetrics {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        DpuNicFirmwareUpdateMetrics {
            pending_firmware_updates: 0,
            pending_firmware_updates_gauge: meter
                .u64_observable_gauge("forge_pending_dpu_nic_firmware_update_count")
                .with_description(
                    "The number of machines in the system that need a firmware update.",
                )
                .init(),

                unavailable_dpu_updates: 0,
                unavailable_dpu_updates_gauge: meter
                .u64_observable_gauge("forge_unavailable_dpu_nic_firmware_update_count")
                .with_description(
                    "The number of machines in the system that need a firmware update but are unavailble for update.",
                )
                .init(),

                running_dpu_updates: 0,
                running_dpu_updates_guage:
                meter
                .u64_observable_gauge("forge_running_dpu_updates_count")
                .with_description(
                    "The number of machines in the system that running a firmware update.",
                )
                .init(),        }
    }

    pub fn instruments(&self) -> Vec<Arc<dyn Any>> {
        vec![
            self.pending_firmware_updates_gauge.as_any(),
            self.unavailable_dpu_updates_gauge.as_any(),
            self.running_dpu_updates_guage.as_any(),
        ]
    }

    pub fn observe(&mut self, observer: &dyn Observer) {
        observer.observe_u64(
            &self.pending_firmware_updates_gauge,
            self.pending_firmware_updates as u64,
            &[],
        );
        observer.observe_u64(
            &self.unavailable_dpu_updates_gauge,
            self.unavailable_dpu_updates as u64,
            &[],
        );
        observer.observe_u64(
            &self.running_dpu_updates_guage,
            self.running_dpu_updates as u64,
            &[],
        );
    }
}
