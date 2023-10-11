use std::{any::Any, sync::Arc};

use opentelemetry_api::metrics::{Meter, ObservableGauge, Observer};

pub struct MachineUpdateManagerMetrics {
    pub machines_in_maintenance: usize,
    pub machine_updates_started: usize,
    pub instruments: MachineUpdateManagerMetricsInstruments,
}

impl MachineUpdateManagerMetrics {
    pub fn new(meter: &Meter) -> Self {
        MachineUpdateManagerMetrics {
            machines_in_maintenance: 0,
            machine_updates_started: 0,
            instruments: MachineUpdateManagerMetricsInstruments::new(meter),
        }
    }

    pub fn observe(&self, observer: &dyn Observer) {
        observer.observe_u64(
            &self.instruments.machines_in_maintenance,
            self.machines_in_maintenance as u64,
            &[],
        );
        observer.observe_u64(
            &self.instruments.machine_updates_started,
            self.machine_updates_started as u64,
            &[],
        );
    }

    pub fn instruments(&self) -> Vec<Arc<dyn Any>> {
        vec![
            self.instruments.machines_in_maintenance.as_any(),
            self.instruments.machine_updates_started.as_any(),
        ]
    }
}

pub struct MachineUpdateManagerMetricsInstruments {
    pub machines_in_maintenance: ObservableGauge<u64>,
    pub machine_updates_started: ObservableGauge<u64>,
}

impl MachineUpdateManagerMetricsInstruments {
    pub fn new(meter: &Meter) -> Self {
        MachineUpdateManagerMetricsInstruments {
            machines_in_maintenance: meter
                .u64_observable_gauge("forge_machines_in_maintenance")
                .with_description(
                    "The total number of machines in the system that are in maintenance.",
                )
                .init(),
            machine_updates_started: meter
                .u64_observable_gauge("forge_machine_updates_started")
                .with_description(
                    "The number of machines in the system that in the process of updating.",
                )
                .init(),
        }
    }
}
