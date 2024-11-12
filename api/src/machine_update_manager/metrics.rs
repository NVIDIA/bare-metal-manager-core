use opentelemetry::metrics::Meter;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct MachineUpdateManagerMetrics {
    pub machines_in_maintenance: Arc<AtomicU64>,
    pub machine_updates_started: Arc<AtomicU64>,
}

impl MachineUpdateManagerMetrics {
    pub fn new() -> Self {
        MachineUpdateManagerMetrics {
            machines_in_maintenance: Arc::new(AtomicU64::new(0)),
            machine_updates_started: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn register_callbacks(&mut self, meter: &Meter) {
        let machines_in_maintenance = self.machines_in_maintenance.clone();
        let machine_updates_started = self.machine_updates_started.clone();
        meter
            .u64_observable_gauge("forge_machines_in_maintenance_count")
            .with_description("The total number of machines in the system that are in maintenance.")
            .with_callback(move |observer| {
                observer.observe(machines_in_maintenance.load(Ordering::Relaxed), &[])
            })
            .init();
        meter
            .u64_observable_gauge("forge_machine_updates_started_count")
            .with_description(
                "The number of machines in the system that in the process of updating.",
            )
            .with_callback(move |observer| {
                observer.observe(machine_updates_started.load(Ordering::Relaxed), &[])
            })
            .init();
    }
}
