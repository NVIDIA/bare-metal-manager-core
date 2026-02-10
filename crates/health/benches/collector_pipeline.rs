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

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use carbide_health::endpoint::{BmcAddr, EndpointMetadata, MachineData};
use carbide_health::metrics::MetricsManager;
use carbide_health::sink::{
    CollectorEvent, CompositeDataSink, DataSink, EventContext, FirmwareInfo, LogRecord,
    MetricSample, PrometheusSink,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

const MACHINE_ID: &str = "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0";

struct CountingSink {
    counter: Arc<AtomicU64>,
}

impl DataSink for CountingSink {
    fn handle_event(
        &self,
        _context: &EventContext,
        _event: &CollectorEvent,
    ) -> Result<(), carbide_health::HealthError> {
        self.counter.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn event_context() -> EventContext {
    EventContext {
        addr: BmcAddr {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: Some(443),
            mac: "aa:bb:cc:dd".to_string(),
        },
        collector_type: "sensor_collector",
        metadata: Some(EndpointMetadata::Machine(MachineData {
            machine_id: MACHINE_ID.parse().expect("valid machine id"),
            machine_serial: None,
        })),
    }
}

fn build_sensor_metric_event(idx: usize, unique_keys: usize) -> CollectorEvent {
    let unique_keys = unique_keys.max(1);
    let sensor_idx = idx % unique_keys;
    let sensor_key = format!("sensor-{sensor_idx}");
    let machine_idx = idx % 16;
    let rack_idx = idx % 4;

    CollectorEvent::Metric(MetricSample {
        key: sensor_key.clone(),
        name: "hw_sensor".to_string(),
        metric_type: "temperature".to_string(),
        unit: "celsius".to_string(),
        value: 25.0 + ((idx % 40) as f64),
        labels: vec![
            ("sensor_name".to_string(), sensor_key),
            ("physical_context".to_string(), "cpu".to_string()),
            ("model".to_string(), "x86-test".to_string()),
            ("machine_slot".to_string(), format!("slot-{machine_idx}")),
            ("rack".to_string(), format!("rack-{rack_idx}")),
        ],
    })
}

fn build_nmxt_metric_event(idx: usize) -> CollectorEvent {
    CollectorEvent::Metric(MetricSample {
        key: format!("effective_ber:{}", idx % 64),
        name: "switch_nmxt".to_string(),
        metric_type: "effective_ber".to_string(),
        unit: "count".to_string(),
        value: (idx % 10) as f64,
        labels: vec![
            ("switch_id".to_string(), "switch-1".to_string()),
            ("switch_ip".to_string(), "10.0.1.1".to_string()),
            ("node_guid".to_string(), format!("0x{:x}", idx)),
            ("port_num".to_string(), (idx % 64).to_string()),
        ],
    })
}

fn build_log_event(idx: usize) -> CollectorEvent {
    CollectorEvent::Log(LogRecord {
        body: format!("BMC event line {idx}"),
        severity: "INFO".to_string(),
        attributes: vec![
            ("machine_id".to_string(), MACHINE_ID.to_string()),
            ("entry_id".to_string(), idx.to_string()),
            ("service_id".to_string(), "logservice-1".to_string()),
        ],
    })
}

fn build_firmware_event(idx: usize) -> CollectorEvent {
    let component = format!("component-{idx}");
    CollectorEvent::Firmware(FirmwareInfo {
        component: component.clone(),
        version: format!("1.0.{}", idx % 100),
        attributes: vec![
            ("firmware_name".to_string(), component),
            ("version".to_string(), format!("1.0.{}", idx % 100)),
        ],
    })
}

fn bench_collector_event_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("collector_event_build");
    let sample_count = 10_000usize;
    group.throughput(Throughput::Elements(sample_count as u64));

    group.bench_function("sensor_metric", |b| {
        b.iter(|| {
            for idx in 0..sample_count {
                black_box(build_sensor_metric_event(idx, 256));
            }
        });
    });

    group.bench_function("nmxt_metric", |b| {
        b.iter(|| {
            for idx in 0..sample_count {
                black_box(build_nmxt_metric_event(idx));
            }
        });
    });

    group.bench_function("log_event", |b| {
        b.iter(|| {
            for idx in 0..sample_count {
                black_box(build_log_event(idx));
            }
        });
    });

    group.bench_function("firmware_event", |b| {
        b.iter(|| {
            for idx in 0..sample_count {
                black_box(build_firmware_event(idx));
            }
        });
    });

    group.finish();
}

fn emit_metric_batch_building(
    sink: &dyn DataSink,
    context: &EventContext,
    batch_size: usize,
    unique_keys: usize,
) {
    let start = CollectorEvent::MetricCollectionStart;
    sink.handle_event(context, &start)
        .expect("start event should succeed");

    for idx in 0..batch_size {
        let event = build_sensor_metric_event(idx, unique_keys);
        sink.handle_event(context, &event)
            .expect("metric event should succeed");
    }

    let end = CollectorEvent::MetricCollectionEnd;
    sink.handle_event(context, &end)
        .expect("end event should succeed");
}

fn bench_collector_build_and_emit_prometheus(c: &mut Criterion) {
    let mut group = c.benchmark_group("collector_build_emit_prometheus");
    let batch_size = 2_000usize;
    group.throughput(Throughput::Elements(batch_size as u64));

    for (scenario, unique_keys) in [("low_cardinality", 64usize), ("high_cardinality", 2_000)] {
        let metrics_manager = Arc::new(MetricsManager::new());
        let sink = PrometheusSink::new(metrics_manager, "bench_collector")
            .expect("prometheus sink should initialize");
        let context = event_context();

        group.bench_with_input(
            BenchmarkId::new("sensor_build_and_emit", scenario),
            &unique_keys,
            |b, unique_keys| {
                b.iter(|| emit_metric_batch_building(&sink, &context, batch_size, *unique_keys));
            },
        );
    }

    group.finish();
}

struct CompositeBuildEmitState {
    _runtime: tokio::runtime::Runtime,
    sink: CompositeDataSink,
    context: EventContext,
    counters: Vec<Arc<AtomicU64>>,
}

impl CompositeBuildEmitState {
    fn new(sink_count: usize) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime should build");

        let mut sinks: Vec<Arc<dyn DataSink>> = Vec::with_capacity(sink_count);
        let mut counters = Vec::with_capacity(sink_count);
        for _ in 0..sink_count {
            let counter = Arc::new(AtomicU64::new(0));
            counters.push(counter.clone());
            sinks.push(Arc::new(CountingSink { counter }));
        }

        let sink = {
            let _guard = runtime.enter();
            CompositeDataSink::new(sinks)
        };

        Self {
            _runtime: runtime,
            sink,
            context: event_context(),
            counters,
        }
    }

    fn total_processed(&self) -> u64 {
        self.counters
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum()
    }

    fn wait_until_processed(&self, expected_total: u64) {
        let timeout_at = Instant::now() + Duration::from_secs(5);
        while self.total_processed() < expected_total {
            assert!(
                Instant::now() < timeout_at,
                "timed out waiting for composite sink workers to drain"
            );
            std::thread::yield_now();
        }
    }
}

fn bench_collector_build_and_emit_composite(c: &mut Criterion) {
    let mut group = c.benchmark_group("collector_build_emit_composite");
    let batch_size = 2_000usize;
    group.throughput(Throughput::Elements(batch_size as u64));

    for sink_count in [2usize, 4usize] {
        let state = CompositeBuildEmitState::new(sink_count);
        group.bench_with_input(
            BenchmarkId::new("sensor_build_emit_and_drain", sink_count),
            &state,
            |b, state| {
                let events_per_sink = (batch_size + 2) as u64;
                let sinks = state.counters.len() as u64;

                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let before = state.total_processed();
                        let expected = before + (events_per_sink * sinks);
                        let start = Instant::now();
                        emit_metric_batch_building(&state.sink, &state.context, batch_size, 64);
                        state.wait_until_processed(expected);
                        total += start.elapsed();
                    }
                    total
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_collector_event_build,
    bench_collector_build_and_emit_prometheus,
    bench_collector_build_and_emit_composite
);
criterion_main!(benches);
