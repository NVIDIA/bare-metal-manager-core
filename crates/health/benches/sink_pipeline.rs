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

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;

use carbide_health::endpoint::{BmcAddr, EndpointMetadata, MachineData};
use carbide_health::metrics::MetricsManager;
use carbide_health::sink::{
    CollectorEvent, CompositeDataSink, DataSink, EventContext, HealthOverride, HealthOverrideSink,
    MetricSample, PrometheusSink,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use health_report::{HealthProbeAlert, HealthReport};
use mac_address::MacAddress;

const MACHINE_ID: &str = "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0";

struct CountingSink;

impl DataSink for CountingSink {
    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        std::hint::black_box(context);
        std::hint::black_box(event);
    }
}

fn event_context() -> EventContext {
    EventContext {
        endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
        addr: BmcAddr {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: Some(443),
            mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").unwrap(),
        },
        collector_type: "sensor_collector",
        metadata: Some(EndpointMetadata::Machine(MachineData {
            machine_id: MACHINE_ID.parse().expect("valid machine id"),
            machine_serial: None,
        })),
    }
}

fn metric_events(batch_size: usize, unique_keys: usize) -> Vec<CollectorEvent> {
    let unique_keys = unique_keys.max(1);

    (0..batch_size)
        .map(|idx| {
            let sensor_idx = idx % unique_keys;
            let key = format!("sensor-{sensor_idx}");

            CollectorEvent::Metric(MetricSample {
                key: key.clone(),
                name: "hw_sensor".to_string(),
                metric_type: "temperature".to_string(),
                unit: "celsius".to_string(),
                value: (idx % 100) as f64,
                labels: vec![(Cow::Borrowed("sensor"), key)],
            })
        })
        .collect()
}

fn emit_metric_batch(sink: &dyn DataSink, context: &EventContext, events: &[CollectorEvent]) {
    let start = CollectorEvent::MetricCollectionStart;
    sink.handle_event(context, &start);
    for event in events {
        sink.handle_event(context, event);
    }
    let end = CollectorEvent::MetricCollectionEnd;
    sink.handle_event(context, &end);
}

fn bench_prometheus_sink(c: &mut Criterion) {
    let mut group = c.benchmark_group("sink_prometheus");
    let batch_size = 2_000usize;
    group.throughput(Throughput::Elements(batch_size as u64));

    for (scenario, unique_keys) in [("low_cardinality", 32usize), ("high_cardinality", 2_000)] {
        let metrics_manager = Arc::new(MetricsManager::new());
        let sink = PrometheusSink::new(metrics_manager, "bench_sink")
            .expect("prometheus sink should initialize");
        let context = event_context();
        let events = metric_events(batch_size, unique_keys);

        group.bench_with_input(
            BenchmarkId::new("emit_batch", scenario),
            &events,
            |b, events| {
                b.iter(|| emit_metric_batch(&sink, &context, events));
            },
        );
    }

    group.finish();
}

struct CompositeBenchState {
    sink: CompositeDataSink,
    context: EventContext,
    events: Vec<CollectorEvent>,
}

impl CompositeBenchState {
    fn new(sink_count: usize, batch_size: usize) -> Self {
        let mut sinks: Vec<Arc<dyn DataSink>> = Vec::with_capacity(sink_count);
        for _ in 0..sink_count {
            sinks.push(Arc::new(CountingSink));
        }

        let sink = CompositeDataSink::new(sinks);

        Self {
            sink,
            context: event_context(),
            events: metric_events(batch_size, 64),
        }
    }
}

fn bench_composite_sink(c: &mut Criterion) {
    let mut group = c.benchmark_group("sink_composite");
    let batch_size = 2_000usize;

    for sink_count in [2usize, 4usize] {
        let state = CompositeBenchState::new(sink_count, batch_size);
        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("emit_only", sink_count),
            &state,
            |b, state| {
                b.iter(|| emit_metric_batch(&state.sink, &state.context, &state.events));
            },
        );
    }

    group.finish();
}

fn health_report_with_alerts(alert_count: usize) -> HealthReport {
    let mut report = HealthReport::empty("bench-health-override".to_string());
    for idx in 0..alert_count {
        report.alerts.push(HealthProbeAlert::heartbeat_timeout(
            format!("target-{idx}"),
            format!("alert message #{idx}"),
        ));
    }
    report
}

struct HealthOverrideBenchState {
    _runtime: tokio::runtime::Runtime,
    sink: HealthOverrideSink,
    context: EventContext,
    small_event: CollectorEvent,
    large_event: CollectorEvent,
}

impl HealthOverrideBenchState {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime should build");

        let sink = {
            let _guard = runtime.enter();
            HealthOverrideSink::new_for_bench().expect("bench sink should initialize")
        };
        let context = event_context();
        let machine_id = MACHINE_ID.parse().expect("valid machine id");

        let small_event = CollectorEvent::HealthOverride(HealthOverride {
            machine_id: Some(machine_id),
            report: Arc::new(health_report_with_alerts(1)),
        });
        let large_event = CollectorEvent::HealthOverride(HealthOverride {
            machine_id: Some(machine_id),
            report: Arc::new(health_report_with_alerts(64)),
        });

        Self {
            _runtime: runtime,
            sink,
            context,
            small_event,
            large_event,
        }
    }
}

fn bench_health_override_sink(c: &mut Criterion) {
    let mut group = c.benchmark_group("sink_health_override");
    let batch_size = 20_000usize;
    group.throughput(Throughput::Elements(batch_size as u64));

    let state = HealthOverrideBenchState::new();

    group.bench_with_input(
        BenchmarkId::new("enqueue", "small_report"),
        &state,
        |b, state| {
            b.iter(|| {
                for _ in 0..batch_size {
                    state.sink.handle_event(&state.context, &state.small_event);
                }
            });
        },
    );

    group.bench_with_input(
        BenchmarkId::new("enqueue", "large_report"),
        &state,
        |b, state| {
            b.iter(|| {
                for _ in 0..batch_size {
                    state.sink.handle_event(&state.context, &state.large_event);
                }
            });
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_prometheus_sink,
    bench_composite_sink,
    bench_health_override_sink
);
criterion_main!(benches);
