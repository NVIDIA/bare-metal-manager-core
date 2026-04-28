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

mod composite;
mod dedup_queue;
#[cfg(not(feature = "bench-hooks"))]
pub(crate) mod event_mapper;
#[cfg(feature = "bench-hooks")]
pub mod event_mapper;
mod events;
mod health_report;
mod log_file;
pub(crate) mod otlp;
mod prometheus;
mod rack_health_report;
mod tracing;

pub use composite::CompositeDataSink;
pub use events::{
    Classification, CollectorEvent, EventContext, FirmwareInfo, HealthReport, HealthReportAlert,
    HealthReportSuccess, LogRecord, Probe, ReportSource, SensorHealthContext, SensorHealthData,
};
pub use health_report::HealthReportSink;
pub use log_file::LogFileSink;
pub use prometheus::PrometheusSink;
pub use rack_health_report::RackHealthReportSink;
pub use tracing::TracingSink;

#[cfg(not(feature = "bench-hooks"))]
pub(crate) use self::otlp::OtlpSink;
#[cfg(feature = "bench-hooks")]
pub use self::otlp::OtlpSink;

pub trait DataSink: Send + Sync {
    fn sink_type(&self) -> &'static str;
    fn handle_event(&self, context: &EventContext, event: &CollectorEvent);
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mac_address::MacAddress;

    use super::{
        CollectorEvent, CompositeDataSink, DataSink, EventContext, LogRecord, PrometheusSink,
        SensorHealthData,
    };
    use crate::endpoint::{BmcAddr, EndpointMetadata, MachineData};
    use crate::metrics::MetricsManager;

    struct CountingSink {
        counter: Arc<AtomicUsize>,
    }

    impl DataSink for CountingSink {
        fn sink_type(&self) -> &'static str {
            "counting_sink"
        }

        fn handle_event(&self, _context: &EventContext, _event: &CollectorEvent) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct NoopSink;

    impl DataSink for NoopSink {
        fn sink_type(&self) -> &'static str {
            "noop_sink"
        }

        fn handle_event(&self, _context: &EventContext, _event: &CollectorEvent) {}
    }

    #[tokio::test]
    async fn test_composite_sink_fanout_with_noop_sink() {
        let success_counter = Arc::new(AtomicUsize::new(0));
        let metrics_manager =
            Arc::new(MetricsManager::new("test").expect("should create metrics manager"));

        let sink_ok_1 = Arc::new(CountingSink {
            counter: success_counter.clone(),
        });
        let sink_noop = Arc::new(NoopSink);
        let sink_ok_2 = Arc::new(CountingSink {
            counter: success_counter.clone(),
        });

        let composite =
            CompositeDataSink::new(vec![sink_ok_1, sink_noop, sink_ok_2], metrics_manager);

        let context = EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: "10.0.0.1".parse().expect("valid ip"),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").unwrap(),
            },
            collector_type: "test",
            metadata: None,
            rack_id: None,
        };

        let event = CollectorEvent::Metric(
            SensorHealthData {
                key: "key".to_string(),
                name: "metric".to_string(),
                metric_type: "gauge".to_string(),
                unit: "count".to_string(),
                value: 1.0,
                labels: Vec::new(),
                context: None,
            }
            .into(),
        );
        composite.handle_event(&context, &event);

        assert_eq!(success_counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_prometheus_sink_only_records_metric_events() {
        let metrics_manager =
            Arc::new(MetricsManager::new("test").expect("should create metrics manager"));
        let sink = PrometheusSink::new(metrics_manager.clone(), "test_sink")
            .expect("sink should initialize");

        let context = EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: "10.0.0.1".parse().expect("valid ip"),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").unwrap(),
            },
            collector_type: "test",
            metadata: Some(EndpointMetadata::Machine(MachineData {
                machine_id: "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0"
                    .parse()
                    .expect("valid machine id"),
                machine_serial: None,
            })),
            rack_id: None,
        };

        let log_event = CollectorEvent::Log(
            LogRecord {
                body: "ignored by prometheus sink".to_string(),
                severity: "INFO".to_string(),
                attributes: Vec::new(),
            }
            .into(),
        );
        sink.handle_event(&context, &log_event);

        let export_after_log = metrics_manager
            .export_all()
            .expect("metrics export should work");
        assert!(!export_after_log.contains("test_sink_hw_sensor"));

        let metric_event = CollectorEvent::Metric(
            SensorHealthData {
                key: "metric_key".to_string(),
                name: "hw_sensor".to_string(),
                metric_type: "temperature".to_string(),
                unit: "celsius".to_string(),
                value: 42.0,
                labels: vec![(Cow::Borrowed("sensor"), "temp1".to_string())],
                context: None,
            }
            .into(),
        );

        sink.handle_event(&context, &metric_event);

        let export_after_metric = metrics_manager
            .export_all()
            .expect("metrics export should work");
        assert!(export_after_metric.contains("test_sink_hw_sensor_temperature_celsius"));
    }

    #[tokio::test]
    async fn test_prometheus_sink_sweeps_stale_metrics_per_collection_window() {
        let metrics_manager =
            Arc::new(MetricsManager::new("test").expect("should create metrics manager"));
        let sink = PrometheusSink::new(metrics_manager.clone(), "test_sink")
            .expect("sink should initialize");

        let context = EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: "10.0.0.1".parse().expect("valid ip"),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").unwrap(),
            },
            collector_type: "sensor_collector",
            metadata: Some(EndpointMetadata::Machine(MachineData {
                machine_id: "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0"
                    .parse()
                    .expect("valid machine id"),
                machine_serial: None,
            })),
            rack_id: None,
        };

        let start_event = CollectorEvent::MetricCollectionStart;
        sink.handle_event(&context, &start_event);
        let s1_event = CollectorEvent::Metric(
            SensorHealthData {
                key: "s1".to_string(),
                name: "hw_sensor".to_string(),
                metric_type: "temperature".to_string(),
                unit: "celsius".to_string(),
                value: 10.0,
                labels: vec![(Cow::Borrowed("sensor"), "temp1".to_string())],
                context: None,
            }
            .into(),
        );
        sink.handle_event(&context, &s1_event);
        let end_event = CollectorEvent::MetricCollectionEnd;
        sink.handle_event(&context, &end_event);

        let first_export = metrics_manager
            .export_all()
            .expect("metrics export should work");
        assert!(first_export.contains("sensor=\"temp1\""));

        let start_event = CollectorEvent::MetricCollectionStart;
        sink.handle_event(&context, &start_event);
        let s2_event = CollectorEvent::Metric(
            SensorHealthData {
                key: "s2".to_string(),
                name: "hw_sensor".to_string(),
                metric_type: "temperature".to_string(),
                unit: "celsius".to_string(),
                value: 20.0,
                labels: vec![(Cow::Borrowed("sensor"), "temp2".to_string())],
                context: None,
            }
            .into(),
        );
        sink.handle_event(&context, &s2_event);
        let end_event = CollectorEvent::MetricCollectionEnd;
        sink.handle_event(&context, &end_event);

        let second_export = metrics_manager
            .export_all()
            .expect("metrics export should work");
        assert!(!second_export.contains("sensor=\"temp1\""));
        assert!(second_export.contains("sensor=\"temp2\""));
    }
}
