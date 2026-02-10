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

use std::future::Future;
use std::pin::Pin;

use crate::HealthError;

mod composite;
mod console;
mod events;
mod health_override;
mod prometheus;

pub use composite::CompositeDataSink;
pub use console::ConsoleSink;
pub use events::{
    CollectorEvent, EventContext, FirmwareInfo, HealthOverride, LogRecord, MetricSample,
};
pub use health_override::HealthOverrideSink;
pub use prometheus::PrometheusSink;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait DataSink: Send + Sync {
    fn handle_event<'a>(
        &'a self,
        context: EventContext,
        event: CollectorEvent,
    ) -> BoxFuture<'a, Result<(), HealthError>>;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        BoxFuture, CollectorEvent, CompositeDataSink, DataSink, EventContext, LogRecord,
        MetricSample, PrometheusSink,
    };
    use crate::HealthError;
    use crate::metrics::MetricsManager;

    struct CountingSink {
        counter: Arc<AtomicUsize>,
        fail: bool,
    }

    impl DataSink for CountingSink {
        fn handle_event<'a>(
            &'a self,
            _context: EventContext,
            _event: CollectorEvent,
        ) -> BoxFuture<'a, Result<(), HealthError>> {
            Box::pin(async move {
                if self.fail {
                    return Err(HealthError::GenericError("forced failure".to_string()));
                }

                self.counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn test_composite_sink_fanout_and_error_isolation() {
        let success_counter = Arc::new(AtomicUsize::new(0));

        let sink_ok_1 = Arc::new(CountingSink {
            counter: success_counter.clone(),
            fail: false,
        });
        let sink_fail = Arc::new(CountingSink {
            counter: success_counter.clone(),
            fail: true,
        });
        let sink_ok_2 = Arc::new(CountingSink {
            counter: success_counter.clone(),
            fail: false,
        });

        let composite = CompositeDataSink::new(vec![sink_ok_1, sink_fail, sink_ok_2]);

        let context = EventContext {
            endpoint_key: "aa:bb:cc:dd".to_string(),
            endpoint_ip: "10.0.0.1".to_string(),
            endpoint_mac: "aa:bb:cc:dd".to_string(),
            collector_type: "test".to_string(),
            machine_id: None,
            switch_serial: None,
        };

        composite
            .handle_event(
                context,
                CollectorEvent::Metric(MetricSample {
                    key: "key".to_string(),
                    name: "metric".to_string(),
                    metric_type: "gauge".to_string(),
                    unit: "count".to_string(),
                    value: 1.0,
                    labels: Vec::new(),
                }),
            )
            .await
            .expect("composite sink should isolate downstream sink failures");

        assert_eq!(success_counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_prometheus_sink_only_records_metric_events() {
        let metrics_manager = Arc::new(MetricsManager::new());
        let sink = PrometheusSink::new(metrics_manager.clone(), "test_sink")
            .expect("sink should initialize");

        let context = EventContext {
            endpoint_key: "aa:bb:cc:dd".to_string(),
            endpoint_ip: "10.0.0.1".to_string(),
            endpoint_mac: "aa:bb:cc:dd".to_string(),
            collector_type: "test".to_string(),
            machine_id: Some("machine-1".to_string()),
            switch_serial: None,
        };

        sink.handle_event(
            context.clone(),
            CollectorEvent::Log(LogRecord {
                body: "ignored by prometheus sink".to_string(),
                severity: "INFO".to_string(),
                attributes: Vec::new(),
            }),
        )
        .await
        .expect("log event should not fail");

        let export_after_log = metrics_manager
            .export_all()
            .expect("metrics export should work");
        assert!(!export_after_log.contains("test_sink_hw_sensor"));

        sink.handle_event(
            context,
            CollectorEvent::Metric(MetricSample {
                key: "metric_key".to_string(),
                name: "hw_sensor".to_string(),
                metric_type: "temperature".to_string(),
                unit: "celsius".to_string(),
                value: 42.0,
                labels: vec![("sensor".to_string(), "temp1".to_string())],
            }),
        )
        .await
        .expect("metric event should be accepted");

        let export_after_metric = metrics_manager
            .export_all()
            .expect("metrics export should work");
        assert!(export_after_metric.contains("test_sink_hw_sensor_temperature_celsius"));
    }

    #[tokio::test]
    async fn test_prometheus_sink_sweeps_stale_metrics_per_collection_window() {
        let metrics_manager = Arc::new(MetricsManager::new());
        let sink = PrometheusSink::new(metrics_manager.clone(), "test_sink")
            .expect("sink should initialize");

        let context = EventContext {
            endpoint_key: "aa:bb:cc:dd".to_string(),
            endpoint_ip: "10.0.0.1".to_string(),
            endpoint_mac: "aa:bb:cc:dd".to_string(),
            collector_type: "sensor_collector".to_string(),
            machine_id: Some("machine-1".to_string()),
            switch_serial: None,
        };

        sink.handle_event(context.clone(), CollectorEvent::MetricCollectionStart)
            .await
            .expect("start should succeed");
        sink.handle_event(
            context.clone(),
            CollectorEvent::Metric(MetricSample {
                key: "s1".to_string(),
                name: "hw_sensor".to_string(),
                metric_type: "temperature".to_string(),
                unit: "celsius".to_string(),
                value: 10.0,
                labels: vec![("sensor".to_string(), "temp1".to_string())],
            }),
        )
        .await
        .expect("metric event should be accepted");
        sink.handle_event(context.clone(), CollectorEvent::MetricCollectionEnd)
            .await
            .expect("end should succeed");

        let first_export = metrics_manager
            .export_all()
            .expect("metrics export should work");
        assert!(first_export.contains("sensor=\"temp1\""));

        sink.handle_event(context.clone(), CollectorEvent::MetricCollectionStart)
            .await
            .expect("start should succeed");
        sink.handle_event(
            context.clone(),
            CollectorEvent::Metric(MetricSample {
                key: "s2".to_string(),
                name: "hw_sensor".to_string(),
                metric_type: "temperature".to_string(),
                unit: "celsius".to_string(),
                value: 20.0,
                labels: vec![("sensor".to_string(), "temp2".to_string())],
            }),
        )
        .await
        .expect("metric event should be accepted");
        sink.handle_event(context, CollectorEvent::MetricCollectionEnd)
            .await
            .expect("end should succeed");

        let second_export = metrics_manager
            .export_all()
            .expect("metrics export should work");
        assert!(!second_export.contains("sensor=\"temp1\""));
        assert!(second_export.contains("sensor=\"temp2\""));
    }
}
