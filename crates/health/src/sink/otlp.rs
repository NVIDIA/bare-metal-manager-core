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

use std::sync::Arc;

use prometheus::Counter;

use super::event_mapper::RedfishEventMapper;
use super::override_queue::OverrideQueue;
use super::{CollectorEvent, DataSink, EventContext, SensorHealthData};
use crate::HealthError;
use crate::config::OtlpSinkConfig;
use crate::metrics::MetricsManager;
use crate::otlp::drain::OtlpDrainTask;
use crate::otlp::metrics_drain::OtlpMetricsDrainTask;

pub(crate) type OtlpQueue = OverrideQueue<String, (EventContext, CollectorEvent)>;
pub(crate) type OtlpMetricsQueue = OverrideQueue<String, (EventContext, SensorHealthData)>;

#[cfg(not(feature = "bench-hooks"))]
pub(crate) struct OtlpSink {
    queue: Arc<OtlpQueue>,
    metrics_queue: Arc<OtlpMetricsQueue>,
    replaced_total: Counter,
    metrics_replaced_total: Counter,
    mapper: Arc<dyn RedfishEventMapper>,
}

#[cfg(feature = "bench-hooks")]
pub struct OtlpSink {
    queue: Arc<OtlpQueue>,
    metrics_queue: Arc<OtlpMetricsQueue>,
    replaced_total: Counter,
    metrics_replaced_total: Counter,
    mapper: Arc<dyn RedfishEventMapper>,
}

/// true for events that belong in the logs drain; metrics and collection sentinels are not.
pub(crate) fn is_otlp_log_relevant(event: &CollectorEvent) -> bool {
    !matches!(
        event,
        CollectorEvent::Metric(_)
            | CollectorEvent::MetricCollectionStart
            | CollectorEvent::MetricCollectionEnd
    )
}

impl OtlpSink {
    pub fn new(
        config: &OtlpSinkConfig,
        mapper: Arc<dyn RedfishEventMapper>,
        metrics_manager: &MetricsManager,
        prefix: &str,
    ) -> Result<Self, HealthError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|e| {
            HealthError::GenericError(format!("otlp sink requires active tokio runtime: {e}"))
        })?;

        let queue: Arc<OtlpQueue> = Arc::new(OverrideQueue::new());
        let metrics_queue: Arc<OtlpMetricsQueue> = Arc::new(OverrideQueue::new());

        let replaced_total = Counter::new(
            format!("{prefix}_otlp_sink_replaced_total"),
            "total log events replaced in the otlp queue before drain could process them",
        )?;
        metrics_manager
            .global_registry()
            .register(Box::new(replaced_total.clone()))?;

        let metrics_replaced_total = Counter::new(
            format!("{prefix}_otlp_sink_metrics_replaced_total"),
            "total metric samples replaced in the otlp queue before drain could process them",
        )?;
        metrics_manager
            .global_registry()
            .register(Box::new(metrics_replaced_total.clone()))?;

        let drain = OtlpDrainTask::new(
            queue.clone(),
            config.endpoint.clone(),
            config.batch_size,
            config.flush_interval,
        );
        handle.spawn(drain.run());

        // separate drain task so metrics don't head-of-line-block the logs export and vice versa
        let metrics_drain = OtlpMetricsDrainTask::new(
            metrics_queue.clone(),
            config.endpoint.clone(),
            config.batch_size,
            config.flush_interval,
        );
        handle.spawn(metrics_drain.run());

        Ok(Self {
            queue,
            metrics_queue,
            replaced_total,
            metrics_replaced_total,
            mapper,
        })
    }
}

#[cfg(any(test, feature = "bench-hooks"))]
impl OtlpSink {
    pub fn new_for_bench(mapper: Arc<dyn RedfishEventMapper>) -> Self {
        Self {
            queue: Arc::new(OverrideQueue::new()),
            metrics_queue: Arc::new(OverrideQueue::new()),
            replaced_total: Counter::new("bench_replaced", "bench").unwrap(),
            metrics_replaced_total: Counter::new("bench_metrics_replaced", "bench").unwrap(),
            mapper,
        }
    }
}

#[cfg(feature = "bench-hooks")]
impl OtlpSink {
    pub fn pop_for_bench(&self) -> Option<(EventContext, CollectorEvent)> {
        self.queue.pop().map(|(_key, value)| value)
    }

    pub fn pop_metric_for_bench(&self) -> Option<(EventContext, SensorHealthData)> {
        self.metrics_queue.pop().map(|(_key, value)| value)
    }
}

impl DataSink for OtlpSink {
    fn sink_type(&self) -> &'static str {
        "otlp_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        if let CollectorEvent::Metric(sample) = event {
            let key = format!("{}|{}", context.endpoint_key, sample.key);
            if self
                .metrics_queue
                .save_latest(key, (context.clone(), (**sample).clone()))
            {
                self.metrics_replaced_total.inc();
            }
            return;
        }

        if !is_otlp_log_relevant(event) {
            return;
        }

        let key = match event {
            CollectorEvent::Log(record) => self
                .mapper
                .queue_key(&context.endpoint_key, &record.attributes),
            CollectorEvent::HealthReport(report) => {
                format!(
                    "{}|health_report|{}",
                    context.endpoint_key,
                    report.source.as_str()
                )
            }
            CollectorEvent::Firmware(info) => {
                format!("{}|firmware|{}", context.endpoint_key, info.component)
            }
            _ => return,
        };

        if self
            .queue
            .save_latest(key, (context.clone(), event.clone()))
        {
            self.replaced_total.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::str::FromStr;
    use std::sync::Arc;

    use mac_address::MacAddress;

    use super::*;
    use crate::sink::event_mapper::OpenBmcEventMapper;
    use crate::sink::{LogRecord, SensorHealthData};

    fn test_context() -> EventContext {
        EventContext {
            endpoint_key: "10.85.14.144".to_string(),
            addr: crate::endpoint::BmcAddr {
                ip: "10.85.14.144".parse().unwrap(),
                port: Some(443),
                mac: MacAddress::from_str("aa:bb:cc:dd:ee:ff").unwrap(),
            },
            collector_type: "test",
            metadata: None,
            rack_id: None,
        }
    }

    fn log_event(message_id: &str, message_args: &str) -> CollectorEvent {
        CollectorEvent::Log(Box::new(LogRecord {
            body: "test".to_string(),
            severity: "OK".to_string(),
            attributes: vec![
                (Cow::Borrowed("message_id"), message_id.to_string()),
                (Cow::Borrowed("message_args"), message_args.to_string()),
            ],
        }))
    }

    fn metric_event() -> CollectorEvent {
        CollectorEvent::Metric(Box::new(SensorHealthData {
            key: "k".to_string(),
            name: "temp".to_string(),
            metric_type: "gauge".to_string(),
            unit: "celsius".to_string(),
            value: 42.0,
            labels: vec![(Cow::Borrowed("sensor"), "temp1".to_string())],
            context: None,
        }))
    }

    fn test_sink() -> OtlpSink {
        OtlpSink::new_for_bench(Arc::new(OpenBmcEventMapper))
    }

    #[test]
    fn is_otlp_log_relevant_excludes_metric_events() {
        assert!(!is_otlp_log_relevant(&metric_event()));
        assert!(!is_otlp_log_relevant(
            &CollectorEvent::MetricCollectionStart
        ));
        assert!(!is_otlp_log_relevant(&CollectorEvent::MetricCollectionEnd));
    }

    #[test]
    fn is_otlp_log_relevant_includes_log_events() {
        assert!(is_otlp_log_relevant(&log_event("OpenBMC.0.1.Test", "[]")));
    }

    #[test]
    fn metric_events_go_to_metrics_queue_not_logs_queue() {
        let sink = test_sink();
        let ctx = test_context();
        sink.handle_event(&ctx, &metric_event());
        assert!(sink.queue.pop().is_none(), "logs queue should be empty");
        assert!(
            sink.metrics_queue.pop().is_some(),
            "metrics queue should have the sample"
        );
    }

    #[test]
    fn metric_collection_sentinels_are_no_op() {
        let sink = test_sink();
        let ctx = test_context();
        sink.handle_event(&ctx, &CollectorEvent::MetricCollectionStart);
        sink.handle_event(&ctx, &CollectorEvent::MetricCollectionEnd);
        assert!(sink.queue.pop().is_none());
        assert!(sink.metrics_queue.pop().is_none());
    }

    #[test]
    fn metric_events_dedup_by_sample_key() {
        let sink = test_sink();
        let ctx = test_context();
        sink.handle_event(&ctx, &metric_event());
        sink.handle_event(&ctx, &metric_event());
        let mut count = 0;
        while sink.metrics_queue.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 1, "same key should dedup to one entry");
        assert_eq!(sink.metrics_replaced_total.get() as u64, 1);
    }

    #[test]
    fn log_events_are_queued() {
        let sink = test_sink();
        let ctx = test_context();
        sink.handle_event(&ctx, &log_event("OpenBMC.0.1.Test", r#"["sensor1"]"#));
        assert!(sink.queue.pop().is_some());
    }

    #[test]
    fn same_sensor_different_direction_deduplicates() {
        let sink = test_sink();
        let ctx = test_context();

        sink.handle_event(
            &ctx,
            &log_event(
                "OpenBMC.0.1.SensorThresholdWarningLowGoingHigh",
                r#"["HGX_GPU_0_Temp_1","3.96","-0.05"]"#,
            ),
        );
        sink.handle_event(
            &ctx,
            &log_event(
                "OpenBMC.0.1.SensorThresholdWarningHighGoingLow",
                r#"["HGX_GPU_0_Temp_1","3.96","-0.05"]"#,
            ),
        );

        let mut count = 0;
        while sink.queue.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 1, "same sensor should dedup to one entry");
    }

    #[test]
    fn replaced_counter_increments_on_dedup() {
        let sink = test_sink();
        let ctx = test_context();

        sink.handle_event(
            &ctx,
            &log_event(
                "OpenBMC.0.1.SensorThresholdWarningLowGoingHigh",
                r#"["HGX_GPU_0_Temp_1","3.96","-0.05"]"#,
            ),
        );
        assert_eq!(sink.replaced_total.get() as u64, 0);

        sink.handle_event(
            &ctx,
            &log_event(
                "OpenBMC.0.1.SensorThresholdWarningHighGoingLow",
                r#"["HGX_GPU_0_Temp_1","3.96","-0.05"]"#,
            ),
        );
        assert_eq!(sink.replaced_total.get() as u64, 1);
    }

    #[test]
    fn different_sensors_are_separate_entries() {
        let sink = test_sink();
        let ctx = test_context();

        sink.handle_event(
            &ctx,
            &log_event(
                "OpenBMC.0.1.SensorThresholdWarningLowGoingHigh",
                r#"["HGX_GPU_0_Temp_1","3.96","-0.05"]"#,
            ),
        );
        sink.handle_event(
            &ctx,
            &log_event(
                "OpenBMC.0.1.SensorThresholdWarningLowGoingHigh",
                r#"["HGX_GPU_1_Temp_1","3.96","-0.05"]"#,
            ),
        );

        let mut count = 0;
        while sink.queue.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }
}
