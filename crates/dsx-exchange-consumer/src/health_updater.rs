/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Health status updater that processes messages and updates the Carbide API.

use std::sync::Arc;

use health_report::{HealthAlertClassification, HealthProbeAlert, HealthReport};
use moka::future::Cache;
use moka::ops::compute::Op;
use opentelemetry::metrics::Meter;
use tokio::sync::mpsc;

use crate::ConsumerMetrics;
use crate::api_client::{HEALTH_REPORT_SOURCE, RackHealthReportSink};
use crate::config::CacheConfig;
use crate::messages::{FaultValue, LeakMetadata, LeakPointType, ValueMessage};
use crate::mqtt_consumer::MqttMessage;

/// Health status updater that processes MQTT messages and updates the API.
pub struct HealthUpdater<S: RackHealthReportSink> {
    topic_prefix: String,
    api: Arc<S>,
    metrics: ConsumerMetrics,
    metadata_cache: Cache<String, LeakMetadata>,
    value_state_cache: Cache<String, FaultValue>,
}

impl<S: RackHealthReportSink> HealthUpdater<S> {
    pub fn new(
        topic_prefix: String,
        cache_config: CacheConfig,
        api: Arc<S>,
        metrics: ConsumerMetrics,
        meter: Meter,
    ) -> Self {
        let metadata_cache: Cache<String, LeakMetadata> = Cache::builder()
            .time_to_live(cache_config.metadata_ttl)
            .build();

        let value_state_cache: Cache<String, FaultValue> = Cache::builder()
            .time_to_live(cache_config.value_state_ttl)
            .build();

        crate::metrics::register_metadata_cache_gauge(&meter, &metadata_cache);
        crate::metrics::register_value_state_cache_gauge(&meter, &value_state_cache);

        Self {
            topic_prefix,
            api,
            metrics,
            metadata_cache,
            value_state_cache,
        }
    }

    /// Run the health updater, processing messages from the receiver.
    pub async fn run(&self, mut rx: mpsc::Receiver<MqttMessage>) {
        tracing::info!("Health updater started");

        while let Some(msg) = rx.recv().await {
            match msg {
                MqttMessage::Metadata { topic, metadata } => {
                    self.handle_metadata_message(&topic, metadata).await;
                }
                MqttMessage::Value { topic, value } => {
                    self.handle_value_message(&topic, value).await;
                }
            }
        }

        tracing::info!("Health updater stopped");
    }

    async fn handle_metadata_message(&self, topic: &str, metadata: LeakMetadata) {
        if !metadata.is_supported_leak_type() {
            tracing::trace!(
                point_type = %metadata.point_type,
                "Ignoring unsupported point type"
            );
            return;
        }

        if let Some(point_path) = extract_point_path(topic, &self.topic_prefix) {
            tracing::debug!(
                point_path = %point_path,
                point_type = %metadata.point_type,
                rack_id = %metadata.rack_id,
                "Cached metadata"
            );
            self.metadata_cache
                .insert(point_path.to_string(), metadata)
                .await;
        }
    }

    async fn handle_value_message(&self, topic: &str, msg: ValueMessage) {
        let point_path = match extract_point_path(topic, &self.topic_prefix) {
            Some(path) => path,
            None => {
                tracing::warn!(topic = %topic, "Could not extract point path from topic");
                return;
            }
        };

        // Look up metadata
        let metadata = match self.metadata_cache.get(point_path).await {
            Some(m) => m,
            None => {
                tracing::debug!(
                    point_path = %point_path,
                    "No metadata found for point, skipping"
                );
                return;
            }
        };

        // Get the leak point type for this metadata
        let leak_type = match metadata.leak_point_type() {
            Some(t) => t,
            None => {
                tracing::warn!(
                    point_path = %point_path,
                    point_type = %metadata.point_type,
                    "Unsupported leak type in cached metadata"
                );
                return;
            }
        };

        let value = msg.value;
        let api = self.api.clone();
        let metrics = self.metrics.clone();

        // Use and_try_compute_with for atomic check-and-update with serialized access.
        // Concurrent calls on the same key are executed serially.
        let result = self
            .value_state_cache
            .entry_by_ref(point_path)
            .and_try_compute_with(|maybe_entry| {
                let metadata = metadata.clone();
                let api = api.clone();
                let metrics = metrics.clone();
                async move {
                    // Check for deduplication
                    if let Some(entry) = &maybe_entry
                        && *entry.value() == value
                    {
                        metrics.record_dedup_skipped();
                        tracing::trace!(
                            point_path = %point_path,
                            point_type = %metadata.point_type,
                            value = ?value,
                            "Deduplicating unchanged value"
                        );
                        return Ok(Op::Nop);
                    }

                    // Value differs or no entry - send API update
                    let send_result = if matches!(value, FaultValue::Faulting) {
                        metrics.record_alert_detected(&metadata.point_type);
                        tracing::info!(
                            point_path = %point_path,
                            rack_id = %metadata.rack_id,
                            rack_name = %metadata.rack_name,
                            point_type = %metadata.point_type,
                            value = ?value,
                            "Leak alert detected, inserting health override"
                        );

                        let report = build_leak_alert_report(&metadata, leak_type);
                        api.insert_rack_health_report(&metadata.rack_id, report)
                            .await
                    } else {
                        tracing::info!(
                            point_path = %point_path,
                            point_type = %metadata.point_type,
                            rack_id = %metadata.rack_id,
                            rack_name = %metadata.rack_name,
                            value = ?value,
                            "Leak cleared, removing health override"
                        );

                        api.remove_rack_health_report(&metadata.rack_id).await
                    };

                    match send_result {
                        Ok(_) => Ok(Op::Put(value)),
                        Err(e) => Err(e),
                    }
                }
            })
            .await;

        match result {
            Ok(_) => {
                self.metrics.record_message_processed();
            }
            Err(_) => {
                // API call failed - will retry on next message
            }
        }
    }
}

/// Build a health report for a leak alert.
fn build_leak_alert_report(metadata: &LeakMetadata, leak_type: LeakPointType) -> HealthReport {
    let alert = HealthProbeAlert {
        id: leak_type.probe_id(),
        target: Some(metadata.rack_id.clone()),
        in_alert_since: Some(chrono::Utc::now()),
        message: format!(
            "{} on rack {} ({})",
            leak_type.description(),
            metadata.rack_name,
            metadata.rack_id
        ),
        tenant_message: None,
        classifications: vec![
            HealthAlertClassification::prevent_allocations(),
            HealthAlertClassification::sensor_critical(),
            HealthAlertClassification::hardware(),
        ],
    };

    HealthReport {
        source: HEALTH_REPORT_SOURCE.to_string(),
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![alert],
    }
}

/// Extract the point path from a topic.
///
/// Topics are in the format: `{prefix}{pointPath}/Metadata` or `{prefix}{pointPath}/Value`
fn extract_point_path<'a>(topic: &'a str, prefix: &str) -> Option<&'a str> {
    topic
        .strip_suffix("/Metadata")
        .or_else(|| topic.strip_suffix("/Value"))
        .and_then(|s| s.strip_prefix(prefix))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use async_trait::async_trait;
    use chrono::Utc;
    use opentelemetry::global;

    use super::*;
    use crate::DsxConsumerError;

    const TEST_PREFIX: &str = "cronus/v1/";

    fn test_meter() -> Meter {
        global::meter("test")
    }

    fn test_cache_config() -> CacheConfig {
        CacheConfig {
            metadata_ttl: Duration::from_secs(3600),
            value_state_ttl: Duration::from_secs(3600),
        }
    }

    fn test_metrics() -> ConsumerMetrics {
        ConsumerMetrics::new(&test_meter())
    }

    fn test_metadata(point_type: &str, rack_id: &str) -> LeakMetadata {
        LeakMetadata {
            point_type: point_type.to_string(),
            object_type: "Rack".to_string(),
            rack_name: format!("Rack-{}", rack_id),
            rack_id: rack_id.to_string(),
        }
    }

    fn test_value_message(value: FaultValue) -> ValueMessage {
        ValueMessage {
            value,
            timestamp: Utc::now(),
        }
    }

    /// Mock sink that records all API calls for verification.
    #[derive(Default)]
    struct RecordingSink {
        inserts: Mutex<Vec<(String, HealthReport)>>,
        removes: Mutex<Vec<String>>,
    }

    impl RecordingSink {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn take_insert_calls(&self) -> Vec<(String, HealthReport)> {
            std::mem::take(&mut *self.inserts.lock().expect("lock poisoned"))
        }

        fn take_remove_calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.removes.lock().expect("lock poisoned"))
        }
    }

    #[async_trait]
    impl RackHealthReportSink for RecordingSink {
        async fn insert_rack_health_report(
            &self,
            rack_id: &str,
            report: HealthReport,
        ) -> Result<(), DsxConsumerError> {
            self.inserts
                .lock()
                .unwrap()
                .push((rack_id.to_string(), report));
            Ok(())
        }

        async fn remove_rack_health_report(&self, rack_id: &str) -> Result<(), DsxConsumerError> {
            self.removes.lock().unwrap().push(rack_id.to_string());
            Ok(())
        }
    }

    /// Mock sink that always fails.
    struct FailingSink;

    #[async_trait]
    impl RackHealthReportSink for FailingSink {
        async fn insert_rack_health_report(
            &self,
            _rack_id: &str,
            _report: HealthReport,
        ) -> Result<(), DsxConsumerError> {
            Err(DsxConsumerError::Api(tonic::Status::internal("test error")))
        }

        async fn remove_rack_health_report(&self, _rack_id: &str) -> Result<(), DsxConsumerError> {
            Err(DsxConsumerError::Api(tonic::Status::internal("test error")))
        }
    }

    #[test]
    fn test_extract_point_path_metadata() {
        let topic = "cronus/v1/some/point/path/Metadata";
        assert_eq!(
            extract_point_path(topic, TEST_PREFIX),
            Some("some/point/path")
        );
    }

    #[test]
    fn test_extract_point_path_value() {
        let topic = "cronus/v1/some/point/path/Value";
        assert_eq!(
            extract_point_path(topic, TEST_PREFIX),
            Some("some/point/path")
        );
    }

    #[test]
    fn test_extract_point_path_unknown() {
        let topic = "cronus/v1/some/point/path/Unknown";
        assert_eq!(extract_point_path(topic, TEST_PREFIX), None);
    }

    #[test]
    fn test_extract_point_path_custom_prefix() {
        let topic = "custom/prefix/some/point/path/Value";
        assert_eq!(
            extract_point_path(topic, "custom/prefix/"),
            Some("some/point/path")
        );
    }

    #[test]
    fn test_extract_point_path_wrong_prefix() {
        let topic = "cronus/v1/some/point/path/Value";
        assert_eq!(extract_point_path(topic, "wrong/prefix/"), None);
    }

    #[test]
    fn test_build_leak_alert_report_structure() {
        let metadata = test_metadata("LeakDetectRack", "rack-001");
        let report = build_leak_alert_report(&metadata, LeakPointType::LeakDetectRack);

        assert_eq!(report.source, HEALTH_REPORT_SOURCE);
        assert!(report.observed_at.is_some());
        assert!(report.successes.is_empty());
        assert_eq!(report.alerts.len(), 1);

        let alert = &report.alerts[0];
        assert_eq!(alert.id.as_str(), "BmsLeakDetectRack");
        assert_eq!(alert.target.as_deref(), Some("rack-001"));
        assert!(alert.message.contains("Leak detected"));
        assert!(alert.message.contains("Rack-rack-001"));

        let classification_strs: Vec<&str> =
            alert.classifications.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            classification_strs,
            vec!["PreventAllocations", "SensorCritical", "Hardware"]
        );
    }

    #[test]
    fn test_build_leak_alert_report_sensor_fault() {
        let metadata = test_metadata("LeakSensorFaultRack", "rack-002");
        let report = build_leak_alert_report(&metadata, LeakPointType::LeakSensorFaultRack);

        let alert = &report.alerts[0];
        assert_eq!(alert.id.as_str(), "BmsLeakSensorFaultRack");
        assert!(alert.message.contains("Leak sensor fault"));
    }

    #[test]
    fn test_build_leak_alert_report_rack_tray() {
        let metadata = test_metadata("LeakDetectRackTray", "rack-003");
        let report = build_leak_alert_report(&metadata, LeakPointType::LeakDetectRackTray);

        let alert = &report.alerts[0];
        assert_eq!(alert.id.as_str(), "BmsLeakDetectRackTray");
        assert!(alert.message.contains("Rack tray leak detected"));
    }

    #[tokio::test]
    async fn test_faulting_value_triggers_insert() {
        let sink = RecordingSink::new();
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            sink.clone(),
            test_metrics(),
            test_meter(),
        );

        // First, cache metadata
        let metadata = test_metadata("LeakDetectRack", "rack-001");
        updater
            .handle_metadata_message("cronus/v1/site/rack/point/Metadata", metadata)
            .await;

        // Now send a faulting value
        let value = test_value_message(FaultValue::Faulting);
        updater
            .handle_value_message("cronus/v1/site/rack/point/Value", value)
            .await;

        let inserts = sink.take_insert_calls();
        assert_eq!(inserts.len(), 1);
        assert_eq!(inserts[0].0, "rack-001");
        assert_eq!(inserts[0].1.alerts.len(), 1);

        let removes = sink.take_remove_calls();
        assert!(removes.is_empty());
    }

    #[tokio::test]
    async fn test_clear_value_triggers_remove() {
        let sink = RecordingSink::new();
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            sink.clone(),
            test_metrics(),
            test_meter(),
        );

        // Cache metadata
        let metadata = test_metadata("LeakDetectRack", "rack-001");
        updater
            .handle_metadata_message("cronus/v1/site/rack/point/Metadata", metadata)
            .await;

        // Send a clear value
        let value = test_value_message(FaultValue::Clear);
        updater
            .handle_value_message("cronus/v1/site/rack/point/Value", value)
            .await;

        let removes = sink.take_remove_calls();
        assert_eq!(removes.len(), 1);
        assert_eq!(removes[0], "rack-001");

        let inserts = sink.take_insert_calls();
        assert!(inserts.is_empty());
    }

    #[tokio::test]
    async fn test_value_without_metadata_is_skipped() {
        let sink = RecordingSink::new();
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            sink.clone(),
            test_metrics(),
            test_meter(),
        );

        // Send value without caching metadata first
        let value = test_value_message(FaultValue::Faulting);
        updater
            .handle_value_message("cronus/v1/site/rack/point/Value", value)
            .await;

        // No API calls should be made
        assert_eq!(sink.take_insert_calls().len(), 0);
        assert_eq!(sink.take_remove_calls().len(), 0);
    }

    #[tokio::test]
    async fn test_unsupported_point_type_metadata_not_cached() {
        let sink = RecordingSink::new();
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            sink.clone(),
            test_metrics(),
            test_meter(),
        );

        // Cache unsupported metadata
        let metadata = test_metadata("UnsupportedType", "rack-001");
        updater
            .handle_metadata_message("cronus/v1/site/rack/point/Metadata", metadata)
            .await;

        // Send value - should be skipped because metadata wasn't cached
        let value = test_value_message(FaultValue::Faulting);
        updater
            .handle_value_message("cronus/v1/site/rack/point/Value", value)
            .await;

        assert_eq!(sink.take_insert_calls().len(), 0);
    }

    #[tokio::test]
    async fn test_deduplication_same_value_skipped() {
        let sink = RecordingSink::new();
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            sink.clone(),
            test_metrics(),
            test_meter(),
        );

        // Cache metadata
        let metadata = test_metadata("LeakDetectRack", "rack-001");
        updater
            .handle_metadata_message("cronus/v1/site/rack/point/Metadata", metadata)
            .await;

        // Send faulting value twice
        let value1 = test_value_message(FaultValue::Faulting);
        updater
            .handle_value_message("cronus/v1/site/rack/point/Value", value1)
            .await;

        let value2 = test_value_message(FaultValue::Faulting);
        updater
            .handle_value_message("cronus/v1/site/rack/point/Value", value2)
            .await;

        // Only one insert should have been made
        assert_eq!(sink.take_insert_calls().len(), 1);
    }

    #[tokio::test]
    async fn test_value_change_not_deduplicated() {
        let sink = RecordingSink::new();
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            sink.clone(),
            test_metrics(),
            test_meter(),
        );

        // Cache metadata
        let metadata = test_metadata("LeakDetectRack", "rack-001");
        updater
            .handle_metadata_message("cronus/v1/site/rack/point/Metadata", metadata)
            .await;

        // Send faulting, then clear, then faulting again
        updater
            .handle_value_message(
                "cronus/v1/site/rack/point/Value",
                test_value_message(FaultValue::Faulting),
            )
            .await;
        updater
            .handle_value_message(
                "cronus/v1/site/rack/point/Value",
                test_value_message(FaultValue::Clear),
            )
            .await;
        updater
            .handle_value_message(
                "cronus/v1/site/rack/point/Value",
                test_value_message(FaultValue::Faulting),
            )
            .await;

        // Should have 2 inserts and 1 remove
        assert_eq!(sink.take_insert_calls().len(), 2);
        assert_eq!(sink.take_remove_calls().len(), 1);
    }

    #[tokio::test]
    async fn test_api_failure_does_not_cache_state() {
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            Arc::new(FailingSink),
            test_metrics(),
            test_meter(),
        );

        // Cache metadata
        let metadata = test_metadata("LeakDetectRack", "rack-001");
        updater
            .handle_metadata_message("cronus/v1/site/rack/point/Metadata", metadata)
            .await;

        // Send value - will fail
        updater
            .handle_value_message(
                "cronus/v1/site/rack/point/Value",
                test_value_message(FaultValue::Faulting),
            )
            .await;

        // Value state should not be cached, so next call should retry
        assert!(
            updater
                .value_state_cache
                .get("site/rack/point")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_multiple_racks_independent() {
        let sink = RecordingSink::new();
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            sink.clone(),
            test_metrics(),
            test_meter(),
        );

        // Cache metadata for two racks
        updater
            .handle_metadata_message(
                "cronus/v1/site/rack1/point/Metadata",
                test_metadata("LeakDetectRack", "rack-001"),
            )
            .await;
        updater
            .handle_metadata_message(
                "cronus/v1/site/rack2/point/Metadata",
                test_metadata("LeakDetectRack", "rack-002"),
            )
            .await;

        // Send faulting to rack1
        updater
            .handle_value_message(
                "cronus/v1/site/rack1/point/Value",
                test_value_message(FaultValue::Faulting),
            )
            .await;

        // Send faulting to rack2
        updater
            .handle_value_message(
                "cronus/v1/site/rack2/point/Value",
                test_value_message(FaultValue::Faulting),
            )
            .await;

        // Both should have triggered inserts
        let inserts = sink.take_insert_calls();
        assert_eq!(inserts.len(), 2);

        let rack_ids: Vec<_> = inserts.iter().map(|(id, _)| id.as_str()).collect();
        assert!(rack_ids.contains(&"rack-001"));
        assert!(rack_ids.contains(&"rack-002"));
    }

    #[tokio::test]
    async fn test_run_processes_messages_until_channel_closed() {
        let sink = RecordingSink::new();
        let updater = HealthUpdater::new(
            TEST_PREFIX.to_string(),
            test_cache_config(),
            sink.clone(),
            test_metrics(),
            test_meter(),
        );

        let (tx, rx) = mpsc::channel(16);

        // Send metadata
        tx.send(MqttMessage::Metadata {
            topic: "cronus/v1/site/rack/point/Metadata".to_string(),
            metadata: test_metadata("LeakDetectRack", "rack-001"),
        })
        .await
        .unwrap();

        // Send value
        tx.send(MqttMessage::Value {
            topic: "cronus/v1/site/rack/point/Value".to_string(),
            value: test_value_message(FaultValue::Faulting),
        })
        .await
        .unwrap();

        // Close channel
        drop(tx);

        // Run updater - should process both messages and exit
        updater.run(rx).await;

        assert_eq!(sink.take_insert_calls().len(), 1);
    }
}
