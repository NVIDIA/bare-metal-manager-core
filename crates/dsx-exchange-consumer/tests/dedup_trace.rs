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

//! Proves the reshape left the dedup site's log line byte-identical: converting
//! the counter to a metric-only event kept the `tracing::trace!` beside it, so
//! the dedup branch still emits exactly one "Deduplicating unchanged value"
//! line at TRACE with its original fields.
//!
//! Its own test binary on purpose: `tracing` caches callsite interest the first
//! time a callsite is hit, so a `capture_logs` (thread-local) subscriber only
//! sees the trace when nothing else raced to that callsite first. Alone in this
//! process, the drive below is that first hit.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use carbide_dsx_exchange_consumer::api_client::RackHealthReportSink;
use carbide_dsx_exchange_consumer::config::CacheConfig;
use carbide_dsx_exchange_consumer::health_updater::HealthUpdater;
use carbide_dsx_exchange_consumer::messages::{FaultValue, LeakMetadata, ValueMessage};
use carbide_dsx_exchange_consumer::mqtt_consumer::MqttMessage;
use carbide_dsx_exchange_consumer::{ConsumerMetrics, DsxConsumerError};
use carbide_instrument::testing::capture_logs;
use health_report::HealthReport;
use tokio::sync::mpsc;

/// Accepts every report so the first value caches and the identical second one
/// takes the dedup branch.
struct OkSink;

#[async_trait]
impl RackHealthReportSink for OkSink {
    async fn insert_rack_health_report(
        &self,
        _rack_id: &str,
        _report: HealthReport,
    ) -> Result<(), DsxConsumerError> {
        Ok(())
    }

    async fn remove_rack_health_report(&self, _rack_id: &str) -> Result<(), DsxConsumerError> {
        Ok(())
    }
}

fn faulting_value() -> ValueMessage {
    ValueMessage {
        value: FaultValue::Faulting,
        timestamp: chrono::Utc::now(),
    }
}

#[test]
fn dedup_site_keeps_its_trace_verbatim() {
    let logs = capture_logs(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        rt.block_on(async {
            let meter = opentelemetry::global::meter("dedup-trace-test");
            let updater = HealthUpdater::new(
                "BMS/v1/".to_string(),
                CacheConfig {
                    metadata_ttl: Duration::from_secs(3600),
                    value_state_ttl: Duration::from_secs(3600),
                },
                Arc::new(OkSink),
                ConsumerMetrics::new(&meter),
                meter.clone(),
            );

            // Drive the real message loop through its public `run`: cache the
            // metadata, process the first faulting value, then feed an identical
            // second value that takes the dedup branch and logs the trace.
            let (tx, rx) = mpsc::channel(16);
            tx.send(MqttMessage::Metadata {
                topic: "BMS/v1/site/rack/point/Metadata".to_string(),
                metadata: LeakMetadata {
                    point_type: "LeakDetectRack".to_string(),
                    object_type: "Rack".to_string(),
                    rack_name: "Rack-001".to_string(),
                    rack_id: "rack-001".to_string(),
                },
            })
            .await
            .unwrap();
            tx.send(MqttMessage::Value {
                topic: "BMS/v1/site/rack/point/Value".to_string(),
                value: faulting_value(),
            })
            .await
            .unwrap();
            tx.send(MqttMessage::Value {
                topic: "BMS/v1/site/rack/point/Value".to_string(),
                value: faulting_value(),
            })
            .await
            .unwrap();
            drop(tx);

            updater.run(rx).await;
        });
    });

    let dedup: Vec<_> = logs
        .iter()
        .filter(|line| line.message == "Deduplicating unchanged value")
        .collect();
    assert_eq!(dedup.len(), 1, "expected one dedup trace; got {logs:?}");
    assert_eq!(dedup[0].level, tracing::Level::TRACE);
    // The original trace's fields ride the line unchanged.
    assert!(
        dedup[0]
            .fields
            .contains(&("point_type".to_string(), "LeakDetectRack".to_string())),
        "dedup fields: {:?}",
        dedup[0].fields
    );
    assert!(dedup[0].fields.iter().any(|(key, _)| key == "point_path"));
    assert!(dedup[0].fields.iter().any(|(key, _)| key == "value"));
}
