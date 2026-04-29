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

use carbide_uuid::machine::MachineId;

use super::dedup_queue::DedupQueue;
use super::{CollectorEvent, DataSink, EventContext, HealthReport, ReportSource};
use crate::HealthError;
use crate::api_client::ApiClientWrapper;
use crate::config::HealthReportSinkConfig;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct HealthReportKey {
    id: MachineId,
    source: ReportSource,
}

pub struct HealthReportSink {
    queue: Arc<DedupQueue<HealthReportKey, Arc<HealthReport>>>,
}

impl HealthReportSink {
    pub fn new(config: &HealthReportSinkConfig) -> Result<Self, HealthError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|error| {
            HealthError::GenericError(format!(
                "health report sink requires active Tokio runtime: {error}"
            ))
        })?;

        let client = Arc::new(ApiClientWrapper::new(
            config.connection.root_ca.clone(),
            config.connection.client_cert.clone(),
            config.connection.client_key.clone(),
            &config.connection.api_url,
        ));

        let queue: Arc<DedupQueue<HealthReportKey, Arc<HealthReport>>> =
            Arc::new(DedupQueue::new());

        for worker_id in 0..config.workers {
            let worker_client = Arc::clone(&client);
            let worker_queue = Arc::clone(&queue);
            handle.spawn(async move {
                loop {
                    let (key, report) = worker_queue.next().await;

                    match report.as_ref().try_into() {
                        Ok(converted) => {
                            if let Err(error) =
                                worker_client.submit_health_report(&key.id, converted).await
                            {
                                tracing::warn!(?error, worker_id, "Failed to submit health report");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                worker_id,
                                machine_id = %key.id,
                                "Failed to convert health report"
                            );
                        }
                    }
                }
            });
        }

        Ok(Self { queue })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn new_for_bench() -> Result<Self, HealthError> {
        Ok(Self {
            queue: Arc::new(DedupQueue::new()),
        })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn pop_pending_for_bench(&self) -> Option<(MachineId, Arc<HealthReport>)> {
        self.queue.pop().map(|(key, report)| (key.id, report))
    }
}

impl DataSink for HealthReportSink {
    fn sink_type(&self) -> &'static str {
        "health_report_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        if let CollectorEvent::HealthReport(report) = event {
            if let Some(machine_id) = context.machine_id() {
                let key = HealthReportKey {
                    id: machine_id,
                    source: report.source,
                };
                self.queue.save_latest(key, Arc::clone(report));
            } else {
                tracing::warn!(
                    report = ?report,
                    "Received HealthReport event without machine_id context"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn machine_id(value: &str) -> MachineId {
        value.parse().expect("valid machine id")
    }

    fn key(id: MachineId, source: ReportSource) -> HealthReportKey {
        HealthReportKey { id, source }
    }

    fn report(source: ReportSource) -> Arc<HealthReport> {
        Arc::new(HealthReport {
            source,
            observed_at: None,
            successes: Vec::new(),
            alerts: Vec::new(),
        })
    }

    #[tokio::test]
    async fn latest_reports_are_preserved() {
        let queue: DedupQueue<HealthReportKey, Arc<HealthReport>> = DedupQueue::new();
        let machine_a = machine_id("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0");
        let machine_b = machine_id("fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g");
        let machine_c = machine_id("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30");

        queue.save_latest(
            key(machine_a, ReportSource::BmcSensors),
            report(ReportSource::BmcSensors),
        );
        queue.save_latest(
            key(machine_a, ReportSource::BmcSensors),
            report(ReportSource::BmcSensors),
        );
        queue.save_latest(
            key(machine_b, ReportSource::TrayLeakDetection),
            report(ReportSource::TrayLeakDetection),
        );
        queue.save_latest(
            key(machine_c, ReportSource::BmcSensors),
            report(ReportSource::BmcSensors),
        );
        queue.save_latest(
            key(machine_b, ReportSource::BmcSensors),
            report(ReportSource::BmcSensors),
        );

        let mut drained = HashMap::new();
        while let Some((k, r)) = queue.pop() {
            drained.insert((k.id, r.source), ());
        }

        assert_eq!(drained.len(), 4);
    }

    #[tokio::test]
    async fn reinserting_hot_key_moves_it_to_back() {
        let queue: DedupQueue<HealthReportKey, Arc<HealthReport>> = DedupQueue::new();
        let machine_a = machine_id("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0");
        let machine_b = machine_id("fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g");

        queue.save_latest(
            key(machine_a, ReportSource::BmcSensors),
            report(ReportSource::BmcSensors),
        );
        queue.save_latest(
            key(machine_b, ReportSource::BmcSensors),
            report(ReportSource::BmcSensors),
        );

        let (first_key, _) = queue.pop().unwrap();
        assert_eq!(first_key.id, machine_a);

        queue.save_latest(
            key(machine_a, ReportSource::TrayLeakDetection),
            report(ReportSource::TrayLeakDetection),
        );

        let (second_key, _) = queue.pop().unwrap();
        let (third_key, third_report) = queue.pop().unwrap();

        assert_eq!(second_key.id, machine_b);
        assert_eq!(third_key.id, machine_a);
        assert_eq!(third_report.source, ReportSource::TrayLeakDetection);
    }
}
