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

use super::override_queue::{OverrideJob, OverrideQueue};
use super::{CollectorEvent, DataSink, EventContext};
use crate::HealthError;
use crate::api_client::ApiClientWrapper;
use crate::config::{HealthOverrideLevel, HealthOverrideSinkConfig};
use crate::sink::{Classification, HealthReport, HealthReportSuccess};

pub struct HealthOverrideSink {
    queue: Arc<OverrideQueue<MachineId>>,
    level: HealthOverrideLevel,
}

impl HealthOverrideSink {
    pub fn new(config: &HealthOverrideSinkConfig) -> Result<Self, HealthError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|error| {
            HealthError::GenericError(format!(
                "health override sink requires active Tokio runtime: {error}"
            ))
        })?;

        let client = Arc::new(ApiClientWrapper::new(
            config.connection.root_ca.clone(),
            config.connection.client_cert.clone(),
            config.connection.client_key.clone(),
            &config.connection.api_url,
        ));

        let queue = Arc::new(OverrideQueue::new());

        for worker_id in 0..config.workers {
            let worker_client = Arc::clone(&client);
            let worker_queue = Arc::clone(&queue);
            handle.spawn(async move {
                loop {
                    let job = worker_queue.next().await;

                    match job.report.as_ref().try_into() {
                        Ok(report) => {
                            if let Err(error) =
                                worker_client.submit_health_report(&job.id, report).await
                            {
                                tracing::warn!(
                                    ?error,
                                    worker_id,
                                    "Failed to submit health override report"
                                );
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                worker_id,
                                machine_id = %job.id,
                                "Failed to convert health override report"
                            );
                        }
                    }
                }
            });
        }

        Ok(Self {
            queue,
            level: config.level,
        })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn new_for_bench() -> Result<Self, HealthError> {
        Ok(Self {
            queue: Arc::new(OverrideQueue::new()),
            level: HealthOverrideLevel::Warning,
        })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn pop_pending_for_bench(&self) -> Option<(MachineId, Arc<super::HealthReport>)> {
        self.queue.pop().map(|job| (job.id, job.report))
    }

    fn classification_rank(classification: Classification) -> u8 {
        match classification {
            Classification::SensorOk => 0,
            Classification::SensorWarning => 1,
            Classification::SensorCritical => 2,
            Classification::SensorFatal => 3,
            Classification::SensorFailure => 4,
            Classification::Leak | Classification::LeakDetector => 4,
        }
    }

    fn threshold_rank(level: HealthOverrideLevel) -> u8 {
        match level {
            HealthOverrideLevel::Warning => 1,
            HealthOverrideLevel::Critical => 2,
            HealthOverrideLevel::Fatal => 3,
        }
    }

    fn should_alert(level: HealthOverrideLevel, classifications: &[Classification]) -> bool {
        let threshold = Self::threshold_rank(level);
        classifications
            .iter()
            .copied()
            .map(Self::classification_rank)
            .max()
            .is_some_and(|rank| rank >= threshold)
    }

    fn filter_report(&self, report: &HealthReport) -> HealthReport {
        let mut successes = report.successes.clone();
        let mut alerts = Vec::new();

        for alert in &report.alerts {
            if Self::should_alert(self.level, &alert.classifications) {
                alerts.push(alert.clone());
            } else {
                successes.push(HealthReportSuccess {
                    probe_id: alert.probe_id,
                    target: alert.target.clone(),
                });
            }
        }

        HealthReport {
            source: report.source,
            observed_at: report.observed_at,
            successes,
            alerts,
        }
    }
}

impl DataSink for HealthOverrideSink {
    fn sink_type(&self) -> &'static str {
        "health_override_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        if let CollectorEvent::HealthReport(report) = event {
            if let Some(machine_id) = context.machine_id() {
                let filtered_report = Arc::new(self.filter_report(report));
                self.queue.save_latest(OverrideJob {
                    id: machine_id,
                    report: filtered_report,
                });
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
    use crate::sink::{Classification, HealthReport, HealthReportAlert, Probe, ReportSource};

    fn report(source: ReportSource) -> HealthReport {
        HealthReport {
            source,
            observed_at: None,
            successes: Vec::new(),
            alerts: Vec::new(),
        }
    }

    fn machine_id(value: &str) -> MachineId {
        value.parse().expect("valid machine id")
    }

    #[tokio::test]
    async fn latest_reports_are_preserved() {
        let queue = OverrideQueue::new();
        let machine_a = machine_id("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0");
        let machine_b = machine_id("fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g");
        let machine_c = machine_id("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30");

        queue.save_latest(OverrideJob {
            id: machine_a,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });
        queue.save_latest(OverrideJob {
            id: machine_a,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });
        queue.save_latest(OverrideJob {
            id: machine_b,
            report: Arc::new(report(ReportSource::TrayLeakDetection)),
        });
        queue.save_latest(OverrideJob {
            id: machine_c,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });
        queue.save_latest(OverrideJob {
            id: machine_b,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });

        let mut drained = HashMap::new();
        while let Some(job) = queue.pop() {
            drained.insert((job.id, job.report.source), ());
        }

        assert_eq!(drained.len(), 4);
    }

    #[tokio::test]
    async fn reinserting_hot_key_moves_it_to_back() {
        let queue = OverrideQueue::new();
        let machine_a = machine_id("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0");
        let machine_b = machine_id("fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g");

        queue.save_latest(OverrideJob {
            id: machine_a,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });
        queue.save_latest(OverrideJob {
            id: machine_b,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });

        let first = queue.pop().unwrap();
        assert_eq!(first.id, machine_a);

        queue.save_latest(OverrideJob {
            id: machine_a,
            report: Arc::new(report(ReportSource::TrayLeakDetection)),
        });

        let second = queue.pop().unwrap();
        let third = queue.pop().unwrap();

        assert_eq!(second.id, machine_b);
        assert_eq!(third.id, machine_a);
        assert_eq!(third.report.source, ReportSource::TrayLeakDetection);
    }

    #[test]
    fn downgrades_alerts_below_configured_level_to_successes() {
        let sink = HealthOverrideSink {
            queue: Arc::new(OverrideQueue::new()),
            level: HealthOverrideLevel::Critical,
        };

        let report = HealthReport {
            source: ReportSource::BmcSensors,
            observed_at: None,
            successes: Vec::new(),
            alerts: vec![HealthReportAlert {
                probe_id: Probe::Sensor,
                target: Some("sensor-1".to_string()),
                message: "warning".to_string(),
                classifications: vec![Classification::SensorWarning],
            }],
        };

        let filtered = sink.filter_report(&report);
        assert!(filtered.alerts.is_empty());
        assert_eq!(filtered.successes.len(), 1);
        assert_eq!(filtered.successes[0].probe_id, Probe::Sensor);
        assert_eq!(filtered.successes[0].target.as_deref(), Some("sensor-1"));
    }

    #[test]
    fn keeps_alerts_at_or_above_configured_level() {
        let sink = HealthOverrideSink {
            queue: Arc::new(OverrideQueue::new()),
            level: HealthOverrideLevel::Critical,
        };

        let report = HealthReport {
            source: ReportSource::BmcSensors,
            observed_at: None,
            successes: Vec::new(),
            alerts: vec![HealthReportAlert {
                probe_id: Probe::Sensor,
                target: Some("sensor-1".to_string()),
                message: "critical".to_string(),
                classifications: vec![Classification::SensorCritical],
            }],
        };

        let filtered = sink.filter_report(&report);
        assert!(filtered.successes.is_empty());
        assert_eq!(filtered.alerts.len(), 1);
    }
}
