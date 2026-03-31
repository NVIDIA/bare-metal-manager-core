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
use crate::config::HealthOverrideSinkConfig;

pub struct HealthOverrideSink {
    queue: Arc<OverrideQueue<MachineId>>,
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

        Ok(Self { queue })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn new_for_bench() -> Result<Self, HealthError> {
        Ok(Self {
            queue: Arc::new(OverrideQueue::new()),
        })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn pop_pending_for_bench(&self) -> Option<(MachineId, Arc<super::HealthReport>)> {
        self.queue.pop().map(|job| (job.id, job.report))
    }
}

impl DataSink for HealthOverrideSink {
    fn sink_type(&self) -> &'static str {
        "health_override_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        if let CollectorEvent::HealthReport(report) = event {
            if let Some(machine_id) = context.machine_id() {
                self.queue.save_latest(OverrideJob {
                    id: machine_id,
                    report: Arc::clone(report),
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
    use crate::sink::{HealthReport, ReportSource};

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
}
