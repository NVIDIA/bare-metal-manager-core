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

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use carbide_uuid::machine::MachineId;
use tokio::sync::Notify;

use super::{CollectorEvent, DataSink, EventContext, HealthReport};
use crate::HealthError;
use crate::api_client::ApiClientWrapper;
use crate::config::HealthOverrideSinkConfig;

#[derive(Clone)]
struct HealthOverrideJob {
    machine_id: MachineId,
    report: Arc<HealthReport>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct HealthOverrideKey {
    machine_id: MachineId,
    source: super::ReportSource,
}

struct PendingReportsState {
    reports: HashMap<HealthOverrideKey, HealthOverrideJob>,
    ready: VecDeque<HealthOverrideKey>,
}

struct PendingReportsStore {
    state: Mutex<PendingReportsState>,
    notify: Notify,
}

impl PendingReportsStore {
    fn new() -> Self {
        Self {
            state: Mutex::new(PendingReportsState {
                reports: HashMap::new(),
                ready: VecDeque::new(),
            }),
            notify: Notify::new(),
        }
    }

    fn save_latest(&self, job: HealthOverrideJob) {
        let key = HealthOverrideKey {
            machine_id: job.machine_id,
            source: job.report.source,
        };

        {
            let mut state = self.state.lock().expect("health override mutex poisoned");
            if let Some(existing) = state.reports.get_mut(&key) {
                *existing = job;
            } else {
                state.reports.insert(key, job);
                state.ready.push_back(key);
            }
        }
        self.notify.notify_one();
    }

    async fn next(&self) -> HealthOverrideJob {
        loop {
            if let Some(job) = self.pop() {
                return job;
            }

            self.notify.notified().await;
        }
    }

    fn pop(&self) -> Option<HealthOverrideJob> {
        let mut state = self.state.lock().expect("health override mutex poisoned");
        while let Some(key) = state.ready.pop_front() {
            if let Some(job) = state.reports.remove(&key) {
                return Some(job);
            }
        }

        None
    }
}

pub struct HealthOverrideSink {
    pending_reports: Arc<PendingReportsStore>,
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

        let pending_reports = Arc::new(PendingReportsStore::new());

        for worker_id in 0..config.workers {
            let worker_client = Arc::clone(&client);
            let pending_reports = Arc::clone(&pending_reports);
            handle.spawn(async move {
                loop {
                    let job = pending_reports.next().await;

                    match job.report.as_ref().try_into() {
                        Ok(report) => {
                            if let Err(error) = worker_client
                                .submit_health_report(&job.machine_id, report)
                                .await
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
                                machine_id = %job.machine_id,
                                "Failed to convert health override report"
                            );
                        }
                    }
                }
            });
        }

        Ok(Self { pending_reports })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn new_for_bench() -> Result<Self, HealthError> {
        Ok(Self {
            pending_reports: Arc::new(PendingReportsStore::new()),
        })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn pop_pending_for_bench(&self) -> Option<(MachineId, Arc<HealthReport>)> {
        self.pending_reports
            .pop()
            .map(|job| (job.machine_id, job.report))
    }
}

impl DataSink for HealthOverrideSink {
    fn sink_type(&self) -> &'static str {
        "health_override_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        if let CollectorEvent::HealthReport(report) = event {
            if let Some(machine_id) = context.machine_id() {
                self.pending_reports.save_latest(HealthOverrideJob {
                    machine_id,
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
    use super::*;
    use crate::sink::ReportSource;

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

    fn report_key(job: &HealthOverrideJob) -> HealthOverrideKey {
        HealthOverrideKey {
            machine_id: job.machine_id,
            source: job.report.source,
        }
    }

    #[tokio::test]
    async fn latest_reports_are_preserved() {
        let queue = PendingReportsStore::new();
        let machine_a = machine_id("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0");
        let machine_b = machine_id("fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g");
        let machine_c = machine_id("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30");

        queue.save_latest(HealthOverrideJob {
            machine_id: machine_a,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });
        queue.save_latest(HealthOverrideJob {
            machine_id: machine_a,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });
        queue.save_latest(HealthOverrideJob {
            machine_id: machine_b,
            report: Arc::new(report(ReportSource::TrayLeakDetection)),
        });
        queue.save_latest(HealthOverrideJob {
            machine_id: machine_c,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });
        queue.save_latest(HealthOverrideJob {
            machine_id: machine_b,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });

        let mut drained = HashMap::new();
        while let Some(job) = queue.pop() {
            drained.insert(report_key(&job), job.report.source);
        }

        assert_eq!(drained.len(), 4);
    }

    #[tokio::test]
    async fn reinserting_hot_key_moves_it_to_back() {
        let queue = PendingReportsStore::new();
        let machine_a = machine_id("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0");
        let machine_b = machine_id("fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g");

        queue.save_latest(HealthOverrideJob {
            machine_id: machine_a,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });
        queue.save_latest(HealthOverrideJob {
            machine_id: machine_b,
            report: Arc::new(report(ReportSource::BmcSensors)),
        });

        let first = queue.pop().unwrap();
        assert_eq!(first.machine_id, machine_a);

        queue.save_latest(HealthOverrideJob {
            machine_id: machine_a,
            report: Arc::new(report(ReportSource::TrayLeakDetection)),
        });

        let second = queue.pop().unwrap();
        let third = queue.pop().unwrap();

        assert_eq!(second.machine_id, machine_b);
        assert_eq!(third.machine_id, machine_a);
        assert_eq!(third.report.source, ReportSource::TrayLeakDetection);
    }
}
