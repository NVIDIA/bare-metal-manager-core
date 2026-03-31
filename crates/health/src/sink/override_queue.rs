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

//! Latest-wins dedup queue for health override submissions.
//!
//! Both machine-level and rack-level override sinks share this queue
//! pattern: reports are keyed by `(Id, ReportSource)`, and a new report
//! for the same key silently replaces the previous one before it is
//! drained by a worker.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

use super::{HealthReport, ReportSource};

pub(crate) struct OverrideJob<Id> {
    pub id: Id,
    pub report: Arc<HealthReport>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct OverrideKey<Id: Eq + Hash> {
    id: Id,
    source: ReportSource,
}

struct QueueState<Id: Eq + Hash> {
    reports: HashMap<OverrideKey<Id>, OverrideJob<Id>>,
    ready: VecDeque<OverrideKey<Id>>,
}

pub(crate) struct OverrideQueue<Id: Eq + Hash + Clone> {
    state: Mutex<QueueState<Id>>,
    notify: Notify,
}

impl<Id: Eq + Hash + Clone> OverrideQueue<Id> {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(QueueState {
                reports: HashMap::new(),
                ready: VecDeque::new(),
            }),
            notify: Notify::new(),
        }
    }

    pub fn save_latest(&self, job: OverrideJob<Id>) {
        let key = OverrideKey {
            id: job.id.clone(),
            source: job.report.source,
        };

        {
            let mut state = self.state.lock().expect("override queue mutex poisoned");
            if let Some(existing) = state.reports.get_mut(&key) {
                *existing = job;
            } else {
                state.reports.insert(key.clone(), job);
                state.ready.push_back(key);
            }
        }
        self.notify.notify_one();
    }

    pub async fn next(&self) -> OverrideJob<Id> {
        loop {
            if let Some(job) = self.pop() {
                return job;
            }

            self.notify.notified().await;
        }
    }

    pub fn pop(&self) -> Option<OverrideJob<Id>> {
        let mut state = self.state.lock().expect("override queue mutex poisoned");
        while let Some(key) = state.ready.pop_front() {
            if let Some(job) = state.reports.remove(&key) {
                return Some(job);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(source: ReportSource) -> OverrideJob<String> {
        OverrideJob {
            id: String::new(),
            report: Arc::new(HealthReport {
                source,
                observed_at: None,
                successes: Vec::new(),
                alerts: Vec::new(),
            }),
        }
    }

    #[test]
    fn deduplicates_by_id_and_source() {
        let queue = OverrideQueue::<String>::new();

        queue.save_latest(OverrideJob {
            id: "a".into(),
            ..report(ReportSource::BmcSensors)
        });
        queue.save_latest(OverrideJob {
            id: "a".into(),
            ..report(ReportSource::BmcSensors)
        });
        queue.save_latest(OverrideJob {
            id: "b".into(),
            ..report(ReportSource::TrayLeakDetection)
        });

        let mut count = 0;
        while queue.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn same_id_different_source_are_separate() {
        let queue = OverrideQueue::<String>::new();

        queue.save_latest(OverrideJob {
            id: "a".into(),
            ..report(ReportSource::BmcSensors)
        });
        queue.save_latest(OverrideJob {
            id: "a".into(),
            ..report(ReportSource::TrayLeakDetection)
        });

        let mut count = 0;
        while queue.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn preserves_fifo_order() {
        let queue = OverrideQueue::<String>::new();

        queue.save_latest(OverrideJob {
            id: "first".into(),
            ..report(ReportSource::BmcSensors)
        });
        queue.save_latest(OverrideJob {
            id: "second".into(),
            ..report(ReportSource::BmcSensors)
        });

        assert_eq!(queue.pop().unwrap().id, "first");
        assert_eq!(queue.pop().unwrap().id, "second");
        assert!(queue.pop().is_none());
    }

    #[test]
    fn update_replaces_value_but_keeps_position() {
        let queue = OverrideQueue::<String>::new();

        queue.save_latest(OverrideJob {
            id: "a".into(),
            ..report(ReportSource::BmcSensors)
        });
        queue.save_latest(OverrideJob {
            id: "b".into(),
            ..report(ReportSource::BmcSensors)
        });
        queue.save_latest(OverrideJob {
            id: "a".into(),
            ..report(ReportSource::BmcSensors)
        });

        assert_eq!(queue.pop().unwrap().id, "a");
        assert_eq!(queue.pop().unwrap().id, "b");
    }
}
