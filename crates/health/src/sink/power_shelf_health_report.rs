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

use carbide_uuid::power_shelf::PowerShelfId;

use super::dedup_queue::DedupQueue;
use super::{
    CollectorEvent, DataSink, EventContext, HealthReport, HealthReportTarget, ReportSource,
};
use crate::HealthError;
use crate::api_client::ApiClientWrapper;
use crate::config::PowerShelfHealthReportSinkConfig;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PowerShelfHealthReportKey {
    id: PowerShelfId,
    source: ReportSource,
}

pub struct PowerShelfHealthReportSink {
    queue: Arc<DedupQueue<PowerShelfHealthReportKey, Arc<HealthReport>>>,
    skip_empty_reports: bool,
}

impl PowerShelfHealthReportSink {
    pub fn new(config: &PowerShelfHealthReportSinkConfig) -> Result<Self, HealthError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|error| {
            HealthError::GenericError(format!(
                "power shelf health report sink requires active Tokio runtime: {error}"
            ))
        })?;

        let client = Arc::new(ApiClientWrapper::new(
            config.connection.root_ca.clone(),
            config.connection.client_cert.clone(),
            config.connection.client_key.clone(),
            &config.connection.api_url,
        ));

        let queue: Arc<DedupQueue<PowerShelfHealthReportKey, Arc<HealthReport>>> =
            Arc::new(DedupQueue::new());

        for worker_id in 0..config.workers {
            let worker_client = Arc::clone(&client);
            let worker_queue = Arc::clone(&queue);
            handle.spawn(async move {
                loop {
                    let (key, report) = worker_queue.next().await;

                    match report.as_ref().try_into() {
                        Ok(converted) => {
                            if let Err(error) = worker_client
                                .submit_power_shelf_health_report(&key.id, converted)
                                .await
                            {
                                tracing::warn!(
                                    ?error,
                                    worker_id,
                                    power_shelf_id = %key.id,
                                    "Failed to submit power shelf health report"
                                );
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                worker_id,
                                power_shelf_id = %key.id,
                                "Failed to convert power shelf health report"
                            );
                        }
                    }
                }
            });
        }

        Ok(Self {
            queue,
            skip_empty_reports: config.skip_empty_reports,
        })
    }
}

impl DataSink for PowerShelfHealthReportSink {
    fn sink_type(&self) -> &'static str {
        "power_shelf_health_report_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        let CollectorEvent::HealthReport(report) = event else {
            return;
        };

        if report.target != Some(HealthReportTarget::PowerShelf) {
            return;
        }

        if self.skip_empty_reports && report.is_empty() {
            tracing::debug!(
                source = ?report.source,
                "Skipping empty power shelf health report"
            );
            return;
        }

        let power_shelf_id = if let Some(power_shelf_id) = context.power_shelf_id() {
            power_shelf_id
        } else {
            tracing::warn!(
                endpoint_key = context.endpoint_key(),
                "Received power-shelf-target HealthReport event without power_shelf_id context"
            );
            return;
        };

        let key = PowerShelfHealthReportKey {
            id: power_shelf_id,
            source: report.source,
        };
        self.queue.save_latest(key, Arc::clone(report));
    }
}
