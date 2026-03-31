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

use carbide_uuid::rack::RackId;

use super::override_queue::{OverrideJob, OverrideQueue};
use super::{CollectorEvent, DataSink, EventContext, ReportSource};
use crate::HealthError;
use crate::api_client::ApiClientWrapper;
use crate::config::RackHealthOverrideSinkConfig;

pub struct RackHealthOverrideSink {
    queue: Arc<OverrideQueue<RackId>>,
}

impl RackHealthOverrideSink {
    pub fn new(config: &RackHealthOverrideSinkConfig) -> Result<Self, HealthError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|error| {
            HealthError::GenericError(format!(
                "rack health override sink requires active Tokio runtime: {error}"
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
                            if let Err(error) = worker_client
                                .submit_rack_health_report(&job.id, report)
                                .await
                            {
                                tracing::warn!(
                                    ?error,
                                    worker_id,
                                    rack_id = %job.id,
                                    "Failed to submit rack health override report"
                                );
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                worker_id,
                                rack_id = %job.id,
                                "Failed to convert rack health override report"
                            );
                        }
                    }
                }
            });
        }

        Ok(Self { queue })
    }
}

impl DataSink for RackHealthOverrideSink {
    fn sink_type(&self) -> &'static str {
        "rack_health_override_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        let CollectorEvent::HealthReport(report) = event else {
            return;
        };

        if report.source != ReportSource::RackLeakDetection {
            return;
        }

        let Some(rack_id) = context.rack_id() else {
            tracing::warn!(
                endpoint_key = context.endpoint_key(),
                "Received RackLeakDetection report without rack_id context"
            );
            return;
        };

        self.queue.save_latest(OverrideJob {
            id: rack_id.clone(),
            report: Arc::clone(report),
        });
    }
}
