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

use tokio::sync::mpsc;

use super::{CollectorEvent, DataSink, EventContext};
use crate::HealthError;
use crate::api_client::ApiClientWrapper;
use crate::config::CarbideApiConnectionConfig;
use crate::sink::HealthOverride;

struct HealthOverrideJob {
    machine_id: carbide_uuid::machine::MachineId,
    report: Arc<health_report::HealthReport>,
}

pub struct HealthOverrideSink {
    sender: mpsc::UnboundedSender<HealthOverrideJob>,
}

impl HealthOverrideSink {
    pub fn new(config: &CarbideApiConnectionConfig) -> Result<Self, HealthError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|error| {
            HealthError::GenericError(format!(
                "health override sink requires active Tokio runtime: {error}"
            ))
        })?;

        let client = Arc::new(ApiClientWrapper::new(
            config.root_ca.clone(),
            config.client_cert.clone(),
            config.client_key.clone(),
            &config.api_url,
            false,
        ));

        let (sender, mut receiver) = mpsc::unbounded_channel::<HealthOverrideJob>();
        let worker_client = Arc::clone(&client);

        handle.spawn(async move {
            while let Some(job) = receiver.recv().await {
                let report = Arc::unwrap_or_clone(job.report);
                if let Err(error) = worker_client
                    .submit_health_report(&job.machine_id, report)
                    .await
                {
                    tracing::warn!(?error, "Failed to submit health override report");
                }
            }
        });

        Ok(Self { sender })
    }

    #[cfg(feature = "bench-hooks")]
    pub fn new_for_bench() -> Result<Self, HealthError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|error| {
            HealthError::GenericError(format!(
                "health override sink requires active Tokio runtime: {error}"
            ))
        })?;

        let (sender, mut receiver) = mpsc::unbounded_channel::<HealthOverrideJob>();
        handle.spawn(async move { while receiver.recv().await.is_some() {} });

        Ok(Self { sender })
    }
}

impl DataSink for HealthOverrideSink {
    fn handle_event(&self, _context: &EventContext, event: &CollectorEvent) {
        if let CollectorEvent::HealthOverride(HealthOverride { machine_id, report }) = event {
            if let Some(machine_id) = machine_id {
                if let Err(error) = self.sender.send(HealthOverrideJob {
                    machine_id: *machine_id,
                    report: report.clone(),
                }) {
                    tracing::warn!(?error, "failed to enqueue health override report");
                }
            } else {
                tracing::warn!(report = ?report, "Received HealthOverride event without machine_id");
            }
        }
    }
}
