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

use std::str::FromStr;
use std::sync::Arc;

use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthProbeSuccess,
};
use tokio::sync::mpsc;

use super::{CollectorEvent, DataSink, EventContext};
use crate::HealthError;
use crate::api_client::ApiClientWrapper;
use crate::config::CarbideApiConnectionConfig;
use crate::sink::{HealthReport, HealthReportAlert, HealthReportSuccess};

struct HealthOverrideJob {
    machine_id: carbide_uuid::machine::MachineId,
    report: health_report::HealthReport,
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
                if let Err(error) = worker_client
                    .submit_health_report(&job.machine_id, job.report)
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

    fn parse_probe_id(probe_id: &str) -> Option<HealthProbeId> {
        match HealthProbeId::from_str(probe_id) {
            Ok(probe_id) => Some(probe_id),
            Err(error) => {
                tracing::warn!(?error, probe_id, "Failed to parse health probe id");
                None
            }
        }
    }

    fn parse_classifications(classifications: &[String]) -> Vec<HealthAlertClassification> {
        let mut parsed = Vec::with_capacity(classifications.len().max(1));
        for classification in classifications {
            match classification.parse::<HealthAlertClassification>() {
                Ok(classification) => parsed.push(classification),
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        classification,
                        "Failed to parse health alert classification"
                    );
                }
            }
        }

        parsed.push(HealthAlertClassification::hardware());

        parsed
    }

    fn convert_success(success: &HealthReportSuccess) -> Option<HealthProbeSuccess> {
        let id = Self::parse_probe_id(&success.probe_id)?;
        Some(HealthProbeSuccess {
            id,
            target: success.target.clone(),
        })
    }

    fn convert_alert(alert: &HealthReportAlert) -> Option<HealthProbeAlert> {
        let id = Self::parse_probe_id(&alert.probe_id)?;
        Some(HealthProbeAlert {
            id,
            target: alert.target.clone(),
            in_alert_since: None,
            message: alert.message.clone(),
            tenant_message: None,
            classifications: Self::parse_classifications(&alert.classifications),
        })
    }

    fn to_carbide_report(report: &HealthReport) -> health_report::HealthReport {
        let successes = report
            .successes
            .iter()
            .filter_map(Self::convert_success)
            .collect();
        let alerts = report
            .alerts
            .iter()
            .filter_map(Self::convert_alert)
            .collect();

        health_report::HealthReport {
            source: report.source.clone(),
            triggered_by: None,
            observed_at: report.observed_at,
            successes,
            alerts,
        }
    }
}

impl DataSink for HealthOverrideSink {
    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        if let CollectorEvent::HealthReport(report) = event {
            if let Some(machine_id) = context.machine_id() {
                if let Err(error) = self.sender.send(HealthOverrideJob {
                    machine_id,
                    report: Self::to_carbide_report(report),
                }) {
                    tracing::warn!(?error, "failed to enqueue health override report");
                }
            } else {
                tracing::warn!(
                    report = ?report,
                    "Received HealthReport event without machine_id context"
                );
            }
        }
    }
}
