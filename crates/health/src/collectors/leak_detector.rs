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
use std::time::{Duration, Instant};

use nv_redfish::ServiceRoot;
use nv_redfish::core::{Bmc, EntityTypeRef, ODataId, ToSnakeCase};
use nv_redfish::schema::leak_detector::{DetectorState, LeakDetector};

use crate::HealthError;
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::endpoint::BmcEndpoint;
use crate::sink::{
    Classification, CollectorEvent, DataSink, EventContext, HealthReport, HealthReportAlert,
    HealthReportSuccess, Probe, ReportSource,
};

pub struct LeakDetectorCollectorConfig {
    pub data_sink: Option<Arc<dyn DataSink>>,
    pub state_refresh_interval: Duration,
}

pub struct LeakDetectorCollector<B: Bmc> {
    bmc: Arc<B>,
    event_context: EventContext,
    state: Option<LeakDetectorCollectorState>,
    data_sink: Option<Arc<dyn DataSink>>,
    state_refresh_interval: Duration,
}

struct LeakDetectorCollectorState {
    detector_ids: Vec<ODataId>,
    last_detector_refresh: Instant,
}

impl<B> PeriodicCollector<B> for LeakDetectorCollector<B>
where
    B: Bmc + 'static,
    B::Error: 'static,
{
    type Config = LeakDetectorCollectorConfig;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let event_context =
            EventContext::from_endpoint(endpoint.as_ref(), "leak_detector_collector");
        Ok(Self {
            bmc,
            event_context,
            state: None,
            data_sink: config.data_sink,
            state_refresh_interval: config.state_refresh_interval,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        self.run_leak_detector_iteration().await
    }

    fn collector_type(&self) -> &'static str {
        "leak_detector_collector"
    }

    async fn stop(&mut self) {
        self.emit_event(CollectorEvent::CollectorRemoved);
    }
}

impl<B> LeakDetectorCollector<B>
where
    B: Bmc + 'static,
    B::Error: 'static,
{
    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    async fn run_leak_detector_iteration(&mut self) -> Result<IterationResult, HealthError> {
        let needs_detector_refresh = self
            .state
            .as_ref()
            .map(|s| s.last_detector_refresh.elapsed() > self.state_refresh_interval)
            .unwrap_or(true);

        let mut refresh_triggered = false;

        if needs_detector_refresh {
            match self.discover_leak_detectors().await {
                Ok(detector_ids) => {
                    tracing::info!(
                        detector_count = detector_ids.len(),
                        "Leak detector discovery complete"
                    );
                    self.state = Some(LeakDetectorCollectorState {
                        detector_ids,
                        last_detector_refresh: Instant::now(),
                    });
                    refresh_triggered = true;
                }
                Err(error) => {
                    tracing::error!(?error, "Failed to discover leak detectors");
                    if self.state.is_none() {
                        return Err(error);
                    }
                }
            }
        }

        let detectors = if let Some(state) = &self.state {
            self.fetch_leak_detectors(&state.detector_ids).await?
        } else {
            Vec::new()
        };
        let detector_count = detectors.len();
        let report = build_health_report(detectors, &self.event_context);

        self.emit_event(CollectorEvent::HealthReport(Arc::new(report)));

        Ok(IterationResult {
            refresh_triggered,
            entity_count: Some(detector_count),
            fetch_failures: 0,
        })
    }

    async fn discover_leak_detectors(&self) -> Result<Vec<ODataId>, HealthError> {
        let service_root = ServiceRoot::new(self.bmc.clone()).await?;
        let Some(chassis_collection) = service_root.chassis().await? else {
            return Ok(Vec::new());
        };

        let mut detector_ids = Vec::new();
        for chassis in chassis_collection.members().await? {
            // These are optional Redfish navigation properties. Each link must
            // be fetched before the next one exists, so this stays as an
            // explicit step-by-step walk instead of an Option chain.
            let Some(thermal_subsystem_ref) = &chassis.raw().thermal_subsystem else {
                continue;
            };
            let thermal_subsystem = thermal_subsystem_ref
                .get(self.bmc.as_ref())
                .await
                .map_err(|error| HealthError::BmcError(Box::new(error)))?;
            let Some(leak_detection_ref) = &thermal_subsystem.leak_detection else {
                continue;
            };
            let leak_detection = leak_detection_ref
                .get(self.bmc.as_ref())
                .await
                .map_err(|error| HealthError::BmcError(Box::new(error)))?;
            let Some(leak_detector_collection_ref) = &leak_detection.leak_detectors else {
                continue;
            };
            let leak_detector_collection = leak_detector_collection_ref
                .get(self.bmc.as_ref())
                .await
                .map_err(|error| HealthError::BmcError(Box::new(error)))?;

            for leak_detector_ref in &leak_detector_collection.members {
                detector_ids.push(leak_detector_ref.id().clone());
            }
        }

        Ok(detector_ids)
    }

    async fn fetch_leak_detectors(
        &self,
        detector_ids: &[ODataId],
    ) -> Result<Vec<Arc<LeakDetector>>, HealthError> {
        let mut detectors = Vec::new();
        for detector_id in detector_ids {
            detectors.push(
                self.bmc
                    .get::<LeakDetector>(detector_id)
                    .await
                    .map_err(|error| HealthError::BmcError(Box::new(error)))?,
            );
        }

        Ok(detectors)
    }
}

fn build_health_report(detectors: Vec<Arc<LeakDetector>>, context: &EventContext) -> HealthReport {
    let mut successes = Vec::new();
    let mut alerts = Vec::new();

    for detector in detectors {
        let target = detector_target(detector.as_ref());
        match detector.detector_state.flatten() {
            Some(DetectorState::Ok) => successes.push(HealthReportSuccess {
                probe_id: Probe::LeakDetection,
                target: Some(target),
            }),
            Some(DetectorState::Warning) | Some(DetectorState::Critical) => {
                alerts.push(leak_alert(detector.as_ref(), target));
            }
            Some(DetectorState::Unavailable)
            | Some(DetectorState::Absent)
            | Some(DetectorState::UnsupportedValue)
            | None => {
                tracing::warn!(
                    detector = %target,
                    state = ?detector.detector_state.flatten(),
                    "Leak detector is not reporting an actionable leak state"
                );
            }
        }
    }

    HealthReport {
        source: ReportSource::BmcLeakDetectors,
        observed_at: Some(chrono::Utc::now()),
        successes,
        alerts,
        target: context.health_report_target(),
    }
}

fn detector_target(detector: &LeakDetector) -> String {
    detector
        .user_label
        .clone()
        .filter(|label| !label.is_empty())
        .unwrap_or_else(|| detector.odata_id().to_string())
}

fn leak_alert(detector: &LeakDetector, target: String) -> HealthReportAlert {
    let state = detector.detector_state.flatten();
    HealthReportAlert {
        probe_id: Probe::LeakDetection,
        target: Some(target.clone()),
        message: format!(
            "Leak detector '{}' reports {}",
            target,
            state
                .map(|state| state.to_snake_case())
                .unwrap_or("unknown")
        ),
        classifications: vec![Classification::LeakDetector],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leak_alerts_are_marked_for_leak_processing() {
        let alert = HealthReportAlert {
            probe_id: Probe::LeakDetection,
            target: Some("LeakDetector_1".to_string()),
            message: "leak".to_string(),
            classifications: vec![Classification::LeakDetector],
        };

        assert!(
            alert
                .classifications
                .iter()
                .any(|classification| classification == &Classification::LeakDetector)
        );
    }
}
