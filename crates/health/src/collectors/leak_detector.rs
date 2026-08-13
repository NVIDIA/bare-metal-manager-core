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
use nv_redfish::resource::State;
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
        let resource_state = detector
            .status
            .as_ref()
            .and_then(|status| status.state.flatten());
        if resource_state != Some(State::Enabled) {
            tracing::warn!(
                detector = %target,
                leak_detector_state = ?detector.detector_state.flatten(),
                leak_detector_resource_state = ?resource_state,
                "Leak detector resource state does not permit leak classification"
            );
            continue;
        }

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
                    leak_detector_state = ?detector.detector_state.flatten(),
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
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use carbide_test_support::{Check, check_values};
    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::{BmcAddr, EndpointMetadata, MachineData, SharedSystemUuid};
    use crate::sink::HealthReportTarget;

    #[derive(Debug, Eq, PartialEq)]
    struct SuccessSummary {
        probe_id: Probe,
        target: Option<String>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct AlertSummary {
        probe_id: Probe,
        target: Option<String>,
        message: String,
        classifications: Vec<Classification>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ReportSummary {
        source: ReportSource,
        target: Option<HealthReportTarget>,
        has_observed_at: bool,
        successes: Vec<SuccessSummary>,
        alerts: Vec<AlertSummary>,
    }

    impl From<HealthReport> for ReportSummary {
        fn from(report: HealthReport) -> Self {
            Self {
                source: report.source,
                target: report.target,
                has_observed_at: report.observed_at.is_some(),
                successes: report
                    .successes
                    .into_iter()
                    .map(|success| SuccessSummary {
                        probe_id: success.probe_id,
                        target: success.target,
                    })
                    .collect(),
                alerts: report
                    .alerts
                    .into_iter()
                    .map(|alert| AlertSummary {
                        probe_id: alert.probe_id,
                        target: alert.target,
                        message: alert.message,
                        classifications: alert.classifications,
                    })
                    .collect(),
            }
        }
    }

    fn context() -> EventContext {
        EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").expect("valid mac"),
            },
            collector_type: "leak_detector_collector",
            metadata: Some(EndpointMetadata::Machine(MachineData {
                machine_id: None,
                machine_serial: None,
                system_uuid: SharedSystemUuid::default(),
                slot_number: None,
                tray_index: None,
                nvlink_domain_uuid: None,
                driver_version: None,
            })),
            rack_id: None,
            labels: Default::default(),
        }
    }

    fn expected_report(successes: Vec<SuccessSummary>, alerts: Vec<AlertSummary>) -> ReportSummary {
        ReportSummary {
            source: ReportSource::BmcLeakDetectors,
            target: Some(HealthReportTarget::Machine),
            has_observed_at: true,
            successes,
            alerts,
        }
    }

    #[test]
    fn leak_detector_health_report_cases() {
        check_values(
            [
                Check {
                    scenario: "no detectors produce an empty timestamped report",
                    input: vec![],
                    expect: expected_report(vec![], vec![]),
                },
                Check {
                    scenario: "actionable states preserve alert order and detector targets",
                    input: vec![
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/Critical",
                            "Id": "Critical",
                            "Name": "Critical leak detector",
                            "DetectorState": "Critical",
                            "Status": { "Health": "Critical", "State": "Enabled" },
                            "UserLabel": ""
                        }"#,
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/OK",
                            "Id": "OK",
                            "Name": "Healthy leak detector",
                            "DetectorState": "OK",
                            "Status": { "Health": "OK", "State": "Enabled" },
                            "UserLabel": "Rack floor"
                        }"#,
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/Warning",
                            "Id": "Warning",
                            "Name": "Warning leak detector",
                            "DetectorState": "Warning",
                            "Status": { "Health": "Warning", "State": "Enabled" },
                            "UserLabel": "Cooling tray"
                        }"#,
                    ],
                    expect: expected_report(
                        vec![SuccessSummary {
                            probe_id: Probe::LeakDetection,
                            target: Some("Rack floor".to_string()),
                        }],
                        vec![
                            AlertSummary {
                                probe_id: Probe::LeakDetection,
                                target: Some(
                                    "/redfish/v1/Chassis/System/LeakDetectors/Critical".to_string(),
                                ),
                                message: "Leak detector '/redfish/v1/Chassis/System/LeakDetectors/Critical' reports critical".to_string(),
                                classifications: vec![Classification::LeakDetector],
                            },
                            AlertSummary {
                                probe_id: Probe::LeakDetection,
                                target: Some("Cooling tray".to_string()),
                                message: "Leak detector 'Cooling tray' reports warning".to_string(),
                                classifications: vec![Classification::LeakDetector],
                            },
                        ],
                    ),
                },
                Check {
                    scenario: "degraded leak detectors do not produce leak alerts",
                    input: vec![
                        r##"{
                            "@odata.id": "/redfish/v1/Chassis/Chassis_0/ThermalSubsystem/LeakDetection/LeakDetectors/Chassis_0_LeakDetector_0_ColdPlate",
                            "@odata.type": "#LeakDetector.v1_1_0.LeakDetector",
                            "Id": "Chassis_0_LeakDetector_0_ColdPlate",
                            "Name": "Chassis 0 LeakDetector 0 ColdPlate",
                            "DetectorState": "Critical",
                            "LeakDetectorType": "Moisture",
                            "Status": { "Health": "Critical", "State": "Degraded" }
                        }"##,
                    ],
                    expect: expected_report(vec![], vec![]),
                },
                Check {
                    scenario: "missing and disabled resource states do not produce leak alerts",
                    input: vec![
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/MissingStatus",
                            "Id": "MissingStatus",
                            "Name": "Missing status leak detector",
                            "DetectorState": "Critical"
                        }"#,
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/MissingResourceState",
                            "Id": "MissingResourceState",
                            "Name": "Missing resource state leak detector",
                            "DetectorState": "Critical",
                            "Status": { "Health": "Critical" }
                        }"#,
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/Disabled",
                            "Id": "Disabled",
                            "Name": "Disabled leak detector",
                            "DetectorState": "Critical",
                            "Status": { "Health": "Critical", "State": "Disabled" }
                        }"#,
                    ],
                    expect: expected_report(vec![], vec![]),
                },
                Check {
                    scenario: "non-actionable and missing states do not produce report entries",
                    input: vec![
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/Unavailable",
                            "Id": "Unavailable",
                            "Name": "Unavailable leak detector",
                            "DetectorState": "Unavailable",
                            "Status": { "State": "Enabled" }
                        }"#,
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/Absent",
                            "Id": "Absent",
                            "Name": "Absent leak detector",
                            "DetectorState": "Absent",
                            "Status": { "State": "Enabled" }
                        }"#,
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/Vendor",
                            "Id": "Vendor",
                            "Name": "Vendor leak detector",
                            "DetectorState": "VendorDefinedState",
                            "Status": { "State": "Enabled" }
                        }"#,
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/Missing",
                            "Id": "Missing",
                            "Name": "Missing state leak detector",
                            "Status": { "State": "Enabled" }
                        }"#,
                        r#"{
                            "@odata.id": "/redfish/v1/Chassis/System/LeakDetectors/Null",
                            "Id": "Null",
                            "Name": "Null state leak detector",
                            "DetectorState": null,
                            "Status": { "State": "Enabled" }
                        }"#,
                    ],
                    expect: expected_report(vec![], vec![]),
                },
            ],
            |json_detectors| {
                let detectors = json_detectors
                    .into_iter()
                    .map(|json| {
                        Arc::new(
                            serde_json::from_str::<LeakDetector>(json)
                                .expect("valid leak detector"),
                        )
                    })
                    .collect();

                build_health_report(detectors, &context()).into()
            },
        );
    }
}
