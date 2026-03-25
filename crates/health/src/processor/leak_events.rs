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

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{EventContext, EventProcessor};
use crate::sink::{
    Classification, CollectorEvent, HealthReport, HealthReportAlert, HealthReportSuccess, Probe,
    ReportSource,
};

const LEAK_DETECTOR_MARKER: &str = Classification::LeakDetector.as_str();

pub struct LeakEventProcessor {
    minimum_alerts_per_report: usize,
}

impl LeakEventProcessor {
    pub fn new(minimum_alerts_per_report: usize) -> Self {
        Self {
            minimum_alerts_per_report,
        }
    }

    fn is_leaking(&self, alerts: usize) -> bool {
        alerts >= self.minimum_alerts_per_report
    }
}

fn is_leak_detector_alert(alert: &HealthReportAlert) -> bool {
    alert
        .target
        .as_deref()
        .is_some_and(|input| input.contains(LEAK_DETECTOR_MARKER))
}

fn leak_details(alerts: &[&HealthReportAlert]) -> String {
    let targets: BTreeSet<String> = alerts
        .iter()
        .filter_map(|alert| alert.target.as_ref().cloned())
        .collect();

    if targets.is_empty() {
        return "unknown".to_string();
    }

    targets.iter().cloned().collect::<Vec<_>>().join(", ")
}

impl EventProcessor for LeakEventProcessor {
    fn processor_type(&self) -> &'static str {
        "leak_event_processor"
    }

    fn process_event(
        &self,
        _context: &EventContext,
        event: &CollectorEvent,
    ) -> Vec<CollectorEvent> {
        let CollectorEvent::HealthReport(report) = event else {
            return Vec::new();
        };

        let leak_alerts: Vec<&HealthReportAlert> = report
            .alerts
            .iter()
            .filter(|alert| is_leak_detector_alert(alert))
            .collect();

        let alerts = if self.is_leaking(leak_alerts.len()) {
            let details = leak_details(&leak_alerts);

            vec![HealthReportAlert {
                probe_id: Probe::LeakDetection,
                target: None,
                message: format!(
                    "Leak detected: {} leak-detector alerts reached threshold {} (detectors: {})",
                    leak_alerts.len(),
                    self.minimum_alerts_per_report,
                    details
                ),
                classifications: vec![Classification::Leak],
            }]
        } else {
            vec![]
        };

        let successes = if self.is_leaking(leak_alerts.len()) {
            vec![]
        } else {
            vec![HealthReportSuccess {
                probe_id: Probe::LeakDetection,
                target: None,
            }]
        };

        let leak_report = HealthReport {
            source: ReportSource::TrayLeakDetection,
            observed_at: Some(chrono::Utc::now()),
            successes,
            alerts,
        };

        vec![CollectorEvent::HealthReport(Arc::new(leak_report))]
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::BmcAddr;

    fn context() -> EventContext {
        EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").expect("valid mac"),
            },
            collector_type: "sensor_collector",
            metadata: None,
        }
    }

    fn leak_alert(target: &str) -> HealthReportAlert {
        HealthReportAlert {
            probe_id: Probe::Sensor,
            target: Some(target.to_string()),
            message: "LeakDetector found leak".to_string(),
            classifications: vec![Classification::LeakDetector],
        }
    }

    #[test]
    fn does_not_emit_alert_when_threshold_not_met() {
        let processor = LeakEventProcessor::new(2);
        let report = HealthReport {
            source: ReportSource::BmcSensors,
            observed_at: Some(chrono::Utc::now()),
            successes: Vec::new(),
            alerts: vec![leak_alert("LeakDetector_Probe")],
        };

        let emitted =
            processor.process_event(&context(), &CollectorEvent::HealthReport(Arc::new(report)));
        assert_eq!(emitted.len(), 1);

        let CollectorEvent::HealthReport(derived) = &emitted[0] else {
            panic!("expected derived health report");
        };

        assert_eq!(derived.alerts.len(), 0);
        assert_eq!(derived.successes.len(), 1);
        assert_eq!(derived.successes[0].probe_id, Probe::LeakDetection);
    }

    #[test]
    fn emits_derived_leak_report_when_threshold_met() {
        let processor = LeakEventProcessor::new(1);
        let report = HealthReport {
            source: ReportSource::BmcSensors,
            observed_at: Some(chrono::Utc::now()),
            successes: Vec::new(),
            alerts: vec![leak_alert("LeakDetector_Probe")],
        };

        let emitted =
            processor.process_event(&context(), &CollectorEvent::HealthReport(Arc::new(report)));
        assert_eq!(emitted.len(), 1);

        let CollectorEvent::HealthReport(derived) = &emitted[0] else {
            panic!("expected derived health report");
        };
        assert_eq!(derived.source, ReportSource::TrayLeakDetection);
        assert_eq!(derived.alerts.len(), 1);
        assert_eq!(derived.alerts[0].probe_id, Probe::LeakDetection);
        assert!(
            derived.alerts[0]
                .classifications
                .iter()
                .any(|classification| classification == &Classification::Leak)
        );
    }

    #[test]
    fn ignores_non_health_report_events() {
        let processor = LeakEventProcessor::new(1);
        let metric_event = CollectorEvent::Metric(
            crate::sink::SensorHealthData {
                key: "k".to_string(),
                name: "n".to_string(),
                metric_type: "gauge".to_string(),
                unit: "count".to_string(),
                value: 1.0,
                labels: Vec::new(),
                context: None,
            }
            .into(),
        );
        let emitted = processor.process_event(&context(), &metric_event);
        assert!(emitted.is_empty());
    }
}
