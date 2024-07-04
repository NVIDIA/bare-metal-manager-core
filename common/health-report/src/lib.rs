/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Reports the aggregate health of a system or subsystem
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Identifies the source of the health report
    /// This could e.g. be `forge-dpu-agent`, `forge-host-validation`,
    /// or an override (e.g. `overrides.sre-team`)
    pub source: String,
    /// The time when this health status was observed.
    ///
    /// Clients submitting a health report can leave this field empty in order
    /// to store the current time as timestamp.
    ///
    /// In case the HealthReport is derived by combining the reports of various
    /// subsystems, the timestamp will relate to the oldest overall report.
    pub observed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// List of all successful health probes
    pub successes: Vec<HealthProbeSuccess>,
    /// List of all alerts that have been raised by health probes
    pub alerts: Vec<HealthProbeAlert>,
}

/// An alert that has been raised by a health-probe
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct HealthProbeAlert {
    /// Stable ID of the health probe that raised an alert
    pub id: HealthProbeId,
    /// The first time the probe raised an alert
    /// If this field is empty while the HealthReport is sent to carbide-api
    /// the behavior is as follows:
    /// - If an alert of the same `id` was reported before, the timestamp of the
    /// previous alert will be retained.
    /// - If this is a new alert, the timestamp will be set to "now".
    pub in_alert_since: Option<chrono::DateTime<chrono::Utc>>,
    /// A message that describes the alert
    pub message: String,
    /// An optional message that will be relayed to tenants
    pub tenant_message: Option<String>,
    /// Classifications for this alert
    /// A string is used here to maintain flexibility
    pub classifications: Vec<HealthAlertClassification>,
}

/// A successful health probe (reported no alerts)
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct HealthProbeSuccess {
    /// Stable ID of the health probe that succeeded
    pub id: HealthProbeId,
}

/// A well-known name of a probe that generated an alert
#[derive(PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct HealthProbeId(String);

impl std::fmt::Debug for HealthProbeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl std::fmt::Display for HealthProbeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for HealthProbeId {
    type Err = HealthReportConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HealthProbeId(s.to_string()))
    }
}

impl HealthProbeId {
    /// Returns a String representation of the probe
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Classifies the impact of a health alert on the system
#[derive(PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct HealthAlertClassification(String);

impl std::fmt::Debug for HealthAlertClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl std::fmt::Display for HealthAlertClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for HealthAlertClassification {
    type Err = HealthReportConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(HealthAlertClassification(s.to_string()))
    }
}

impl HealthAlertClassification {
    /// Returns a String representation of the Health Alert
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Prevents Hosts from transitioning between any state
    pub fn prevent_host_state_changes() -> Self {
        Self("PreventHostStateChanges".to_string())
    }
}

/// A health report could not be converted from an external format
#[derive(thiserror::Error, Debug, Clone)]
#[error("Can not convert Health Report")]
pub struct HealthReportConversionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_probe_id() {
        let classification = HealthProbeId("Network".to_string());
        assert_eq!(
            format!("{:?} {}", classification, classification).as_str(),
            "\"Network\" Network"
        );
    }

    #[test]
    fn print_classification() {
        let classification = HealthAlertClassification::prevent_host_state_changes();
        assert_eq!(
            format!("{:?} {}", classification, classification).as_str(),
            "\"PreventHostStateChanges\" PreventHostStateChanges"
        );
    }

    #[test]
    fn serialize_health_report() {
        let report = HealthReport {
            source: "Reporter".to_string(),
            observed_at: Some("2024-01-01T19:00:01.100Z".parse().unwrap()),
            successes: vec![
                HealthProbeSuccess {
                    id: HealthProbeId("Probe1".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("Probe2".to_string()),
                },
            ],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("Probe3".to_string()),
                    in_alert_since: Some("2024-01-02T21:00:01.100Z".parse().unwrap()),
                    message: "Probe3 failed".to_string(),
                    tenant_message: Some("Internal Error".to_string()),
                    classifications: vec![
                        HealthAlertClassification("C1".to_string()),
                        HealthAlertClassification("C2".to_string()),
                    ],
                },
                HealthProbeAlert {
                    id: HealthProbeId("Probe4".to_string()),
                    in_alert_since: None,
                    message: "Probe4 failed".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            "{\"source\":\"Reporter\",\"observed_at\":\"2024-01-01T19:00:01.100Z\",\"successes\":[{\"id\":\"Probe1\"},{\"id\":\"Probe2\"}],\"alerts\":[{\"id\":\"Probe3\",\"in_alert_since\":\"2024-01-02T21:00:01.100Z\",\"message\":\"Probe3 failed\",\"tenant_message\":\"Internal Error\",\"classifications\":[\"C1\",\"C2\"]},{\"id\":\"Probe4\",\"in_alert_since\":null,\"message\":\"Probe4 failed\",\"tenant_message\":null,\"classifications\":[]}]}"
        );

        assert_eq!(
            serde_json::from_str::<HealthReport>(&serialized).unwrap(),
            report
        );
    }
}
