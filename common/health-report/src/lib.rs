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

/// Reports the aggregate health of a system or subsystem
pub struct HealthReport {
    /// Identifies the source of the health report
    /// This could e.g. be `forge-dpu-agent`, `forge-host-validation`,
    /// or an override (e.g. `overrides.sre-team`)
    pub source: String,
    /// List of all successful health probes
    pub successes: Vec<HealthProbeSuccess>,
    /// List of all alerts that have been raised by health probes
    pub alerts: Vec<HealthProbeAlert>,
}

/// An alert that has been raised by a health-probe
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
pub struct HealthProbeSuccess {
    /// Stable ID of the health probe that raised an alert
    pub id: HealthProbeId,
}

/// A well-known name of a probe that generated an alert
#[derive(PartialEq, Eq, Hash, Clone)]
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
#[derive(PartialEq, Eq, Hash, Clone)]
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
}
