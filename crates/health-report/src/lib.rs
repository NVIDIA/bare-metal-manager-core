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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::Hash;
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

impl Default for HealthReport {
    fn default() -> Self {
        Self::empty("Default::default".to_string())
    }
}

impl HealthReport {
    pub const SKU_VALIDATION_SOURCE: &str = "sku-validation";

    /// Returns a health report with no successes or errors reported
    pub fn empty(source: String) -> Self {
        Self {
            source,
            observed_at: Some(chrono::Utc::now()),
            successes: vec![],
            alerts: vec![],
        }
    }

    /// Calculate a hash value for all the Alerts and Successes in the Report
    ///
    /// The hash value can be used to quickly compare health reports - even in
    /// cases where timestamps of the reports might be different
    pub fn hash_without_timestamps<H: std::hash::Hasher>(&self, hasher: &mut H) {
        // The BTreeMaps are used to retain ordering while hashing in order to make the hash consistent
        let mut successes = BTreeMap::new();
        for success in self.successes.iter() {
            successes.insert((success.id.clone(), success.target.clone()), success);
        }
        hasher.write_usize(successes.len());
        for success in successes.values() {
            success.hash_without_timestamps(hasher);
        }

        let mut alerts = BTreeMap::new();
        for alert in self.alerts.iter() {
            alerts.insert((alert.id.clone(), alert.target.clone()), alert);
        }
        hasher.write_usize(alerts.len());
        for alert in alerts.values() {
            alert.hash_without_timestamps(hasher);
        }
    }

    /// Returns an iterator over all classifications stored in the Health Report
    /// The iterator can report duplicates
    pub fn classifications(&self) -> impl Iterator<Item = &HealthAlertClassification> {
        self.alerts
            .iter()
            .flat_map(|alert| alert.classifications.iter())
    }

    /// Returns `true` if the report contains any alert with the given classification
    pub fn has_classification(&self, classification: &HealthAlertClassification) -> bool {
        self.find_alert_by_classification(classification).is_some()
    }

    /// Finds the first alert given a given classification
    pub fn find_alert_by_classification(
        &self,
        classification: &HealthAlertClassification,
    ) -> Option<&HealthProbeAlert> {
        self.alerts
            .iter()
            .find(|alert| alert.classifications.contains(classification))
    }

    /// Returns a health report which indicates that an actually expected health report was absent
    pub fn missing_report() -> Self {
        Self {
            source: "MissingReport".to_string(),
            observed_at: Some(chrono::Utc::now()),
            successes: vec![],
            alerts: vec![HealthProbeAlert::missing_report()],
        }
    }

    /// Returns a health report which indicates that a HealthReport could not be parsed
    pub fn malformed_report(error: impl std::error::Error) -> Self {
        Self {
            source: "MalformedReport".to_string(),
            observed_at: Some(chrono::Utc::now()),
            successes: vec![],
            alerts: vec![HealthProbeAlert::malformed_report(error.to_string())],
        }
    }

    /// Returns a health report that indicates that no fresh data health data
    /// has been received from a certain subsystem
    pub fn heartbeat_timeout(source: String, target: String, message: String) -> Self {
        Self {
            source,
            observed_at: Some(chrono::Utc::now()),
            successes: vec![],
            alerts: vec![HealthProbeAlert::heartbeat_timeout(target, message)],
        }
    }

    /// Returns a health report that indicates that the DPU agent is on a stale version, older than
    /// some threshold
    pub fn stale_agent_version(
        source: String,
        dpu_id: String,
        message: String,
        prevent_allocations: bool,
    ) -> Self {
        Self {
            source,
            observed_at: Some(chrono::Utc::now()),
            successes: vec![],
            alerts: vec![HealthProbeAlert::stale_agent_version(
                dpu_id,
                message,
                prevent_allocations,
            )],
        }
    }

    /// Returns a health report which indicates that a machine failed SKU validation
    pub fn sku_mismatch(mismatches: Vec<String>) -> Self {
        Self {
            source: Self::SKU_VALIDATION_SOURCE.to_string(),
            observed_at: Some(chrono::Utc::now()),
            successes: vec![],
            alerts: vec![HealthProbeAlert::sku_mismatch(mismatches)],
        }
    }

    /// Returns a health report which indicates that a machine failed SKU validation
    pub fn sku_validation_success() -> Self {
        Self {
            source: Self::SKU_VALIDATION_SOURCE.to_string(),
            observed_at: Some(chrono::Utc::now()),
            successes: vec![HealthProbeSuccess {
                id: HealthProbeId::sku_validation(),
                target: None,
            }],
            alerts: vec![],
        }
    }

    /// Returns a health report which indicates that a machine failed SKU validation
    pub fn sku_missing(sku_id: &str) -> Self {
        Self {
            source: Self::SKU_VALIDATION_SOURCE.to_string(),
            observed_at: Some(chrono::Utc::now()),
            successes: vec![],
            alerts: vec![HealthProbeAlert::sku_missing(sku_id)],
        }
    }

    /// Update the in_alert_since timestamps on all alerts in the reports
    /// by taking into account the timestaps in a previous report
    /// - If the alert has been reported in the previous report, the old timestamp
    ///   will be retained.
    /// - If the alert has not been reported, the current time will be used
    pub fn update_in_alert_since(&mut self, previous: Option<&HealthReport>) {
        let mut previous_in_alert_times = HashMap::new();
        if let Some(previous) = previous {
            for prev_alert in previous.alerts.iter() {
                if let Some(timestamp) = prev_alert.in_alert_since {
                    previous_in_alert_times.insert(
                        (prev_alert.id.clone(), prev_alert.target.clone()),
                        timestamp,
                    );
                }
            }
        }

        for alert in self.alerts.iter_mut() {
            alert.in_alert_since = Some(
                match previous_in_alert_times.get(&(alert.id.clone(), alert.target.clone())) {
                    Some(time) => *time,
                    None => chrono::Utc::now(),
                },
            );
        }
    }

    /// Merges the content of another health report into the current health report
    /// The merge operations works as follows:
    /// - If the current report does not mention a certain health probe report
    ///   (based on the ID and target), then the result from `other` is copied over
    /// - If both reports reference the same probe IDs and targets
    ///   - the classifications of both alerts will be merged
    ///   - messages of both alerts will be concatenated
    ///   - the smaller `in_alert_since` timestamp of both alerts will be utilized
    pub fn merge(&mut self, other: &HealthReport) {
        self.observed_at = match (self.observed_at, other.observed_at) {
            (Some(t1), Some(t2)) => Some(t1.min(t2)),
            (Some(t1), None) => Some(t1),
            (None, Some(t2)) => Some(t2),
            (None, None) => None,
        };

        // BTreeMap here is used to retain ordering
        let mut successes = BTreeSet::new();
        for success in self.successes.iter() {
            successes.insert((success.id.clone(), success.target.clone()));
        }
        for success in other.successes.iter() {
            successes.insert((success.id.clone(), success.target.clone()));
        }

        let mut alerts = BTreeMap::new();
        for alert in self.alerts.iter() {
            // If an alarm and success are reported for the same probe, then
            // the alarm takes precedence
            successes.remove(&(alert.id.clone(), alert.target.clone()));
            alerts.insert((alert.id.clone(), alert.target.clone()), alert.clone());
        }
        for alert in other.alerts.iter() {
            successes.remove(&(alert.id.clone(), alert.target.clone()));
            match alerts.entry((alert.id.clone(), alert.target.clone())) {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(alert.clone());
                }
                std::collections::btree_map::Entry::Occupied(mut existing) => {
                    existing.get_mut().merge(alert);
                }
            }
        }

        self.successes = successes
            .into_iter()
            .map(|(id, target)| HealthProbeSuccess { id, target })
            .collect();
        self.alerts = alerts.into_values().collect();
    }

    /// Check if reboot from state machine is blocked.
    pub fn is_reboot_blocked_in_state_machine(&self) -> bool {
        self.alerts.iter().any(|x| {
            x.classifications.iter().any(|a| {
                *a == HealthAlertClassification::stop_reboot_for_automatic_recovery_from_state_machine()
            })
        })
    }
}

fn merge_classifications(
    c1: &[HealthAlertClassification],
    c2: &[HealthAlertClassification],
) -> Vec<HealthAlertClassification> {
    let mut set = BTreeSet::from_iter(c1.iter().cloned());
    set.extend(c2.iter().cloned());
    set.into_iter().collect()
}

/// How to apply a HealthReport override.
#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum OverrideMode {
    /// Successes or alerts in the override HealthReports will supersede any
    /// successes and alerts in the non-override HealthReports, merging by id
    /// and target.
    Merge,
    /// The replacement HealthReport will completely replace any existing
    /// HealthReports. Any successes or alerts in the original or merged HealthReports
    /// are ignored.
    Replace,
}

/// An alert that has been raised by a health-probe
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct HealthProbeAlert {
    /// Stable ID of the health probe that raised an alert
    pub id: HealthProbeId,
    /// The component that the probe is targeting.
    /// This could be e.g.
    /// - a physical component (e.g. a Fan probe might check various chassis fans)
    /// - a logical component (a check which probes whether disk space is available
    ///   can list the volume name as target)
    ///
    /// The field is optional. It can be absent if the probe ID already fully
    /// describes what is tested.
    ///
    /// Targets are useful if the same type of probe checks the health of multiple components.
    /// If a health report lists multiple probes of the same type and with different targets,
    /// then those probe/target combinations are treated individually.
    /// E.g. the `in_alert_since` and `classifications` fields for each probe/target
    /// combination are calculated individually when reports are merged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The first time the probe raised an alert
    /// If this field is empty while the HealthReport is sent to carbide-api
    /// the behavior is as follows:
    /// - If an alert of the same `id` was reported before, the timestamp of the
    ///   previous alert will be retained.
    /// - If this is a new alert, the timestamp will be set to "now".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_alert_since: Option<chrono::DateTime<chrono::Utc>>,
    /// A message that describes the alert
    pub message: String,
    /// An optional message that will be relayed to tenants
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_message: Option<String>,
    /// Classifications for this alert
    /// A string is used here to maintain flexibility
    pub classifications: Vec<HealthAlertClassification>,
}

impl HealthProbeAlert {
    /// Calculate a hash value for the Alert while excluding the timestamp
    pub fn hash_without_timestamps<H: std::hash::Hasher>(&self, hasher: &mut H) {
        self.id.0.hash(hasher);
        self.target.hash(hasher);
        self.message.hash(hasher);
        self.tenant_message.hash(hasher);
        let sorted_classifications: BTreeSet<_> = self.classifications.iter().collect();
        sorted_classifications.hash(hasher);
    }

    /// Creates a HeartbeatTimeout alert
    pub fn heartbeat_timeout(target: String, message: String) -> Self {
        Self {
            id: HealthProbeId::heartbeat_timeout(),
            target: Some(target),
            in_alert_since: Some(chrono::Utc::now()),
            message,
            tenant_message: None,
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::prevent_host_state_changes(),
            ],
        }
    }

    /// Creates a StaleAgentVersion alert
    pub fn stale_agent_version(dpu_id: String, message: String, prevent_allocations: bool) -> Self {
        Self {
            id: HealthProbeId::stale_agent_version(),
            target: Some(dpu_id),
            in_alert_since: Some(chrono::Utc::now()),
            message,
            tenant_message: None,
            classifications: if prevent_allocations {
                vec![HealthAlertClassification::prevent_allocations()]
            } else {
                vec![]
            },
        }
    }

    /// Creates a MissingReport alert
    pub fn missing_report() -> Self {
        Self {
            id: HealthProbeId::missing_report(),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: "A HealthReport is not available".to_string(),
            tenant_message: None,
            classifications: vec![],
        }
    }

    /// Creates a MalformedReport alert
    pub fn malformed_report(error: String) -> Self {
        Self {
            id: HealthProbeId::malformed_report(),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: format!("Health report can not be parsed: {error}"),
            tenant_message: None,
            classifications: vec![],
        }
    }

    pub fn sku_mismatch(mismatches: Vec<String>) -> Self {
        Self {
            id: HealthProbeId::sku_validation(),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: mismatches.join("\n"),
            tenant_message: None,
            classifications: vec![HealthAlertClassification::prevent_allocations()],
        }
    }

    pub fn sku_missing(sku_id: &str) -> Self {
        Self {
            id: HealthProbeId::sku_validation(),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: format!("The assigned sku {sku_id} does not exist"),
            tenant_message: None,
            classifications: vec![HealthAlertClassification::prevent_allocations()],
        }
    }
    /// Merge a HealthProbeAlert with the report from another probe of the same type
    ///
    /// The function does not check whether the Probe ID and target are equivalent.
    /// It's expected from the caller to only call this function for probes with the same target.
    fn merge(&mut self, other: &HealthProbeAlert) {
        self.classifications = merge_classifications(&self.classifications, &other.classifications);
        if self.message.is_empty() {
            self.message = other.message.clone();
        } else if !other.message.is_empty() {
            self.message.push('\n');
            self.message += other.message.as_str();
        }
        self.tenant_message = match (&self.tenant_message, &other.tenant_message) {
            (Some(m1), Some(m2)) => Some(format!("{m1}\n{m2}")),
            (Some(m1), None) => Some(m1.clone()),
            (None, Some(m2)) => Some(m2.clone()),
            (None, None) => None,
        };
        self.in_alert_since = match (other.in_alert_since, self.in_alert_since) {
            (Some(d1), Some(d2)) => Some(d1.min(d2)),
            (Some(d1), None) => Some(d1),
            (None, Some(d2)) => Some(d2),
            (None, None) => None,
        };
    }
}

/// A successful health probe (reported no alerts)
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct HealthProbeSuccess {
    /// Stable ID of the health probe that succeeded
    pub id: HealthProbeId,
    /// The component that the probe is targeting.
    /// This could be e.g.
    /// - a physical component (e.g. a Fan probe might check various chassis fans)
    /// - a logical component (a check which probes whether disk space is available
    ///   can list the volume name as target)
    ///
    /// The field is optional. It can be absent if the probe ID already fully
    /// describes what is tested.
    ///
    /// Targets are useful if the same type of probe checks the health of multiple components.
    /// If a health report lists multiple probes of the same type and with different targets,
    /// then those probe/target combinations are treated individually.
    /// E.g. the `in_alert_since` and `classifications` fields for each probe/target
    /// combination are calculated individually when reports are merged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl HealthProbeSuccess {
    /// Calculate a hash value for the Success while excluding the timestamp
    pub fn hash_without_timestamps<H: std::hash::Hasher>(&self, hasher: &mut H) {
        self.id.0.hash(hasher);
        self.target.hash(hasher);
    }
}

/// A well-known name of a probe that generated an alert
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Serialize, Deserialize)]
pub struct HealthProbeId(String);

impl HealthProbeId {
    /// Returns the ID of the HealthProbe that indicates that no fresh data has been received
    pub fn heartbeat_timeout() -> Self {
        HealthProbeId("HeartbeatTimeout".to_string())
    }

    /// Returns the ID of the HealthProbe that indicates that the Agent Version is outdated
    pub fn stale_agent_version() -> Self {
        HealthProbeId("StaleAgentVersion".to_string())
    }

    /// The alert indicates that no health report was received, where health report
    /// was expected. It is different from `heartbeat_timeout` in the following sense
    /// - HeartbeatTimeout alerts can be emitted if data is available, but stale.
    ///   MissingReport is only emitted if data has never been received.
    /// - MissingReport is mainly used on the client side. It has no impact on
    ///   state changes.
    /// - MissingReport carries no classifications
    pub fn missing_report() -> Self {
        HealthProbeId("MissingReport".to_string())
    }

    /// An alert which can be generated if a HealthReport can not be parsed
    ///
    /// This alert should only be used client side if failing to render the health
    /// report is preferrable to failing the workflow.
    pub fn malformed_report() -> Self {
        HealthProbeId("MalformedReport".to_string())
    }

    /// The ID used by SKU validation for sending health reports
    ///
    /// Used by the state machine when SKU validation completes.
    pub fn sku_validation() -> Self {
        HealthProbeId("SkuValidation".to_string())
    }

    /// The ID is used to mark host under internal maintenance.
    /// This is mandatory if tenant wants to turn off the machine.
    pub fn internal_maintenance() -> Self {
        HealthProbeId("Maintenance".to_string())
    }
}

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
        if s.is_empty() {
            return Err(HealthReportConversionError::MissingId);
        }
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
#[derive(PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Serialize, Deserialize)]
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
        if s.is_empty() {
            return Err(HealthReportConversionError::MissingClassification);
        }
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

    /// Prevents hosts from being allocated as instances
    pub fn prevent_allocations() -> Self {
        Self("PreventAllocations".to_string())
    }

    /// The threshold that is used to externally alert on unhealthy hosts in the datacenter
    /// (e.g. via Prometheus/AlertManager alerts)
    /// will not take hosts with this classification into account
    pub fn suppress_external_alerting() -> Self {
        Self("SuppressExternalAlerting".to_string())
    }

    pub fn stop_reboot_for_automatic_recovery_from_state_machine() -> Self {
        Self("StopRebootForAutomaticRecoveryFromStateMachine".to_string())
    }

    // Hardware related issues, such as sensor failures, bmc errors, BMS issues etc.
    pub fn hardware() -> Self {
        Self("Hardware".to_string())
    }
}

/// A health report could not be converted from an external format
#[derive(thiserror::Error, Debug, Clone)]
#[error("Can not convert Health Report")]
pub enum HealthReportConversionError {
    #[error("Could not parse timestamp")]
    TimestampParseError,
    #[error("Missing source field")]
    MissingSource,
    #[error("Missing alert or success id field")]
    MissingId,
    #[error("Empty classification")]
    MissingClassification,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_probe_id() {
        let classification = HealthProbeId("Network".to_string());
        assert_eq!(
            format!("{classification:?} {classification}").as_str(),
            "\"Network\" Network"
        );
    }

    #[test]
    fn print_classification() {
        let classification = HealthAlertClassification::prevent_host_state_changes();
        assert_eq!(
            format!("{classification:?} {classification}").as_str(),
            "\"PreventHostStateChanges\" PreventHostStateChanges"
        );
    }

    #[test]
    fn has_classification() {
        let r1 = HealthReport {
            source: "Reporter".to_string(),
            observed_at: None,
            successes: vec![],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA1".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![HealthAlertClassification::prevent_allocations()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA2".to_string()),
                    target: Some("t1".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![
                        HealthAlertClassification::prevent_allocations(),
                        HealthAlertClassification::prevent_host_state_changes(),
                    ],
                },
            ],
        };

        assert!(r1.has_classification(&HealthAlertClassification::prevent_allocations()));
        assert_eq!(
            r1.find_alert_by_classification(&HealthAlertClassification::prevent_allocations())
                .unwrap()
                .id
                .0,
            "ProbeA1"
        );
        assert!(r1.has_classification(&HealthAlertClassification::prevent_host_state_changes()));
        assert_eq!(
            r1.find_alert_by_classification(
                &HealthAlertClassification::prevent_host_state_changes()
            )
            .unwrap()
            .id
            .0,
            "ProbeA2"
        );
        assert!(!r1.has_classification(&HealthAlertClassification("NotFound".to_string())));
        assert!(
            r1.find_alert_by_classification(&HealthAlertClassification("NotFound".to_string()))
                .is_none()
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
                    target: None,
                },
                HealthProbeSuccess {
                    id: HealthProbeId("Probe2".to_string()),
                    target: Some("c1".to_string()),
                },
            ],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("Probe3".to_string()),
                    target: None,
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
                    target: Some("c4".to_string()),
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
            "{\"source\":\"Reporter\",\"observed_at\":\"2024-01-01T19:00:01.100Z\",\"successes\":[{\"id\":\"Probe1\"},{\"id\":\"Probe2\",\"target\":\"c1\"}],\"alerts\":[{\"id\":\"Probe3\",\"in_alert_since\":\"2024-01-02T21:00:01.100Z\",\"message\":\"Probe3 failed\",\"tenant_message\":\"Internal Error\",\"classifications\":[\"C1\",\"C2\"]},{\"id\":\"Probe4\",\"target\":\"c4\",\"message\":\"Probe4 failed\",\"classifications\":[]}]}"
        );

        assert_eq!(
            serde_json::from_str::<HealthReport>(&serialized).unwrap(),
            report
        );
    }

    #[test]
    fn test_update_in_alert_since() {
        let old = HealthReport {
            source: "Reporter".to_string(),
            observed_at: Some("2024-01-01T19:00:01.100Z".parse().unwrap()),
            successes: vec![],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("Probe3".to_string()),
                    target: None,
                    in_alert_since: Some("2023-01-02T21:00:01.100Z".parse().unwrap()),
                    message: "Probe3 failed".to_string(),
                    tenant_message: Some("Internal Error".to_string()),
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeWithTarget".to_string()),
                    target: Some("t1".to_string()),
                    in_alert_since: Some("2023-01-02T22:00:01.100Z".parse().unwrap()),
                    message: "ProbeWithTarget.t1 failed".to_string(),
                    tenant_message: Some("Internal Error".to_string()),
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeWithTarget".to_string()),
                    target: Some("t2".to_string()),
                    in_alert_since: Some("2023-01-02T23:00:01.100Z".parse().unwrap()),
                    message: "ProbeWithTarget.t2 failed".to_string(),
                    tenant_message: Some("Internal Error".to_string()),
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("Probe4".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "Probe4 failed".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        let mut new = HealthReport {
            source: "Reporter".to_string(),
            observed_at: Some("2024-01-01T19:00:01.100Z".parse().unwrap()),
            successes: vec![],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("Probe3".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "Probe3 failed".to_string(),
                    tenant_message: Some("Internal Error".to_string()),
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeWithTarget".to_string()),
                    target: Some("t1".to_string()),
                    in_alert_since: None,
                    message: "ProbeWithTarget.t1 failed".to_string(),
                    tenant_message: Some("Internal Error".to_string()),
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeWithTarget".to_string()),
                    target: Some("t2".to_string()),
                    in_alert_since: None,
                    message: "ProbeWithTarget.t2 failed".to_string(),
                    tenant_message: Some("Internal Error".to_string()),
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("Probe4".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "Probe4 failed".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("Probe5".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "Probe5 failed".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        new.update_in_alert_since(Some(&old));
        assert_eq!(
            new.alerts[0].in_alert_since,
            Some("2023-01-02T21:00:01.100Z".parse().unwrap())
        );
        assert_eq!(
            new.alerts[1].in_alert_since,
            Some("2023-01-02T22:00:01.100Z".parse().unwrap())
        );
        assert_eq!(
            new.alerts[2].in_alert_since,
            Some("2023-01-02T23:00:01.100Z".parse().unwrap())
        );
        assert!(new.alerts[3].in_alert_since.is_some());
        assert!(new.alerts[4].in_alert_since.is_some());

        // The source timestamp is ignored and replaced by current time
        let mut new2 = HealthReport {
            source: "Reporter".to_string(),
            observed_at: Some("2024-01-01T19:00:01.100Z".parse().unwrap()),
            successes: vec![],
            alerts: vec![HealthProbeAlert {
                id: HealthProbeId("Probe3".to_string()),
                target: None,
                in_alert_since: None,
                message: "Probe3 failed".to_string(),
                tenant_message: Some("Internal Error".to_string()),
                classifications: vec![],
            }],
        };
        new2.update_in_alert_since(None);
        assert!(new.alerts[0].in_alert_since.is_some());
        assert_ne!(
            new.alerts[0].in_alert_since,
            Some("2024-01-01T19:00:01.100Z".parse().unwrap())
        );
    }

    #[test]
    fn test_merge_health_reports() {
        let r1 = HealthReport {
            source: "Reporter".to_string(),
            observed_at: Some("2024-01-01T19:00:01.100Z".parse().unwrap()),
            successes: vec![
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS1".to_string()),
                    target: None,
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t1".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t2".to_string()),
                },
            ],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA1".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA2".to_string()),
                    target: Some("t1".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA2".to_string()),
                    target: Some("t2".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec!["a".parse().unwrap(), "b".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA4".to_string()),
                    target: None,
                    in_alert_since: Some("2023-01-02T21:00:01.100Z".parse().unwrap()),
                    message: "m1".to_string(),
                    tenant_message: Some("t1".to_string()),
                    classifications: vec!["a".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA5".to_string()),
                    target: None,
                    in_alert_since: Some("2023-01-02T21:00:01.100Z".parse().unwrap()),
                    message: "m1".to_string(),
                    tenant_message: Some("t1".to_string()),
                    classifications: vec!["a".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA6".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA7".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        let r2 = HealthReport {
            source: "Reporter2".to_string(),
            observed_at: Some("2025-01-01T19:00:01.100Z".parse().unwrap()),
            successes: vec![
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t2".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t3".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS3".to_string()),
                    target: None,
                },
            ],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA2".to_string()),
                    target: Some("t2".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec!["b".parse().unwrap(), "c".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA2".to_string()),
                    target: Some("t3".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA3".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA4".to_string()),
                    target: None,
                    in_alert_since: Some("2023-01-02T20:00:01.100Z".parse().unwrap()),
                    message: "m2".to_string(),
                    tenant_message: Some("t2".to_string()),
                    classifications: vec!["b".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA5".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA6".to_string()),
                    target: None,
                    in_alert_since: Some("2023-01-02T21:00:01.100Z".parse().unwrap()),
                    message: "m1".to_string(),
                    tenant_message: Some("t1".to_string()),
                    classifications: vec!["b".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA7".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        let expected = HealthReport {
            source: "Reporter".to_string(),
            observed_at: Some("2024-01-01T19:00:01.100Z".parse().unwrap()),
            successes: vec![
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS1".to_string()),
                    target: None,
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t1".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t2".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t3".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS3".to_string()),
                    target: None,
                },
            ],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA1".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA2".to_string()),
                    target: Some("t1".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA2".to_string()),
                    target: Some("t2".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![
                        "a".parse().unwrap(),
                        "b".parse().unwrap(),
                        "c".parse().unwrap(),
                    ],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA2".to_string()),
                    target: Some("t3".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA3".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA4".to_string()),
                    target: None,
                    in_alert_since: Some("2023-01-02T20:00:01.100Z".parse().unwrap()),
                    message: "m1\nm2".to_string(),
                    tenant_message: Some("t1\nt2".to_string()),
                    classifications: vec!["a".parse().unwrap(), "b".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA5".to_string()),
                    target: None,
                    in_alert_since: Some("2023-01-02T21:00:01.100Z".parse().unwrap()),
                    message: "m1".to_string(),
                    tenant_message: Some("t1".to_string()),
                    classifications: vec!["a".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA6".to_string()),
                    target: None,
                    in_alert_since: Some("2023-01-02T21:00:01.100Z".parse().unwrap()),
                    message: "m1".to_string(),
                    tenant_message: Some("t1".to_string()),
                    classifications: vec!["b".parse().unwrap()],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeA7".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        let mut merged = r1.clone();
        merged.merge(&r2);

        assert_eq!(merged, expected);

        // Reverse merging should yield the same observed_at timestamp
        // We can't fully compare since the message ordering will be different
        let mut merged2 = r2.clone();
        merged2.merge(&r1);
        assert_eq!(merged2.observed_at, expected.observed_at);
    }

    #[test]
    fn test_alerts_remove_succeses_during_merge() {
        let r1 = HealthReport {
            source: "Reporter".to_string(),
            observed_at: None,
            successes: vec![
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS1".to_string()),
                    target: None,
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t1".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t2".to_string()),
                },
            ],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t2".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t3".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS3".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        let r2 = HealthReport {
            source: "Reporter2".to_string(),
            observed_at: None,
            successes: vec![
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t2".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t3".to_string()),
                },
                HealthProbeSuccess {
                    id: HealthProbeId("ProbeS3".to_string()),
                    target: None,
                },
            ],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS1".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t1".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        let expected = HealthReport {
            source: "Reporter".to_string(),
            observed_at: None,
            successes: vec![],
            alerts: vec![
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS1".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t1".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t2".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS2".to_string()),
                    target: Some("t3".to_string()),
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
                HealthProbeAlert {
                    id: HealthProbeId("ProbeS3".to_string()),
                    target: None,
                    in_alert_since: None,
                    message: "".to_string(),
                    tenant_message: None,
                    classifications: vec![],
                },
            ],
        };

        let mut merged = r1.clone();
        merged.merge(&r2);

        assert_eq!(merged, expected);

        // Reverse merging should yield the same observed_at timestamp
        // We can't fully compare since the message ordering will be different
        let mut merged2 = r2.clone();
        merged2.merge(&r1);
        assert_eq!(merged2.observed_at, expected.observed_at);
    }
}
