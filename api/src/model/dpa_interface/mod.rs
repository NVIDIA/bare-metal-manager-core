/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::model::StateSla;
use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

mod slas;

/// State of a dpa interface as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum DpaInterfaceControllerState {
    /// Initial state
    Provisioning,
    /// The dpa interface is ready. It has been configured with a zero VNI
    Ready,
    /// The VNI associated with the DPA interface is being set
    WaitingForSetVNI,
    /// The Dpa Interface has been configured with a non-zero VNI
    Assigned,
    /// The VNI associated with the DPA interface is being reset
    WaitingForResetVNI,
}

impl Display for DpaInterfaceControllerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpaInterfaceNetworkConfig {
    pub use_admin_network: Option<bool>,
    pub quarantine_state: Option<DpaInterfaceQuarantineState>,
}

impl Display for DpaInterfaceNetworkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Default for DpaInterfaceNetworkConfig {
    fn default() -> Self {
        DpaInterfaceNetworkConfig {
            use_admin_network: Some(true),
            quarantine_state: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpaInterfaceQuarantineState {
    pub reason: Option<String>,
    pub mode: DpaInterfaceQuarantineMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpaInterfaceQuarantineMode {
    BlockAllTraffic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpaInterfaceNetworkStatusObservation {
    pub observed_at: DateTime<Utc>,
    pub network_config_version: Option<ConfigVersion>,
}

impl Display for DpaInterfaceNetworkStatusObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Returns the SLA for the current state
pub fn state_sla(state: &DpaInterfaceControllerState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));
    match state {
        DpaInterfaceControllerState::Provisioning => StateSla::with_sla(
            std::time::Duration::from_secs(slas::PROVISIONING),
            time_in_state,
        ),
        DpaInterfaceControllerState::Ready => StateSla::no_sla(),
        DpaInterfaceControllerState::WaitingForSetVNI => StateSla::with_sla(
            std::time::Duration::from_secs(slas::WAITINGFORSETVNI),
            time_in_state,
        ),
        DpaInterfaceControllerState::Assigned => StateSla::no_sla(),
        DpaInterfaceControllerState::WaitingForResetVNI => StateSla::with_sla(
            std::time::Duration::from_secs(slas::WAITINGFORRESETVNI),
            time_in_state,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = DpaInterfaceControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<DpaInterfaceControllerState>(&serialized).unwrap(),
            state
        );

        let state = DpaInterfaceControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<DpaInterfaceControllerState>(&serialized).unwrap(),
            state
        );
    }
}
