/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Message types for the MQTT state change hook.

use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use model::machine::ManagedHostState;
use serde::Serialize;

/// MQTT message for managed host state changes.
///
/// Serializes to JSON with the state flattened directly into the message,
/// using `ManagedHostState`'s native serde serialization (lowercase state names).
#[derive(Debug, Clone, Serialize)]
pub struct ManagedHostStateChangeMessage<'a> {
    /// Unique identifier for the managed host machine.
    pub machine_id: &'a MachineId,
    /// ISO 8601 timestamp of the state change.
    pub timestamp: DateTime<Utc>,
    /// The managed host state.
    pub managed_host_state: &'a ManagedHostState,
}

impl<'a> ManagedHostStateChangeMessage<'a> {
    /// Create a new message from the given state change data.
    pub fn new(
        machine_id: &'a MachineId,
        state: &'a ManagedHostState,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            machine_id,
            timestamp,
            managed_host_state: state,
        }
    }

    /// Serialize the message to JSON bytes for MQTT publishing.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[cfg(test)]
mod tests {
    use model::machine::InstanceState;

    use super::*;

    #[allow(deprecated)]
    fn test_machine_id() -> MachineId {
        MachineId::default()
    }

    #[test]
    fn test_ready_state_serialization() {
        let machine_id = test_machine_id();
        let state = ManagedHostState::Ready;
        let timestamp = Utc::now();

        let message = ManagedHostStateChangeMessage::new(&machine_id, &state, timestamp);
        let json = message.to_json_bytes().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();

        let state_obj = parsed.get("managed_host_state").unwrap();
        assert_eq!(state_obj.get("state").unwrap(), "ready");
        assert!(parsed.get("machine_id").is_some());
        assert!(parsed.get("timestamp").is_some());
    }

    #[test]
    fn test_assigned_state_has_nested_fields() {
        let machine_id = test_machine_id();
        let state = ManagedHostState::Assigned {
            instance_state: InstanceState::Ready,
        };
        let timestamp = Utc::now();

        let message = ManagedHostStateChangeMessage::new(&machine_id, &state, timestamp);
        let json = message.to_json_bytes().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();

        let state_obj = parsed.get("managed_host_state").unwrap();
        assert_eq!(state_obj.get("state").unwrap(), "assigned");
        assert!(state_obj.get("instance_state").is_some());
    }

    #[test]
    fn test_timestamp_is_rfc3339() {
        let machine_id = test_machine_id();
        let state = ManagedHostState::Ready;
        let timestamp = Utc::now();

        let message = ManagedHostStateChangeMessage::new(&machine_id, &state, timestamp);
        let json = message.to_json_bytes().unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();

        let ts = parsed.get("timestamp").unwrap().as_str().unwrap();
        chrono::DateTime::parse_from_rfc3339(ts).expect("timestamp should be RFC 3339");
    }
}
