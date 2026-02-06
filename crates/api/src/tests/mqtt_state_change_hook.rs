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

//! Integration tests for the MQTT state change hook.
//!
//! Unit tests for message serialization are in the message module itself.
//! These tests verify the hook behavior and MQTT topic construction.

use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use chrono::Utc;
use model::machine::ManagedHostState;

use crate::mqtt_state_change_hook::message::ManagedHostStateChangeMessage;

fn test_machine_id() -> MachineId {
    MachineId::new(
        MachineIdSource::ProductBoardChassisSerial,
        [0; 32],
        MachineType::Host,
    )
}

/// Tests that the message JSON is valid and contains required fields
#[test]
fn test_message_json_structure() {
    let machine_id = test_machine_id();
    let state = ManagedHostState::Ready;
    let timestamp = Utc::now();

    let message = ManagedHostStateChangeMessage::new(&machine_id, &state, timestamp);
    let json = message
        .to_json_bytes()
        .expect("serialization should succeed");
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();

    // Required fields
    assert!(parsed.get("machine_id").is_some());
    assert!(parsed.get("managed_host_state").is_some());
    assert!(parsed.get("timestamp").is_some());

    // State should be nested with its serde tag
    let state_obj = parsed.get("managed_host_state").unwrap();
    assert_eq!(state_obj.get("state").unwrap(), "ready");
}

/// Tests that complex states include their nested fields
#[test]
fn test_complex_state_has_nested_fields() {
    use model::machine::InstanceState;

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

/// Tests that the timestamp is in RFC 3339 format (ISO 8601)
#[test]
fn test_timestamp_format() {
    let machine_id = test_machine_id();
    let state = ManagedHostState::Ready;
    let timestamp = Utc::now();

    let message = ManagedHostStateChangeMessage::new(&machine_id, &state, timestamp);
    let json = message.to_json_bytes().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();

    let ts = parsed.get("timestamp").unwrap().as_str().unwrap();
    chrono::DateTime::parse_from_rfc3339(ts).expect("timestamp should be RFC 3339");
}
