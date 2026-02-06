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

// src/registry/entry.rs
// MqttRegistryEntry implementation for message registration data
// encapsulation..
//
// Contains the entry abstraction that encapsulates message metadata
// plus serialization handlers as one entry type. Each entry represents
// a complete registration for one message type with all the information
// needed to handle that type.

use super::types::{
    DeserializeHandler, MessageTypeInfo, PublishOptions, SerializationFormat, SerializeHandler,
};
use crate::errors::MqtteaClientError;

// MqttRegistryEntry stores complete registration information for a
// message type. It encapsulates metadata and handlers together.
pub struct MqttRegistryEntry {
    // message_type_info contains the metadata for this
    // registered message type.
    pub message_type_info: MessageTypeInfo,
    // serialize_handler converts typed messages to bytes for
    // MQTT transmission.
    pub serialize_handler: SerializeHandler,
    // deserialize_handler converts received bytes back to
    // typed messages.
    pub deserialize_handler: DeserializeHandler,
}

// Debug implementation for MqttRegistryEntry.
impl std::fmt::Debug for MqttRegistryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MqttRegistryEntry")
            .field("message_type_info", &self.message_type_info)
            .field("serialize_handler", &"<function>")
            .field("deserialize_handler", &"<function>")
            .finish()
    }
}

impl MqttRegistryEntry {
    // new creates a new registry entry with all required components.
    pub fn new(
        message_type_info: MessageTypeInfo,
        serialize_handler: SerializeHandler,
        deserialize_handler: DeserializeHandler,
    ) -> Self {
        Self {
            message_type_info,
            serialize_handler,
            deserialize_handler,
        }
    }

    // type_name returns the human-readable type name for this entry.
    pub fn type_name(&self) -> &str {
        &self.message_type_info.type_name
    }

    // patterns returns the topic patterns for this entry.
    pub fn patterns(&self) -> &[String] {
        &self.message_type_info.patterns
    }

    // publish_options returns the PublishOptions override for this entry.
    pub fn publish_options(&self) -> Option<PublishOptions> {
        self.message_type_info.publish_options
    }

    // qos returns the QoS override for this entry.
    pub fn qos(&self) -> Option<rumqttc::QoS> {
        self.message_type_info
            .publish_options
            .and_then(|opts| opts.qos)
    }

    // qos returns the retain override for this entry.
    pub fn retain(&self) -> Option<bool> {
        self.message_type_info
            .publish_options
            .and_then(|opts| opts.retain)
    }

    // format returns the serialization format for this entry.
    pub fn format(&self) -> SerializationFormat {
        self.message_type_info.format
    }

    // serialize converts a message to bytes using this entry's handler.
    pub fn serialize(&self, message: &dyn std::any::Any) -> Result<Vec<u8>, MqtteaClientError> {
        (self.serialize_handler)(message)
    }

    // deserialize converts bytes to a message using this entry's handler.
    pub fn deserialize(
        &self,
        bytes: &[u8],
    ) -> Result<Box<dyn std::any::Any + Send>, MqtteaClientError> {
        (self.deserialize_handler)(bytes)
    }

    // pattern_count returns the number of patterns registered for this entry.
    pub fn pattern_count(&self) -> usize {
        self.message_type_info.pattern_count()
    }

    // has_pattern checks if this entry is registered for a specific pattern.
    pub fn has_pattern(&self, pattern: &str) -> bool {
        self.message_type_info.has_pattern(pattern)
    }

    // uses_qos_override checks if this entry has a custom QoS setting.
    pub fn uses_qos_override(&self) -> bool {
        self.message_type_info.uses_qos_override()
    }

    // effective_qos returns the QoS that would be used for this entry.
    pub fn effective_qos(&self, default_qos: rumqttc::QoS) -> rumqttc::QoS {
        self.message_type_info.effective_qos(default_qos)
    }

    // is_format checks if this entry uses a specific serialization format.
    pub fn is_format(&self, format: SerializationFormat) -> bool {
        self.message_type_info.is_format(format)
    }

    // validate_serialization_round_trip performs a test serialization and
    // deserialization. Useful for debugging serialization handler implementations.
    pub fn validate_serialization_round_trip<T: 'static + PartialEq + std::fmt::Debug>(
        &self,
        test_message: &T,
    ) -> Result<(), MqtteaClientError> {
        // Serialize the test message
        let bytes = self.serialize(test_message as &dyn std::any::Any)?;

        // Deserialize back to Any
        let any_result = self.deserialize(&bytes)?;

        // Try to downcast back to original type
        if let Ok(restored) = any_result.downcast::<T>() {
            if test_message == &*restored {
                Ok(())
            } else {
                Err(MqtteaClientError::RawMessageError(
                    "Round-trip test failed: restored message differs from original".to_string(),
                ))
            }
        } else {
            Err(MqtteaClientError::RawMessageError(
                "Round-trip test failed: could not downcast restored message".to_string(),
            ))
        }
    }
}
