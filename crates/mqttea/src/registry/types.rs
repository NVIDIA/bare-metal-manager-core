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

// src/registry/types.rs
// Common types and enums used throughout the registry system.
//
// Contains shared registry bits like serialization formats and
// message metadata that are used throughout this code.

use rumqttc::QoS;

use crate::errors::MqtteaClientError;

// SerializationFormat defines the supported message serialization
// formats. This is a core registry concept used for routing messages
// to appropriate handlers.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SerializationFormat {
    Protobuf,
    Json,
    Yaml,
    Raw,
}

// MessageTypeInfo stores metadata about a registered message type.
// Contains all information needed to route and configure message
// handling for a specific type.
#[derive(Clone, Debug)]
pub struct MessageTypeInfo {
    // type_name is the human-readable type name for debugging
    // and logging.
    pub type_name: String,
    // patterns are regex patterns that map topics to this
    // message type.
    pub patterns: Vec<String>,
    // publish_options are the optional overrides for
    // any global publish options.
    pub publish_options: Option<PublishOptions>,
    // format specifies which serialization format this type uses.
    pub format: SerializationFormat,
}

// PublishOptions contains options used for publishing
// messages. There is a global/default PublishOptions
// that are used for all messages, and then users can
// set type and topic-specific overrides as needed.
#[derive(Clone, Copy, Debug, Default)]
pub struct PublishOptions {
    // qos is the MQTT QoS level override for this
    // message type.
    pub qos: Option<QoS>,
    // retain is the MQTT retain override for this message type.
    pub retain: Option<bool>,
}
impl PublishOptions {
    pub fn with_qos(mut self, qos: QoS) -> Self {
        self.qos = Some(qos);
        self
    }

    pub fn with_retain(mut self, retain: bool) -> Self {
        self.retain = Some(retain);
        self
    }
}

// SerializeHandler converts any message to bytes for
// MQTT transmission.
pub type SerializeHandler =
    Box<dyn Fn(&dyn std::any::Any) -> Result<Vec<u8>, MqtteaClientError> + Send + Sync>;

// DeserializeHandler converts bytes back to typed messages
// from MQTT reception.
pub type DeserializeHandler =
    Box<dyn Fn(&[u8]) -> Result<Box<dyn std::any::Any + Send>, MqtteaClientError> + Send + Sync>;

impl MessageTypeInfo {
    // new creates a new MessageTypeInfo with specified configuration.
    pub fn new(
        type_name: String,
        patterns: Vec<String>,
        publish_options: Option<PublishOptions>,
        format: SerializationFormat,
    ) -> Self {
        Self {
            type_name,
            patterns,
            publish_options,
            format,
        }
    }

    // has_pattern checks if this message type is registered
    // for a specific pattern. Useful for validating registration state
    // and debugging pattern conflicts.
    pub fn has_pattern(&self, pattern: &str) -> bool {
        self.patterns.iter().any(|p| p == pattern)
    }

    // pattern_count returns the number of patterns registered for
    // this message type. Useful for monitoring and debugging message
    // type registration complexity.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    // uses_qos_override checks if this message type has a custom
    // QoS setting. Useful for determining message delivery guarantees
    // and debugging QoS behavior.
    pub fn uses_qos_override(&self) -> bool {
        self.publish_options
            .map(|opts| opts.qos.is_some())
            .unwrap_or(false)
    }

    // effective_qos returns the QoS that should be used for this
    // message type. Falls back to provided default if no type-specific
    // override is set.
    pub fn effective_qos(&self, default_qos: QoS) -> QoS {
        self.publish_options
            .and_then(|opts| opts.qos)
            .unwrap_or(default_qos)
    }

    // effective_retain returns the retain that should be used for this
    // message type. Falls back to provided default if no type-specific
    // override is set.
    pub fn effective_retain(&self, default_retain: bool) -> bool {
        self.publish_options
            .and_then(|opts| opts.retain)
            .unwrap_or(default_retain)
    }

    // is_format checks if this message type uses a specific
    // serialization format. Useful for filtering and categorizing
    // registered message types.
    pub fn is_format(&self, format: SerializationFormat) -> bool {
        self.format == format
    }
}
