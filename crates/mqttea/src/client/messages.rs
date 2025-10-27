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

// src/client/message.rs
// MQTT message envelope for internal processing and routing.
//
// ReceivedMessage represents a parsed MQTT message that has been
// matched to a registered message type through the client's registry.
// It contains all information needed to route and deserialize an
// incoming message to the appropriate handler.

use std::sync::Arc;

use rumqttc::Publish;
use tokio::sync::RwLock;
use tracing::debug;

use crate::registry::MqttRegistry;

// ReceivedMessage stores a parsed MQTT message ready for processing. It
// contains all information needed to route and deserialize an
// incoming message.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    // topic is the full MQTT topic where the message was received.
    pub topic: String,
    // type_name identifies the registered message type that matched this topic.
    pub type_name: String,
    // payload contains the raw message bytes for deserialization.
    pub payload: Vec<u8>,
    // payload_size caches the payload size for efficient statistics tracking.
    pub payload_size: usize,
}

impl ReceivedMessage {
    // from_publish converts MQTT publish packet to internal message
    // format (e.g. parsing HelloWorld from publish packet). Uses registry
    // to determine message type from topic patterns.
    pub async fn from_publish(
        publish: &Publish,
        registry: Arc<RwLock<MqttRegistry>>,
    ) -> Option<Self> {
        let topic = publish.topic.clone();
        let payload = publish.payload.to_vec();
        let payload_size = payload.len();

        debug!("Looking for pattern match for topic: {}", topic);
        let registry_guard = registry.read().await;
        registry_guard
            .find_matching_type_for_topic(&topic)
            .map(|type_info| Self {
                topic,
                type_name: type_info.type_name.clone(),
                payload,
                payload_size,
            })
    }
}
