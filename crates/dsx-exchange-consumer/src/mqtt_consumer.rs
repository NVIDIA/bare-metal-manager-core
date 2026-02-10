/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! MQTT consumer that receives messages and writes them to a channel.

use mqttea::QoS;
use mqttea::client::{ClientOptions, MqtteaClient};
use mqttea::registry::JsonRegistration;
use tokio::sync::mpsc;

use crate::config::MqttConfig;
use crate::messages::{LeakMetadata, ValueMessage};
use crate::{ConsumerMetrics, DsxConsumerError};

/// Message types received from MQTT.
#[derive(Debug, Clone)]
pub enum MqttMessage {
    Metadata {
        topic: String,
        metadata: LeakMetadata,
    },
    Value {
        topic: String,
        value: ValueMessage,
    },
}

/// Connect to MQTT and return a receiver for incoming messages.
///
/// Sets up the MQTT client, registers message handlers, subscribes to topics,
/// and connects. Returns a receiver that yields messages with drop-on-overflow.
pub async fn connect(
    config: &MqttConfig,
    metrics: ConsumerMetrics,
) -> Result<mpsc::Receiver<MqttMessage>, DsxConsumerError> {
    let (tx, rx) = mpsc::channel(config.queue_capacity);

    let client = MqtteaClient::new(
        &config.endpoint,
        config.port,
        &config.client_id,
        // QoS 0 is the recommended setting for DSX Exchange integrations.
        // BMS will republish all messages periodically to handle missed messages.
        Some(ClientOptions::default().with_qos(QoS::AtMostOnce)),
    )
    .await
    .map_err(|e| DsxConsumerError::Mqtt(e.to_string()))?;

    // Register message types with distinct suffix patterns.
    // mqttea converts simple strings to suffix regex: "Metadata" -> "/Metadata$"
    client
        .register_json_message::<LeakMetadata>("Metadata".to_string())
        .await
        .map_err(|e| DsxConsumerError::Mqtt(e.to_string()))?;

    client
        .register_json_message::<ValueMessage>("Value".to_string())
        .await
        .map_err(|e| DsxConsumerError::Mqtt(e.to_string()))?;

    // Register handler for metadata messages
    client
        .on_message::<LeakMetadata, _, _>({
            let tx = tx.clone();
            let metrics = metrics.clone();
            move |_client, metadata, topic| {
                metrics.record_message_received();
                let msg = MqttMessage::Metadata { topic, metadata };
                if tx.try_send(msg).is_err() {
                    metrics.record_message_dropped();
                    tracing::warn!("Message queue full, dropping metadata message");
                }
                std::future::ready(())
            }
        })
        .await;

    // Register handler for value messages
    client
        .on_message::<ValueMessage, _, _>(move |_client, value, topic| {
            metrics.record_message_received();
            let msg = MqttMessage::Value { topic, value };
            if tx.try_send(msg).is_err() {
                metrics.record_message_dropped();
                tracing::warn!("Message queue full, dropping value message");
            }
            std::future::ready(())
        })
        .await;

    // Subscribe to all topics under the prefix
    let subscribe_pattern = format!("{}/#", config.topic_prefix);
    client
        .subscribe(&subscribe_pattern, QoS::AtMostOnce)
        .await
        .map_err(|e| DsxConsumerError::Mqtt(e.to_string()))?;

    tracing::info!(topic = %subscribe_pattern, "Subscribed to MQTT topics");

    // Connect
    client
        .connect()
        .await
        .map_err(|e| DsxConsumerError::Mqtt(e.to_string()))?;

    tracing::info!("MQTT consumer connected");

    Ok(rx)
}
