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

//! MQTT consumer that receives messages and writes them to a channel.

use std::sync::Arc;

use forge_secrets::credentials::CredentialReader;
use mqttea::QoS;
use mqttea::client::{ClientOptions, MqtteaClient};
use mqttea::registry::JsonRegistration;
use tokio::sync::mpsc;

use crate::config::{MqttAuthMode, MqttConfig};
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
    credential_reader: Arc<dyn CredentialReader>,
) -> Result<mpsc::Receiver<MqttMessage>, DsxConsumerError> {
    let (tx, rx) = mpsc::channel(config.queue_capacity);

    // QoS 0 is the recommended setting for DSX Exchange integrations.
    // BMS will republish all messages periodically to handle missed messages.
    let options = {
        let defaults = ClientOptions::default().with_qos(QoS::AtMostOnce);
        if let Some(provider) =
            build_credentials_provider(config, credential_reader.clone()).await?
        {
            defaults.with_credentials_provider(provider)
        } else {
            defaults
        }
    };

    // Suffix the broker-level client identifier so multiple replicas (or a new
    // pod coming up while the old one is still terminating) do not race for
    // the same MQTT session and ping-pong each other off the broker.
    let client_id = mqttea::unique_client_id(&config.client_id);
    let client = MqtteaClient::new(&config.endpoint, config.port, &client_id, Some(options))
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

async fn build_credentials_provider(
    config: &MqttConfig,
    credential_reader: Arc<dyn CredentialReader>,
) -> Result<Option<Arc<dyn mqttea::auth::CredentialsProvider>>, DsxConsumerError> {
    let credential_key = forge_secrets::credentials::CredentialKey::MqttAuth {
        credential_type: forge_secrets::credentials::MqttCredentialType::DsxExchangeConsumer,
    };

    match config.auth.auth_mode {
        MqttAuthMode::None => Ok(None),
        MqttAuthMode::BasicAuth => {
            let creds = credential_reader
                .get_credentials(&credential_key)
                .await
                .map_err(|e| DsxConsumerError::Secrets(e.to_string()))?
                .ok_or_else(|| {
                    DsxConsumerError::Secrets(format!(
                        "Missing MQTT credentials for {}",
                        credential_key.to_key_str()
                    ))
                })?;
            let forge_secrets::credentials::Credentials::UsernamePassword { username, password } =
                creds;
            Ok(Some(Arc::new(mqttea::auth::StaticCredentials::new(
                username, password,
            ))
            // cast not needed by rustc, but satisfies rust-analyzer
            as Arc<dyn mqttea::auth::CredentialsProvider>))
        }
        MqttAuthMode::Oauth2 => {
            let oauth2 = config.auth.oauth2.as_ref().ok_or_else(|| {
                DsxConsumerError::Config(
                    "auth_mode is oauth2 but oauth2 config is missing".to_string(),
                )
            })?;
            let config = mqttea::auth::OAuth2Config::new(
                &oauth2.token_url,
                oauth2.scopes.clone(),
                oauth2.http_timeout,
            );
            let client_credentials = Arc::new(SecretBackedOAuth2Credentials {
                credential_key,
                credential_reader,
            });
            let token_provider = mqttea::auth::OAuth2TokenProvider::new(config, client_credentials)
                .map_err(|e| DsxConsumerError::Mqtt(e.to_string()))?;
            let provider =
                mqttea::auth::TokenCredentialsProvider::new(&oauth2.username, token_provider);
            // cast not needed by rustc, but satisfies rust-analyzer
            Ok(Some(
                Arc::new(provider) as Arc<dyn mqttea::auth::CredentialsProvider>
            ))
        }
    }
}

struct SecretBackedOAuth2Credentials {
    credential_key: forge_secrets::credentials::CredentialKey,
    credential_reader: Arc<dyn CredentialReader>,
}

#[async_trait::async_trait]
impl mqttea::auth::ClientCredentialsProvider for SecretBackedOAuth2Credentials {
    async fn get_client_credentials(
        &self,
    ) -> Result<(mqttea::ClientId, mqttea::ClientSecret), mqttea::MqtteaClientError> {
        let creds = self
            .credential_reader
            .get_credentials(&self.credential_key)
            .await
            .map_err(|e| mqttea::MqtteaClientError::CredentialsError(e.to_string()))?
            .ok_or_else(|| {
                mqttea::MqtteaClientError::CredentialsError(format!(
                    "Missing MQTT OAuth2 credentials for {}",
                    self.credential_key.to_key_str()
                ))
            })?;
        let forge_secrets::credentials::Credentials::UsernamePassword { username, password } =
            creds;
        Ok((
            mqttea::ClientId::new(username),
            mqttea::ClientSecret::new(password),
        ))
    }
}
