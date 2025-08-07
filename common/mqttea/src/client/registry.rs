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

// src/client/registry.rs
// Registry trait implementations for MqtteaClient.
//
// Implements all the format-specific registration traits for MqtteaClient by
// delegating to the client's internal registry. This separates registration
// logic from the main client implementation while maintaining clean trait-based
// organization.

use async_trait::async_trait;

use crate::client::{MqtteaClient, TopicPatterns};
use crate::errors::MqtteaClientError;
use crate::registry::traits::{
    JsonRegistration, ProtobufRegistration, RawRegistration, YamlRegistration,
};
use crate::registry::types::PublishOptions;

#[async_trait]
impl ProtobufRegistration for MqtteaClient {
    // register_protobuf_message registers a protobuf message type.
    async fn register_protobuf_message<T: prost::Message + Default + 'static>(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
    ) -> Result<(), MqtteaClientError> {
        self.register_protobuf_message_with_opts::<T>(patterns, None)
            .await
    }

    // register_protobuf_message_with_opts registers a protobuf message type
    // with explicit PublishOptions for QoS, retain, etc.
    async fn register_protobuf_message_with_opts<T: prost::Message + Default + 'static>(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
        publish_options: Option<PublishOptions>,
    ) -> Result<(), MqtteaClientError> {
        let patterns_vec = patterns.into().into_vec();
        let mut registry_guard = self.registry.write().await;
        registry_guard.register_protobuf_message::<T>(patterns_vec, publish_options)
    }
}

#[async_trait]
impl JsonRegistration for MqtteaClient {
    // register_json_message registers a JSON message type.
    async fn register_json_message<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
    ) -> Result<(), MqtteaClientError> {
        self.register_json_message_with_opts::<T>(patterns, None)
            .await
    }

    // register_json_message_with_opts registers a JSON message type
    // with explicit PublishOptions for QoS, retain, etc.
    async fn register_json_message_with_opts<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
        publish_options: Option<PublishOptions>,
    ) -> Result<(), MqtteaClientError> {
        let patterns_vec = patterns.into().into_vec();
        let mut registry_guard = self.registry.write().await;
        registry_guard.register_json_message::<T>(patterns_vec, publish_options)
    }
}

#[async_trait]
impl YamlRegistration for MqtteaClient {
    // register_yaml_message registers a YAML message type.
    async fn register_yaml_message<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
    ) -> Result<(), MqtteaClientError> {
        self.register_yaml_message_with_opts::<T>(patterns, None)
            .await
    }

    // register_yaml_message_with_opts registers a YAML message type
    // with explicit PublishOptions for QoS, retain, etc.
    async fn register_yaml_message_with_opts<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
        publish_options: Option<PublishOptions>,
    ) -> Result<(), MqtteaClientError> {
        let patterns_vec = patterns.into().into_vec();
        let mut registry_guard = self.registry.write().await;
        registry_guard.register_yaml_message::<T>(patterns_vec, publish_options)
    }
}

#[async_trait]
impl RawRegistration for MqtteaClient {
    // register_raw_message registers a raw message type.
    async fn register_raw_message<T: crate::traits::RawMessageType + 'static>(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
    ) -> Result<(), MqtteaClientError> {
        self.register_raw_message_with_opts::<T>(patterns, None)
            .await
    }

    // register_raw_message_with_opts registers a raw message
    // with explicit PublishOptions for QoS, retain, etc.
    async fn register_raw_message_with_opts<T: crate::traits::RawMessageType + 'static>(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
        publish_options: Option<PublishOptions>,
    ) -> Result<(), MqtteaClientError> {
        let patterns_vec = patterns.into().into_vec();
        let mut registry_guard = self.registry.write().await;
        registry_guard.register_raw_message::<T>(patterns_vec, publish_options)
    }
}
