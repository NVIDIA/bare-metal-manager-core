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

// src/registry/traits.rs
// Registration traits for separation of message type registration concerns.
//
// Defines traits for each serialization format to enable clean delegation from
// MqtteaClient to format-specific registration logic. This keeps the main client
// focused on MQTT operations, and puts the type registration logic here.

use async_trait::async_trait;

use crate::client::TopicPatterns;
use crate::errors::MqtteaClientError;
use crate::registry::types::PublishOptions;

// ProtobufRegistration trait defines protobuf message registration methods.
#[async_trait]
pub trait ProtobufRegistration {
    // register_protobuf_message registers a protobuf message type.
    // Accepts: &str, String, Vec<&str>, Vec<String>, ["a", "b"], etc.
    async fn register_protobuf_message<T: prost::Message + Default + 'static>(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
    ) -> Result<(), MqtteaClientError>;

    // register_protobuf_message_with_opts registers a protobuf message
    // type with explicit QoS control.
    async fn register_protobuf_message_with_opts<T: prost::Message + Default + 'static>(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
        publish_options: Option<PublishOptions>,
    ) -> Result<(), MqtteaClientError>;
}

// JsonRegistration trait defines JSON message registration methods.
#[async_trait]
pub trait JsonRegistration {
    // register_json_message registers a JSON message type.
    async fn register_json_message<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
    ) -> Result<(), MqtteaClientError>;

    // register_json_message_with_opts registers a JSON message type
    // with explicit QoS control.
    async fn register_json_message_with_opts<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
        publish_options: Option<PublishOptions>,
    ) -> Result<(), MqtteaClientError>;
}

// YamlRegistration trait defines YAML message registration methods.
#[async_trait]
pub trait YamlRegistration {
    // register_yaml_message registers a YAML message type.
    async fn register_yaml_message<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
    ) -> Result<(), MqtteaClientError>;

    // register_yaml_message_with_opts registers a YAML message
    // type with explicit QoS control.
    async fn register_yaml_message_with_opts<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + 'static,
    >(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
        publish_options: Option<PublishOptions>,
    ) -> Result<(), MqtteaClientError>;
}

// RawRegistration trait defines raw message registration methods.
#[async_trait]
pub trait RawRegistration {
    // register_raw_message registers a raw message type.
    async fn register_raw_message<T: crate::traits::RawMessageType + 'static>(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
    ) -> Result<(), MqtteaClientError>;

    // register_raw_message_with_opts registers a raw message type
    // with type-specific PublishOptions.
    async fn register_raw_message_with_opts<T: crate::traits::RawMessageType + 'static>(
        &self,
        patterns: impl Into<TopicPatterns> + Send,
        publish_options: Option<PublishOptions>,
    ) -> Result<(), MqtteaClientError>;
}

// MessageRegistration trait combines all format-specific registration traits
// Provides a single trait for types that want to support all message formats.
#[async_trait]
pub trait MessageRegistration:
    ProtobufRegistration + JsonRegistration + YamlRegistration + RawRegistration
{
}

// Blanket implementation: any type that implements all format traits automatically
// gets MessageRegistration
impl<T> MessageRegistration for T where
    T: ProtobufRegistration + JsonRegistration + YamlRegistration + RawRegistration
{
}
