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

// src/lib.rs
// Main exports for the mqttea MQTT client library.

pub mod client;
pub mod errors;
pub mod message_types;
pub mod registry;
pub mod stats;
pub mod traits;

// Export some things for convenience.
pub use client::{MqtteaClient, TopicPatterns};
pub use errors::MqtteaClientError;
pub use message_types::RawMessage;
pub use registry::{MessageTypeInfo, MqttRegistry, SerializationFormat};
pub use rumqttc::QoS;
pub use stats::{PublishStats, QueueStats};
pub use traits::{MessageHandler, MqttRecipient, RawMessageType};
