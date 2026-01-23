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

// src/registry/mod.rs
// Registry module coordination and re-exports for client-scoped
// message registration.

mod core;
mod entry;
pub mod traits;
pub mod types;

pub use core::MqttRegistry;

pub use entry::MqttRegistryEntry;
pub use traits::{
    JsonRegistration, MessageRegistration, ProtobufRegistration, RawRegistration, YamlRegistration,
};
pub use types::{DeserializeHandler, MessageTypeInfo, SerializationFormat, SerializeHandler};
