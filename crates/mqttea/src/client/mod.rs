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

// src/client/mod.rs
// Client module exports and re-exports to maintain existing API compatibility.
//
// Provides a clean interface by re-exporting the main client and supporting types
// while hiding the internal module structure from external users.

mod core;
mod handlers;
mod messages;
mod options;
mod registry;
mod topic_patterns;

pub use core::MqtteaClient;

pub use handlers::{ClosureAdapter, ErasedHandler};
pub use messages::ReceivedMessage;
pub use options::{ClientCredentials, ClientOptions, ClientTlsConfig, ClientTlsIdentity};
pub use topic_patterns::TopicPatterns;
