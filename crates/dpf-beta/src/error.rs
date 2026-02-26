/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Error types for the DPF SDK.

use thiserror::Error;

/// Error type for DPF operations.
#[derive(Error, Debug)]
pub enum DpfError {
    #[error("Kubernetes client error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Resource not found: {kind} '{name}'")]
    NotFound { kind: &'static str, name: String },

    #[error("Resource already exists: {kind} '{name}'")]
    AlreadyExists { kind: &'static str, name: String },

    #[error("Timeout waiting for {operation}: {details}")]
    Timeout { operation: String, details: String },

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Watcher error: {0}")]
    WatcherError(String),
}

impl DpfError {
    pub fn not_found(kind: &'static str, name: impl Into<String>) -> Self {
        Self::NotFound {
            kind,
            name: name.into(),
        }
    }

    pub fn already_exists(kind: &'static str, name: impl Into<String>) -> Self {
        Self::AlreadyExists {
            kind,
            name: name.into(),
        }
    }

    pub fn timeout(operation: impl Into<String>, details: impl Into<String>) -> Self {
        Self::Timeout {
            operation: operation.into(),
            details: details.into(),
        }
    }
}

impl From<kube::runtime::watcher::Error> for DpfError {
    fn from(e: kube::runtime::watcher::Error) -> Self {
        Self::WatcherError(e.to_string())
    }
}
