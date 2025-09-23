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

use thiserror::Error;

// MlxError is a custom error type for Mellanox NIC operations.
#[derive(Error, Debug)]
pub enum MlxError {
    #[error("Command execution failed: {0}")]
    CommandFailed(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Invalid device ID format: {0}")]
    InvalidDeviceId(String),

    #[error("Hardware access is already disabled")]
    AlreadyLocked,

    #[error("Hardware access is already enabled")]
    AlreadyUnlocked,

    #[error("Invalid key format or length")]
    InvalidKey,

    #[error("Permission denied - requires root privileges")]
    PermissionDenied,

    #[error("flint tool not found or not executable")]
    FlintNotFound,

    #[error("Failed to parse command output: {0}")]
    ParseError(String),

    #[error("Dry run - would have executed: {0}")]
    DryRun(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

// MlxResult is a result type alias for operations that
// can fail with MlxError.
pub type MlxResult<T> = Result<T, MlxError>;
