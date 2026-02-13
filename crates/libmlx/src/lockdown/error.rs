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
