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

use crate::types::CompletionCode;

/// Errors that can occur during IPMI operations.
#[derive(Debug, thiserror::Error)]
pub enum IpmitoolError {
    /// The BMC returned a non-zero completion code.
    #[error("IPMI command failed: {0}")]
    CompletionCode(CompletionCode),

    /// Transport-layer error (UDP socket, network unreachable, etc.).
    #[error("transport error: {0}")]
    Transport(String),

    /// RAKP authentication failed (wrong credentials, privilege denied).
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Request timed out after all retries.
    #[error("request timed out after {retries} retries")]
    Timeout { retries: u32 },

    /// Response could not be parsed.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// Cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// I/O error from the underlying socket.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Session is not in the expected state for this operation.
    #[error("invalid session state: expected {expected}, got {actual}")]
    InvalidSessionState {
        expected: &'static str,
        actual: &'static str,
    },

    /// FRU data parsing error.
    #[error("FRU parse error: {0}")]
    FruParse(String),

    /// SDR record parsing error.
    #[error("SDR parse error: {0}")]
    SdrParse(String),

    /// SEL record parsing error.
    #[error("SEL parse error: {0}")]
    SelParse(String),
}

/// Convenience type alias for Results using [`IpmitoolError`].
pub type Result<T> = std::result::Result<T, IpmitoolError>;
