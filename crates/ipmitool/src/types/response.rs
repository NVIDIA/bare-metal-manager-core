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

//! IPMI response message type.

use super::CompletionCode;

/// An IPMI command response received from a BMC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpmiResponse {
    /// Completion code indicating success or failure.
    pub completion_code: CompletionCode,
    /// Response data payload (may be empty, especially on error).
    pub data: Vec<u8>,
}

impl IpmiResponse {
    /// Parse a response from raw bytes. The first byte is the completion code,
    /// remaining bytes are the response data.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice is empty.
    pub fn from_bytes(bytes: &[u8]) -> crate::error::Result<Self> {
        if bytes.is_empty() {
            return Err(crate::error::IpmitoolError::InvalidResponse(
                "empty response".to_owned(),
            ));
        }
        Ok(Self {
            completion_code: CompletionCode::from(bytes[0]),
            data: bytes[1..].to_vec(),
        })
    }

    /// Returns `Ok(())` if the completion code is success, otherwise returns
    /// an error with the completion code.
    pub fn check_completion(&self) -> crate::error::Result<()> {
        if self.completion_code.is_success() {
            Ok(())
        } else {
            Err(crate::error::IpmitoolError::CompletionCode(
                self.completion_code,
            ))
        }
    }
}
