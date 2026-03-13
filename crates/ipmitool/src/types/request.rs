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

//! IPMI request message type.

use super::NetFn;

/// An IPMI command request to be sent over a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpmiRequest {
    /// Network function code identifying the command group.
    pub netfn: NetFn,
    /// Command code within the network function.
    pub cmd: u8,
    /// Command-specific request data (may be empty).
    pub data: Vec<u8>,
}

impl IpmiRequest {
    /// Create a new request with no data payload.
    #[must_use]
    pub fn new(netfn: NetFn, cmd: u8) -> Self {
        Self {
            netfn,
            cmd,
            data: Vec::new(),
        }
    }

    /// Create a new request with the given data payload.
    #[must_use]
    pub fn with_data(netfn: NetFn, cmd: u8, data: Vec<u8>) -> Self {
        Self { netfn, cmd, data }
    }
}
