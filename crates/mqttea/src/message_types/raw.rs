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

// src/message_types/raw.rs
// Raw message types for binary data handling

use crate::traits::RawMessageType;

// RawMessage handles arbitrary binary data, including
// from unmapped MQTT topics.
#[derive(Clone, Debug, PartialEq)]
pub struct RawMessage {
    pub payload: Vec<u8>,
}

impl RawMessageType for RawMessage {
    fn to_bytes(&self) -> Vec<u8> {
        self.payload.clone()
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { payload: bytes }
    }
}
