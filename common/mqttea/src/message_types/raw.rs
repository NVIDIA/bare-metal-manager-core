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
