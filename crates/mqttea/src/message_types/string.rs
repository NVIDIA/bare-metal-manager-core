/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
// src/message_types/string.rs
// StringMessage provides a simple wrapper around String that
// implements RawMessageType, enabling direct sending of string
// messages without complex serialization.

use crate::traits::RawMessageType;

// StringMessage stores a simple text string for MQTT transmission.
// This allows for easy sending of plain text messages using the client's
// send_message method without needing protobuf or JSON serialization.
#[derive(Clone, Debug, PartialEq)]
pub struct StringMessage {
    // content is used for storing the actual text content
    // of the message.
    pub content: String,
}

impl StringMessage {
    // new creates a new StringMessage with the given content
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
        }
    }

    // as_str returns the content as a string slice
    pub fn as_str(&self) -> &str {
        &self.content
    }

    // into_string consumes the StringMessage and
    // returns the inner String.
    pub fn into_string(self) -> String {
        self.content
    }
}

impl RawMessageType for StringMessage {
    // to_bytes converts the string content to UTF-8 bytes
    // for transmission
    fn to_bytes(&self) -> Vec<u8> {
        self.content.as_bytes().to_vec()
    }

    // from_bytes recreates a StringMessage from received UTF-8 bytes
    fn from_bytes(bytes: Vec<u8>) -> Self {
        let content = String::from_utf8(bytes).unwrap_or_else(|e| {
            // If invalid UTF-8, include the error info in the content
            format!("Invalid UTF-8 data: {e}")
        });
        Self { content }
    }
}

// Implement From traits.
impl From<String> for StringMessage {
    fn from(content: String) -> Self {
        Self { content }
    }
}

impl From<&str> for StringMessage {
    fn from(content: &str) -> Self {
        Self {
            content: content.to_string(),
        }
    }
}

impl From<StringMessage> for String {
    fn from(msg: StringMessage) -> String {
        msg.content
    }
}

// Implement FromStr trait for parsing from strings.
impl std::str::FromStr for StringMessage {
    type Err = std::convert::Infallible;

    fn from_str(content: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            content: content.to_string(),
        })
    }
}

impl std::fmt::Display for StringMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.content)
    }
}
