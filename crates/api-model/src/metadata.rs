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

use std::collections::HashMap;

use serde::Deserialize;

use crate::ConfigValidationError;

/// Metadata that can get associated with Forge managed resources
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct Metadata {
    /// user-defined resource name
    pub name: String,
    /// optional user-defined resource description
    pub description: String,
    /// optional user-defined key/ value pairs
    pub labels: HashMap<String, String>,
}

impl Metadata {
    pub fn new_with_default_name() -> Self {
        Metadata {
            name: "default_name".to_string(),
            ..Metadata::default()
        }
    }
}

/// default_metadata_for_deserializer returns empty Metadata for serde deserialization of expected device models.
pub fn default_metadata_for_deserializer() -> Metadata {
    Metadata::default()
}

impl Metadata {
    pub fn validate(&self, require_min_length: bool) -> Result<(), ConfigValidationError> {
        let min_len = if require_min_length { 2 } else { 0 };

        if self.name.len() < min_len || self.name.len() > 256 {
            return Err(ConfigValidationError::InvalidValue(format!(
                "Name must be between {} and 256 characters long, got {} characters",
                min_len,
                self.name.len()
            )));
        }

        if !self.name.is_ascii() {
            return Err(ConfigValidationError::InvalidValue(format!(
                "Name '{}' must contain ASCII characters only",
                self.name
            )));
        }

        if self.description.len() > 1024 {
            return Err(ConfigValidationError::InvalidValue(format!(
                "Description must be between 0 and 1024 characters long, got {} characters",
                self.description.len()
            )));
        }

        for (key, value) in &self.labels {
            if !key.is_ascii() {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "Label key '{key}' must contain ASCII characters only"
                )));
            }

            if key.len() > 255 {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "Label key '{key}' is too long (max 255 characters)"
                )));
            }
            if key.is_empty() {
                return Err(ConfigValidationError::InvalidValue(
                    "Label key cannot be empty.".to_string(),
                ));
            }
            if value.len() > 255 {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "Label value '{value}' for key '{key}' is too long (max 255 characters)"
                )));
            }
        }

        if self.labels.len() > 10 {
            return Err(ConfigValidationError::InvalidValue(format!(
                "Cannot have more than 10 labels, got {}",
                self.labels.len()
            )));
        }

        Ok(())
    }
}

/// A single label filter used for searching resources by label key and/or value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelFilter {
    pub key: String,
    pub value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_invalid_metadata() {
        // Good metadata
        let metadata = Metadata {
            name: "nice_name".to_string(),
            description: "anything is fine".to_string(),
            labels: HashMap::from([("key1".to_string(), "val1".to_string())]),
        };

        assert!(metadata.validate(true).is_ok());

        // And now lots of bad metadata

        // name too short
        let metadata = Metadata {
            name: "x".to_string(),
            description: "anything is fine".to_string(),
            labels: HashMap::from([("key1".to_string(), "val1".to_string())]),
        };

        assert!(matches!(
            metadata.validate(true),
            Err(ConfigValidationError::InvalidValue(_))
        ));

        // name too short without requiring min length is ok
        let metadata = Metadata {
            name: "".to_string(),
            description: "anything is fine".to_string(),
            labels: HashMap::from([("key1".to_string(), "val1".to_string())]),
        };

        assert!(metadata.validate(false).is_ok());

        // name too long
        let metadata = Metadata {
            name: [0; 257].iter().fold(String::new(), |name, _| name + "a"),
            description: "anything is fine".to_string(),
            labels: HashMap::from([("key1".to_string(), "val1".to_string())]),
        };

        assert!(matches!(
            metadata.validate(true),
            Err(ConfigValidationError::InvalidValue(_))
        ));

        // non-ascii name
        let metadata = Metadata {
            name: "것봐".to_string(),
            description: "anything is fine".to_string(),
            labels: HashMap::from([("key1".to_string(), "val1".to_string())]),
        };

        assert!(matches!(
            metadata.validate(true),
            Err(ConfigValidationError::InvalidValue(_))
        ));

        // Empty key
        let metadata = Metadata {
            name: "nice name".to_string(),
            description: "anything is fine".to_string(),
            labels: HashMap::from([("".to_string(), "val1".to_string())]),
        };

        assert!(matches!(
            metadata.validate(true),
            Err(ConfigValidationError::InvalidValue(_))
        ));

        // Non-ascii key
        let metadata = Metadata {
            name: "nice name".to_string(),
            description: "anything is fine".to_string(),
            labels: HashMap::from([("것봐".to_string(), "val1".to_string())]),
        };

        assert!(matches!(
            metadata.validate(true),
            Err(ConfigValidationError::InvalidValue(_))
        ));

        // Key too big
        let metadata = Metadata {
            name: "nice name".to_string(),
            description: "anything is fine".to_string(),
            labels: HashMap::from([(
                [0; 256].iter().fold(String::new(), |name, _| name + "a"),
                "val1".to_string(),
            )]),
        };

        assert!(matches!(
            metadata.validate(true),
            Err(ConfigValidationError::InvalidValue(_))
        ));

        // Value too big
        let metadata = Metadata {
            name: "nice name".to_string(),
            description: "anything is fine".to_string(),
            labels: HashMap::from([(
                "key1".to_string(),
                [0; 256].iter().fold(String::new(), |name, _| name + "a"),
            )]),
        };

        assert!(matches!(
            metadata.validate(true),
            Err(ConfigValidationError::InvalidValue(_))
        ));

        // Too many labels
        let metadata = Metadata {
            name: "nice name".to_string(),
            description: "anything is fine".to_string(),
            labels: "abcdefghijk"
                .chars()
                .map(|c| (c.to_string(), "x".to_string()))
                .collect(),
        };

        assert!(matches!(
            metadata.validate(true),
            Err(ConfigValidationError::InvalidValue(_))
        ));
    }
}
