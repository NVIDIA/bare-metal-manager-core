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

/// Maximum number of labels allowed on a resource's metadata.
const MAX_LABELS: usize = 16;

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

        if self.labels.len() > MAX_LABELS {
            return Err(ConfigValidationError::InvalidValue(format!(
                "Cannot have more than {} labels, got {}",
                MAX_LABELS,
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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    /// Build a `Metadata` from parts, with sensible defaults so each row only
    /// names the field it is exercising.
    fn meta(name: &str, description: &str, labels: &[(&str, &str)]) -> Metadata {
        Metadata {
            name: name.to_string(),
            description: description.to_string(),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// A string of `n` repeated `'a'` characters.
    fn long(n: usize) -> String {
        "a".repeat(n)
    }

    #[test]
    fn validate_with_min_length_required() {
        check_cases(
            [
                Case {
                    scenario: "valid name, description, and label",
                    input: meta("nice_name", "anything is fine", &[("key1", "val1")]),
                    expect: Yields(()),
                },
                Case {
                    scenario: "no labels is fine",
                    input: meta("nice_name", "", &[]),
                    expect: Yields(()),
                },
                Case {
                    scenario: "name at min length (2)",
                    input: meta("ab", "", &[]),
                    expect: Yields(()),
                },
                Case {
                    scenario: "name one below min length (1)",
                    input: meta("x", "", &[]),
                    expect: Fails,
                },
                Case {
                    scenario: "empty name rejected when min length required",
                    input: meta("", "", &[]),
                    expect: Fails,
                },
                Case {
                    scenario: "name at max length (256)",
                    input: Metadata {
                        name: long(256),
                        ..Metadata::default()
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "name one over max length (257)",
                    input: Metadata {
                        name: long(257),
                        ..Metadata::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "non-ascii name rejected",
                    input: meta("것봐", "", &[]),
                    expect: Fails,
                },
                Case {
                    scenario: "description at max length (1024)",
                    input: Metadata {
                        name: "nice name".to_string(),
                        description: long(1024),
                        ..Metadata::default()
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "description one over max length (1025)",
                    input: Metadata {
                        name: "nice name".to_string(),
                        description: long(1025),
                        ..Metadata::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "empty label key rejected",
                    input: meta("nice name", "", &[("", "val1")]),
                    expect: Fails,
                },
                Case {
                    scenario: "non-ascii label key rejected",
                    input: meta("nice name", "", &[("것봐", "val1")]),
                    expect: Fails,
                },
                Case {
                    scenario: "label key at max length (255)",
                    input: Metadata {
                        name: "nice name".to_string(),
                        labels: HashMap::from([(long(255), "val1".to_string())]),
                        ..Metadata::default()
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "label key one over max length (256)",
                    input: Metadata {
                        name: "nice name".to_string(),
                        labels: HashMap::from([(long(256), "val1".to_string())]),
                        ..Metadata::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "label value at max length (255)",
                    input: Metadata {
                        name: "nice name".to_string(),
                        labels: HashMap::from([("key1".to_string(), long(255))]),
                        ..Metadata::default()
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "label value one over max length (256)",
                    input: Metadata {
                        name: "nice name".to_string(),
                        labels: HashMap::from([("key1".to_string(), long(256))]),
                        ..Metadata::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "empty label value is fine",
                    input: meta("nice name", "", &[("key1", "")]),
                    expect: Yields(()),
                },
                Case {
                    scenario: "labels at max count (16)",
                    input: Metadata {
                        name: "nice name".to_string(),
                        labels: "abcdefghijklmnop"
                            .chars()
                            .map(|c| (c.to_string(), "x".to_string()))
                            .collect(),
                        ..Metadata::default()
                    },
                    expect: Yields(()),
                },
                Case {
                    scenario: "labels one over max count (17)",
                    input: Metadata {
                        name: "nice name".to_string(),
                        labels: "abcdefghijklmnopq"
                            .chars()
                            .map(|c| (c.to_string(), "x".to_string()))
                            .collect(),
                        ..Metadata::default()
                    },
                    expect: Fails,
                },
            ],
            |m| m.validate(true).map_err(drop),
        );
    }

    #[test]
    fn validate_without_min_length_required() {
        check_cases(
            [
                Case {
                    scenario: "empty name allowed when min length not required",
                    input: meta("", "anything is fine", &[("key1", "val1")]),
                    expect: Yields(()),
                },
                Case {
                    scenario: "single-char name allowed when min length not required",
                    input: meta("x", "", &[]),
                    expect: Yields(()),
                },
                Case {
                    scenario: "name still capped at max length (257 rejected)",
                    input: Metadata {
                        name: long(257),
                        ..Metadata::default()
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "non-ascii name still rejected",
                    input: meta("것봐", "", &[]),
                    expect: Fails,
                },
                Case {
                    scenario: "label checks still apply (empty key rejected)",
                    input: meta("", "", &[("", "val1")]),
                    expect: Fails,
                },
            ],
            |m| m.validate(false).map_err(drop),
        );
    }

    #[test]
    fn validate_error_message_names_the_offending_field() {
        check_cases(
            [
                Case {
                    scenario: "short-name error mentions length bounds",
                    input: (meta("x", "", &[]), &["between", "256"][..]),
                    expect: Yields(true),
                },
                Case {
                    scenario: "non-ascii name error mentions ASCII",
                    input: (meta("것봐", "", &[]), &["ASCII"][..]),
                    expect: Yields(true),
                },
                Case {
                    scenario: "long-description error mentions Description",
                    input: (
                        Metadata {
                            name: "nice name".to_string(),
                            description: long(1025),
                            ..Metadata::default()
                        },
                        &["Description", "1024"][..],
                    ),
                    expect: Yields(true),
                },
                Case {
                    scenario: "empty-key error mentions empty",
                    input: (meta("nice name", "", &[("", "v")]), &["empty"][..]),
                    expect: Yields(true),
                },
                Case {
                    scenario: "too-many-labels error mentions the count",
                    input: (
                        Metadata {
                            name: "nice name".to_string(),
                            labels: "abcdefghijklmnopq"
                                .chars()
                                .map(|c| (c.to_string(), "x".to_string()))
                                .collect(),
                            ..Metadata::default()
                        },
                        &["more than 16", "17"][..],
                    ),
                    expect: Yields(true),
                },
            ],
            |(m, tokens)| {
                let message = m.validate(true).unwrap_err().to_string();
                Ok::<_, ()>(tokens.iter().all(|t| message.contains(t)))
            },
        );
    }

    #[test]
    fn constructors_produce_expected_metadata() {
        check_values(
            [
                Check {
                    scenario: "new_with_default_name sets the default name",
                    input: Metadata::new_with_default_name(),
                    expect: Metadata {
                        name: "default_name".to_string(),
                        description: String::new(),
                        labels: HashMap::new(),
                    },
                },
                Check {
                    scenario: "default is fully empty",
                    input: Metadata::default(),
                    expect: Metadata {
                        name: String::new(),
                        description: String::new(),
                        labels: HashMap::new(),
                    },
                },
                Check {
                    scenario: "deserializer default matches Metadata::default",
                    input: default_metadata_for_deserializer(),
                    expect: Metadata::default(),
                },
            ],
            |m| m,
        );
    }
}
