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

// src/client/topic_patterns.rs
// Flexible topic pattern input handling for registration methods.
//
// Provides the TopicPatterns enum and From implementations to allow users
// to pass topics in many convenient formats without manual conversions.

// TopicPatterns provides flexible input handling for topic registration methods.
// Accepts single topics, multiple topics, string literals, owned strings, etc.
#[derive(Debug, Clone, PartialEq)]
pub enum TopicPatterns {
    // Single pattern.
    Single(String),
    // Multiple patterns for one message type.
    Multiple(Vec<String>),
}

impl TopicPatterns {
    // into_vec converts any TopicPatterns variant to Vec<String>.
    // Used internally by registration methods to normalize input.
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::Single(pattern) => vec![pattern],
            Self::Multiple(patterns) => patterns,
        }
    }

    // len returns the number of patterns contained.
    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Multiple(patterns) => patterns.len(),
        }
    }

    // is_empty checks if there are any patterns.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(pattern) => pattern.is_empty(),
            Self::Multiple(patterns) => {
                patterns.is_empty() || patterns.iter().all(|p| p.is_empty())
            }
        }
    }

    // contains checks if a specific pattern is included.
    pub fn contains(&self, pattern: &str) -> bool {
        match self {
            Self::Single(p) => p == pattern,
            Self::Multiple(patterns) => patterns.iter().any(|p| p == pattern),
        }
    }

    // as_slice returns a slice view of all patterns.
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            Self::Single(pattern) => vec![pattern.as_str()],
            Self::Multiple(patterns) => patterns.iter().map(|s| s.as_str()).collect(),
        }
    }

    // from_single creates TopicPatterns from a single pattern.
    pub fn from_single(pattern: impl Into<String>) -> Self {
        Self::Single(pattern.into())
    }

    // from_multiple creates TopicPatterns from multiple patterns.
    pub fn from_multiple(patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Multiple(patterns.into_iter().map(|p| p.into()).collect())
    }
}

// Convert string literal to TopicPatterns.
// register_message("hello-world")
impl From<&str> for TopicPatterns {
    fn from(pattern: &str) -> Self {
        Self::Single(pattern.to_string())
    }
}

// Convert owned String to TopicPatterns.
// register_message(some_string_var)
impl From<String> for TopicPatterns {
    fn from(pattern: String) -> Self {
        Self::Single(pattern)
    }
}

// Convert Vec<&str> to TopicPatterns.
// register_message(vec!["hello", "hi", "greeting"])
impl From<Vec<&str>> for TopicPatterns {
    fn from(patterns: Vec<&str>) -> Self {
        Self::Multiple(patterns.into_iter().map(String::from).collect())
    }
}

// Convert Vec<String> to TopicPatterns.
// register_message(my_string_vec)
impl From<Vec<String>> for TopicPatterns {
    fn from(patterns: Vec<String>) -> Self {
        Self::Multiple(patterns)
    }
}

// Convert array of string literals to TopicPatterns.
// register_message(["hello", "hi", "greeting"])
impl<const N: usize> From<[&str; N]> for TopicPatterns {
    fn from(patterns: [&str; N]) -> Self {
        Self::Multiple(patterns.into_iter().map(String::from).collect())
    }
}

// Convert array of Strings to TopicPatterns.
// register_message([string1, string2, string3])
impl<const N: usize> From<[String; N]> for TopicPatterns {
    fn from(patterns: [String; N]) -> Self {
        Self::Multiple(patterns.into_iter().collect())
    }
}

// Convert slice of string literals to TopicPatterns.
// register_message(&["hello", "hi"])
impl From<&[&str]> for TopicPatterns {
    fn from(patterns: &[&str]) -> Self {
        Self::Multiple(patterns.iter().map(|s| s.to_string()).collect())
    }
}

// Convert slice of Strings to TopicPatterns.
// register_message(&[string1, string2])
impl From<&[String]> for TopicPatterns {
    fn from(patterns: &[String]) -> Self {
        Self::Multiple(patterns.to_vec())
    }
}

impl std::fmt::Display for TopicPatterns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Single(pattern) => write!(f, "'{pattern}'"),
            Self::Multiple(patterns) => {
                write!(
                    f,
                    "[{}]",
                    patterns
                        .iter()
                        .map(|p| format!("'{p}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            }
        }
    }
}
