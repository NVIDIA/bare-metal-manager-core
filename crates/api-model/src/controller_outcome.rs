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

use std::fmt::{Debug, Display};
use std::panic::Location;

use serde::{Deserialize, Serialize};

/// DB storage of the result of a state handler iteration
/// It is different from a StateHandlerOutcome in that it also stores the error message,
/// and does not store the state, which is already stored elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum PersistentStateHandlerOutcome {
    Wait {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_ref: Option<PersistentSourceReference>,
    },
    Error {
        err: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_ref: Option<PersistentSourceReference>,
    },
    Transition {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_ref: Option<PersistentSourceReference>,
    },
    DoNothing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_ref: Option<PersistentSourceReference>,
    },
    /// Exists for backward compatibility with DB in case of a race condition with migration.
    /// Remove in future
    DoNothingWithDetails,
}

impl Display for PersistentStateHandlerOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PersistentSourceReference {
    pub file: String,
    pub line: u32,
}

impl Display for PersistentSourceReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl From<&&'static Location<'static>> for PersistentSourceReference {
    fn from(value: &&'static Location) -> Self {
        Self {
            file: value.file().to_string(),
            line: value.line(),
        }
    }
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases};

    use super::*;

    // Serialize each outcome variant to JSON. The serialized String is the
    // contract, so we yield it directly. serde_json::Error is not PartialEq, so
    // the (unreachable here) failing path would use Fails; every row succeeds.
    #[test]
    fn test_state_outcome_serialize() {
        check_cases(
            [
                Case {
                    scenario: "wait with reason",
                    input: PersistentStateHandlerOutcome::Wait {
                        reason: "Reason goes here".to_string(),
                        source_ref: None,
                    },
                    expect: Yields(r#"{"outcome":"wait","reason":"Reason goes here"}"#.to_string()),
                },
                Case {
                    scenario: "transition, no source ref",
                    input: PersistentStateHandlerOutcome::Transition { source_ref: None },
                    expect: Yields(r#"{"outcome":"transition"}"#.to_string()),
                },
                Case {
                    scenario: "donothing with source ref details",
                    input: PersistentStateHandlerOutcome::DoNothing {
                        source_ref: Some(PersistentSourceReference {
                            file: "a.rs".to_string(),
                            line: 100,
                        }),
                    },
                    expect: Yields(
                        r#"{"outcome":"donothing","source_ref":{"file":"a.rs","line":100}}"#
                            .to_string(),
                    ),
                },
            ],
            |outcome| serde_json::to_string(&outcome).map_err(drop),
        );
    }

    // Deserialize JSON back into the outcome variant (the round-trip targets and
    // the standalone deserialize case). The deserialized type is PartialEq+Debug,
    // so we yield it directly. serde_json::Error is not PartialEq, hence map_err.
    #[test]
    fn test_state_outcome_deserialize() {
        check_cases(
            [
                Case {
                    scenario: "error variant",
                    input: r#"{"outcome":"error","err":"Error message here"}"#,
                    expect: Yields(PersistentStateHandlerOutcome::Error {
                        err: "Error message here".to_string(),
                        source_ref: None,
                    }),
                },
                Case {
                    scenario: "transition round-trip",
                    input: r#"{"outcome":"transition"}"#,
                    expect: Yields(PersistentStateHandlerOutcome::Transition { source_ref: None }),
                },
                Case {
                    scenario: "donothing with source ref round-trip",
                    input: r#"{"outcome":"donothing","source_ref":{"file":"a.rs","line":100}}"#,
                    expect: Yields(PersistentStateHandlerOutcome::DoNothing {
                        source_ref: Some(PersistentSourceReference {
                            file: "a.rs".to_string(),
                            line: 100,
                        }),
                    }),
                },
            ],
            |json| serde_json::from_str::<PersistentStateHandlerOutcome>(json).map_err(drop),
        );
    }
}
