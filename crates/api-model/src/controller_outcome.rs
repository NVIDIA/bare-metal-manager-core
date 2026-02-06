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

impl From<PersistentSourceReference> for rpc::forge::ControllerStateSourceReference {
    fn from(source_ref: PersistentSourceReference) -> Self {
        rpc::forge::ControllerStateSourceReference {
            file: source_ref.file,
            line: source_ref.line.try_into().unwrap_or_default(),
        }
    }
}

impl From<PersistentStateHandlerOutcome> for rpc::forge::ControllerStateReason {
    fn from(p: PersistentStateHandlerOutcome) -> rpc::forge::ControllerStateReason {
        use rpc::forge::ControllerStateOutcome::*;
        let (outcome, outcome_msg, source_ref) = match p {
            PersistentStateHandlerOutcome::Wait { reason, source_ref } => {
                (Wait, Some(reason), source_ref)
            }
            PersistentStateHandlerOutcome::Error { err, source_ref } => {
                (Error, Some(err), source_ref)
            }
            PersistentStateHandlerOutcome::Transition { source_ref } => {
                (Transition, None, source_ref)
            }
            PersistentStateHandlerOutcome::DoNothing { source_ref } => {
                (DoNothing, None, source_ref)
            }
            PersistentStateHandlerOutcome::DoNothingWithDetails => (DoNothing, None, None),
        };
        rpc::forge::ControllerStateReason {
            outcome: outcome.into(), // into converts it to i32
            outcome_msg,
            source_ref: source_ref.map(Into::into),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_state_outcome_serialize() {
        let wait_state = PersistentStateHandlerOutcome::Wait {
            reason: "Reason goes here".to_string(),
            source_ref: None,
        };
        let serialized = serde_json::to_string(&wait_state).unwrap();
        assert_eq!(
            serialized,
            r#"{"outcome":"wait","reason":"Reason goes here"}"#
        );
    }

    #[test]
    fn test_state_outcome_deserialize() {
        let serialized = r#"{"outcome":"error","err":"Error message here"}"#;
        let expected_error_state = PersistentStateHandlerOutcome::Error {
            err: "Error message here".to_string(),
            source_ref: None,
        };
        let deserialized: PersistentStateHandlerOutcome = serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized, expected_error_state);
    }

    #[test]
    fn test_state_outcome_serialize_deserialize_basic() {
        let transition_state = PersistentStateHandlerOutcome::Transition { source_ref: None };
        let serialized = serde_json::to_string(&transition_state).unwrap();
        assert_eq!(serialized, r#"{"outcome":"transition"}"#);

        let deserialized: PersistentStateHandlerOutcome =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, transition_state);
    }

    #[test]
    fn test_state_outcome_serialize_details() {
        let state = PersistentStateHandlerOutcome::DoNothing {
            source_ref: Some(PersistentSourceReference {
                file: "a.rs".to_string(),
                line: 100,
            }),
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serialized,
            r#"{"outcome":"donothing","source_ref":{"file":"a.rs","line":100}}"#
        );
        let deserialized: PersistentStateHandlerOutcome =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, state);
    }
}
