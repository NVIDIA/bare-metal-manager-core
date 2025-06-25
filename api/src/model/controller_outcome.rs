/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use serde::{Deserialize, Serialize};

use crate::state_controller::state_handler::{
    SourceReference, StateHandlerError, StateHandlerOutcome,
};

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
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PersistentSourceReference {
    pub file: String,
    pub line: u32,
}

impl From<&SourceReference> for PersistentSourceReference {
    fn from(value: &SourceReference) -> Self {
        Self {
            file: value.file.to_string(),
            line: value.line,
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

impl<S> From<Result<&StateHandlerOutcome<S>, &StateHandlerError>>
    for PersistentStateHandlerOutcome
{
    fn from(
        r: Result<&StateHandlerOutcome<S>, &StateHandlerError>,
    ) -> PersistentStateHandlerOutcome {
        match r {
            Ok(StateHandlerOutcome::Wait { reason, source_ref }) => {
                PersistentStateHandlerOutcome::Wait {
                    reason: reason.clone(),
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::Transition { source_ref, .. }) => {
                PersistentStateHandlerOutcome::Transition {
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::DoNothing { source_ref }) => {
                PersistentStateHandlerOutcome::DoNothing {
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::Deleted { .. }) => unreachable!(),
            Err(err) => PersistentStateHandlerOutcome::Error {
                err: err.to_string(),
                // TODO: Make it possible to determine where errors are generated
                source_ref: None,
            },
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
