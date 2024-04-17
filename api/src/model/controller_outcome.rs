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

use crate::state_controller::state_handler::{StateHandlerError, StateHandlerOutcome};

/// DB storage of the result of a state handler iteration
/// It is different from a StateHandlerOutcome in that it also stores the error message,
/// and does not store the state, which is already stored elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum PersistentStateHandlerOutcome {
    Wait { reason: String },
    Error { err: String },
    Transition,
    DoNothing,
}

impl<S> From<Result<&StateHandlerOutcome<S>, &StateHandlerError>>
    for PersistentStateHandlerOutcome
{
    fn from(
        r: Result<&StateHandlerOutcome<S>, &StateHandlerError>,
    ) -> PersistentStateHandlerOutcome {
        match r {
            Ok(StateHandlerOutcome::Wait(reason)) => PersistentStateHandlerOutcome::Wait {
                reason: reason.clone(),
            },
            Ok(StateHandlerOutcome::Transition(_)) => PersistentStateHandlerOutcome::Transition,
            Ok(StateHandlerOutcome::DoNothing) => PersistentStateHandlerOutcome::DoNothing,
            Ok(StateHandlerOutcome::Deleted) => unreachable!(),
            Err(err) => PersistentStateHandlerOutcome::Error {
                err: err.to_string(),
            },
        }
    }
}

impl From<PersistentStateHandlerOutcome> for rpc::forge::ControllerStateReason {
    fn from(p: PersistentStateHandlerOutcome) -> rpc::forge::ControllerStateReason {
        use rpc::forge::ControllerStateOutcome::*;
        let (outcome, outcome_msg) = match p {
            PersistentStateHandlerOutcome::Wait { reason } => (Wait, Some(reason)),
            PersistentStateHandlerOutcome::Error { err } => (Error, Some(err)),
            PersistentStateHandlerOutcome::Transition => (Transition, None),
            PersistentStateHandlerOutcome::DoNothing => (DoNothing, None),
        };
        rpc::forge::ControllerStateReason {
            outcome: outcome.into(), // into converts it to i32
            outcome_msg,
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
        };
        let deserialized: PersistentStateHandlerOutcome = serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized, expected_error_state);
    }

    #[test]
    fn test_state_outcome_serialize_deserialize_basic() {
        let transition_state = PersistentStateHandlerOutcome::Transition;
        let serialized = serde_json::to_string(&transition_state).unwrap();
        assert_eq!(serialized, r#"{"outcome":"transition"}"#);

        let deserialized: PersistentStateHandlerOutcome =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, transition_state);
    }
}
