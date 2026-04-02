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

//! Handler for RackState::Validating.

use carbide_uuid::rack::RackId;
use db::{self, machine as db_machine};
use model::machine::machine_search_config::MachineSearchConfig;
use model::rack::{Rack, RackState, RackValidationState};

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::rv::{RackPartitionSummary, RvPartitions};
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

pub async fn handle_validating(
    id: &RackId,
    state: &mut Rack,
    validating_state: &RackValidationState,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    if !ctx.services.site_config.rack_validation_config.enabled {
        tracing::info!("Rack {} validation disabled, skipping to Ready", id);
        return Ok(StateHandlerOutcome::transition(RackState::Ready));
    }

    let summary = load_partition_summary(id, state, ctx).await?;

    tracing::debug!(
        "Rack {} partition summary: total={}, pending={}, in_progress={}, validated={}, failed={}",
        id,
        summary.total_partitions,
        summary.pending,
        summary.in_progress,
        summary.validated,
        summary.failed
    );

    if let Some(next_vs) = compute_validation_transition(validating_state, &summary) {
        tracing::info!(
            "Rack {} validation transitioning from {} to {}",
            id,
            validating_state,
            next_vs
        );
        Ok(StateHandlerOutcome::transition(RackState::Validating {
            validating_state: next_vs,
        }))
    } else if matches!(validating_state, RackValidationState::Validated) {
        tracing::info!("Rack {} fully validated, transitioning to Ready", id);
        Ok(StateHandlerOutcome::transition(RackState::Ready))
    } else if matches!(validating_state, RackValidationState::Failed) {
        tracing::error!(
            "Rack {} all validation partitions failed, transitioning to Error",
            id
        );
        Ok(StateHandlerOutcome::transition(RackState::Error {
            cause: "All validation partitions failed".to_string(),
        }))
    } else {
        Ok(StateHandlerOutcome::wait(format!(
            "validation in progress ({})",
            validating_state
        )))
    }
}

/// Loads the aggregated partition validation summary for a rack.
pub(crate) async fn load_partition_summary(
    rack_id: &RackId,
    rack: &Rack,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<RackPartitionSummary, StateHandlerError> {
    let mut txn = ctx.services.db_pool.begin().await?;
    let machine_ids = db_machine::find_machine_ids(
        txn.as_mut(),
        MachineSearchConfig {
            rack_id: Some(rack_id.clone()),
            ..Default::default()
        },
    )
    .await?;
    drop(txn);

    if machine_ids.is_empty() {
        tracing::debug!(
            "Rack {} has no compute trays, returning empty summary",
            rack_id
        );
        return Ok(RackPartitionSummary::default());
    }

    let mut txn = ctx.services.db_pool.begin().await?;
    let machines = db_machine::find(
        &mut *txn,
        db::ObjectFilter::List(&machine_ids),
        MachineSearchConfig::default(),
    )
    .await?;
    txn.commit().await?;

    tracing::debug!(
        "Rack {} has {} machines for {} compute trays",
        rack_id,
        machines.len(),
        machine_ids.len(),
    );

    let validation_run_id = &rack.config.validation_run_id;
    let partitions = RvPartitions::from_machines(machines, validation_run_id.clone())?;
    Ok(partitions.summarize())
}

/// Computes the next validation sub-state based on current sub-state and
/// partition summary. Returns `None` if no transition should occur.
pub(crate) fn compute_validation_transition(
    current: &RackValidationState,
    summary: &RackPartitionSummary,
) -> Option<RackValidationState> {
    match current {
        RackValidationState::Pending => {
            if summary.in_progress > 0 || summary.validated > 0 || summary.failed > 0 {
                Some(RackValidationState::InProgress)
            } else {
                None
            }
        }
        RackValidationState::InProgress => {
            if summary.failed > 0 {
                Some(RackValidationState::FailedPartial)
            } else if summary.validated > 0 {
                Some(RackValidationState::Partial)
            } else {
                None
            }
        }
        RackValidationState::Partial => {
            if summary.validated == summary.total_partitions {
                Some(RackValidationState::Validated)
            } else if summary.failed > 0 {
                Some(RackValidationState::FailedPartial)
            } else {
                None
            }
        }
        RackValidationState::FailedPartial => {
            if summary.total_partitions == 0 {
                Some(RackValidationState::Pending)
            } else if summary.failed == summary.total_partitions {
                Some(RackValidationState::Failed)
            } else if summary.failed == 0 {
                if summary.validated > 0 {
                    Some(RackValidationState::Partial)
                } else if summary.in_progress > 0 {
                    Some(RackValidationState::InProgress)
                } else {
                    Some(RackValidationState::Pending)
                }
            } else {
                None
            }
        }
        RackValidationState::Failed => {
            if summary.failed != summary.total_partitions {
                Some(RackValidationState::FailedPartial)
            } else {
                None
            }
        }
        RackValidationState::Validated => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_validation_transition_from_pending() {
        let state = RackValidationState::Pending;

        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 4,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 3,
            in_progress: 1,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::InProgress)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_in_progress() {
        let state = RackValidationState::InProgress;

        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 2,
            in_progress: 2,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 2,
            in_progress: 1,
            validated: 1,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::Partial)
        );

        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 1,
            in_progress: 1,
            validated: 1,
            failed: 1,
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_partial() {
        let state = RackValidationState::Partial;

        let summary = RackPartitionSummary {
            total_partitions: 4,
            in_progress: 2,
            validated: 2,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 4,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::Validated)
        );

        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 3,
            failed: 1,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_failed_partial() {
        let state = RackValidationState::FailedPartial;

        let summary = RackPartitionSummary {
            total_partitions: 4,
            failed: 4,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::Failed)
        );

        let summary = RackPartitionSummary {
            total_partitions: 4,
            in_progress: 2,
            validated: 2,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::Partial)
        );

        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 2,
            in_progress: 2,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::InProgress)
        );

        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 2,
            failed: 2,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 4,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::Pending)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_failed() {
        let state = RackValidationState::Failed;

        let summary = RackPartitionSummary {
            total_partitions: 4,
            failed: 4,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        let summary = RackPartitionSummary {
            total_partitions: 4,
            in_progress: 1,
            failed: 3,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_validated() {
        let state = RackValidationState::Validated;

        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 4,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);
    }
}
