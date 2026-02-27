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

//! Rack State Handler - Partition-aware validation state machine
//!
//! This handler manages rack lifecycle through discovery and validation phases.
//! Validation state is derived by aggregating partition status from instance metadata,
//! which is set by an external validation service (Anvil).
//!
//! ## Key Design Principles
//!
//! 1. **Carbide core is minimal**: It only tracks state, not orchestration
//! 2. **Anvil drives validation**: External service sets instance metadata
//! 3. **Partition-aware**: Tracks validation at partition (node group) level

use std::cmp::Ordering;

use carbide_uuid::rack::RackId;
use db::{expected_machine as db_expected_machine, rack as db_rack};
use model::machine::{LoadSnapshotOptions, ManagedHostState};
use model::rack::{Rack, RackState};
use sqlx::PgTransaction;

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};


/// Aggregated summary of all partition validation statuses in a rack.
/// Used by the state handler to determine state transitions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RackPartitionSummary {
    /// Total number of partitions in the rack
    pub total_partitions: usize,
    /// Number of partitions that haven't started validation
    pub pending: usize,
    /// Number of partitions currently being validated
    pub in_progress: usize,
    /// Number of partitions that passed validation
    pub validated: usize,
    /// Number of partitions that failed validation
    pub failed: usize,
}

impl RackPartitionSummary {
    /// Returns true if at least one partition has started validation
    pub fn any_started(&self) -> bool {
        self.in_progress > 0 || self.validated > 0 || self.failed > 0
    }

    /// Returns true if at least one partition has passed validation
    pub fn any_validated(&self) -> bool {
        self.validated > 0
    }

    /// Returns true if at least one partition has failed validation
    pub fn any_failed(&self) -> bool {
        self.failed > 0
    }

    /// Returns true if all partitions have passed validation
    pub fn all_validated(&self) -> bool {
        self.total_partitions > 0 && self.validated == self.total_partitions
    }

    /// Returns true if all partitions have failed validation
    pub fn all_failed(&self) -> bool {
        self.total_partitions > 0 && self.failed == self.total_partitions
    }

    /// Returns true if no partitions have failed
    pub fn none_failed(&self) -> bool {
        self.failed == 0
    }

    /// Returns true if there are no partitions
    /// TODO[542]: Have a discussion about it
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.total_partitions == 0
    }
}

// ============================================================================
// PARTITION SUMMARY LOADING - Stub for DB/metadata queries
// ============================================================================

/// Loads the aggregated partition validation summary for a rack.
///
/// This function queries all instances belonging to the rack, reads their
/// validation metadata labels, and aggregates the status by partition.
///
/// ## Expected Instance Metadata Labels
///
/// - `validation.partition-id`: Identifies which partition the node belongs to
/// - `validation.status`: One of "pending", "in_progress", "validated", "failed"
///
/// ## Implementation Notes
///
/// The actual implementation will:
/// 1. Query all instances associated with machines in this rack
/// 2. Group instances by `validation.partition-id`
/// 3. For each partition, determine aggregate status:
///    - If any node is "failed" → partition is Failed
///    - Else if any node is "in_progress" → partition is InProgress
///    - Else if all nodes are "validated" → partition is Validated
///    - Else → partition is Pending
/// 4. Count partitions in each status and return summary
///
/// TBD0: potential race condition where partitions aren't fully manifested yet,
/// but the rack validation is already started on some of them. Maybe in such
/// case, Anvil should restrain from advertising paritions right during the
/// instance creation (respective API call can carry the metadata), and instead,
/// it should update the metadata _after_ all instances are in place.
/// TBD1: if above is true - we may want to capture a state of ongoing instance
/// creation as something like "InstancesInitializing".
async fn load_partition_summary(
    _rack_id: &RackId,
    _rack: &Rack,
    _ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<RackPartitionSummary, StateHandlerError> {
    // TODO[542]: Implement partition summary loading from instance metadata
    //
    // Pseudocode:
    // ```
    //
    // /// Validation status for a single partition (derived from instance metadata)
    // #[derive(Clone, Debug, PartialEq, Eq)]
    // pub enum PartitionValidationStatus {
    //     /// Partition exists but validation hasn't started
    //     Pending,
    //     /// Validation is in progress
    //     InProgress,
    //     /// Validation completed successfully
    //     Validated,
    //     /// Validation failed
    //     Failed,
    // }
    //
    // let instances = db::instance::find_by_rack(txn, rack_id).await?;
    // let mut partitions: HashMap<String, Vec<PartitionValidationStatus>> = HashMap::new();
    //
    // for instance in instances {
    //     let partition_id = instance.metadata.labels.get("validation.partition-id");
    //     let status = instance.metadata.labels.get("validation.status");
    //     partitions.entry(partition_id).or_default().push(parse_status(status));
    // }
    //
    // // Aggregate per-partition status
    // let mut summary = RackPartitionSummary::default();
    // summary.total_partitions = partitions.len();
    // for (_, statuses) in partitions {
    //     match aggregate_partition_status(&statuses) {
    //         Pending => summary.pending += 1,
    //         InProgress => summary.in_progress += 1,
    //         Validated => summary.validated += 1,
    //         Failed => summary.failed += 1,
    //     }
    // }
    // Ok(summary)
    // ```
    unimplemented!("load_partition_summary: requires instance metadata query implementation")
}

///
/// Checks if all expected machines in the rack have been discovered and linked.
///
/// Returns `true` if:
/// - All expected compute trays have been linked to actual machines
/// - All expected power shelves have been discovered
/// - (Future) All expected NVLink switches have been discovered
///
/// TODO[542]: this part was reused from an old state machine, hence it should be
/// re-reviewed to make sure it matches the original code.
async fn all_expected_devices_discovered(
    rack_id: &RackId,
    rack: &Rack,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<(bool, Option<PgTransaction<'static>>), StateHandlerError> {
    let mut config = rack.config.clone();

    // Check compute trays
    let compute_done = match config
        .expected_compute_trays
        .len()
        .cmp(&config.compute_trays.len())
    {
        Ordering::Greater => {
            // Still waiting for some machines to be linked
            let mut txn = ctx.services.db_pool.begin().await?;
            for macaddr in config.expected_compute_trays.clone().as_slice() {
                match db_expected_machine::find_one_linked(&mut txn, *macaddr).await {
                    Ok(machine) => {
                        if let Some(machine_id) = machine.machine_id
                            && !config.compute_trays.contains(&machine_id)
                        {
                            config.compute_trays.push(machine_id);
                            db_rack::update(&mut txn, *rack_id, &config).await?;
                        }
                    }
                    Err(_) => {
                        // BMC not yet explored, continue waiting
                    }
                }
            }
            return Ok((false, Some(txn)));
        }
        Ordering::Less => {
            tracing::warn!(
                "Rack {} has more compute trays discovered ({}) than expected ({})",
                rack_id,
                config.compute_trays.len(),
                config.expected_compute_trays.len()
            );
            // This is a configuration issue but we consider discovery "done"
            true
        }
        Ordering::Equal => true,
    };

    // Check power shelves
    let ps_done = match config
        .expected_power_shelves
        .len()
        .cmp(&config.power_shelves.len())
    {
        Ordering::Greater => {
            // TODO[542]: Walk through power shelves and check if linked
            false
        }
        Ordering::Less => {
            tracing::warn!(
                "Rack {} has more power shelves discovered ({}) than expected ({})",
                rack_id,
                config.power_shelves.len(),
                config.expected_power_shelves.len()
            );
            true
        }
        Ordering::Equal => true,
    };

    // TODO[542]: Check NVLink switches when that code lands
    // let nvswitch_done = ...

    Ok((compute_done && ps_done, None))
}

/// Checks if all machines in the rack have reached ManagedHostState::Ready.
///
/// This is a prerequisite for entering the validation phase.
///
/// TODO[542]: this part was reused from an old state machine, hence it should be
/// re-reviewed/covered with units to make sure it does what's intended
/// TODO[542]: eventually, the check must migrate from queriying ::Ready state to
/// something like ::WaitingForPartitionValidation or something similar.
async fn all_machines_ready(
    rack_id: &RackId,
    rack: &Rack,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<(bool, PgTransaction<'static>), StateHandlerError> {
    let mut txn = ctx.services.db_pool.begin().await?;

    for machine_id in rack.config.compute_trays.iter() {
        let mh_snapshot = db::managed_host::load_snapshot(
            txn.as_mut(),
            machine_id,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: false,
                host_health_config: ctx.services.site_config.host_health,
            },
        )
        .await?
        .ok_or(StateHandlerError::MissingData {
            object_id: machine_id.to_string(),
            missing: "managed host not found",
        })?;

        if mh_snapshot.managed_state != ManagedHostState::Ready {
            tracing::debug!(
                "Rack {} has compute tray {} in {} state (waiting for Ready)",
                rack_id,
                machine_id,
                mh_snapshot.managed_state
            );
            return Ok((false, txn));
        }
    }

    // TODO[542]: Check NVLink switches
    // TODO[542]: Check power shelves

    Ok((true, txn))
}

// ============================================================================
// VALIDATION STATE TRANSITIONS
// ============================================================================

/// Computes the next validation state based on current state and partition summary.
///
/// This is a pure function that encodes the validation state machine transitions.
/// Returns `None` if no transition should occur.
fn compute_validation_transition(
    current: &RackState,
    summary: &RackPartitionSummary,
) -> Option<RackState> {
    match current {
        RackState::Discovered => {
            // Transition when at least one partition starts validation
            if summary.any_started() {
                Some(RackState::ValidationInProgress)
            } else {
                None
            }
        }

        RackState::ValidationInProgress => {
            // Check for failures first (higher priority)
            if summary.any_failed() {
                Some(RackState::FailedPartial)
            } else if summary.any_validated() {
                Some(RackState::ValidationPartial)
            } else {
                None
            }
        }

        RackState::ValidationPartial => {
            // Check if all done, or if any failed
            if summary.all_validated() {
                Some(RackState::RackValidated)
            } else if summary.any_failed() {
                Some(RackState::FailedPartial)
            } else {
                None
            }
        }

        RackState::FailedPartial => {
            if summary.all_failed() {
                Some(RackState::RackFailed)
            } else if summary.none_failed() {
                // Can recover if failures are resolved
                if summary.any_validated() {
                    Some(RackState::ValidationPartial)
                } else if summary.any_started() {
                    Some(RackState::ValidationInProgress)
                } else {
                    None
                }
            } else {
                None
            }
        }

        RackState::RackFailed => {
            // Can recover if at least one partition is no longer failed
            if !summary.all_failed() {
                Some(RackState::FailedPartial)
            } else {
                None
            }
        }

        RackState::RackValidated => {
            // Terminal success state - transition to Ready
            // TODO[542]: any additional checks?
            Some(RackState::Ready)
        }

        // Non-validation states don't use this function
        _ => None,
    }
}

// ============================================================================
// STATE HANDLER IMPLEMENTATION
// ============================================================================

#[derive(Debug, Default, Clone)]
pub struct RackStateHandler {}

#[async_trait::async_trait]
impl StateHandler for RackStateHandler {
    type ObjectId = RackId;
    type State = Rack;
    type ControllerState = RackState;
    type ContextObjects = RackStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        id: &Self::ObjectId,
        state: &mut Rack,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
        tracing::info!("Rack {} is in state {}", id, controller_state);

        match controller_state {
            // =================================================================
            // DISCOVERY PHASE
            // =================================================================
            RackState::Unknown => {
                // Unknown is the default state - wait for Expected to be set
                // via ExpectedMachine/Switch/PS API calls
                Ok(StateHandlerOutcome::do_nothing())
            }

            RackState::Expected => {
                // Wait for all expected devices to be discovered and linked
                let (all_discovered, pending_txn) =
                    all_expected_devices_discovered(id, state, ctx).await?;

                if all_discovered {
                    tracing::info!("Rack {} has all expected devices discovered", id);
                    Ok(
                        StateHandlerOutcome::transition(RackState::Discovering)
                            .with_txn_opt(pending_txn),
                    )
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn_opt(pending_txn))
                }
            }

            RackState::Discovering => {
                // Wait for all machines to reach ManagedHostState::Ready
                // TODO[542]: The responsibility of gating production
                // instance allocation should live in the node/tray-level state
                // machine, not here. Each node should have an
                // `AwaitingPartitionValidation` (or similar) state (instead of
                // Ready) that prevents it from transitioning to Ready until
                // rack validation completes. Until that is implemented, there's
                // a potential race condition where nodes could be allocated
                // before validation.
                let (all_ready, txn) = all_machines_ready(id, state, ctx).await?;

                if all_ready {
                    tracing::info!(
                        "Rack {} has all machines ready, entering Discovered state",
                        id
                    );
                    Ok(StateHandlerOutcome::transition(RackState::Discovered).with_txn(txn))
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
                }
            }

            // =================================================================
            // VALIDATION PHASE - State derived from partition metadata
            // =================================================================
            RackState::Discovered
            | RackState::ValidationInProgress
            | RackState::ValidationPartial
            | RackState::FailedPartial => {
                // Load current partition summary from instance metadata
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

                // Compute state transition based on summary
                if let Some(next_state) = compute_validation_transition(controller_state, &summary)
                {
                    tracing::info!(
                        "Rack {} transitioning from {} to {}",
                        id,
                        controller_state,
                        next_state
                    );
                    Ok(StateHandlerOutcome::transition(next_state))
                } else {
                    Ok(StateHandlerOutcome::do_nothing())
                }
            }

            // =================================================================
            // TERMINAL STATES
            // =================================================================
            RackState::RackValidated => {
                // All partitions validated - transition to Ready
                tracing::info!("Rack {} fully validated, transitioning to Ready", id);
                Ok(StateHandlerOutcome::transition(RackState::Ready))
            }

            RackState::RackFailed => {
                // All partitions failed - check for recovery
                let summary = load_partition_summary(id, state, ctx).await?;

                if let Some(next_state) = compute_validation_transition(controller_state, &summary)
                {
                    tracing::info!(
                        "Rack {} recovering from RackFailed to {}",
                        id,
                        next_state
                    );
                    Ok(StateHandlerOutcome::transition(next_state))
                } else {
                    // Still fully failed - needs manual intervention
                    tracing::warn!(
                        "Rack {} is in RackFailed state, requires intervention",
                        id
                    );
                    Ok(StateHandlerOutcome::do_nothing())
                }
            }

            RackState::Ready => {
                // Rack is ready for production workloads
                // TODO[542]: add reset condition if validation if triggered externally
                Ok(StateHandlerOutcome::do_nothing())
            }

            RackState::Error { cause } => {
                // Error state - log and wait for manual intervention
                tracing::error!("Rack {} is in error state: {}", id, cause);
                // TODO[542]: add the error reset condition
                Ok(StateHandlerOutcome::do_nothing())
            }

            RackState::Deleting => {
                // Rack is being deleted - no action needed for now
                // TODO[542]: add espace condition in case rack is recreated
                Ok(StateHandlerOutcome::do_nothing())
            }
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_validation_transition_from_discovered() {
        let state = RackState::Discovered;

        // No partitions started yet
        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 4,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        // One partition in progress
        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 3,
            in_progress: 1,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::ValidationInProgress)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_in_progress() {
        let state = RackState::ValidationInProgress;

        // Still in progress
        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 2,
            in_progress: 2,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        // One validated
        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 2,
            in_progress: 1,
            validated: 1,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::ValidationPartial)
        );

        // One failed (higher priority than validated)
        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 1,
            in_progress: 1,
            validated: 1,
            failed: 1,
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_partial() {
        let state = RackState::ValidationPartial;

        // More in progress
        let summary = RackPartitionSummary {
            total_partitions: 4,
            in_progress: 2,
            validated: 2,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        // All validated
        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 4,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::RackValidated)
        );

        // One failed
        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 3,
            failed: 1,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_failed() {
        let state = RackState::FailedPartial;

        // All failed -> RackFailed
        let summary = RackPartitionSummary {
            total_partitions: 4,
            failed: 4,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::RackFailed)
        );

        // Recovery: no failures, some validated
        let summary = RackPartitionSummary {
            total_partitions: 4,
            in_progress: 2,
            validated: 2,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::ValidationPartial)
        );

        // Recovery: no failures, none validated yet
        let summary = RackPartitionSummary {
            total_partitions: 4,
            pending: 2,
            in_progress: 2,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::ValidationInProgress)
        );

        // Still some failed, some validated
        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 2,
            failed: 2,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);
    }

    #[test]
    fn test_compute_validation_transition_from_rack_failed() {
        let state = RackState::RackFailed;

        // Still all failed
        let summary = RackPartitionSummary {
            total_partitions: 4,
            failed: 4,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        // Recovery started
        let summary = RackPartitionSummary {
            total_partitions: 4,
            in_progress: 1,
            failed: 3,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_validated() {
        let state = RackState::RackValidated;

        // Always transitions to Ready
        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 4,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackState::Ready)
        );
    }
}
