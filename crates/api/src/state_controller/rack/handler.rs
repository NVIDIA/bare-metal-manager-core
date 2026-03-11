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
//! which is set by an external validation service (RVS).
//!
//! ## Key Design Principles
//!
//! 1. Carbide core is minimal: It only tracks state, not orchestration
//! 2. RVS drives validation: External service sets instance metadata
//! 3. Partition-aware: Tracks validation at partition (node group) level

use std::cmp::Ordering;
use std::collections::HashMap;

use carbide_uuid::machine::MachineId;
use carbide_uuid::rack::RackId;
use db::{self, expected_machine as db_expected_machine, rack as db_rack};
use model::instance::snapshot::InstanceSnapshot;
use model::machine::{LoadSnapshotOptions, ManagedHostState};
use model::metadata::Metadata;
use model::rack::{
    Rack, RackFirmwareUpgradeState, RackMaintenanceState, RackPowerState, RackState,
    RackValidationState,
};
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
    /// TODO: make sure all fields below sums together to total
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

//------------------------------------------------------------------------------

/// Instance metadata labels assigned as a part of instance creation by RVS to
/// communicate the state of the instance.
enum InstanceRvLabels {
    /// Label key for the partition ID that groups nodes into validation
    /// partitions.
    PartitionId,
    // Label key for the validation run correlation ID. Not used yet -- will be
    // needed when RVS sets run correlation metadata.
    // Not yet used anywhere in the code.
    // RunId,
    /// Label key for the per-node validation status.
    State,
    /// Label key for a failure description (only meaningful when status is
    /// `fail`).
    FailDesc,
}

impl InstanceRvLabels {
    fn as_str(&self) -> &'static str {
        match self {
            InstanceRvLabels::PartitionId => "rv.part-id",
            // TBD: use the run-id somewhere
            // InstanceRvLabels::RunId => "rv.run-id",
            InstanceRvLabels::State => "rv.st",
            InstanceRvLabels::FailDesc => "rv.fail-desc",
        }
    }
}

/// Per-instance rack-validation state, derived from instance metadata labels.
#[derive(Clone, Debug, PartialEq, Eq)]
enum InstanceRvState {
    Idle,
    Inp,
    Pass,
    Fail(String),
}

impl TryFrom<Metadata> for InstanceRvState {
    type Error = StateHandlerError;

    fn try_from(metadata: Metadata) -> Result<Self, Self::Error> {
        let st_label = InstanceRvLabels::State.as_str();
        let fail_label = InstanceRvLabels::FailDesc.as_str();

        let st = metadata.labels.get(st_label).ok_or_else(|| {
            StateHandlerError::InvalidState(format!("missing required label '{}'", st_label))
        })?;

        match st.as_str() {
            "idle" => Ok(InstanceRvState::Idle),
            "inp" => Ok(InstanceRvState::Inp),
            "pass" => Ok(InstanceRvState::Pass),
            "fail" => {
                let desc = metadata.labels.get(fail_label).cloned().unwrap_or_default();
                Ok(InstanceRvState::Fail(desc))
            }
            other => Err(StateHandlerError::InvalidState(format!(
                "unknown '{}' value: '{}'",
                st_label, other
            ))),
        }
    }
}

//------------------------------------------------------------------------------

/// Partition grouping: maps partition ID -> per-node validation states.
///
/// Only instances that carry the `rv.part-id` label are considered
/// validation instances. Instances without it are silently skipped.
struct RvPartitions {
    inner: HashMap<String, Vec<InstanceRvState>>,
}

impl TryFrom<&[InstanceSnapshot]> for RvPartitions {
    type Error = StateHandlerError;

    /// Build from a slice of instance snapshots (the DB-facing entry point).
    fn try_from(instances: &[InstanceSnapshot]) -> Result<Self, Self::Error> {
        Self::from_meta_iter(instances.iter().map(|i| &i.metadata).cloned())
    }
}

impl RvPartitions {
    /// Core grouping logic over any iterator of `&Metadata`.
    /// Extracted so unit tests can feed plain metadata without constructing
    /// full `InstanceSnapshot` values.
    fn from_meta_iter(iter: impl Iterator<Item = Metadata>) -> Result<Self, StateHandlerError> {
        let mut inner: HashMap<String, Vec<InstanceRvState>> = HashMap::new();
        let part_label = InstanceRvLabels::PartitionId.as_str();

        for mut meta in iter {
            // Skip instances that aren't part of rack validation
            let Some(part_id) = meta.labels.remove(part_label) else {
                continue;
            };

            let rv_state = meta.try_into()?;
            inner.entry(part_id).or_default().push(rv_state);
        }

        Ok(RvPartitions { inner })
    }

    /// Aggregate per-node states into a [`RackPartitionSummary`].
    ///
    /// For each partition, the aggregate status is:
    /// - Validated   if all nodes are `Pass`
    /// - Failed      else if any node is `Fail`
    /// - InProgress  else if any node is `Inp`
    /// - Pending     otherwise (all `Idle`, or a mix of `Idle`/`Pass`)
    fn summarize(&self) -> RackPartitionSummary {
        let mut summary = RackPartitionSummary {
            total_partitions: self.inner.len(),
            ..Default::default()
        };

        for states in self.inner.values() {
            // Order of checks matter

            if states.iter().all(|s| *s == InstanceRvState::Pass) {
                summary.validated += 1;
            } else if states.iter().any(|s| matches!(s, InstanceRvState::Fail(_))) {
                summary.failed += 1;
            } else if states.iter().any(|s| *s == InstanceRvState::Inp) {
                summary.in_progress += 1;
            } else {
                summary.pending += 1;
            }
        }

        summary
    }
}

//------------------------------------------------------------------------------

/// Loads the aggregated partition validation summary for a rack.
///
/// This function queries all instances belonging to the rack, reads their
/// validation metadata labels, and aggregates the status by partition.
///
/// ## Expected Instance Metadata Labels
///
/// - `rv.part-id`: Identifies which partition the node belongs to
/// - `rv.st`: One of "idle", "inp", "pass", "fail"
///
/// TBD0: potential race condition where partitions aren't fully manifested yet,
/// but the rack validation is already started on some of them. Maybe in such
/// case, RVS should restrain from advertising partitions right during the
/// instance creation (respective API call can carry the metadata), and instead,
/// it should update the metadata _after_ all instances are in place.
/// TBD1: if above is true - we may want to capture a state of ongoing instance
/// creation as something like "InstancesInitializing".
async fn load_partition_summary(
    rack_id: &RackId,
    rack: &Rack,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<RackPartitionSummary, StateHandlerError> {
    let machine_ids: Vec<&MachineId> = rack.config.compute_trays.iter().collect();

    if machine_ids.is_empty() {
        tracing::debug!(
            "Rack {} has no compute trays, returning empty summary",
            rack_id
        );
        return Ok(RackPartitionSummary::default());
    }

    let mut txn = ctx.services.db_pool.begin().await?;
    let instances = db::instance::find_by_machine_ids(txn.as_mut(), &machine_ids).await?;

    tracing::debug!(
        "Rack {} has {} instances across {} machines",
        rack_id,
        instances.len(),
        machine_ids.len()
    );

    let partitions: RvPartitions = instances.as_slice().try_into()?;
    Ok(partitions.summarize())
}

/// Checks if all expected machines in the rack have been discovered and linked.
///
/// Returns `true` if:
/// - All expected compute trays have been linked to actual machines
/// - All expected power shelves have been discovered
/// - (Future) All expected NVLink switches have been discovered
///
/// TODO[#416]: this part was reused from an old state machine, hence it should be
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
            // TODO[#416]: Walk through power shelves and check if linked
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

    // TODO[#416]: Check NVLink switches when that code lands
    // let nvswitch_done = ...

    Ok((compute_done && ps_done, None))
}

/// Checks if all machines in the rack have reached ManagedHostState::Ready.
///
/// This is a prerequisite for entering the validation phase.
///
/// TODO[#416]: eventually, the check must migrate from querying ::Ready state to
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

    // TODO[#416]: Check NVLink switches
    // TODO[#416]: Check power shelves

    Ok((true, txn))
}

//------------------------------------------------------------------------------

// VALIDATION STATE TRANSITIONS

/// Computes the next validation sub-state based on current sub-state and
/// partition summary.
///
/// This is a pure function that encodes the validation state machine
/// transitions. It operates purely on `RackValidationState` -- the caller
/// is responsible for wrapping the result back into
/// `RackState::Validation { .. }` (or handling the Validated -> Ready
/// promotion).
///
/// Returns `None` if no transition should occur.
fn compute_validation_transition(
    current: &RackValidationState,
    summary: &RackPartitionSummary,
) -> Option<RackValidationState> {
    match current {
        RackValidationState::Pending => {
            // Transition when at least one partition starts validation
            if summary.in_progress > 0 || summary.validated > 0 || summary.failed > 0 {
                Some(RackValidationState::InProgress)
            } else {
                None
            }
        }
        RackValidationState::InProgress => {
            // Check for failures first (higher priority)
            if summary.failed > 0 {
                Some(RackValidationState::FailedPartial)
            } else if summary.validated > 0 {
                Some(RackValidationState::Partial)
            } else {
                None
            }
        }
        RackValidationState::Partial => {
            // Check if all done, or if any failed
            if summary.validated == summary.total_partitions {
                Some(RackValidationState::Validated)
            } else if summary.failed > 0 {
                Some(RackValidationState::FailedPartial)
            } else {
                None
            }
        }
        RackValidationState::FailedPartial => {
            if summary.failed == summary.total_partitions {
                Some(RackValidationState::Failed)
            } else if summary.failed == 0 {
                // All failures resolved -- figure out where to go next
                if summary.validated > 0 {
                    Some(RackValidationState::Partial)
                } else if summary.in_progress > 0 {
                    Some(RackValidationState::InProgress)
                } else {
                    // All partitions back to idle/pending (e.g. RVS reset
                    // instances before a re-run). Transition to Pending so
                    // the validation cycle can restart cleanly.
                    Some(RackValidationState::Pending)
                }
            } else {
                None
            }
        }
        RackValidationState::Failed => {
            // Can recover if at least one partition is no longer failed
            if summary.failed != summary.total_partitions {
                Some(RackValidationState::FailedPartial)
            } else {
                None
            }
        }
        RackValidationState::Validated => {
            // Terminal success sub-state. The handler promotes this to
            // RackState::Ready; no further validation transition needed.
            None
        }
    }
}

//------------------------------------------------------------------------------

// STATE HANDLER IMPLEMENTATION

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

        // If the rack has been marked as deleted in the DB (via the DeleteRack
        // API), transition to Deleting regardless of current state. This
        // bridges the `deleted` DB column with the state machine -- without it,
        // a deleted rack could keep being processed if it was already enqueued
        // in the controller's work queue.
        if state.deleted.is_some() && !matches!(controller_state, RackState::Deleting) {
            tracing::info!(
                "Rack {} is marked as deleted, transitioning from {} to Deleting",
                id,
                controller_state
            );
            return Ok(StateHandlerOutcome::transition(RackState::Deleting));
        }

        match controller_state {
            // DISCOVERY PHASE & STATES
            RackState::Unknown => {
                // Default DB column value. The transition to Expected is forced
                // by db::rack::create(), not by the state machine. If a rack
                // somehow ends up here, just wait.
                tracing::debug!("Rack {} is in Unknown state, waiting for create()", id);
                Ok(StateHandlerOutcome::do_nothing())
            }

            RackState::Expected => {
                // Wait for all expected devices to be discovered and linked
                let (all_discovered, pending_txn) =
                    all_expected_devices_discovered(id, state, ctx).await?;

                if all_discovered {
                    tracing::info!("Rack {} has all expected devices discovered", id);
                    Ok(StateHandlerOutcome::transition(RackState::Discovering)
                        .with_txn_opt(pending_txn))
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn_opt(pending_txn))
                }
            }

            RackState::Discovering => {
                // Wait for all machines to reach ManagedHostState::Ready
                // TODO[#416]: The responsibility of gating production
                // instance allocation should live in the node/tray-level state
                // machine, not here.
                // The proposed mechanism is to force health overrides for each
                // node that transitioning into READY state, essentially make
                // nodes "unhealthy". This way no instance can be allocated
                // for the tenant. RVS, however, will be able to force the
                // instance via supplying "allow_unhealthy" flag while creating
                // instances.
                let (all_ready, txn) = all_machines_ready(id, state, ctx).await?;

                if all_ready {
                    // TODO[#416]: The entry point into maintenance is currently
                    // hardcoded to FirmwareUpgrade(Compute). This should become
                    // configurable or determined by rack/site config so that
                    // different maintenance workflows can be selected.
                    tracing::info!("Rack {} has all machines ready, entering maintenance", id);
                    Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                        rack_maintenance: RackMaintenanceState::FirmwareUpgrade {
                            rack_firmware_upgrade: RackFirmwareUpgradeState::Compute,
                        },
                    })
                    .with_txn(txn))
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
                }
            }

            RackState::Maintenance { rack_maintenance } => {
                match rack_maintenance {
                    RackMaintenanceState::FirmwareUpgrade {
                        rack_firmware_upgrade,
                    } => {
                        match rack_firmware_upgrade {
                            RackFirmwareUpgradeState::Compute => {
                                // TODO[#416]: Implement compute firmware upgrade
                                // orchestration via Rack Manager Service.
                                // For now, skip straight to Completed.
                                tracing::info!(
                                    "Rack {} firmware upgrade (compute) - stubbed, completing",
                                    id
                                );
                                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                                    rack_maintenance: RackMaintenanceState::Completed,
                                }))
                            }
                            RackFirmwareUpgradeState::Switch => {
                                // TODO[#416]: Implement switch firmware upgrade
                                tracing::info!("Rack {} firmware upgrade (switch) - stubbed", id);
                                Ok(StateHandlerOutcome::do_nothing())
                            }
                            RackFirmwareUpgradeState::PowerShelf => {
                                // TODO[#416]: Implement power shelf firmware upgrade
                                tracing::info!(
                                    "Rack {} firmware upgrade (power shelf) - stubbed",
                                    id
                                );
                                Ok(StateHandlerOutcome::do_nothing())
                            }
                            RackFirmwareUpgradeState::All => {
                                // TODO[#416]: Implement full-rack firmware upgrade
                                // (likely delegated to Rack Manager for the entire rack)
                                tracing::info!("Rack {} firmware upgrade (all) - stubbed", id);
                                Ok(StateHandlerOutcome::do_nothing())
                            }
                        }
                    }
                    RackMaintenanceState::PowerSequence { rack_power } => {
                        match rack_power {
                            RackPowerState::PoweringOn => {
                                // TODO[#416]: Implement power-on sequencing
                                tracing::info!("Rack {} power sequence (on) - stubbed", id);
                                Ok(StateHandlerOutcome::do_nothing())
                            }
                            RackPowerState::PoweringOff => {
                                // TODO[#416]: Implement power-off sequencing
                                tracing::info!("Rack {} power sequence (off) - stubbed", id);
                                Ok(StateHandlerOutcome::do_nothing())
                            }
                            RackPowerState::PowerReset => {
                                // TODO[#416]: Implement power reset sequencing
                                tracing::info!("Rack {} power sequence (reset) - stubbed", id);
                                Ok(StateHandlerOutcome::do_nothing())
                            }
                        }
                    }
                    RackMaintenanceState::Completed => {
                        // Maintenance is done -- enter the validation phase.
                        tracing::info!(
                            "Rack {} maintenance completed, entering validation phase",
                            id
                        );
                        Ok(StateHandlerOutcome::transition(RackState::Validation {
                            rack_validation: RackValidationState::Pending,
                        }))
                    }
                }
            }

            // VALIDATION PHASE -- state derived from partition metadata.
            // All validation sub-states are handled uniformly: load the
            // partition summary, compute the next sub-state, and wrap it
            // back into RackState::Validation. The special case is
            // Validated, which promotes to RackState::Ready.
            RackState::Validation { rack_validation } => {
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

                if let Some(next_vs) = compute_validation_transition(rack_validation, &summary) {
                    tracing::info!(
                        "Rack {} validation transitioning from {} to {}",
                        id,
                        rack_validation,
                        next_vs
                    );
                    Ok(StateHandlerOutcome::transition(RackState::Validation {
                        rack_validation: next_vs,
                    }))
                } else if matches!(rack_validation, RackValidationState::Validated) {
                    // Validated is the terminal validation sub-state --
                    // promote to the top-level Ready state.
                    tracing::info!("Rack {} fully validated, transitioning to Ready", id);
                    Ok(StateHandlerOutcome::transition(RackState::Ready))
                } else if matches!(rack_validation, RackValidationState::Failed) {
                    // All partitions failed -- stay here and wait for
                    // recovery or manual intervention.
                    tracing::warn!(
                        "Rack {} is in Validation(Failed) state, requires intervention",
                        id
                    );
                    Ok(StateHandlerOutcome::do_nothing())
                } else {
                    Ok(StateHandlerOutcome::do_nothing())
                }
            }

            RackState::Ready => {
                // Rack is ready for production workloads, but check if
                // a new validation run has been kicked off.
                // TODO[#416]: Ready should also be able to transition into
                // Maintenance (e.g. firmware upgrade triggered on a live
                // rack). The mechanism for that is TBD -- it may come from
                // an external API call or a config change rather than being
                // polled here.
                let summary = load_partition_summary(id, state, ctx).await?;

                // Stay in Ready when all partitions are still validated, or
                // when there are no validation partitions at all (vacuously
                // true -- e.g. tenant instances replaced the validation ones).
                if summary.validated == summary.total_partitions {
                    Ok(StateHandlerOutcome::do_nothing())
                }
                // A new validation run has failures -- re-enter validation.
                else if summary.failed > 0 {
                    tracing::info!(
                        "Rack {} re-entering validation from Ready (failures detected)",
                        id
                    );
                    Ok(StateHandlerOutcome::transition(RackState::Validation {
                        rack_validation: RackValidationState::FailedPartial,
                    }))
                }
                // A new validation run is underway -- re-enter validation.
                else if summary.in_progress > 0 || summary.validated > 0 || summary.failed > 0 {
                    tracing::info!(
                        "Rack {} re-entering validation from Ready",
                        id
                    );
                    Ok(StateHandlerOutcome::transition(RackState::Validation {
                        rack_validation: RackValidationState::InProgress,
                    }))
                } else {
                    Ok(StateHandlerOutcome::do_nothing())
                }
            }

            RackState::Error { cause } => {
                // Error state - log and wait for manual intervention
                tracing::error!("Rack {} is in error state: {}", id, cause);
                // TODO[#416]: add the error reset condition
                Ok(StateHandlerOutcome::do_nothing())
            }

            RackState::Deleting => {
                // Rack is being deleted - no action needed for now
                // TODO[#416]: add escape condition in case rack is recreated
                Ok(StateHandlerOutcome::do_nothing())
            }
        }
    }
}

//------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // -------------------------------------------------------------------------
    // State transitions test

    #[test]
    fn test_compute_validation_transition_from_pending() {
        let state = RackValidationState::Pending;

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
            Some(RackValidationState::InProgress)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_in_progress() {
        let state = RackValidationState::InProgress;

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
            Some(RackValidationState::Partial)
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
            Some(RackValidationState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_partial() {
        let state = RackValidationState::Partial;

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
            Some(RackValidationState::Validated)
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
            Some(RackValidationState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_failed_partial() {
        let state = RackValidationState::FailedPartial;

        // All failed -> Failed
        let summary = RackPartitionSummary {
            total_partitions: 4,
            failed: 4,
            ..Default::default()
        };
        assert_eq!(
            compute_validation_transition(&state, &summary),
            Some(RackValidationState::Failed)
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
            Some(RackValidationState::Partial)
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
            Some(RackValidationState::InProgress)
        );

        // Still some failed, some validated
        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 2,
            failed: 2,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);

        // All partitions reset to idle (RVS cleared labels before re-run)
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
            Some(RackValidationState::FailedPartial)
        );
    }

    #[test]
    fn test_compute_validation_transition_from_validated() {
        let state = RackValidationState::Validated;

        // Terminal sub-state -- always returns None.
        // The handler is responsible for promoting to RackState::Ready.
        let summary = RackPartitionSummary {
            total_partitions: 4,
            validated: 4,
            ..Default::default()
        };
        assert_eq!(compute_validation_transition(&state, &summary), None);
    }

    // -------------------------------------------------------------------------
    // RV state inference tests

    /// Helper: build a Metadata with given label pairs.
    fn metadata_with_labels(pairs: &[(&str, &str)]) -> Metadata {
        Metadata {
            name: String::new(),
            description: String::new(),
            labels: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn test_instance_rv_state_from_metadata() {
        // All four valid statuses
        let m = metadata_with_labels(&[("rv.st", "idle"), ("rv.part-id", "p0")]);
        let s: InstanceRvState = m.try_into().unwrap();
        assert_eq!(s, InstanceRvState::Idle);

        let m = metadata_with_labels(&[("rv.st", "inp")]);
        let s: InstanceRvState = m.try_into().unwrap();
        assert_eq!(s, InstanceRvState::Inp);

        let m = metadata_with_labels(&[("rv.st", "pass")]);
        let s: InstanceRvState = m.try_into().unwrap();
        assert_eq!(s, InstanceRvState::Pass);

        // Fail without description
        let m = metadata_with_labels(&[("rv.st", "fail")]);
        let s: InstanceRvState = m.try_into().unwrap();
        assert_eq!(s, InstanceRvState::Fail(String::new()));

        // Fail with description
        let m = metadata_with_labels(&[("rv.st", "fail"), ("rv.fail-desc", "nccl-timeout")]);
        let s: InstanceRvState = m.try_into().unwrap();
        assert_eq!(s, InstanceRvState::Fail("nccl-timeout".into()));

        // Missing rv.st label
        let m = metadata_with_labels(&[("rv.part-id", "p0")]);
        let s: Result<InstanceRvState, StateHandlerError> = m.try_into();
        assert!(matches!(
            s,
            Err(StateHandlerError::InvalidState(msg)) if msg.contains("missing")
        ));

        // Unknown status value
        let m = metadata_with_labels(&[("rv.st", "bogus")]);
        let s: Result<InstanceRvState, StateHandlerError> = m.try_into();
        assert!(matches!(
            s,
            Err(StateHandlerError::InvalidState(msg)) if msg.contains("bogus")
        ));
    }

    // -----------------------------------------------------------------
    // RvPartitions tests

    #[test]
    fn test_partitions_from_meta_iter() {
        let metas = vec![
            metadata_with_labels(&[("rv.part-id", "p0"), ("rv.st", "pass")]),
            metadata_with_labels(&[("rv.part-id", "p0"), ("rv.st", "inp")]),
            metadata_with_labels(&[("rv.part-id", "p1"), ("rv.st", "idle")]),
            // No rv.part-id -> should be skipped
            metadata_with_labels(&[("some-other", "label")]),
        ];

        let parts = RvPartitions::from_meta_iter(metas.iter().cloned()).unwrap();

        assert_eq!(parts.inner.len(), 2);
        assert_eq!(parts.inner["p0"].len(), 2);
        assert_eq!(parts.inner["p0"][0], InstanceRvState::Pass);
        assert_eq!(parts.inner["p0"][1], InstanceRvState::Inp);
        assert_eq!(parts.inner["p1"].len(), 1);
        assert_eq!(parts.inner["p1"][0], InstanceRvState::Idle);
    }

    #[test]
    fn test_partitions_summarize() {
        let metas = vec![
            // Partition p0: one node pass, one node fail -> Failed
            metadata_with_labels(&[("rv.part-id", "p0"), ("rv.st", "pass")]),
            metadata_with_labels(&[
                ("rv.part-id", "p0"),
                ("rv.st", "fail"),
                ("rv.fail-desc", "nccl"),
            ]),
            // Partition p1: all nodes pass -> Validated
            metadata_with_labels(&[("rv.part-id", "p1"), ("rv.st", "pass")]),
            metadata_with_labels(&[("rv.part-id", "p1"), ("rv.st", "pass")]),
            // Partition p2: one node is idle, one is inp -> InProgress
            metadata_with_labels(&[("rv.part-id", "p2"), ("rv.st", "idle")]),
            metadata_with_labels(&[("rv.part-id", "p2"), ("rv.st", "inp")]),
            // Partition p3: all nodes idle -> Pending
            metadata_with_labels(&[("rv.part-id", "p3"), ("rv.st", "idle")]),
        ];

        let parts = RvPartitions::from_meta_iter(metas.iter().cloned()).unwrap();
        let summary = parts.summarize();

        assert_eq!(summary.total_partitions, 4);
        assert_eq!(summary.failed, 1); // p0
        assert_eq!(summary.validated, 1); // p1
        assert_eq!(summary.in_progress, 1); // p2
        assert_eq!(summary.pending, 1); // p3
    }
}
