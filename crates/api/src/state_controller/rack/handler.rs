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

use std::cmp::Ordering;

use carbide_uuid::machine::MachineId;
use carbide_uuid::rack::RackId;
use db::{
    self, expected_machine as db_expected_machine, expected_power_shelf as db_expected_power_shelf,
    expected_switch as db_expected_switch, machine as db_machine, rack as db_rack,
};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{LoadSnapshotOptions, ManagedHostState};
use model::power_shelf::PowerShelfControllerState;
use model::rack::{
    Rack, RackConfig, RackFirmwareUpgradeState, RackMaintenanceState, RackPowerState, RackState,
    RackValidationState,
};
use model::rack_type::RackCapabilitiesSet;
use model::switch::SwitchControllerState;
use sqlx::{PgPool, PgTransaction};

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::rv::{RackPartitionSummary, RvPartitions};
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
//------------------------------------------------------------------------------

/// Loads the aggregated partition validation summary for a rack.
///
/// This function queries all machines belonging to the rack, reads their
/// validation metadata labels, and aggregates the status by partition.
///
/// ## Expected Machine Metadata Labels
///
/// - `rv.part-id`: Identifies which partition the node belongs to
/// - `rv.st`: One of "idle", "inp", "pass", "fail"
///
/// Machine metadata persists across instance create/delete cycles, so
/// validation state survives ephemeral instance lifetimes.
async fn load_partition_summary(
    rack_id: &RackId,
    rack: &Rack,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<RackPartitionSummary, StateHandlerError> {
    let machine_ids: Vec<MachineId> = rack.config.compute_trays.to_vec();

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
            if summary.total_partitions == 0 {
                // No partitions currently observed. Treat this as a reset to
                // Pending so racks don't enter terminal failure just because
                // validation instances/labels are temporarily absent.
                Some(RackValidationState::Pending)
            } else if summary.failed == summary.total_partitions {
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

/// adopt_dangling_devices finds expected devices that reference this rack_id
/// but haven't been added to the rack config yet, and adds them. Returns true
/// if any devices were adopted (config was changed).
pub(crate) async fn adopt_dangling_devices(
    pool: &PgPool,
    id: &RackId,
    config: &mut RackConfig,
) -> Result<bool, StateHandlerError> {
    let mut txn = pool.begin().await?;
    let mut changed = false;

    // Adopt expected machines with this rack_id.
    let expected_machines = db_expected_machine::find_all_by_rack_id(&mut txn, id).await?;
    for em in &expected_machines {
        if !config.expected_compute_trays.contains(&em.bmc_mac_address) {
            config.expected_compute_trays.push(em.bmc_mac_address);
            changed = true;
        }
    }

    // Adopt expected switches with this rack_id.
    let expected_switches = db_expected_switch::find_all_by_rack_id(&mut txn, id).await?;
    for es in &expected_switches {
        if !config.expected_switches.contains(&es.bmc_mac_address) {
            config.expected_switches.push(es.bmc_mac_address);
            changed = true;
        }
    }

    // Adopt expected power shelves with this rack_id.
    let expected_ps = db_expected_power_shelf::find_all_by_rack_id(&mut txn, id).await?;
    for eps in &expected_ps {
        if !config.expected_power_shelves.contains(&eps.bmc_mac_address) {
            config.expected_power_shelves.push(eps.bmc_mac_address);
            changed = true;
        }
    }

    if changed {
        db_rack::update(&mut txn, id, config).await?;
        txn.commit().await?;
    }

    Ok(changed)
}

/// validate_device_counts checks whether the registered device counts match
/// the rack capabilities. Returns true if all counts match.
pub(crate) fn validate_device_counts(
    id: &RackId,
    config: &RackConfig,
    capabilities: &RackCapabilitiesSet,
) -> bool {
    let registered_compute = config.expected_compute_trays.len() as u32;
    let registered_switches = config.expected_switches.len() as u32;
    let registered_ps = config.expected_power_shelves.len() as u32;

    if registered_compute != capabilities.compute.count {
        tracing::info!(
            "rack {} has {} of {} expected registered compute trays. waiting.",
            id,
            registered_compute,
            capabilities.compute.count
        );
        return false;
    }
    if registered_switches != capabilities.switch.count {
        tracing::info!(
            "rack {} has {} of {} expected registered switches. waiting.",
            id,
            registered_switches,
            capabilities.switch.count
        );
        return false;
    }
    if registered_ps != capabilities.power_shelf.count {
        tracing::info!(
            "rack {} has {} of {} expected registered power shelves. waiting.",
            id,
            registered_ps,
            capabilities.power_shelf.count
        );
        return false;
    }
    true
}

/// log_capability_hints logs debug messages about optional name/vendor matching
/// fields in the rack capabilities.
pub(crate) fn log_capability_hints(id: &RackId, capabilities: &RackCapabilitiesSet) {
    if let Some(ref name) = capabilities.compute.name {
        tracing::debug!(
            "rack {} would match compute model name '{}' if available.",
            id,
            name
        );
    }
    if let Some(ref vendor) = capabilities.compute.vendor {
        tracing::debug!(
            "rack {} would match compute vendor '{}' if available.",
            id,
            vendor
        );
    }
    if let Some(ref name) = capabilities.switch.name {
        tracing::debug!(
            "rack {} would match switch model name '{}' if available.",
            id,
            name
        );
    }
    if let Some(ref vendor) = capabilities.switch.vendor {
        tracing::debug!(
            "rack {} would match switch vendor '{}' if available.",
            id,
            vendor
        );
    }
    if let Some(ref name) = capabilities.power_shelf.name {
        tracing::debug!(
            "rack {} would match power shelf model name '{}' if available.",
            id,
            name
        );
    }
    if let Some(ref vendor) = capabilities.power_shelf.vendor {
        tracing::debug!(
            "rack {} would match power shelf vendor '{}' if available.",
            id,
            vendor
        );
    }
}

/// check_compute_linked checks whether all expected compute trays have been
/// explored and linked to actual machines. Returns (done, optional_txn).
pub(crate) async fn check_compute_linked(
    pool: &PgPool,
    id: &RackId,
    config: &mut RackConfig,
) -> Result<(bool, Option<PgTransaction<'static>>), StateHandlerError> {
    match config
        .expected_compute_trays
        .len()
        .cmp(&config.compute_trays.len())
    {
        Ordering::Greater => {
            let mut txn = pool.begin().await?;
            for macaddr in config.expected_compute_trays.clone().as_slice() {
                match db_expected_machine::find_one_linked(&mut txn, *macaddr).await {
                    Ok(Some(machine)) => {
                        if let Some(machine_id) = machine.machine_id
                            && !config.compute_trays.contains(&machine_id)
                        {
                            config.compute_trays.push(machine_id);
                            db_rack::update(&mut txn, id, config).await?;
                        }
                    }
                    Ok(None) | Err(_) => {
                        tracing::debug!(
                            "rack {} expected compute tray {} not yet explored.",
                            id,
                            macaddr
                        );
                    }
                }
            }
            Ok((false, Some(txn)))
        }
        Ordering::Less => {
            tracing::info!(
                "Rack {} has more compute trays discovered {} than expected {}",
                id,
                config.compute_trays.len(),
                config.expected_compute_trays.len()
            );
            Ok((true, None))
        }
        Ordering::Equal => Ok((true, None)),
    }
}

/// check_power_shelves_linked checks whether all expected power shelves have
/// been explored and linked.
pub(crate) async fn check_power_shelves_linked(
    pool: &PgPool,
    id: &RackId,
    config: &mut RackConfig,
) -> Result<bool, StateHandlerError> {
    match config
        .expected_power_shelves
        .len()
        .cmp(&config.power_shelves.len())
    {
        Ordering::Greater => {
            let mut txn = pool.begin().await?;
            let linked = db_expected_power_shelf::find_all_linked(&mut txn).await?;
            for expected_mac in config.expected_power_shelves.iter() {
                if let Some(l) = linked
                    .iter()
                    .find(|l| l.bmc_mac_address == *expected_mac && l.power_shelf_id.is_some())
                {
                    let ps_id = l.power_shelf_id.unwrap();
                    if !config.power_shelves.contains(&ps_id) {
                        config.power_shelves.push(ps_id);
                        db_rack::update(txn.as_mut(), id, config).await?;
                    }
                }
            }
            txn.commit().await?;
            Ok(false)
        }
        Ordering::Less => {
            tracing::info!(
                "Rack {} has more power shelves discovered {} than expected {}",
                id,
                config.power_shelves.len(),
                config.expected_power_shelves.len()
            );
            Ok(true)
        }
        Ordering::Equal => Ok(true),
    }
}

/// check_switches_linked checks whether all expected switches have been
/// explored and linked.
pub(crate) async fn check_switches_linked(
    pool: &PgPool,
    config: &RackConfig,
) -> Result<bool, StateHandlerError> {
    if config.expected_switches.is_empty() {
        return Ok(true);
    }
    let mut txn = pool.begin().await?;
    let linked = db_expected_switch::find_all_linked(&mut txn).await?;
    let discovered_count = config
        .expected_switches
        .iter()
        .filter(|expected_mac| {
            linked
                .iter()
                .any(|l| l.bmc_mac_address == **expected_mac && l.switch_id.is_some())
        })
        .count();
    drop(txn);
    Ok(discovered_count >= config.expected_switches.len())
}

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
        let mut config = state.config.clone();
        tracing::info!("Rack {} is in state {}", id, controller_state.to_string());

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
                // Racks without a rack_type stay parked in Expected until
                // an expected rack is created via add_expected_rack.
                let rack_type_name = match config.rack_type {
                    Some(ref name) => name.clone(),
                    None => {
                        tracing::info!("rack {} has no rack_type set, staying in Expected.", id);
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                };

                // Look up the capabilities from the config file.
                let capabilities = match ctx.services.site_config.rack_types.get(&rack_type_name) {
                    Some(caps) => caps.clone(),
                    None => {
                        tracing::error!(
                            "rack {} has rack_type '{}' but no matching definition in config. skipping.",
                            id,
                            rack_type_name
                        );
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                };

                // Adopt dangling expected devices that have this rack_id but
                // haven't been added to the rack config yet.
                if adopt_dangling_devices(&ctx.services.db_pool, id, &mut config).await? {
                    return Ok(StateHandlerOutcome::do_nothing());
                }

                log_capability_hints(id, &capabilities);

                // Validate expected device counts against the capabilities.
                if !validate_device_counts(id, &config, &capabilities) {
                    return Ok(StateHandlerOutcome::do_nothing());
                }

                // Check if all expected devices have been explored and linked.
                let (compute_done, pending_txn) =
                    check_compute_linked(&ctx.services.db_pool, id, &mut config).await?;
                let ps_done =
                    check_power_shelves_linked(&ctx.services.db_pool, id, &mut config).await?;
                let switch_done = check_switches_linked(&ctx.services.db_pool, &config).await?;

                if compute_done && ps_done && switch_done {
                    Ok(StateHandlerOutcome::transition(RackState::Discovering)
                        .with_txn_opt(pending_txn))
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn_opt(pending_txn))
                }
            }
            RackState::Discovering => {
                // Check if each compute machine has reached ManagedHostState::Ready.
                let mut txn = ctx.services.db_pool.begin().await?;
                for machine_id in config.compute_trays.iter() {
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
                            "Rack {} has compute tray {} in {} state",
                            id,
                            machine_id,
                            mh_snapshot.managed_state
                        );
                        return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
                    }
                }

                // Check if each expected switch has reached SwitchControllerState::Ready.
                if !config.expected_switches.is_empty() {
                    let linked_switches = db_expected_switch::find_all_linked(txn.as_mut()).await?;
                    for expected_mac in config.expected_switches.iter() {
                        if let Some(linked) = linked_switches
                            .iter()
                            .find(|l| l.bmc_mac_address == *expected_mac && l.switch_id.is_some())
                        {
                            let switch_id = linked.switch_id.unwrap();
                            let switch = db::switch::find_by_id(txn.as_mut(), &switch_id)
                                .await?
                                .ok_or(StateHandlerError::MissingData {
                                    object_id: switch_id.to_string(),
                                    missing: "switch not found",
                                })?;
                            if *switch.controller_state != SwitchControllerState::Ready {
                                tracing::debug!(
                                    "Rack {} has switch {} in {:?} state",
                                    id,
                                    switch_id,
                                    *switch.controller_state
                                );
                                return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
                            }
                        } else {
                            tracing::debug!(
                                "Rack {} has expected switch {} not yet linked",
                                id,
                                expected_mac
                            );
                            return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
                        }
                    }
                }

                // Check if each expected power shelf has reached PowerShelfControllerState::Ready.
                for ps_id in config.power_shelves.iter() {
                    let power_shelf = db::power_shelf::find_by_id(txn.as_mut(), ps_id)
                        .await?
                        .ok_or(StateHandlerError::MissingData {
                            object_id: ps_id.to_string(),
                            missing: "power shelf not found",
                        })?;
                    if *power_shelf.controller_state != PowerShelfControllerState::Ready {
                        tracing::debug!(
                            "Rack {} has power shelf {} in {:?} state",
                            id,
                            ps_id,
                            *power_shelf.controller_state
                        );
                        return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
                    }
                }

                // All devices are ready, transition to firmware upgrade.
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    rack_maintenance: RackMaintenanceState::FirmwareUpgrade {
                        rack_firmware_upgrade: RackFirmwareUpgradeState::Compute,
                    },
                })
                .with_txn(txn))
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
                        // Bump the run ID so stale labels from prior runs are
                        // ignored.
                        let run_id =
                            format!("run-{}-{}", id, chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                        tracing::info!(
                            "Rack {} maintenance completed, entering validation (run_id={})",
                            id,
                            run_id
                        );
                        state.config.validation_run_id = Some(run_id);
                        let mut txn = ctx.services.db_pool.begin().await?;
                        db_rack::update(&mut txn, id, &state.config).await?;
                        Ok(StateHandlerOutcome::transition(RackState::Validation {
                            rack_validation: RackValidationState::Pending,
                        })
                        .with_txn(txn))
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
                    tracing::info!("Rack {} re-entering validation from Ready", id);
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
                // Rack is being deleted
                let mut txn = ctx.services.db_pool.begin().await?;
                db::rack::final_delete(&mut txn, id).await?;
                Ok(StateHandlerOutcome::deleted().with_txn(txn))
            }
        }
    }
}

//------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
}
