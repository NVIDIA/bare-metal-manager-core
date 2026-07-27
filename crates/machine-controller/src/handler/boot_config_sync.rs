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

//! Durable synchronization of a host's selected boot interface.
//!
//! The unassigned parent runs automatically before `Ready`; the assigned
//! parent is entered only after an operator authorization for the exact
//! interface generation is validated. Both parents use the shared
//! boot-configuration driver and require a target-correlated Site Explorer
//! observation before returning to their respective Ready state.

use carbide_redfish::libredfish::error::state_handler_redfish_error as redfish_error;
use config_version::ConfigVersion;
use libredfish::{EnabledDisabled, RedfishError, SystemPowerControl};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    BootConfigSynchronizationCompletion, BootConfigSynchronizationState,
    BootConfigSynchronizationTarget, FailureCause, FailureDetails, FailureSource, InstanceState,
    ManagedHostState, ManagedHostStateSnapshot, StateMachineArea, UnlockHostState,
};
use model::machine_boot_interface::MachineBootInterfaceTarget;
use model::site_explorer::{
    ExploredEndpoint, MACHINE_SETUP_VERIFICATION_VERSION, MachineSetupStatus,
};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use super::host_boot_config::{
    HostBootConfigCheckOutcome, HostBootConfigDecision, HostBootConfigDpuFreshness,
    HostBootConfigOutcome, HostBootConfigStage, HostBootInterfaceSource, check_host_boot_config,
    initial_set_boot_order_info, run_host_boot_config_stage, should_skip_boot_order_remediation,
};
use super::{
    ReachabilityParams, host_power_control, load_boot_predictions, resolve_boot_interface, wait,
};
use crate::boot_interface::{
    BootInterfaceResolution, ResolvedBootInterface, resolved_boot_interface_from_stores,
};
use crate::context::{MachineStateHandlerContextObjects, MachineStateHandlerServices};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BootConfigSynchronizationOwner {
    Unassigned,
    Assigned,
}

impl BootConfigSynchronizationOwner {
    fn ready_state(self) -> ManagedHostState {
        match self {
            Self::Unassigned => ManagedHostState::Ready,
            Self::Assigned => ManagedHostState::Assigned {
                instance_state: InstanceState::Ready,
            },
        }
    }

    fn target_changed_state(self) -> ManagedHostState {
        match self {
            Self::Unassigned => ManagedHostState::BootConfigSynchronization {
                synchronization_state: BootConfigSynchronizationState::Initialize { target: None },
                synchronization_retry_count: 0,
            },
            Self::Assigned => self.ready_state(),
        }
    }

    fn failure_state(
        self,
        machine_id: carbide_uuid::machine::MachineId,
        error: String,
    ) -> ManagedHostState {
        let details = FailureDetails {
            cause: FailureCause::BiosSetupFailed { err: error },
            failed_at: chrono::Utc::now(),
            source: FailureSource::StateMachineArea(match self {
                Self::Unassigned => StateMachineArea::MainFlow,
                Self::Assigned => StateMachineArea::AssignedInstance,
            }),
        };
        self.machine_failure_state(machine_id, details)
    }

    fn machine_failure_state(
        self,
        machine_id: carbide_uuid::machine::MachineId,
        details: FailureDetails,
    ) -> ManagedHostState {
        match self {
            Self::Unassigned => ManagedHostState::Failed {
                details,
                machine_id,
                retry_count: 0,
            },
            Self::Assigned => ManagedHostState::Assigned {
                instance_state: InstanceState::Failed {
                    details,
                    machine_id,
                },
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BootConfigSynchronizationDriver {
    owner: BootConfigSynchronizationOwner,
    retry_count: u32,
}

impl BootConfigSynchronizationDriver {
    fn new(owner: BootConfigSynchronizationOwner) -> Self {
        Self {
            owner,
            retry_count: 0,
        }
    }

    fn resume(owner: BootConfigSynchronizationOwner, retry_count: u32) -> Self {
        Self { owner, retry_count }
    }

    fn retry(self) -> Self {
        Self {
            retry_count: self.retry_count + 1,
            ..self
        }
    }

    fn state(self, synchronization_state: BootConfigSynchronizationState) -> ManagedHostState {
        match self.owner {
            BootConfigSynchronizationOwner::Unassigned => {
                ManagedHostState::BootConfigSynchronization {
                    synchronization_state,
                    synchronization_retry_count: self.retry_count,
                }
            }
            BootConfigSynchronizationOwner::Assigned => ManagedHostState::Assigned {
                instance_state: InstanceState::BootConfigSynchronization {
                    synchronization_state,
                    synchronization_retry_count: self.retry_count,
                },
            },
        }
    }

    fn ready_state(self) -> ManagedHostState {
        self.owner.ready_state()
    }

    fn target_changed_state(self) -> ManagedHostState {
        self.owner.target_changed_state()
    }

    fn failure_state(
        self,
        machine_id: carbide_uuid::machine::MachineId,
        error: String,
    ) -> ManagedHostState {
        self.owner.failure_state(machine_id, error)
    }

    fn machine_failure_state(
        self,
        machine_id: carbide_uuid::machine::MachineId,
        details: FailureDetails,
    ) -> ManagedHostState {
        self.owner.machine_failure_state(machine_id, details)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AssignedSynchronizationPreemption {
    None,
    ResumeAfterReady,
    Discard,
}

fn synchronization_owner_and_state(
    state: &ManagedHostState,
) -> Option<(
    BootConfigSynchronizationDriver,
    &BootConfigSynchronizationState,
)> {
    match state {
        ManagedHostState::BootConfigSynchronization {
            synchronization_state,
            synchronization_retry_count,
        } => Some((
            BootConfigSynchronizationDriver::resume(
                BootConfigSynchronizationOwner::Unassigned,
                *synchronization_retry_count,
            ),
            synchronization_state,
        )),
        ManagedHostState::Assigned {
            instance_state:
                InstanceState::BootConfigSynchronization {
                    synchronization_state,
                    synchronization_retry_count,
                },
        } => Some((
            BootConfigSynchronizationDriver::resume(
                BootConfigSynchronizationOwner::Assigned,
                *synchronization_retry_count,
            ),
            synchronization_state,
        )),
        _ => None,
    }
}

/// Identifies both the unassigned parent and assigned nested synchronization.
///
/// The outer machine handler uses this to keep unrelated lifecycle shortcuts
/// from bypassing the synchronization cleanup barrier.
pub(super) fn is_boot_config_synchronization(state: &ManagedHostState) -> bool {
    synchronization_owner_and_state(state).is_some()
}

/// Returns whether boot synchronization must finish safety cleanup before an
/// outer lifecycle transition may replace it.
///
/// This covers both lockdown restoration and BIOS-job recovery that has
/// deliberately powered the host off. Health, maintenance, and authorization
/// changes remain pending until the host is powered back on and lockdown can
/// be restored.
pub(super) fn is_boot_config_cleanup_barrier(state: &ManagedHostState) -> bool {
    synchronization_owner_and_state(state).is_some_and(|(_, state)| {
        matches!(
            state,
            BootConfigSynchronizationState::RestoreLockdown { .. }
        ) || power_recovery_in_progress(state)
    })
}

/// Routes an outer machine/DPU failure through lockdown restoration when
/// Redfish work may have disabled it.
pub(super) fn machine_failure_transition(
    mh_snapshot: &ManagedHostStateSnapshot,
    machine_id: carbide_uuid::machine::MachineId,
    details: FailureDetails,
) -> Option<ManagedHostState> {
    let (owner, state) = synchronization_owner_and_state(&mh_snapshot.managed_state)?;
    if power_recovery_in_progress(state) {
        return None;
    }
    if matches!(
        state,
        BootConfigSynchronizationState::RestoreLockdown {
            completion: BootConfigSynchronizationCompletion::MachineFailed { .. },
        }
    ) {
        return None;
    }
    let completion = BootConfigSynchronizationCompletion::MachineFailed {
        machine_id,
        details,
    };
    let lockdown_may_be_disabled = state_may_require_lockdown_restore(state)
        || matches!(
            state,
            BootConfigSynchronizationState::RestoreLockdown { .. }
        );
    if lockdown_may_be_disabled && !mh_snapshot.host_snapshot.host_profile.disable_lockdown {
        Some(owner.state(BootConfigSynchronizationState::RestoreLockdown { completion }))
    } else {
        Some(completion_state(
            owner,
            completion,
            mh_snapshot.host_snapshot.id,
        ))
    }
}

/// Moves an active Redfish phase into lockdown restoration when its managed
/// DPU snapshots disappear.
///
/// After cleanup, the same parent restarts with its pinned target and waits for
/// the missing observations before doing more boot-configuration work.
pub(super) fn missing_dpu_cleanup_transition(
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Option<ManagedHostState> {
    let (owner, state) = synchronization_owner_and_state(&mh_snapshot.managed_state)?;
    if power_recovery_in_progress(state) {
        return None;
    }
    if mh_snapshot.host_snapshot.host_profile.disable_lockdown
        || !state_may_require_lockdown_restore(state)
    {
        return None;
    }
    Some(
        owner.state(BootConfigSynchronizationState::RestoreLockdown {
            completion: BootConfigSynchronizationCompletion::ResumeSynchronization {
                target: state_target(state).cloned(),
            },
        }),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationProgress {
    Waiting,
    Configured,
    NeedsSynchronization,
}

#[derive(Debug, Eq, PartialEq)]
struct ObservationEvaluation {
    progress: ObservationProgress,
    reason: String,
    request_exploration: bool,
}

impl ObservationEvaluation {
    fn waiting(reason: impl Into<String>, request_exploration: bool) -> Self {
        Self {
            progress: ObservationProgress::Waiting,
            reason: reason.into(),
            request_exploration,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ObservationPolicy {
    allow_disabled_lockdown: bool,
    skip_boot_order: bool,
}

impl ObservationPolicy {
    fn for_host(mh_snapshot: &ManagedHostStateSnapshot) -> Self {
        Self {
            allow_disabled_lockdown: mh_snapshot.host_snapshot.host_profile.disable_lockdown,
            skip_boot_order: should_skip_boot_order_remediation(mh_snapshot),
        }
    }

    fn accepts(self, status: &MachineSetupStatus) -> bool {
        status.is_done
            || (!status.diffs.is_empty()
                && status.diffs.iter().all(|diff| {
                    (self.allow_disabled_lockdown && diff.key == "lockdown")
                        || (self.skip_boot_order && diff.key == "boot_first")
                }))
    }
}

struct LockedBootConfigView {
    endpoint: Option<ExploredEndpoint>,
    target: Option<BootConfigSynchronizationTarget>,
}

async fn lock_boot_config_view(
    txn: &mut sqlx::PgConnection,
    machine_id: carbide_uuid::machine::MachineId,
    address: std::net::IpAddr,
) -> Result<LockedBootConfigView, StateHandlerError> {
    // This order matches explicit selection and first-lease promotion.
    // Loading both interface stores after every lock makes promotion and
    // Redfish-id enrichment visible to the same transaction.
    let endpoint =
        db::explored_endpoints::find_by_ip_for_update_optional(address, &mut *txn).await?;
    db::machine_interface::lock_for_machine(&mut *txn, machine_id).await?;
    let selection_version =
        db::machine::lock_boot_interface_selection_version(&mut *txn, machine_id).await?;
    db::predicted_machine_interface::lock_for_machine(&mut *txn, machine_id).await?;
    let live_bmc_address =
        db::machine::find_one(&mut *txn, &machine_id, MachineSearchConfig::default())
            .await?
            .and_then(|machine| machine.status.bmc_info.ip);
    let endpoint = if live_bmc_address == Some(address) {
        endpoint
    } else {
        tracing::warn!(
            %machine_id,
            snapshot_bmc_address = %address,
            live_bmc_address = ?live_bmc_address,
            "Ignoring a boot-config endpoint loaded from a stale machine snapshot",
        );
        None
    };
    let interfaces = db::machine_interface::find_by_machine_ids(&mut *txn, &[machine_id])
        .await?
        .remove(&machine_id)
        .unwrap_or_default();
    let predictions =
        db::predicted_machine_interface::find_by_machine_id(&mut *txn, &machine_id).await?;
    let target = resolved_boot_interface_from_stores(&interfaces, &predictions)
        .map(|resolved| synchronization_target(&resolved, selection_version));
    Ok(LockedBootConfigView { endpoint, target })
}

/// Revalidates boot configuration in the transaction that crosses the
/// unassigned-to-assigned boundary.
///
/// A concurrent explicit selection either commits before these locks and is
/// evaluated here, or waits until the state transition commits and then uses
/// assigned-host semantics. First-lease promotion and Redfish-id enrichment
/// use the same locks but preserve the selection generation and MAC; if they
/// follow the gate, they can safely finish as metadata enrichment without
/// changing the boot device.
pub(super) async fn assignment_boot_config_gate(
    mh_snapshot: &ManagedHostStateSnapshot,
    txn: &mut sqlx::PgConnection,
) -> Result<Option<ManagedHostState>, StateHandlerError> {
    let machine_id = mh_snapshot.host_snapshot.id;
    let Some(address) = mh_snapshot.host_snapshot.status.bmc_info.ip else {
        return Err(StateHandlerError::MissingData {
            object_id: machine_id.to_string(),
            missing: "BMC IP",
        });
    };
    let locked = lock_boot_config_view(txn, machine_id, address).await?;
    // Authorization belongs to one assigned lifecycle. Never let a deferred
    // request from an earlier tenant cross this unassigned boundary.
    db::machine::clear_boot_config_synchronization_request(txn, machine_id).await?;
    let (configured, reason) = match (locked.endpoint.as_ref(), locked.target.as_ref()) {
        (Some(endpoint), Some(target)) => {
            let evaluation = evaluate_observation(
                endpoint,
                target,
                ConfigVersion::invalid(),
                ObservationPolicy::for_host(mh_snapshot),
            );
            (
                evaluation.progress == ObservationProgress::Configured,
                evaluation.reason,
            )
        }
        (None, _) => (false, format!("explored endpoint {address} is missing")),
        (_, None) => (false, "selected boot interface is unresolved".to_string()),
    };
    if configured {
        return Ok(None);
    }

    tracing::info!(
        %machine_id,
        reason,
        target = ?locked.target,
        "Boot-interface synchronization is required before assignment",
    );
    Ok(Some(ManagedHostState::BootConfigSynchronization {
        synchronization_state: BootConfigSynchronizationState::Initialize {
            target: locked.target,
        },
        synchronization_retry_count: 0,
    }))
}

/// Returns whether an unassigned Ready host needs to enter boot-interface
/// synchronization.
///
/// Called before instance assignment. A matching successful observation keeps
/// the host Ready; missing, stale, failed, or mismatched evidence routes it
/// through the durable parent state.
pub(super) async fn unassigned_ready_needs_synchronization(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<bool, StateHandlerError> {
    let Some(target) = resolve_current_target(mh_snapshot, ctx)
        .await?
        .into_option()
    else {
        return Ok(true);
    };
    let Some(endpoint) = find_endpoint(mh_snapshot, ctx.services).await? else {
        return Ok(true);
    };
    let evaluation = evaluate_observation(
        &endpoint,
        &target,
        ConfigVersion::invalid(),
        ObservationPolicy::for_host(mh_snapshot),
    );
    Ok(evaluation.progress != ObservationProgress::Configured)
}

/// Enters synchronization for a matching assigned-host authorization.
///
/// Called from `InstanceState::Ready` after higher-priority network updates.
/// The exact request remains persisted until synchronization succeeds so a
/// temporary preemption can return to Ready and resume it. Stale or
/// destructive requests are cleared with a conditional database update.
pub(super) async fn assigned_ready_synchronization_transition(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    preemption: AssignedSynchronizationPreemption,
) -> Result<Option<StateHandlerOutcome<ManagedHostState>>, StateHandlerError> {
    let Some(request) = mh_snapshot
        .host_snapshot
        .boot_config_synchronization_requested
        .as_ref()
    else {
        return Ok(None);
    };

    if preemption == AssignedSynchronizationPreemption::Discard {
        let mut txn = ctx.services.db_pool.begin().await?;
        let consumed = db::machine::consume_boot_config_synchronization_request(
            &mut txn,
            mh_snapshot.host_snapshot.id,
            request.interface_id,
            request.selection_version,
        )
        .await?;
        if !consumed {
            txn.rollback().await?;
            return Ok(None);
        }
        tracing::info!(
            machine_id = %mh_snapshot.host_snapshot.id,
            "Discarded assigned boot-interface synchronization authorization for higher-priority instance work",
        );
        return Ok(Some(StateHandlerOutcome::do_nothing().with_txn(txn)));
    }
    if preemption == AssignedSynchronizationPreemption::ResumeAfterReady {
        return Ok(None);
    }

    let current_target = resolve_current_target(mh_snapshot, ctx)
        .await?
        .into_option();
    let request_matches = current_target.as_ref().is_some_and(|target| {
        target.machine_interface_id == Some(request.interface_id)
            && target.selection_version == request.selection_version
    });
    if !request_matches {
        let mut txn = ctx.services.db_pool.begin().await?;
        let consumed = db::machine::consume_boot_config_synchronization_request(
            &mut txn,
            mh_snapshot.host_snapshot.id,
            request.interface_id,
            request.selection_version,
        )
        .await?;
        if !consumed {
            txn.rollback().await?;
            return Ok(None);
        }
        tracing::info!(
            machine_id = %mh_snapshot.host_snapshot.id,
            requested_machine_interface_id = %request.interface_id,
            requested_selection_version = %request.selection_version,
            current_target = ?current_target,
            "Discarded stale assigned boot-interface synchronization authorization",
        );
        return Ok(Some(StateHandlerOutcome::do_nothing().with_txn(txn)));
    }

    let target = current_target.expect("checked as present above");
    tracing::info!(
        machine_id = %mh_snapshot.host_snapshot.id,
        machine_interface_id = ?target.machine_interface_id,
        boot_interface = ?target.boot_interface,
        selection_version = %target.selection_version,
        "Starting authorized assigned boot-interface synchronization",
    );
    let mut txn = ctx.services.db_pool.begin().await?;
    if !db::machine::lock_boot_config_synchronization_request(
        &mut txn,
        mh_snapshot.host_snapshot.id,
        request.interface_id,
        request.selection_version,
    )
    .await?
    {
        txn.rollback().await?;
        return Ok(None);
    }
    Ok(Some(
        StateHandlerOutcome::transition(
            BootConfigSynchronizationDriver::new(BootConfigSynchronizationOwner::Assigned).state(
                BootConfigSynchronizationState::Initialize {
                    target: Some(target),
                },
            ),
        )
        .with_txn(txn),
    ))
}

/// Handles one persisted boot-interface synchronization phase.
///
/// Called by both the top-level unassigned parent and the nested assigned
/// parent. Every active phase first compares its pinned target with the current
/// selected interface generation, so work for an older selection cannot count
/// as completion for a newer one. Lockdown restoration is deliberately
/// target-independent so missing selection data cannot prevent cleanup.
pub(super) async fn handle_boot_config_synchronization(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    owner: BootConfigSynchronizationOwner,
    synchronization_retry_count: u32,
    state: &BootConfigSynchronizationState,
    assigned_preemption: AssignedSynchronizationPreemption,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let driver = BootConfigSynchronizationDriver::resume(owner, synchronization_retry_count);
    if owner == BootConfigSynchronizationOwner::Assigned
        && assigned_preemption == AssignedSynchronizationPreemption::Discard
        && let Some(target) = authorization_target(state)
        && let Some(interface_id) = target.machine_interface_id
        && mh_snapshot
            .host_snapshot
            .boot_config_synchronization_requested
            .as_ref()
            .is_some_and(|request| {
                request.interface_id == interface_id
                    && request.selection_version == target.selection_version
            })
    {
        let mut txn = ctx.services.db_pool.begin().await?;
        if db::machine::consume_boot_config_synchronization_request(
            &mut txn,
            mh_snapshot.host_snapshot.id,
            interface_id,
            target.selection_version,
        )
        .await?
        {
            return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
        }
        txn.rollback().await?;
    }

    if owner == BootConfigSynchronizationOwner::Assigned
        && !matches!(
            state,
            BootConfigSynchronizationState::RestoreLockdown { .. }
        )
        && !power_recovery_in_progress(state)
    {
        let Some(target) = state_target(state) else {
            tracing::warn!(
                machine_id = %mh_snapshot.host_snapshot.id,
                "Stopping assigned boot-interface synchronization without a pinned target",
            );
            return Ok(StateHandlerOutcome::transition(driver.ready_state()));
        };
        if !assigned_authorization_matches(mh_snapshot, target) {
            let request = mh_snapshot
                .host_snapshot
                .boot_config_synchronization_requested
                .as_ref();
            tracing::info!(
                machine_id = %mh_snapshot.host_snapshot.id,
                machine_interface_id = ?target.machine_interface_id,
                selection_version = %target.selection_version,
                authorized_machine_interface_id = ?request.map(|request| request.interface_id),
                authorized_selection_version = ?request.map(|request| request.selection_version),
                "Stopping assigned boot-interface synchronization because its authorization is no longer current",
            );
            let completion = BootConfigSynchronizationCompletion::ReturnToReady {
                target: target.clone(),
            };
            let next_state = if state_may_require_lockdown_restore(state)
                && !mh_snapshot.host_snapshot.host_profile.disable_lockdown
            {
                driver.state(BootConfigSynchronizationState::RestoreLockdown { completion })
            } else {
                completion_state(driver, completion, mh_snapshot.host_snapshot.id)
            };
            return Ok(StateHandlerOutcome::transition(next_state));
        }
    }

    if let Some(completion) = preemption_completion(mh_snapshot, owner, state, assigned_preemption)
    {
        if state_may_require_lockdown_restore(state)
            && !mh_snapshot.host_snapshot.host_profile.disable_lockdown
        {
            return Ok(StateHandlerOutcome::transition(driver.state(
                BootConfigSynchronizationState::RestoreLockdown { completion },
            )));
        } else {
            return Ok(StateHandlerOutcome::transition(completion_state(
                driver,
                completion,
                mh_snapshot.host_snapshot.id,
            )));
        }
    }

    // Lockdown restoration is a cleanup barrier and deliberately needs no
    // selected interface. Resolving one here could strand a disabled BMC when
    // the target data that interrupted synchronization is missing.
    let should_resolve_current_target = uses_current_target(state);
    let current_target = if should_resolve_current_target {
        match resolve_current_target(mh_snapshot, ctx).await? {
            CurrentTargetResolution::Ready(target) => Some(target),
            CurrentTargetResolution::AwaitingNic => None,
            CurrentTargetResolution::Missing if state_target(state).is_some() => None,
            CurrentTargetResolution::Missing => {
                return Err(StateHandlerError::GenericError(eyre::eyre!(
                    "missing selected boot interface for managed-DPU host {}",
                    mh_snapshot.host_snapshot.id
                )));
            }
        }
    } else {
        None
    };
    if should_resolve_current_target
        && let Some(expected_target) = state_target(state)
        && current_target.as_ref() != Some(expected_target)
    {
        let completion = target_mismatch_completion(expected_target, current_target);
        tracing::warn!(
            machine_id = %mh_snapshot.host_snapshot.id,
            expected_target = ?expected_target,
            completion = ?completion,
            "Selected boot interface changed during synchronization",
        );
        let next_state = if state_may_require_lockdown_restore(state)
            && !mh_snapshot.host_snapshot.host_profile.disable_lockdown
        {
            driver.state(BootConfigSynchronizationState::RestoreLockdown { completion })
        } else {
            completion_state(driver, completion, mh_snapshot.host_snapshot.id)
        };
        return Ok(StateHandlerOutcome::transition(next_state));
    }

    match state {
        BootConfigSynchronizationState::Initialize { target } => {
            let Some(target) = target.clone().or(current_target) else {
                return Ok(StateHandlerOutcome::wait(format!(
                    "Waiting for host {} to expose a selected boot interface",
                    mh_snapshot.host_snapshot.id
                )));
            };
            request_observation(mh_snapshot, ctx, driver, target, ObservationPhase::Initial).await
        }
        BootConfigSynchronizationState::WaitingForInitialObservation {
            target,
            minimum_report_version,
        } => {
            let evaluation =
                observe_target(mh_snapshot, ctx, target, *minimum_report_version).await?;
            match evaluation.progress {
                ObservationProgress::Waiting => {
                    wait_for_observation(mh_snapshot, ctx, driver, target, evaluation).await
                }
                ObservationProgress::Configured => {
                    tracing::info!(
                        machine_id = %mh_snapshot.host_snapshot.id,
                        boot_interface = ?target.boot_interface,
                        selection_version = %target.selection_version,
                        "Selected boot interface is configured",
                    );
                    finish_synchronization(
                        mh_snapshot,
                        ctx,
                        driver,
                        target,
                        *minimum_report_version,
                        ObservationPhase::Initial,
                    )
                    .await
                }
                ObservationProgress::NeedsSynchronization => Ok(StateHandlerOutcome::transition(
                    driver.state(BootConfigSynchronizationState::PrepareHost {
                        target: target.clone(),
                    }),
                )),
            }
        }
        BootConfigSynchronizationState::PrepareHost { target } => {
            prepare_host(mh_snapshot, ctx, driver, target.clone()).await
        }
        BootConfigSynchronizationState::UnlockHost {
            target,
            unlock_host_state,
        } => {
            unlock_host(
                mh_snapshot,
                ctx,
                reachability_params,
                driver,
                target.clone(),
                unlock_host_state,
            )
            .await
        }
        BootConfigSynchronizationState::CheckHostConfig { target } => {
            check_host(
                mh_snapshot,
                ctx,
                reachability_params,
                driver,
                target.clone(),
            )
            .await
        }
        BootConfigSynchronizationState::ConfigureBios {
            target,
            retry_count,
        } => {
            run_stage(
                mh_snapshot,
                ctx,
                reachability_params,
                driver,
                target.clone(),
                HostBootConfigStage::ConfigureBios {
                    retry_count: *retry_count,
                },
            )
            .await
        }
        BootConfigSynchronizationState::WaitingForBiosJob {
            target,
            bios_config_info,
        } => {
            run_stage(
                mh_snapshot,
                ctx,
                reachability_params,
                driver,
                target.clone(),
                HostBootConfigStage::WaitingForBiosJob {
                    bios_config_info: bios_config_info.clone(),
                },
            )
            .await
        }
        BootConfigSynchronizationState::PollingBiosSetup {
            target,
            retry_count,
        } => {
            run_stage(
                mh_snapshot,
                ctx,
                reachability_params,
                driver,
                target.clone(),
                HostBootConfigStage::PollingBiosSetup {
                    retry_count: *retry_count,
                },
            )
            .await
        }
        BootConfigSynchronizationState::SetBootOrder {
            target,
            set_boot_order_info,
        } => {
            run_stage(
                mh_snapshot,
                ctx,
                reachability_params,
                driver,
                target.clone(),
                HostBootConfigStage::SetBootOrder {
                    set_boot_order_info: set_boot_order_info.clone(),
                },
            )
            .await
        }
        BootConfigSynchronizationState::RestoreLockdown { completion } => {
            restore_lockdown(mh_snapshot, ctx, driver, completion).await
        }
        BootConfigSynchronizationState::LockHost { target } => {
            lock_host_and_request_final_observation(mh_snapshot, ctx, driver, target.clone()).await
        }
        BootConfigSynchronizationState::WaitingForFinalObservation {
            target,
            minimum_report_version,
        } => {
            let evaluation =
                observe_target(mh_snapshot, ctx, target, *minimum_report_version).await?;
            match evaluation.progress {
                ObservationProgress::Waiting => {
                    wait_for_observation(mh_snapshot, ctx, driver, target, evaluation).await
                }
                ObservationProgress::Configured => {
                    tracing::info!(
                        machine_id = %mh_snapshot.host_snapshot.id,
                        boot_interface = ?target.boot_interface,
                        selection_version = %target.selection_version,
                        "Verified the synchronized boot interface",
                    );
                    finish_synchronization(
                        mh_snapshot,
                        ctx,
                        driver,
                        target,
                        *minimum_report_version,
                        ObservationPhase::Final,
                    )
                    .await
                }
                ObservationProgress::NeedsSynchronization => {
                    let next_state = retry_after_final_mismatch(
                        mh_snapshot,
                        ctx,
                        driver,
                        target,
                        &evaluation.reason,
                    )?;
                    Ok(StateHandlerOutcome::transition(next_state))
                }
            }
        }
    }
}

fn uses_current_target(state: &BootConfigSynchronizationState) -> bool {
    !matches!(
        state,
        BootConfigSynchronizationState::RestoreLockdown { .. }
    ) && !power_recovery_in_progress(state)
}

fn preemption_completion(
    mh_snapshot: &ManagedHostStateSnapshot,
    owner: BootConfigSynchronizationOwner,
    state: &BootConfigSynchronizationState,
    assigned_preemption: AssignedSynchronizationPreemption,
) -> Option<BootConfigSynchronizationCompletion> {
    if matches!(
        state,
        BootConfigSynchronizationState::RestoreLockdown { .. }
    ) || power_recovery_in_progress(state)
    {
        return None;
    }
    match owner {
        BootConfigSynchronizationOwner::Unassigned => mh_snapshot
            .host_snapshot
            .machine_maintenance_requested
            .as_ref()
            .map(|request| BootConfigSynchronizationCompletion::Maintenance {
                operation: request.operation,
            }),
        BootConfigSynchronizationOwner::Assigned => {
            if assigned_preemption == AssignedSynchronizationPreemption::None {
                None
            } else {
                state_target(state).map(|target| {
                    BootConfigSynchronizationCompletion::ReturnToReady {
                        target: target.clone(),
                    }
                })
            }
        }
    }
}

fn state_target(
    state: &BootConfigSynchronizationState,
) -> Option<&BootConfigSynchronizationTarget> {
    match state {
        BootConfigSynchronizationState::Initialize { target } => target.as_ref(),
        BootConfigSynchronizationState::WaitingForInitialObservation { target, .. }
        | BootConfigSynchronizationState::PrepareHost { target }
        | BootConfigSynchronizationState::UnlockHost { target, .. }
        | BootConfigSynchronizationState::CheckHostConfig { target }
        | BootConfigSynchronizationState::ConfigureBios { target, .. }
        | BootConfigSynchronizationState::WaitingForBiosJob { target, .. }
        | BootConfigSynchronizationState::PollingBiosSetup { target, .. }
        | BootConfigSynchronizationState::SetBootOrder { target, .. }
        | BootConfigSynchronizationState::LockHost { target }
        | BootConfigSynchronizationState::WaitingForFinalObservation { target, .. } => Some(target),
        BootConfigSynchronizationState::RestoreLockdown { .. } => None,
    }
}

fn authorization_target(
    state: &BootConfigSynchronizationState,
) -> Option<&BootConfigSynchronizationTarget> {
    state_target(state).or(match state {
        BootConfigSynchronizationState::RestoreLockdown {
            completion: BootConfigSynchronizationCompletion::ReturnToReady { target },
        } => Some(target),
        _ => None,
    })
}

fn assigned_authorization_matches(
    mh_snapshot: &ManagedHostStateSnapshot,
    target: &BootConfigSynchronizationTarget,
) -> bool {
    let Some(interface_id) = target.machine_interface_id else {
        return false;
    };
    mh_snapshot
        .host_snapshot
        .boot_config_synchronization_requested
        .as_ref()
        .is_some_and(|request| {
            request.interface_id == interface_id
                && request.selection_version == target.selection_version
        })
}

fn state_may_require_lockdown_restore(state: &BootConfigSynchronizationState) -> bool {
    matches!(
        state,
        BootConfigSynchronizationState::UnlockHost { .. }
            | BootConfigSynchronizationState::CheckHostConfig { .. }
            | BootConfigSynchronizationState::ConfigureBios { .. }
            | BootConfigSynchronizationState::WaitingForBiosJob { .. }
            | BootConfigSynchronizationState::PollingBiosSetup { .. }
            | BootConfigSynchronizationState::SetBootOrder { .. }
            | BootConfigSynchronizationState::LockHost { .. }
    )
}

fn power_recovery_in_progress(state: &BootConfigSynchronizationState) -> bool {
    match state {
        BootConfigSynchronizationState::WaitingForBiosJob {
            bios_config_info, ..
        } => matches!(
            bios_config_info.bios_config_state,
            model::machine::BiosConfigState::HandleBiosJobFailure { .. }
        ),
        BootConfigSynchronizationState::SetBootOrder {
            set_boot_order_info,
            ..
        } => matches!(
            set_boot_order_info.set_boot_order_state,
            model::machine::SetBootOrderState::HandleJobFailure { .. }
        ),
        _ => false,
    }
}

fn same_selection(
    expected: &BootConfigSynchronizationTarget,
    current: &BootConfigSynchronizationTarget,
) -> bool {
    // A first lease promotes the predicted interface into a machine-interface
    // row, and later exploration may enrich its Redfish id. The selection
    // generation and MAC remain the durable identity across both changes.
    expected.selection_version == current.selection_version
        && boot_interface_mac(&expected.boot_interface)
            == boot_interface_mac(&current.boot_interface)
}

fn boot_interface_mac(target: &MachineBootInterfaceTarget) -> mac_address::MacAddress {
    match target {
        MachineBootInterfaceTarget::Pair(interface) => interface.mac_address,
        MachineBootInterfaceTarget::MacOnly(mac_address) => *mac_address,
    }
}

fn target_mismatch_completion(
    expected: &BootConfigSynchronizationTarget,
    current: Option<BootConfigSynchronizationTarget>,
) -> BootConfigSynchronizationCompletion {
    current
        .filter(|current| same_selection(expected, current))
        .map_or(
            BootConfigSynchronizationCompletion::TargetChanged,
            |target| BootConfigSynchronizationCompletion::Retarget { target },
        )
}

fn completion_state(
    driver: BootConfigSynchronizationDriver,
    completion: BootConfigSynchronizationCompletion,
    machine_id: carbide_uuid::machine::MachineId,
) -> ManagedHostState {
    match completion {
        BootConfigSynchronizationCompletion::Retarget { target } => {
            driver.state(BootConfigSynchronizationState::Initialize {
                target: Some(target),
            })
        }
        BootConfigSynchronizationCompletion::ResumeSynchronization { target } => {
            driver.state(BootConfigSynchronizationState::Initialize { target })
        }
        BootConfigSynchronizationCompletion::TargetChanged => driver.target_changed_state(),
        BootConfigSynchronizationCompletion::ReturnToReady { .. } => driver.ready_state(),
        BootConfigSynchronizationCompletion::Maintenance { operation } => {
            ManagedHostState::maintenance_for_operation(operation)
        }
        BootConfigSynchronizationCompletion::MachineFailed {
            machine_id,
            details,
        } => driver.machine_failure_state(machine_id, details),
        BootConfigSynchronizationCompletion::Failed { error } => {
            driver.failure_state(machine_id, error)
        }
        BootConfigSynchronizationCompletion::ManualInterventionRequired { error } => {
            driver.failure_state(machine_id, error)
        }
    }
}

enum CurrentTargetResolution {
    Ready(BootConfigSynchronizationTarget),
    AwaitingNic,
    Missing,
}

impl CurrentTargetResolution {
    fn into_option(self) -> Option<BootConfigSynchronizationTarget> {
        match self {
            Self::Ready(target) => Some(target),
            Self::AwaitingNic | Self::Missing => None,
        }
    }
}

async fn resolve_current_target(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<CurrentTargetResolution, StateHandlerError> {
    let predictions = load_boot_predictions(ctx, mh_snapshot).await?;
    match resolve_boot_interface(mh_snapshot, &predictions) {
        BootInterfaceResolution::Ready(resolved) => {
            Ok(CurrentTargetResolution::Ready(synchronization_target(
                &resolved,
                mh_snapshot.host_snapshot.boot_interface_selection_version,
            )))
        }
        BootInterfaceResolution::AwaitingNic => Ok(CurrentTargetResolution::AwaitingNic),
        BootInterfaceResolution::Missing => Ok(CurrentTargetResolution::Missing),
    }
}

fn synchronization_target(
    resolved: &ResolvedBootInterface,
    selection_version: ConfigVersion,
) -> BootConfigSynchronizationTarget {
    BootConfigSynchronizationTarget {
        machine_interface_id: resolved.machine_interface_id,
        boot_interface: (&resolved.target).into(),
        selection_version,
    }
}

async fn find_endpoint(
    mh_snapshot: &ManagedHostStateSnapshot,
    services: &mut MachineStateHandlerServices,
) -> Result<Option<ExploredEndpoint>, StateHandlerError> {
    let Some(address) = mh_snapshot.host_snapshot.status.bmc_info.ip else {
        return Err(StateHandlerError::MissingData {
            object_id: mh_snapshot.host_snapshot.id.to_string(),
            missing: "BMC IP",
        });
    };
    Ok(
        db::explored_endpoints::find_by_ips(&mut services.db_reader, vec![address])
            .await?
            .into_iter()
            .next(),
    )
}

#[derive(Clone, Copy)]
enum ObservationPhase {
    Initial,
    Final,
}

async fn request_observation(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    driver: BootConfigSynchronizationDriver,
    target: BootConfigSynchronizationTarget,
    phase: ObservationPhase,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let Some(address) = mh_snapshot.host_snapshot.status.bmc_info.ip else {
        return Err(StateHandlerError::MissingData {
            object_id: mh_snapshot.host_snapshot.id.to_string(),
            missing: "BMC IP",
        });
    };
    if find_endpoint(mh_snapshot, ctx.services).await?.is_none() {
        return Ok(StateHandlerOutcome::wait(format!(
            "Waiting for explored endpoint {address} before observing the selected boot interface"
        )));
    }

    // State persistence later uses this same transaction. Lock the endpoint
    // before the machine row, matching Site Explorer and Scout discovery.
    let mut txn = ctx.services.db_pool.begin().await?;
    if db::explored_endpoints::find_by_ip_for_update_optional(address, &mut txn)
        .await?
        .is_none()
    {
        return Ok(StateHandlerOutcome::wait(format!(
            "Waiting for explored endpoint {address} before observing the selected boot interface"
        ))
        .with_txn(txn));
    }
    let current_selection_version =
        db::machine::lock_boot_interface_selection_version(&mut txn, mh_snapshot.host_snapshot.id)
            .await?;
    if current_selection_version != target.selection_version {
        txn.rollback().await?;
        return Ok(StateHandlerOutcome::transition(
            driver.target_changed_state(),
        ));
    }
    let minimum_report_version = db::explored_endpoints::request_boot_interface_observation(
        address,
        &target.boot_interface,
        &mut txn,
    )
    .await?;
    let next = match phase {
        ObservationPhase::Initial => BootConfigSynchronizationState::WaitingForInitialObservation {
            target,
            minimum_report_version,
        },
        ObservationPhase::Final => BootConfigSynchronizationState::WaitingForFinalObservation {
            target,
            minimum_report_version,
        },
    };
    Ok(StateHandlerOutcome::transition(driver.state(next)).with_txn(txn))
}

async fn observe_target(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    target: &BootConfigSynchronizationTarget,
    minimum_report_version: ConfigVersion,
) -> Result<ObservationEvaluation, StateHandlerError> {
    let Some(endpoint) = find_endpoint(mh_snapshot, ctx.services).await? else {
        return Ok(ObservationEvaluation::waiting(
            "Waiting for the host's explored endpoint",
            false,
        ));
    };
    Ok(evaluate_observation(
        &endpoint,
        target,
        minimum_report_version,
        ObservationPolicy::for_host(mh_snapshot),
    ))
}

async fn finish_synchronization(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    driver: BootConfigSynchronizationDriver,
    target: &BootConfigSynchronizationTarget,
    minimum_report_version: ConfigVersion,
    phase: ObservationPhase,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let machine_id = mh_snapshot.host_snapshot.id;
    let Some(address) = mh_snapshot.host_snapshot.status.bmc_info.ip else {
        return Err(StateHandlerError::MissingData {
            object_id: machine_id.to_string(),
            missing: "BMC IP",
        });
    };
    let mut txn = ctx.services.db_pool.begin().await?;
    let locked = lock_boot_config_view(&mut txn, machine_id, address).await?;
    let Some(endpoint) = locked.endpoint else {
        return Ok(StateHandlerOutcome::wait(format!(
            "Waiting for explored endpoint {address} before completing boot-interface synchronization"
        ))
        .with_txn(txn));
    };
    let current_target = locked
        .target
        .filter(|current| current.selection_version == target.selection_version);

    if current_target.as_ref() != Some(target) {
        let completion = target_mismatch_completion(target, current_target);
        return Ok(StateHandlerOutcome::transition(completion_state(
            driver, completion, machine_id,
        ))
        .with_txn(txn));
    }

    let evaluation = evaluate_observation(
        &endpoint,
        target,
        minimum_report_version,
        ObservationPolicy::for_host(mh_snapshot),
    );
    match evaluation.progress {
        ObservationProgress::Configured => {
            if driver.owner == BootConfigSynchronizationOwner::Assigned
                && let Some(interface_id) = target.machine_interface_id
            {
                // A replacement authorization names a newer request and must
                // remain available when this older synchronization completes.
                db::machine::consume_boot_config_synchronization_request(
                    &mut txn,
                    machine_id,
                    interface_id,
                    target.selection_version,
                )
                .await?;
            } else if driver.owner == BootConfigSynchronizationOwner::Unassigned {
                // Assigned authorization cannot cross the unassigned Ready
                // boundary and become usable by a later tenant.
                db::machine::clear_boot_config_synchronization_request(&mut txn, machine_id)
                    .await?;
            }
            Ok(StateHandlerOutcome::transition(driver.ready_state()).with_txn(txn))
        }
        ObservationProgress::NeedsSynchronization => {
            let next_state = match phase {
                ObservationPhase::Initial => {
                    driver.state(BootConfigSynchronizationState::PrepareHost {
                        target: target.clone(),
                    })
                }
                ObservationPhase::Final => retry_after_final_mismatch(
                    mh_snapshot,
                    ctx,
                    driver,
                    target,
                    &evaluation.reason,
                )?,
            };
            Ok(StateHandlerOutcome::transition(next_state).with_txn(txn))
        }
        ObservationProgress::Waiting => {
            if evaluation.request_exploration {
                request_target_observation(address, &endpoint, target, &mut txn).await?;
            }
            Ok(StateHandlerOutcome::wait(evaluation.reason).with_txn(txn))
        }
    }
}

fn retry_after_final_mismatch(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    driver: BootConfigSynchronizationDriver,
    target: &BootConfigSynchronizationTarget,
    mismatch: &str,
) -> Result<ManagedHostState, StateHandlerError> {
    let max_retries = ctx
        .services
        .site_config
        .machine_state_controller
        .max_bios_config_retries;
    if driver.retry_count >= max_retries {
        return Err(StateHandlerError::ManualInterventionRequired(format!(
            "Selected boot interface is still not configured for host {} after automated boot-config synchronization; retry budget exhausted (retry_count: {}, max_retries: {}); {}",
            mh_snapshot.host_snapshot.id, driver.retry_count, max_retries, mismatch,
        )));
    }

    let next_driver = driver.retry();
    tracing::warn!(
        machine_id = %mh_snapshot.host_snapshot.id,
        boot_interface = ?target.boot_interface,
        selection_version = %target.selection_version,
        retry_count = next_driver.retry_count,
        max_retries,
        mismatch = %mismatch,
        "Selected boot interface is still not configured after final verification; synchronizing again",
    );
    Ok(
        next_driver.state(BootConfigSynchronizationState::PrepareHost {
            target: target.clone(),
        }),
    )
}

fn evaluate_observation(
    endpoint: &ExploredEndpoint,
    target: &BootConfigSynchronizationTarget,
    minimum_report_version: ConfigVersion,
    policy: ObservationPolicy,
) -> ObservationEvaluation {
    if !version_is_newer(endpoint.report_version, minimum_report_version) {
        return ObservationEvaluation::waiting(
            format!(
                "Waiting for a boot-interface observation newer than {}",
                minimum_report_version
            ),
            !endpoint.exploration_requested,
        );
    }
    if let Some(error) = endpoint.report.last_exploration_error.as_ref() {
        return ObservationEvaluation::waiting(
            format!("Waiting for Site Explorer after exploration error: {error}"),
            !endpoint.exploration_requested,
        );
    }
    if endpoint.waiting_for_explorer_refresh {
        return ObservationEvaluation::waiting(
            "Waiting for Site Explorer to refresh the boot-interface observation",
            !endpoint.exploration_requested,
        );
    }
    if endpoint.exploration_requested {
        return ObservationEvaluation::waiting(
            "Waiting for the requested Site Explorer run",
            false,
        );
    }
    if endpoint.boot_interface_target().as_ref() != Some(&target.boot_interface) {
        return ObservationEvaluation::waiting(
            "Waiting for Site Explorer to evaluate the current endpoint target",
            true,
        );
    }
    let Some(status) = endpoint.report.machine_setup_status.as_ref() else {
        return ObservationEvaluation::waiting("Waiting for a machine-setup observation", true);
    };
    if status.verification_version < MACHINE_SETUP_VERIFICATION_VERSION {
        return ObservationEvaluation::waiting(
            format!(
                "Waiting for machine-setup verification version {}",
                MACHINE_SETUP_VERIFICATION_VERSION
            ),
            true,
        );
    }
    if status.evaluated_boot_interface.as_ref() != Some(&target.boot_interface) {
        return ObservationEvaluation::waiting(
            "Waiting for a machine-setup observation of the selected boot interface",
            true,
        );
    }

    if policy.accepts(status) {
        ObservationEvaluation {
            progress: ObservationProgress::Configured,
            reason: "Selected boot interface is configured".to_string(),
            request_exploration: false,
        }
    } else {
        ObservationEvaluation {
            progress: ObservationProgress::NeedsSynchronization,
            reason: format!(
                "machine-setup differences for the selected boot interface: {:?}",
                status.diffs
            ),
            request_exploration: false,
        }
    }
}

// Either component can advance independently when an endpoint row is
// recreated, so freshness intentionally uses OR rather than tuple ordering.
fn version_is_newer(report: ConfigVersion, minimum: ConfigVersion) -> bool {
    report.version_nr() > minimum.version_nr() || report.timestamp() > minimum.timestamp()
}

async fn wait_for_observation(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    driver: BootConfigSynchronizationDriver,
    target: &BootConfigSynchronizationTarget,
    evaluation: ObservationEvaluation,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if !evaluation.request_exploration {
        return Ok(StateHandlerOutcome::wait(evaluation.reason));
    }

    let Some(address) = mh_snapshot.host_snapshot.status.bmc_info.ip else {
        return Err(StateHandlerError::MissingData {
            object_id: mh_snapshot.host_snapshot.id.to_string(),
            missing: "BMC IP",
        });
    };
    let mut txn = ctx.services.db_pool.begin().await?;
    let Some(endpoint) =
        db::explored_endpoints::find_by_ip_for_update_optional(address, &mut txn).await?
    else {
        return Ok(StateHandlerOutcome::wait(evaluation.reason).with_txn(txn));
    };
    let current_selection_version =
        db::machine::lock_boot_interface_selection_version(&mut txn, mh_snapshot.host_snapshot.id)
            .await?;
    if current_selection_version != target.selection_version {
        txn.rollback().await?;
        return Ok(StateHandlerOutcome::transition(
            driver.target_changed_state(),
        ));
    }
    request_target_observation(address, &endpoint, target, &mut txn).await?;
    Ok(StateHandlerOutcome::wait(evaluation.reason).with_txn(txn))
}

/// Reasserts the pinned endpoint target before requesting another observation.
///
/// A recreated or concurrently changed endpoint can lose its target while the
/// controller is waiting. Re-exploration alone would keep evaluating the wrong
/// interface, so a mismatch crosses a new version barrier first.
async fn request_target_observation(
    address: std::net::IpAddr,
    endpoint: &ExploredEndpoint,
    target: &BootConfigSynchronizationTarget,
    txn: &mut sqlx::PgConnection,
) -> Result<(), StateHandlerError> {
    if endpoint.boot_interface_target().as_ref() != Some(&target.boot_interface) {
        db::explored_endpoints::set_boot_interface_target(address, &target.boot_interface, txn)
            .await?;
    } else {
        db::explored_endpoints::re_explore_if_version_matches(
            address,
            endpoint.report_version,
            txn,
        )
        .await?;
    }
    Ok(())
}

async fn prepare_host(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    driver: BootConfigSynchronizationDriver,
    target: BootConfigSynchronizationTarget,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let redfish_client = ctx
        .services
        .create_redfish_client_from_machine(&mh_snapshot.host_snapshot)
        .await?;
    let next = match redfish_client.lockdown_status().await {
        Err(RedfishError::NotSupported(_)) => {
            BootConfigSynchronizationState::CheckHostConfig { target }
        }
        Err(error) => {
            tracing::warn!(
                machine_id = %mh_snapshot.host_snapshot.id,
                error = %error,
                "Failed to read BMC lockdown before boot-interface synchronization",
            );
            return Ok(StateHandlerOutcome::wait(format!(
                "Failed to read BMC lockdown: {error}"
            )));
        }
        Ok(status) if !status.is_fully_disabled() => BootConfigSynchronizationState::UnlockHost {
            target,
            unlock_host_state: UnlockHostState::DisableLockdown,
        },
        Ok(_) => BootConfigSynchronizationState::CheckHostConfig { target },
    };
    Ok(StateHandlerOutcome::transition(driver.state(next)))
}

async fn unlock_host(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    driver: BootConfigSynchronizationDriver,
    target: BootConfigSynchronizationTarget,
    unlock_host_state: &UnlockHostState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let redfish_client = ctx
        .services
        .create_redfish_client_from_machine(&mh_snapshot.host_snapshot)
        .await?;
    let next = match unlock_host_state {
        UnlockHostState::DisableLockdown => {
            match redfish_client.lockdown_bmc(EnabledDisabled::Disabled).await {
                Ok(()) | Err(RedfishError::NotSupported(_)) => {}
                Err(error) => return Err(redfish_error("lockdown_bmc", error)),
            }
            if mh_snapshot.host_snapshot.bmc_vendor().is_supermicro() {
                BootConfigSynchronizationState::UnlockHost {
                    target,
                    unlock_host_state: UnlockHostState::RebootHost,
                }
            } else {
                BootConfigSynchronizationState::CheckHostConfig { target }
            }
        }
        UnlockHostState::RebootHost => {
            host_power_control(
                redfish_client.as_ref(),
                &mh_snapshot.host_snapshot,
                SystemPowerControl::ForceRestart,
                ctx,
            )
            .await
            .map_err(|error| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "failed to restart host after disabling BMC lockdown: {error}"
                ))
            })?;
            BootConfigSynchronizationState::UnlockHost {
                target,
                unlock_host_state: UnlockHostState::WaitForUefiBoot,
            }
        }
        UnlockHostState::WaitForUefiBoot => {
            let entered_at = mh_snapshot.host_snapshot.state.version.timestamp();
            if wait(&entered_at, reachability_params.uefi_boot_wait) {
                return Ok(StateHandlerOutcome::wait(format!(
                    "Waiting for UEFI boot on {} after disabling BMC lockdown",
                    mh_snapshot.host_snapshot.id
                )));
            }
            BootConfigSynchronizationState::CheckHostConfig { target }
        }
    };
    Ok(StateHandlerOutcome::transition(driver.state(next)))
}

async fn check_host(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    driver: BootConfigSynchronizationDriver,
    target: BootConfigSynchronizationTarget,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let redfish_client = ctx
        .services
        .create_redfish_client_from_machine(&mh_snapshot.host_snapshot)
        .await?;
    let next = match check_host_boot_config(
        redfish_client.as_ref(),
        mh_snapshot,
        reachability_params,
        HostBootConfigDpuFreshness::CurrentHostState,
        HostBootInterfaceSource::Pinned(target.boot_interface.clone().into()),
        ctx,
    )
    .await?
    {
        HostBootConfigCheckOutcome::Wait(reason) => {
            return Ok(StateHandlerOutcome::wait(reason));
        }
        HostBootConfigCheckOutcome::Ready(HostBootConfigDecision::ConfigureBios) => {
            BootConfigSynchronizationState::ConfigureBios {
                target,
                retry_count: 0,
            }
        }
        HostBootConfigCheckOutcome::Ready(HostBootConfigDecision::SetBootOrder) => {
            BootConfigSynchronizationState::SetBootOrder {
                target,
                set_boot_order_info: initial_set_boot_order_info(),
            }
        }
        HostBootConfigCheckOutcome::Ready(HostBootConfigDecision::Complete) => {
            BootConfigSynchronizationState::LockHost { target }
        }
    };
    Ok(StateHandlerOutcome::transition(driver.state(next)))
}

async fn run_stage(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    driver: BootConfigSynchronizationDriver,
    target: BootConfigSynchronizationTarget,
    stage: HostBootConfigStage,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let redfish_client = ctx
        .services
        .create_redfish_client_from_machine(&mh_snapshot.host_snapshot)
        .await?;
    let stage_outcome = match run_host_boot_config_stage(
        ctx,
        reachability_params,
        redfish_client.as_ref(),
        mh_snapshot,
        HostBootInterfaceSource::Pinned(target.boot_interface.clone().into()),
        stage,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(StateHandlerError::ManualInterventionRequired(error)) => {
            if mh_snapshot.host_snapshot.host_profile.disable_lockdown {
                return Err(StateHandlerError::ManualInterventionRequired(error));
            }
            return Ok(StateHandlerOutcome::transition(driver.state(
                BootConfigSynchronizationState::RestoreLockdown {
                    completion: BootConfigSynchronizationCompletion::ManualInterventionRequired {
                        error,
                    },
                },
            )));
        }
        Err(error) => return Err(error),
    };
    match stage_outcome {
        HostBootConfigOutcome::Continue(stage) => {
            let next = match stage {
                HostBootConfigStage::ConfigureBios { retry_count } => {
                    BootConfigSynchronizationState::ConfigureBios {
                        target,
                        retry_count,
                    }
                }
                HostBootConfigStage::WaitingForBiosJob { bios_config_info } => {
                    BootConfigSynchronizationState::WaitingForBiosJob {
                        target,
                        bios_config_info,
                    }
                }
                HostBootConfigStage::PollingBiosSetup { retry_count } => {
                    BootConfigSynchronizationState::PollingBiosSetup {
                        target,
                        retry_count,
                    }
                }
                HostBootConfigStage::SetBootOrder {
                    set_boot_order_info,
                } => BootConfigSynchronizationState::SetBootOrder {
                    target,
                    set_boot_order_info,
                },
            };
            Ok(StateHandlerOutcome::transition(driver.state(next)))
        }
        HostBootConfigOutcome::Complete => Ok(StateHandlerOutcome::transition(
            driver.state(BootConfigSynchronizationState::LockHost { target }),
        )),
        HostBootConfigOutcome::Wait(reason) => Ok(StateHandlerOutcome::wait(reason)),
        HostBootConfigOutcome::Failed { failure } => {
            let next = if mh_snapshot.host_snapshot.host_profile.disable_lockdown {
                driver.failure_state(mh_snapshot.host_snapshot.id, failure)
            } else {
                driver.state(BootConfigSynchronizationState::RestoreLockdown {
                    completion: BootConfigSynchronizationCompletion::Failed { error: failure },
                })
            };
            Ok(StateHandlerOutcome::transition(next))
        }
    }
}

async fn restore_lockdown(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    driver: BootConfigSynchronizationDriver,
    completion: &BootConfigSynchronizationCompletion,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    enable_lockdown(mh_snapshot, ctx).await?;
    if let BootConfigSynchronizationCompletion::ManualInterventionRequired { error } = completion {
        return Err(StateHandlerError::ManualInterventionRequired(error.clone()));
    }
    let next = completion_state(driver, completion.clone(), mh_snapshot.host_snapshot.id);
    Ok(StateHandlerOutcome::transition(next))
}

async fn enable_lockdown(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<(), StateHandlerError> {
    let redfish_client = ctx
        .services
        .create_redfish_client_from_machine(&mh_snapshot.host_snapshot)
        .await?;
    match redfish_client.lockdown_bmc(EnabledDisabled::Enabled).await {
        Ok(()) | Err(RedfishError::NotSupported(_)) => Ok(()),
        Err(error) => Err(redfish_error("lockdown_bmc", error)),
    }
}

async fn lock_host_and_request_final_observation(
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    driver: BootConfigSynchronizationDriver,
    target: BootConfigSynchronizationTarget,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if mh_snapshot.host_snapshot.host_profile.disable_lockdown {
        tracing::info!(
            machine_id = %mh_snapshot.host_snapshot.id,
            "Skipping BMC lockdown after boot-interface synchronization per host profile",
        );
    } else {
        enable_lockdown(mh_snapshot, ctx).await?;
    }
    request_observation(mh_snapshot, ctx, driver, target, ObservationPhase::Final).await
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;
    use mac_address::MacAddress;
    use model::machine_boot_interface::{MachineBootInterface, MachineBootInterfaceTarget};
    use model::network_segment::NetworkSegmentType;
    use model::site_explorer::{
        EndpointExplorationError, EndpointExplorationReport, MachineSetupDiff, MachineSetupStatus,
        PreingestionState,
    };

    use super::*;

    #[derive(Clone, Copy)]
    enum ObservationCase {
        OlderReport,
        EqualReportVersion,
        IncrementWithEarlierTimestamp,
        RecreatedEndpointWithNewerTimestamp,
        WaitingForRefresh,
        ExplorationRequested,
        ExplorationError,
        EndpointTargetMismatch,
        MissingSetupStatus,
        LegacyVerification,
        MissingEvaluatedTarget,
        PairEvaluatedAsMacOnly,
        MacOnlyEvaluatedAsPair,
        NeedsSynchronization,
        AllowedDisabledLockdown,
        AllowedSkippedBootOrder,
        PolicyDoesNotHideOtherDiffs,
        Configured,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct EvaluationSummary {
        progress: ObservationProgress,
        request_exploration: bool,
    }

    fn pair(interface_id: &str) -> MachineBootInterfaceTarget {
        MachineBootInterfaceTarget::Pair(MachineBootInterface {
            mac_address: MacAddress::new([0x02, 0, 0, 0, 0, 1]),
            interface_id: interface_id.to_string(),
        })
    }

    fn mac_only() -> MachineBootInterfaceTarget {
        MachineBootInterfaceTarget::MacOnly(MacAddress::new([0x02, 0, 0, 0, 0, 1]))
    }

    fn synchronization_target_for_test(
        machine_interface_id: Option<carbide_uuid::machine::MachineInterfaceId>,
        boot_interface: MachineBootInterfaceTarget,
        selection_version: ConfigVersion,
    ) -> BootConfigSynchronizationTarget {
        BootConfigSynchronizationTarget {
            machine_interface_id,
            boot_interface,
            selection_version,
        }
    }

    fn evaluate(case: ObservationCase) -> EvaluationSummary {
        let mut target = BootConfigSynchronizationTarget {
            machine_interface_id: None,
            boot_interface: pair("NIC.Slot.7-1-1"),
            selection_version: ConfigVersion::new(7),
        };
        let mut endpoint_target = target.boot_interface.clone();
        let minimum_report_version = "V2-T100".parse().expect("valid minimum version");
        let mut report_version = "V3-T101".parse().expect("valid newer version");
        let mut waiting_for_explorer_refresh = false;
        let mut exploration_requested = false;
        let mut last_exploration_error = None;
        let mut machine_setup_status = Some(MachineSetupStatus {
            is_done: true,
            diffs: Vec::new(),
            verification_version: MACHINE_SETUP_VERIFICATION_VERSION,
            evaluated_boot_interface: Some(target.boot_interface.clone()),
        });
        let mut policy = ObservationPolicy::default();

        match case {
            ObservationCase::OlderReport => {
                report_version = "V1-T99".parse().expect("valid older version");
            }
            ObservationCase::EqualReportVersion => report_version = minimum_report_version,
            ObservationCase::IncrementWithEarlierTimestamp => {
                report_version = "V3-T99".parse().expect("valid clock-regressed version");
            }
            ObservationCase::RecreatedEndpointWithNewerTimestamp => {
                report_version = "V1-T101".parse().expect("valid recreated version");
            }
            ObservationCase::WaitingForRefresh => waiting_for_explorer_refresh = true,
            ObservationCase::ExplorationRequested => exploration_requested = true,
            ObservationCase::ExplorationError => {
                last_exploration_error = Some(EndpointExplorationError::ConnectionTimeout {
                    details: "test timeout".to_string(),
                });
            }
            ObservationCase::EndpointTargetMismatch => {
                endpoint_target = pair("NIC.Slot.8-1-1");
            }
            ObservationCase::MissingSetupStatus => machine_setup_status = None,
            ObservationCase::LegacyVerification => {
                machine_setup_status
                    .as_mut()
                    .expect("setup status starts present")
                    .verification_version = 0;
            }
            ObservationCase::MissingEvaluatedTarget => {
                machine_setup_status
                    .as_mut()
                    .expect("setup status starts present")
                    .evaluated_boot_interface = None;
            }
            ObservationCase::PairEvaluatedAsMacOnly => {
                machine_setup_status
                    .as_mut()
                    .expect("setup status starts present")
                    .evaluated_boot_interface = Some(mac_only());
            }
            ObservationCase::MacOnlyEvaluatedAsPair => {
                target.boot_interface = mac_only();
                endpoint_target = mac_only();
            }
            ObservationCase::NeedsSynchronization => {
                machine_setup_status
                    .as_mut()
                    .expect("setup status starts present")
                    .is_done = false;
            }
            ObservationCase::AllowedDisabledLockdown => {
                let status = machine_setup_status
                    .as_mut()
                    .expect("setup status starts present");
                status.is_done = false;
                status.diffs.push(MachineSetupDiff {
                    key: "lockdown".to_string(),
                    expected: "Enabled".to_string(),
                    actual: "Disabled".to_string(),
                });
                policy.allow_disabled_lockdown = true;
            }
            ObservationCase::AllowedSkippedBootOrder => {
                let status = machine_setup_status
                    .as_mut()
                    .expect("setup status starts present");
                status.is_done = false;
                status.diffs.push(MachineSetupDiff {
                    key: "boot_first".to_string(),
                    expected: "selected interface".to_string(),
                    actual: "another interface".to_string(),
                });
                policy.skip_boot_order = true;
            }
            ObservationCase::PolicyDoesNotHideOtherDiffs => {
                let status = machine_setup_status
                    .as_mut()
                    .expect("setup status starts present");
                status.is_done = false;
                status.diffs.push(MachineSetupDiff {
                    key: "bios_setting".to_string(),
                    expected: "expected".to_string(),
                    actual: "actual".to_string(),
                });
                policy.allow_disabled_lockdown = true;
                policy.skip_boot_order = true;
            }
            ObservationCase::Configured => {}
        }

        let (boot_interface_mac, boot_interface_id) = match endpoint_target {
            MachineBootInterfaceTarget::Pair(interface) => {
                (Some(interface.mac_address), Some(interface.interface_id))
            }
            MachineBootInterfaceTarget::MacOnly(mac_address) => (Some(mac_address), None),
        };
        let endpoint = ExploredEndpoint {
            address: "192.0.2.10".parse().expect("test address is valid"),
            report: EndpointExplorationReport {
                last_exploration_error,
                machine_setup_status,
                ..Default::default()
            },
            report_version,
            preingestion_state: PreingestionState::Initial,
            waiting_for_explorer_refresh,
            exploration_requested,
            last_redfish_bmc_reset: None,
            last_ipmitool_bmc_reset: None,
            last_redfish_reboot: None,
            last_redfish_powercycle: None,
            pause_ingestion_and_poweron: false,
            pause_remediation: false,
            boot_interface_mac,
            boot_interface_id,
        };
        let evaluation = evaluate_observation(&endpoint, &target, minimum_report_version, policy);

        EvaluationSummary {
            progress: evaluation.progress,
            request_exploration: evaluation.request_exploration,
        }
    }

    #[test]
    fn observation_evaluation_requires_fresh_target_correlated_evidence() {
        value_scenarios!(evaluate:
            "stale reports wait and request another exploration" {
                ObservationCase::OlderReport => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
                ObservationCase::EqualReportVersion => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
            }

            "in-flight exploration waits without duplicating a request" {
                ObservationCase::WaitingForRefresh => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
                ObservationCase::ExplorationRequested => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: false,
                },
            }

            "failed or incomplete reports request another exploration" {
                ObservationCase::ExplorationError => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
                ObservationCase::EndpointTargetMismatch => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
                ObservationCase::MissingSetupStatus => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
                ObservationCase::LegacyVerification => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
                ObservationCase::MissingEvaluatedTarget => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
            }

            "pair and MAC-only observations must match exactly" {
                ObservationCase::PairEvaluatedAsMacOnly => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
                ObservationCase::MacOnlyEvaluatedAsPair => EvaluationSummary {
                    progress: ObservationProgress::Waiting,
                    request_exploration: true,
                },
            }

            "exact observations determine whether synchronization is needed" {
                ObservationCase::IncrementWithEarlierTimestamp => EvaluationSummary {
                    progress: ObservationProgress::Configured,
                    request_exploration: false,
                },
                ObservationCase::RecreatedEndpointWithNewerTimestamp => EvaluationSummary {
                    progress: ObservationProgress::Configured,
                    request_exploration: false,
                },
                ObservationCase::NeedsSynchronization => EvaluationSummary {
                    progress: ObservationProgress::NeedsSynchronization,
                    request_exploration: false,
                },
                ObservationCase::PolicyDoesNotHideOtherDiffs => EvaluationSummary {
                    progress: ObservationProgress::NeedsSynchronization,
                    request_exploration: false,
                },
                ObservationCase::AllowedDisabledLockdown => EvaluationSummary {
                    progress: ObservationProgress::Configured,
                    request_exploration: false,
                },
                ObservationCase::AllowedSkippedBootOrder => EvaluationSummary {
                    progress: ObservationProgress::Configured,
                    request_exploration: false,
                },
                ObservationCase::Configured => EvaluationSummary {
                    progress: ObservationProgress::Configured,
                    request_exploration: false,
                },
            }
        );
    }

    #[test]
    fn interrupted_redfish_work_restores_lockdown_before_leaving_synchronization() {
        let mut snapshot = model::test_support::machine_snapshot::managed_host_state_snapshot();
        let target = BootConfigSynchronizationTarget {
            machine_interface_id: None,
            boot_interface: pair("NIC.Slot.7-1-1"),
            selection_version: ConfigVersion::new(7),
        };
        snapshot.managed_state = ManagedHostState::BootConfigSynchronization {
            synchronization_state: BootConfigSynchronizationState::ConfigureBios {
                target: target.clone(),
                retry_count: 0,
            },
            synchronization_retry_count: 2,
        };
        let failed_machine_id = snapshot.dpu_snapshots[0].id;
        let details = FailureDetails {
            cause: FailureCause::BiosSetupFailed {
                err: "test failure".to_string(),
            },
            failed_at: chrono::Utc::now(),
            source: FailureSource::StateMachineArea(StateMachineArea::MainFlow),
        };

        let failure_transition =
            machine_failure_transition(&snapshot, failed_machine_id, details.clone())
                .expect("synchronization should intercept the failure");
        snapshot.managed_state = failure_transition.clone();
        assert!(
            machine_failure_transition(&snapshot, failed_machine_id, details.clone()).is_none(),
            "the persisted cleanup state must be allowed to restore lockdown"
        );
        let ManagedHostState::BootConfigSynchronization {
            synchronization_state: BootConfigSynchronizationState::RestoreLockdown { completion },
            synchronization_retry_count: 2,
        } = failure_transition
        else {
            panic!("failure must restore lockdown before leaving synchronization");
        };
        assert_eq!(
            completion,
            BootConfigSynchronizationCompletion::MachineFailed {
                machine_id: failed_machine_id,
                details: details.clone(),
            }
        );
        assert_eq!(
            completion_state(
                BootConfigSynchronizationDriver::resume(
                    BootConfigSynchronizationOwner::Unassigned,
                    2,
                ),
                completion,
                snapshot.host_snapshot.id,
            ),
            ManagedHostState::Failed {
                details,
                machine_id: failed_machine_id,
                retry_count: 0,
            }
        );

        snapshot.managed_state = ManagedHostState::BootConfigSynchronization {
            synchronization_state: BootConfigSynchronizationState::ConfigureBios {
                target: target.clone(),
                retry_count: 0,
            },
            synchronization_retry_count: 2,
        };
        let missing_dpu_transition = missing_dpu_cleanup_transition(&snapshot)
            .expect("missing DPUs should also enter the cleanup barrier");
        assert!(matches!(
            missing_dpu_transition,
            ManagedHostState::BootConfigSynchronization {
                synchronization_state: BootConfigSynchronizationState::RestoreLockdown {
                    completion:
                        BootConfigSynchronizationCompletion::ResumeSynchronization {
                            target: Some(resume_target),
                        },
                },
                synchronization_retry_count: 2,
            } if resume_target == target
        ));
    }

    #[test]
    fn lockdown_restoration_does_not_require_a_selected_target() {
        let state = BootConfigSynchronizationState::RestoreLockdown {
            completion: BootConfigSynchronizationCompletion::TargetChanged,
        };

        assert!(!uses_current_target(&state));
    }

    #[test]
    fn promoted_interface_retargets_the_same_selection() {
        let selection_version = ConfigVersion::new(7);
        let expected = synchronization_target_for_test(None, mac_only(), selection_version);
        let mut promoted_interface = model::machine::MachineInterfaceSnapshot::mock_with_mac(
            boot_interface_mac(&expected.boot_interface),
        );
        promoted_interface.boot_interface_id = Some("NIC.Slot.7-1-1".to_string());
        promoted_interface.network_segment_type = Some(NetworkSegmentType::HostInband);
        let resolved = resolved_boot_interface_from_stores(&[promoted_interface], &[])
            .expect("the freshly loaded owned row should resolve");
        let current = synchronization_target(&resolved, selection_version);

        assert_eq!(
            target_mismatch_completion(&expected, Some(current.clone())),
            BootConfigSynchronizationCompletion::Retarget { target: current },
            "promoting a prediction and enriching its Redfish identity must preserve synchronization progress",
        );
    }

    #[test]
    fn logical_selection_requires_the_same_mac_and_generation() {
        let selection_version = ConfigVersion::new(7);
        let expected = synchronization_target_for_test(None, mac_only(), selection_version);
        let different_mac = synchronization_target_for_test(
            None,
            MachineBootInterfaceTarget::MacOnly(MacAddress::new([0x02, 0, 0, 0, 0, 2])),
            selection_version,
        );
        let newer_generation =
            synchronization_target_for_test(None, pair("NIC.Slot.7-1-1"), ConfigVersion::new(8));

        assert!(!same_selection(&expected, &different_mac));
        assert!(!same_selection(&expected, &newer_generation));
        assert_eq!(
            target_mismatch_completion(&expected, Some(different_mac)),
            BootConfigSynchronizationCompletion::TargetChanged,
        );
        assert_eq!(
            target_mismatch_completion(&expected, Some(newer_generation)),
            BootConfigSynchronizationCompletion::TargetChanged,
            "the generation must prevent an A-to-B-to-A selection from reusing old progress",
        );
    }
}
