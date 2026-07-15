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

//! The DPF operator manages all provisioning logic. Carbide's role is:
//! 1. Declare setup (register devices + node)
//! 2. Wait for watcher callbacks (DPU ready, reboot required)
//! 3. Handle cleanup on error/reprovisioning

use std::net::IpAddr;

use carbide_dpf::{DpfError, DpuPhase, dpu_node_cr_name};
use carbide_uuid::machine::MachineId;
use libredfish::SystemPowerControl;
use model::machine::{
    DpfState, DpuInitState, FailureCause, FailureDetails, FailureSource, InstanceState, Machine,
    ManagedHostState, ManagedHostStateSnapshot, ReprovisionState, StateMachineArea,
};
use state_controller::state_handler::{
    ExternalServiceError, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use super::helpers::{DpuInitStateHelper, ManagedHostStateHelper, ReprovisionStateHelper};
use super::{handler_host_power_control, host_power_state};
use crate::context::MachineStateHandlerContextObjects;
use crate::dpf::DpfOperations;

fn dpf_error(error: DpfError) -> StateHandlerError {
    ExternalServiceError::with_source("dpf", "", error.to_string(), "dpf_error", error).into()
}

fn bmc_ip(machine: &Machine) -> Result<IpAddr, StateHandlerError> {
    machine.bmc_info.ip.ok_or_else(|| {
        StateHandlerError::GenericError(eyre::eyre!("BMC IP is not set for machine {}", machine.id))
    })
}

// wrapper so we can get an error without copying it at every call site
fn dpf_id(machine: &Machine) -> Result<String, StateHandlerError> {
    machine.dpf_id().ok_or_else(|| {
        StateHandlerError::InvalidState(format!("BMC MAC is not set for machine {}", machine.id))
    })
}

/// Transition all DPU sub-states to the given DPF state, preserving the
/// outer managed-host state (`DPUInit` or `DPUReprovision`).
fn transition_all_dpus_to_dpf_state(
    next_dpf: DpfState,
    state: &ManagedHostStateSnapshot,
) -> Result<ManagedHostState, StateHandlerError> {
    match &state.managed_state {
        ManagedHostState::DPUInit { .. } | ManagedHostState::DpuDiscoveringState { .. } => {
            DpuInitState::DpfStates { state: next_dpf }
                .next_state_with_all_dpus_updated(&state.managed_state)
        }
        ManagedHostState::DPUReprovision { .. }
        | ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision { .. },
        } => {
            let all_dpu_ids = state.dpu_snapshots.iter().map(|x| &x.id).collect();
            ReprovisionState::DpfStates { substate: next_dpf }.next_state_with_all_dpus_updated(
                &state.managed_state,
                &state.dpu_snapshots,
                all_dpu_ids,
            )
        }
        other => Err(StateHandlerError::InvalidState(format!(
            "Cannot transition DPF sub-states in {other:?}"
        ))),
    }
}

/// Update a single DPU's DPF sub-state. All other DPUs are unchanged.
/// Use when persisting a phase change or moving one DPU to the next DpfState.
fn set_one_dpu_dpf_state(
    state: &ManagedHostStateSnapshot,
    dpu_id: &MachineId,
    next_dpf: DpfState,
) -> Result<ManagedHostState, StateHandlerError> {
    let mut next_state = state.managed_state.clone();
    match &mut next_state {
        ManagedHostState::DPUInit { dpu_states } => {
            dpu_states
                .states
                .insert(*dpu_id, DpuInitState::DpfStates { state: next_dpf });
        }
        ManagedHostState::DPUReprovision { dpu_states } => {
            dpu_states
                .states
                .insert(*dpu_id, ReprovisionState::DpfStates { substate: next_dpf });
        }
        ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision { dpu_states },
        } => {
            dpu_states
                .states
                .insert(*dpu_id, ReprovisionState::DpfStates { substate: next_dpf });
        }
        other => {
            return Err(StateHandlerError::InvalidState(format!(
                "Cannot set DPF state for one DPU in {other:?}"
            )));
        }
    }
    Ok(next_state)
}

/// If the DPU phase reported by the DPF operator changed since last
/// persisted, return a `Transition` that writes the new phase string.
/// Otherwise return a `Wait` with the given reason.
fn update_phase_detail_or_wait(
    state: &ManagedHostStateSnapshot,
    dpu_id: &MachineId,
    stored_phase_detail: &Option<String>,
    current_phase: &carbide_dpf::DpuPhase,
    wait_reason: &str,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    // if we're no longer in provisioning, there's no need to update the phase detail.
    // the phase detail will be dropped when we move from WaitingForReady to another state.
    if let DpuPhase::Provisioning(phase_detail) = current_phase
        && stored_phase_detail.as_ref() != Some(phase_detail)
    {
        let updated = set_one_dpu_dpf_state(
            state,
            dpu_id,
            DpfState::WaitingForReady {
                phase_detail: Some(phase_detail.clone()),
            },
        )?;
        return Ok(StateHandlerOutcome::transition(updated));
    }
    Ok(StateHandlerOutcome::wait(wait_reason.to_string()))
}

/// Determine the correct next state when exiting `DeviceReady`, based on
/// whether we are in initial provisioning (`DPUInit` -> `WaitingForPlatformConfiguration`)
/// or reprovisioning (`DPUReprovision`).
fn waiting_for_ready_exit_state(
    state: &ManagedHostStateSnapshot,
) -> Result<ManagedHostState, StateHandlerError> {
    match &state.managed_state {
        ManagedHostState::DPUInit { .. } | ManagedHostState::DpuDiscoveringState { .. } => {
            DpuInitState::WaitingForPlatformConfiguration
                .next_state_with_all_dpus_updated(&state.managed_state)
        }
        ManagedHostState::DPUReprovision { .. }
        | ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision { .. },
        } => {
            let all_dpu_ids = state.dpu_snapshots.iter().map(|x| &x.id).collect();
            ReprovisionState::WaitingForNetworkConfig.next_state_with_all_dpus_updated(
                &state.managed_state,
                &state.dpu_snapshots,
                all_dpu_ids,
            )
        }
        other => Err(StateHandlerError::InvalidState(format!(
            "Cannot exit DPF WaitingForReady in {other:?}"
        ))),
    }
}

async fn create_and_register_dpudevices_and_dpunode(
    state: &ManagedHostStateSnapshot,
    dpf_sdk: &dyn DpfOperations,
) -> Result<(), StateHandlerError> {
    let primary_dpu_id = state
        .host_snapshot
        .interfaces
        .iter()
        .find(|iface| iface.primary_interface)
        .and_then(|iface| iface.attached_dpu_machine_id)
        .ok_or_else(|| StateHandlerError::MissingData {
            object_id: state.host_snapshot.id.to_string(),
            missing: "primary_dpu",
        })?;

    for dpu in &state.dpu_snapshots {
        let serial_number = dpu
            .hardware_info
            .as_ref()
            .and_then(|x| x.dmi_data.as_ref())
            .map(|x| x.product_serial.as_str())
            .unwrap_or_default();
        let device_info = carbide_dpf::DpuDeviceInfo {
            device_id: dpf_id(dpu)?,
            dpu_bmc_ip: bmc_ip(dpu)?,
            host_bmc_ip: bmc_ip(&state.host_snapshot)?,
            serial_number: serial_number.to_string(),
            dpu_machine_id: dpu.id.to_string(),
            is_primary: dpu.id == primary_dpu_id,
        };
        dpf_sdk
            .register_dpu_device(device_info)
            .await
            .map_err(dpf_error)?;
    }

    let primary_dpu = state
        .dpu_snapshots
        .iter()
        .find(|dpu| dpu.id == primary_dpu_id)
        .ok_or_else(|| StateHandlerError::MissingData {
            object_id: state.host_snapshot.id.to_string(),
            missing: "primary_dpu_snapshot",
        })?;
    let deployment_type = dpf_sdk
        .deployment_type_for_dpu(primary_dpu)
        .map_err(dpf_error)?;

    let device_ids: Vec<String> = state
        .dpu_snapshots
        .iter()
        .map(dpf_id)
        .collect::<Result<_, _>>()?;
    let node_info = carbide_dpf::DpuNodeInfo {
        node_id: dpf_id(&state.host_snapshot)?,
        host_bmc_ip: bmc_ip(&state.host_snapshot)?,
        device_ids,
        deployment_type,
    };
    dpf_sdk
        .register_dpu_node(node_info)
        .await
        .map_err(dpf_error)?;

    Ok(())
}

/// Build the correct failure state depending on whether the host is currently
/// `Assigned` (DPU reprovision path). When `Assigned`, we preserve the outer
/// state and embed the failure as `InstanceState::Failed`; otherwise we use
/// the top-level `ManagedHostState::Failed`.
fn make_failure_state(
    state: &ManagedHostStateSnapshot,
    details: FailureDetails,
    machine_id: MachineId,
) -> ManagedHostState {
    if matches!(state.managed_state, ManagedHostState::Assigned { .. }) {
        ManagedHostState::Assigned {
            instance_state: InstanceState::Failed {
                details,
                machine_id,
            },
        }
    } else {
        ManagedHostState::Failed {
            details,
            machine_id,
            retry_count: 0,
        }
    }
}

fn dpf_cr_creation_failed(
    state: &ManagedHostStateSnapshot,
    err: &StateHandlerError,
) -> StateHandlerOutcome<ManagedHostState> {
    let details = FailureDetails {
        cause: FailureCause::DpfProvisioning {
            err: format!(
                "DPUDevice/DPUNode creation failed. Force-delete/restart reprovisioning (reprovisioning case) to clean old values. Wait until DPU CR are deleted. {err}"
            ),
        },
        failed_at: chrono::Utc::now(),
        source: FailureSource::StateMachineArea(StateMachineArea::MainFlow),
    };
    StateHandlerOutcome::transition(make_failure_state(state, details, state.host_snapshot.id))
}

/// Handle DpfState::Provisioning: register all DPU devices and the node, then
/// transition all DPUs to WaitingForReady.
async fn handle_dpf_provisioning(
    state: &ManagedHostStateSnapshot,
    dpf_sdk: &dyn DpfOperations,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if let Err(err) = create_and_register_dpudevices_and_dpunode(state, dpf_sdk).await {
        return Ok(dpf_cr_creation_failed(state, &err));
    }

    let next =
        transition_all_dpus_to_dpf_state(DpfState::WaitingForReady { phase_detail: None }, state)?;
    Ok(StateHandlerOutcome::transition(next))
}

/// Power-cycle the host for a DPF reboot request. ForceOff then On across
/// iterations; calls `reboot_complete` as soon as the On command is issued.
async fn handle_dpf_reboot(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    waiting_phase_detail: &Option<String>,
    current_phase: &DpuPhase,
    node_name: &str,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    dpf_sdk: &dyn DpfOperations,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let reboot_already_requested = state
        .host_snapshot
        .last_reboot_requested
        .as_ref()
        .is_some_and(|r| r.time > state.host_snapshot.state.version.timestamp());

    let power_state = {
        let redfish_client = ctx
            .services
            .create_redfish_client_from_machine(&state.host_snapshot)
            .await?;
        host_power_state(redfish_client.as_ref()).await?
    };

    if !reboot_already_requested && power_state != libredfish::PowerState::Off {
        handler_host_power_control(state, ctx, SystemPowerControl::ForceOff).await?;
    } else if power_state == libredfish::PowerState::Off {
        handler_host_power_control(state, ctx, SystemPowerControl::On).await?;
        dpf_sdk
            .reboot_complete(node_name)
            .await
            .map_err(dpf_error)?;
    }

    update_phase_detail_or_wait(
        state,
        &dpu_snapshot.id,
        waiting_phase_detail,
        current_phase,
        "Power cycling host for DPF reboot",
    )
}

/// Handle DpfState::WaitingForReady: release hold, reboot handling,
/// phase/error checks, and per-DPU transition to DeviceReady.
async fn handle_dpf_waiting_for_ready(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    waiting_phase_detail: &Option<String>,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    dpf_sdk: &dyn DpfOperations,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let node_name = dpu_node_cr_name(&dpf_id(&state.host_snapshot)?);
    let dpu_device_name = dpf_id(dpu_snapshot)?;
    let current_phase = dpf_sdk
        .get_dpu_phase(&dpu_device_name, &node_name)
        .await
        .map_err(dpf_error)?;

    dpf_sdk
        .release_maintenance_hold(&node_name)
        .await
        .map_err(dpf_error)?;

    if dpf_sdk
        .is_reboot_required(&node_name)
        .await
        .map_err(dpf_error)?
    {
        return handle_dpf_reboot(
            state,
            dpu_snapshot,
            waiting_phase_detail,
            &current_phase,
            &node_name,
            ctx,
            dpf_sdk,
        )
        .await;
    }

    if current_phase == carbide_dpf::DpuPhase::Error {
        tracing::error!(
            machine_id = %state.host_snapshot.id,
            dpu_machine_id = %dpu_snapshot.id,
            "DPU entered error phase during DPF provisioning"
        );
        let details = FailureDetails {
            cause: FailureCause::DpfProvisioning {
                err: format!(
                    "DPU {} entered error phase during DPF provisioning",
                    dpu_snapshot.id
                ),
            },
            failed_at: chrono::Utc::now(),
            source: FailureSource::StateMachineArea(StateMachineArea::MainFlow),
        };
        return Ok(StateHandlerOutcome::transition(make_failure_state(
            state,
            details,
            dpu_snapshot.id,
        )));
    }
    // wait for dpf to report that the dpu is ready
    if current_phase != carbide_dpf::DpuPhase::Ready {
        return update_phase_detail_or_wait(
            state,
            &dpu_snapshot.id,
            waiting_phase_detail,
            &current_phase,
            "Waiting for DPU to reach Ready phase",
        );
    }

    let next = set_one_dpu_dpf_state(state, &dpu_snapshot.id, DpfState::DeviceReady)?;
    Ok(StateHandlerOutcome::transition(next))
}

/// Handle DpfState::DeviceReady: wait for all DPUs to sync, then
/// transition to the next state.
fn handle_dpf_device_ready(
    state: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if !state.managed_state.all_dpu_states_in_sync()? {
        return Ok(StateHandlerOutcome::wait(
            "Waiting for all DPUs to reach DeviceReady".to_string(),
        ));
    }

    let next = waiting_for_ready_exit_state(state)?;
    Ok(StateHandlerOutcome::transition(next))
}

/// Handle DpfState::Reprovisioning
/// If the DPUNode and DPUDevice CRs do not exist, then create them
/// and transition to the next state to reprovision all DPUs to DPF.
/// Else handle the reprovisioning of a single DPU
async fn handle_dpf_reprovisioning(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    dpf_sdk: &dyn DpfOperations,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let node_name = dpu_node_cr_name(&dpf_id(&state.host_snapshot)?);
    let dpf_dpudevices_and_dpunode_crs_noexist =
        crate::dpf::dpf_dpudevices_and_dpunode_crs_noexist(state, dpf_sdk)
            .await
            .map_err(dpf_error)?;
    if dpf_dpudevices_and_dpunode_crs_noexist {
        tracing::info!(
            machine_id = %state.host_snapshot.id,
            "DPUDevice/DPUNode CRs do not exist, creating them before reprovisioning"
        );
        if let Err(err) = create_and_register_dpudevices_and_dpunode(state, dpf_sdk).await {
            return Ok(dpf_cr_creation_failed(state, &err));
        }
        let next = transition_all_dpus_to_dpf_state(
            DpfState::WaitingForReady { phase_detail: None },
            state,
        )?;

        let outcome = StateHandlerOutcome::transition(next);
        let mut txn = ctx.services.db_pool.begin().await?;
        db::machine::mark_machine_ingestion_done_with_dpf(&mut txn, &state.host_snapshot.id)
            .await?;
        return Ok(outcome.with_txn(txn));
    }

    tracing::info!(machine_id = %dpu_snapshot.id, "DPF initiate reprovision of DPU");
    dpf_sdk
        .reprovision_dpu(&dpf_id(dpu_snapshot)?, &node_name)
        .await
        .map_err(dpf_error)?;
    let next = set_one_dpu_dpf_state(
        state,
        &dpu_snapshot.id,
        DpfState::WaitingForReady { phase_detail: None },
    )?;
    Ok(StateHandlerOutcome::transition(next))
}

/// Handle DPF state transitions.
///
/// Provisioning registers all DPUs at once and moves them to WaitingForReady
/// together. All other states (Reprovisioning, WaitingForReady, DeviceReady)
/// advance the given `dpu_snapshot` independently. DeviceReady acts as a sync
/// barrier that waits for all DPUs before proceeding.
pub async fn handle_dpf_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_state: &DpfState,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    dpf_sdk: &dyn DpfOperations,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let node_name = dpu_node_cr_name(&dpf_id(&state.host_snapshot)?);
    let deployment_type = dpf_sdk
        .deployment_type_for_dpu(dpu_snapshot)
        .map_err(dpf_error)?;
    if !dpf_sdk
        .verify_node_labels(&node_name, deployment_type)
        .await
        .map_err(dpf_error)?
    {
        tracing::error!(
            machine_id = %state.host_snapshot.id,
            node = %node_name,
            "DPUNode has stale labels, failing for reprovisioning"
        );
        let details = FailureDetails {
            cause: FailureCause::DpfProvisioning {
                err: format!(
                    "DPUNode {node_name} has stale labels; \
                     must be deleted and reprovisioned"
                ),
            },
            failed_at: chrono::Utc::now(),
            source: FailureSource::StateMachineArea(StateMachineArea::MainFlow),
        };
        return Ok(StateHandlerOutcome::transition(make_failure_state(
            state,
            details,
            state.host_snapshot.id,
        )));
    }

    match dpf_state {
        DpfState::Provisioning => handle_dpf_provisioning(state, dpf_sdk).await,
        DpfState::WaitingForReady { phase_detail } => {
            handle_dpf_waiting_for_ready(state, dpu_snapshot, phase_detail, ctx, dpf_sdk).await
        }
        DpfState::DeviceReady => handle_dpf_device_ready(state),
        DpfState::Reprovisioning => {
            handle_dpf_reprovisioning(state, dpu_snapshot, ctx, dpf_sdk).await
        }
        DpfState::Unknown => {
            tracing::warn!(dpu_machine_id = %dpu_snapshot.id, "unknown DPF state in DB, transitioning to provisioning");
            let next = set_one_dpu_dpf_state(state, &dpu_snapshot.id, DpfState::Provisioning)?;
            Ok(StateHandlerOutcome::transition(next))
        }
    }
}
