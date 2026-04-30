/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! The DPF operator manages all provisioning logic. Carbide's role is:
//! 1. Declare setup (register devices + node)
//! 2. Wait for watcher callbacks (DPU ready, reboot required)
//! 3. Handle cleanup on error/reprovisioning

use carbide_dpf::{DpuPhase, dpu_node_cr_name};
use carbide_uuid::machine::MachineId;
use libredfish::SystemPowerControl;
use model::machine::{
    DpfState, DpuInitState, FailureCause, FailureDetails, FailureSource, InstanceState, Machine,
    ManagedHostState, ManagedHostStateSnapshot, ReprovisionState, StateMachineArea,
};

use super::helpers::{DpuInitStateHelper, ManagedHostStateHelper, ReprovisionStateHelper};
use super::{handler_host_power_control, host_power_state};
use crate::dpf::DpfOperations;
use crate::state_controller::machine::context::MachineStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

// wrapper so we can get an error without copying it at every call site
fn bmc_ip(machine: &Machine) -> Result<&str, StateHandlerError> {
    machine.bmc_info.ip.as_deref().ok_or_else(|| {
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

/// Handle DpfState::Provisioning: register all DPU devices and the node, then
/// transition all DPUs to WaitingForReady.
async fn handle_dpf_provisioning(
    state: &ManagedHostStateSnapshot,
    dpf_sdk: &dyn DpfOperations,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    for dpu in &state.dpu_snapshots {
        let serial_number = dpu
            .hardware_info
            .as_ref()
            .and_then(|x| x.dmi_data.as_ref())
            .map(|x| x.product_serial.as_str())
            .unwrap_or_default();
        let device_info = carbide_dpf::DpuDeviceInfo {
            device_id: dpf_id(dpu)?,
            dpu_bmc_ip: bmc_ip(dpu)?.to_string(),
            host_bmc_ip: bmc_ip(&state.host_snapshot)?.to_string(),
            serial_number: serial_number.to_string(),
            host_machine_id: state.host_snapshot.id.to_string(),
            dpu_machine_id: dpu.id.to_string(),
        };
        dpf_sdk.register_dpu_device(device_info).await?;
    }

    let device_ids: Vec<String> = state
        .dpu_snapshots
        .iter()
        .map(dpf_id)
        .collect::<Result<_, _>>()?;
    let node_info = carbide_dpf::DpuNodeInfo {
        node_id: dpf_id(&state.host_snapshot)?,
        host_bmc_ip: bmc_ip(&state.host_snapshot)?.to_string(),
        device_ids,
        host_machine_id: state.host_snapshot.id.to_string(),
    };
    dpf_sdk.register_dpu_node(node_info).await?;

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
    // Custom BFB: wait for all DPU agents to complete discovery before rebooting
    // the host. This indicates cloud-init has completed on every DPU.
    // Remove when switching to a vanilla BFB.

    // BUG ALERT: This is a bug. This might work fine for M1 for initial ingestion, but will fail for reprovisioning.
    // Quickest fix might be clearing discovery_time on reprovisioning.
    if !ctx.services.site_config.dpf.v2
        && let Some(pending) = state
            .dpu_snapshots
            .iter()
            .find(|d| d.last_discovery_time.is_none())
    {
        return update_phase_detail_or_wait(
            state,
            &dpu_snapshot.id,
            waiting_phase_detail,
            current_phase,
            &format!(
                "Waiting for DPU {} scout discovery to complete before reboot",
                pending.id
            ),
        );
    }

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
        dpf_sdk.reboot_complete(node_name).await?;
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
    let current_phase = dpf_sdk.get_dpu_phase(&dpu_device_name, &node_name).await?;

    dpf_sdk.release_maintenance_hold(&node_name).await?;

    if dpf_sdk.is_reboot_required(&node_name).await? {
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
            host = %state.host_snapshot.id,
            dpu = %dpu_snapshot.id,
            "DPU entered error phase during DPF provisioning"
        );
        return Ok(StateHandlerOutcome::transition(ManagedHostState::Failed {
            details: FailureDetails {
                cause: FailureCause::DpfProvisioning {
                    err: format!(
                        "DPU {} entered error phase during DPF provisioning",
                        dpu_snapshot.id
                    ),
                },
                failed_at: chrono::Utc::now(),
                source: FailureSource::StateMachineArea(StateMachineArea::MainFlow),
            },
            machine_id: dpu_snapshot.id,
            retry_count: 0,
        }));
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
    // also wait for dpu scout discovery to complete
    if !ctx.services.site_config.dpf.v2 && dpu_snapshot.last_discovery_time.is_none() {
        return update_phase_detail_or_wait(
            state,
            &dpu_snapshot.id,
            waiting_phase_detail,
            &current_phase,
            "Waiting for DPU scout discovery to complete",
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

/// Handle DpfState::Reprovisioning for a single DPU: call reprovision_dpu,
/// then transition that DPU to WaitingForReady.
async fn handle_dpf_reprovisioning(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_sdk: &dyn DpfOperations,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let node_name = dpu_node_cr_name(&dpf_id(&state.host_snapshot)?);
    dpf_sdk
        .reprovision_dpu(&dpf_id(dpu_snapshot)?, &node_name)
        .await?;
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
    if !dpf_sdk.verify_node_labels(&node_name).await? {
        tracing::error!(
            host = %state.host_snapshot.id,
            node = %node_name,
            "DPUNode has stale labels, failing for reprovisioning"
        );
        return Ok(StateHandlerOutcome::transition(ManagedHostState::Failed {
            details: FailureDetails {
                cause: FailureCause::DpfProvisioning {
                    err: format!(
                        "DPUNode {node_name} has stale labels; \
                         must be deleted and reprovisioned"
                    ),
                },
                failed_at: chrono::Utc::now(),
                source: FailureSource::StateMachineArea(StateMachineArea::MainFlow),
            },
            machine_id: state.host_snapshot.id,
            retry_count: 0,
        }));
    }

    match dpf_state {
        DpfState::Provisioning => handle_dpf_provisioning(state, dpf_sdk).await,
        DpfState::WaitingForReady { phase_detail } => {
            handle_dpf_waiting_for_ready(state, dpu_snapshot, phase_detail, ctx, dpf_sdk).await
        }
        DpfState::DeviceReady => handle_dpf_device_ready(state),
        DpfState::Reprovisioning => handle_dpf_reprovisioning(state, dpu_snapshot, dpf_sdk).await,
        DpfState::Unknown => {
            tracing::warn!(dpu_id = %dpu_snapshot.id, "unknown DPF state in DB, transitioning to provisioning");
            let next = set_one_dpu_dpf_state(state, &dpu_snapshot.id, DpfState::Provisioning)?;
            Ok(StateHandlerOutcome::transition(next))
        }
    }
}
