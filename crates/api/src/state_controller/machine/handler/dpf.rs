/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::machine::MachineId;
use model::machine::{
    DpfState, DpuInitNextStateResolver, DpuInitState, Machine, ManagedHostState,
    ManagedHostStateSnapshot, PerformPowerOperation, ReprovisioingPhase, ReprovisionState,
    WaitForNetworkConfigAndRemoveAnnotationResult,
};
use sqlx::PgConnection;

use crate::state_controller::machine::context::MachineStateHandlerContextObjects;
use crate::state_controller::machine::handler::helpers::{ManagedHostStateHelper, NextState};
use crate::state_controller::machine::handler::{
    DpfConfig, DpuInitStateHelper, ReachabilityParams, all_equal,
    discovered_after_state_transition, handler_restart_dpu,
    managed_host_network_config_version_synced_and_dpu_healthy, trigger_reboot_if_needed,
};
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

fn bmc_ip(machine: &Machine) -> Result<&str, StateHandlerError> {
    machine.bmc_info.ip.as_deref().ok_or_else(|| {
        StateHandlerError::GenericError(eyre::eyre!("BMC IP is not set for machine {}", machine.id))
    })
}

/// Handles the transition between different DPF states for a DPU during the host's state machine process.
///
/// # Arguments
/// * `state` - The full host and DPU managed state snapshot.
/// * `dpu_snapshot` - The current DPU's state snapshot.
/// * `dpf_state` - The DPF state to process.
/// * `txn` - The database transaction.
/// * `ctx` - Context object giving access to services and other helpers.
/// * `dpf_config` - DPF controller configuration options.
/// * `reachability_params` - Parameters for network reachability.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>` with the outcome of the transition.
#[allow(txn_held_across_await)]
pub async fn handle_dpf_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_state: &DpfState,
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    dpf_config: &DpfConfig,
    reachability_params: &ReachabilityParams,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if !dpf_config.enabled {
        return Err(StateHandlerError::GenericError(eyre::eyre!(
            "DPF is not enabled at site. Force-delete host: {} to restart ingestion.",
            state.host_snapshot.id
        )));
    }

    match dpf_state {
        DpfState::CreateDpuDevice => {
            handle_create_dpu_device(state, dpu_snapshot, dpf_config).await
        }
        DpfState::DpuDeviceCreated => handle_dpu_device_created_state(state, dpu_snapshot),
        DpfState::CreateDpuNode => handle_create_dpu_node_state(state, dpf_config).await,
        DpfState::WaitForDpuDeviceToReady => {
            handle_wait_for_dpu_device_to_ready_state(state, dpu_snapshot, dpf_config).await
        }
        DpfState::DpuDeviceReady => handle_dpu_device_ready_state(state),
        DpfState::UpdateNodeEffectAnnotation => {
            handle_update_node_effect_annotation_state(
                state,
                dpu_snapshot,
                dpf_config,
                &DpuInitNextStateResolver {},
            )
            .await
        }
        DpfState::WaitingForOsInstallToComplete => {
            handle_wait_for_os_install_and_discovery(
                state,
                dpu_snapshot,
                false,
                txn,
                ctx,
                reachability_params,
                &DpuInitNextStateResolver {},
            )
            .await
        }
        DpfState::WaitForNetworkConfigAndRemoveAnnotation => {
            // This is a sync state
            handle_wait_for_discovery_and_remove_annotation_state(
                state,
                dpu_snapshot,
                txn,
                ctx,
                reachability_params,
                dpf_config,
            )
            .await
        }
        _ => Err(StateHandlerError::InvalidState(format!(
            "Unhandled {dpf_state:?} state for dpf state."
        ))),
    }
}

/// Handles the transition between different DPF states for a DPU with reprovision logic.
///
/// # Arguments
/// * `state` - The full host and DPU managed state snapshot.
/// * `dpu_snapshot` - The current DPU's state snapshot.
/// * `dpf_state` - The DPF state to process.
/// * `txn` - The database transaction.
/// * `ctx` - Context object giving access to services and other helpers.
/// * `dpf_config` - DPF controller configuration options.
/// * `reachability_params` - Parameters for network reachability.
/// * `state_resolver` - Object for resolving next state transitions.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>` with the outcome of the transition.
#[allow(txn_held_across_await)]
#[allow(clippy::too_many_arguments)]
pub async fn handle_dpf_state_with_reprovision(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_state: &DpfState,
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    dpf_config: &DpfConfig,
    reachability_params: &ReachabilityParams,
    state_resolver: &impl NextState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if !dpf_config.enabled {
        return Err(StateHandlerError::GenericError(eyre::eyre!(
            "DPF is not enabled at site. Force-delete host: {} to restart ingestion.",
            state.host_snapshot.id
        )));
    }

    match dpf_state {
        DpfState::TriggerReprovisioing { phase } => match phase {
            // There is a bug in DPF which does not handle multi-dpu correctly (https://redmine.mellanox.com/issues/4845800).
            // Due to this, if carbide deletes both DPUs together, the DPF will wait to remove "NodeEffectAnnotation" annotation.
            // If Carbide removes only one DPU, DPU moves to directly "Os Installing" phase.
            // To avoid this, we will make UpdateNodeEffectAnnotation to false regardless of whatever its state it and move with next state.
            // There is another problem where DPF stuck and does not move to next state if it is in some intermediate phase.
            // To avoid this, we will set the DPU status to Error. DPF always starts provisioing if state is either "Error" or "Ready".
            // (In case of milestone 1, Cluster Config)
            ReprovisioingPhase::UpdateDpuStatusToError => {
                handle_update_dpu_status_to_error_state(
                    state,
                    dpu_snapshot,
                    dpf_config,
                    state_resolver,
                )
                .await
            }
            ReprovisioingPhase::DeleteDpu => {
                handle_delete_dpu_state(state, dpu_snapshot, dpf_config, state_resolver).await
            }
            ReprovisioingPhase::WaitingForAllDpusUnderReprovisioingToBeDeleted => {
                handle_waiting_for_all_dpus_to_be_deleted_state(state, dpu_snapshot, state_resolver)
            }
        },
        DpfState::UpdateNodeEffectAnnotation => {
            handle_update_node_effect_annotation_state(
                state,
                dpu_snapshot,
                dpf_config,
                state_resolver,
            )
            .await
        }
        DpfState::WaitingForOsInstallToComplete => {
            handle_wait_for_os_install_and_discovery(
                state,
                dpu_snapshot,
                true,
                txn,
                ctx,
                reachability_params,
                state_resolver,
            )
            .await
        }
        DpfState::WaitForNetworkConfigAndRemoveAnnotation => {
            // This is a sync state
            handle_wait_for_discovery_and_remove_annotation_state_with_reprovision(
                state,
                dpu_snapshot,
                txn,
                ctx,
                reachability_params,
                dpf_config,
                state_resolver,
            )
            .await
        }
        _ => Err(StateHandlerError::InvalidState(format!(
            "Unhandled {dpf_state:?} state for dpf state with reprovision."
        ))),
    }
}

/// Handles the "Update DPU Status To Error" reprovisioning transition for DPF state.
///
/// # Arguments
/// * `state` - The full managed host state snapshot.
/// * `dpu_snapshot` - The current DPU's state snapshot.
/// * `dpf_config` - DPF controller configuration options.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>` with the transition outcome.
async fn handle_update_dpu_status_to_error_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_config: &DpfConfig,
    next_state_resolver: &impl NextState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    // If reprovisioning is not requested for this DPU, we will not update the DPU status to Error.
    if dpu_snapshot.reprovision_requested.is_none() {
        let next_state = DpuInitState::DpfStates {
            state: DpfState::TriggerReprovisioing {
                phase: ReprovisioingPhase::WaitingForAllDpusUnderReprovisioingToBeDeleted,
            },
        }
        .next_state(&state.managed_state, &dpu_snapshot.id)?;
        return Ok(StateHandlerOutcome::transition(next_state));
    }

    // Force the DPU status to Error so the DPF provisioning can restart.
    carbide_dpf::utils::force_dpu_status_failed(
        &dpu_snapshot.id,
        bmc_ip(&state.host_snapshot)?,
        &*dpf_config.kube_client_provider,
    )
    .await?;

    let next_state = next_state_resolver.next_dpf_state(
        &state.managed_state,
        &dpu_snapshot.id,
        DpfState::TriggerReprovisioing {
            phase: ReprovisioingPhase::DeleteDpu,
        },
    )?;
    Ok(StateHandlerOutcome::transition(next_state))
}

/// Handles the "Delete DPU" transition for DPF reprovisioning state.
///
/// # Arguments
/// * `state` - The full managed host state snapshot.
/// * `dpu_snapshot` - The current DPU's state snapshot.
/// * `dpf_config` - DPF controller configuration options.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>` with the transition outcome.
async fn handle_delete_dpu_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_config: &DpfConfig,
    next_state_resolver: &impl NextState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    carbide_dpf::utils::delete_dpu(
        &dpu_snapshot.id,
        bmc_ip(&state.host_snapshot)?,
        &*dpf_config.kube_client_provider,
    )
    .await?;

    let next_state = next_state_resolver.next_dpf_state(
        &state.managed_state,
        &dpu_snapshot.id,
        DpfState::TriggerReprovisioing {
            phase: ReprovisioingPhase::WaitingForAllDpusUnderReprovisioingToBeDeleted,
        },
    )?;
    Ok(StateHandlerOutcome::transition(next_state))
}

/// Handles waiting for all DPUs to be deleted under reprovisioning process.
///
/// # Arguments
/// * `state` - The full managed host state snapshot.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
fn handle_waiting_for_all_dpus_to_be_deleted_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    next_state_resolver: &impl NextState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let mut dpu_reprov_states = vec![];
    for dsnapshot in &state.dpu_snapshots {
        if dpu_snapshot.reprovision_requested.is_some() {
            dpu_reprov_states.push(
                state
                    .managed_state
                    .as_reprovision_state(&dsnapshot.id)
                    .ok_or_else(|| {
                        StateHandlerError::GenericError(eyre::eyre!(
                            "DPU {} is not under reprovisioning.",
                            dsnapshot.id
                        ))
                    })?,
            );
        }
    }

    if !all_equal(&dpu_reprov_states)? {
        return Ok(StateHandlerOutcome::wait(format!(
            "Waiting for all dpus to be deleted for host {}",
            state.host_snapshot.id
        )));
    }

    let reprov_state = state
        .managed_state
        .as_reprovision_state(&dpu_snapshot.id)
        .ok_or_else(|| {
            StateHandlerError::GenericError(eyre::eyre!(
                "DPU {} is not under reprovisioning.",
                dpu_snapshot.id
            ))
        })?;

    let next_state = next_state_resolver.next_state_with_all_dpus_updated(state, reprov_state)?;
    Ok(StateHandlerOutcome::transition(next_state))
}

/// Handles waiting for all DPUs to be rediscovered and removes the maintenance/restart annotation from the k8s DPU node.
/// If not yet rediscovered, this will instruct the caller to wait; otherwise removes the annotation and transitions to platform powercycle.
///
/// # Arguments
/// * `state` - Full host and DPU managed state snapshot.
/// * `dpu_snapshot` - The current DPU's state snapshot.
/// * `txn` - The database connection/transaction.
/// * `ctx` - Context object giving access to services and state control.
/// * `reachability_params` - Parameters for host/network reachability.
/// * `dpf_config` - DPF controller configuration options.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>` outcome for the handler.
#[allow(txn_held_across_await)]
async fn handle_wait_for_discovery_and_remove_annotation_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    dpf_config: &DpfConfig,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if let WaitForNetworkConfigAndRemoveAnnotationResult::NetworkConfigPending(dpu_id) =
        handle_wait_for_network_config_and_remove_annotation(
            state,
            dpu_snapshot,
            txn,
            ctx,
            reachability_params,
            dpf_config,
        )
        .await?
    {
        return Ok(StateHandlerOutcome::wait(format!(
            "Waiting for DPU {dpu_id} discovery."
        )));
    }
    // Regular flow of legacy state machine.
    let next_state = DpuInitState::WaitingForPlatformPowercycle {
        substate: PerformPowerOperation::Off,
    }
    .next_state_with_all_dpus_updated(&state.managed_state)?;
    Ok(StateHandlerOutcome::transition(next_state))
}

/// Handles waiting for discovery and removal of annotation, in the reprovisioning flow.
///
/// # Arguments
/// * `state` - The full managed host state snapshot.
/// * `dpu_snapshot` - The current DPU's state snapshot.
/// * `txn` - The database transaction.
/// * `ctx` - Service/container context.
/// * `reachability_params` - Parameters for network reachability checks.
/// * `dpf_config` - DPF controller configuration.
/// * `state_resolver` - State resolver for reprovisioning.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
#[allow(txn_held_across_await)]
async fn handle_wait_for_discovery_and_remove_annotation_state_with_reprovision(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    dpf_config: &DpfConfig,
    state_resolver: &impl NextState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if let WaitForNetworkConfigAndRemoveAnnotationResult::NetworkConfigPending(dpu_id) =
        handle_wait_for_network_config_and_remove_annotation(
            state,
            dpu_snapshot,
            txn,
            ctx,
            reachability_params,
            dpf_config,
        )
        .await?
    {
        return Ok(StateHandlerOutcome::wait(format!(
            "Waiting for DPU {dpu_id} discovery."
        )));
    }

    // Regular flow of legacy state machine.
    let next_state = state_resolver.next_state_with_all_dpus_updated(
        state,
        &ReprovisionState::DpfStates {
            substate: DpfState::WaitForNetworkConfigAndRemoveAnnotation,
        },
    )?;
    Ok(StateHandlerOutcome::transition(next_state))
}

/// Handles DPU discovery-wait and removal of restart annotation (internal utility).
///
/// # Arguments
/// * `state` - The full managed host state snapshot.
/// * `dpu_snapshot` - The current DPU's state snapshot.
/// * `txn` - The database transaction.
/// * `ctx` - Service/container context.
/// * `reachability_params` - Parameters for network reachability checks.
/// * `dpf_config` - DPF controller configuration.
/// * `reprovision_case` - Boolean for reprovisioning flow.
///
/// # Returns
/// * `Result<(), StateHandlerError>`
#[allow(txn_held_across_await)]
async fn handle_wait_for_network_config_and_remove_annotation(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    dpf_config: &DpfConfig,
) -> Result<WaitForNetworkConfigAndRemoveAnnotationResult, StateHandlerError> {
    for dsnapshot in &state.dpu_snapshots {
        // Even if a DPU is not under reprovisioing, we need to check if the network config is synced and the DPU is healthy.
        if !managed_host_network_config_version_synced_and_dpu_healthy(dsnapshot) {
            // Only reboot the DPU which is targeted in this event loop.
            if dsnapshot.id == dpu_snapshot.id {
                trigger_reboot_if_needed(
                    dsnapshot,
                    state,
                    None,
                    reachability_params,
                    ctx.services,
                    txn,
                )
                .await?;
            }

            return Ok(
                WaitForNetworkConfigAndRemoveAnnotationResult::NetworkConfigPending(dsnapshot.id),
            );
        }
    }

    carbide_dpf::utils::remove_restart_annotation_from_node(
        bmc_ip(&state.host_snapshot)?,
        &*dpf_config.kube_client_provider,
    )
    .await?;

    Ok(WaitForNetworkConfigAndRemoveAnnotationResult::ConfigSyncedAndAnnotationRemoved)
}

/// Handles the transition for a DPU after a reboot is triggered. Initiates the reboot and transitions to discovery/removal annotation state.
///
/// # Arguments
/// * `state` - The managed host state snapshot.
/// * `dpu_snapshot` - The DPU machine snapshot.
/// * `reprovision_case` - Whether reprovisioning flow is active.
/// * `txn` - Database transaction.
/// * `ctx` - Handler context/service container.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
#[allow(txn_held_across_await)]
async fn handle_wait_for_os_install_and_discovery(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    reprovision_case: bool,
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    reachability_params: &ReachabilityParams,
    next_state_resolver: &impl NextState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let next_state = next_state_resolver.next_dpf_state(
        &state.managed_state,
        &dpu_snapshot.id,
        DpfState::WaitForNetworkConfigAndRemoveAnnotation,
    )?;

    // In case of reprovisioning, we will not restart DPU if reprovisioing is not requested for this DPU.
    if reprovision_case && dpu_snapshot.reprovision_requested.is_none() {
        return Ok(StateHandlerOutcome::transition(next_state));
    }

    if !discovered_after_state_transition(
        dpu_snapshot.state.version,
        dpu_snapshot.last_discovery_time,
    ) {
        let _status = trigger_reboot_if_needed(
            dpu_snapshot,
            state,
            None,
            reachability_params,
            ctx.services,
            txn,
        )
        .await?;

        return Ok(StateHandlerOutcome::wait(format!(
            "Waiting for DPU {} to be discovered.",
            dpu_snapshot.id
        )));
    }

    handler_restart_dpu(dpu_snapshot, ctx.services, txn).await?;
    Ok(StateHandlerOutcome::transition(next_state))
}

/// Updates the Kubernetes node effect annotation and transitions state.
/// Used as part of DPF state transitions post DPU node creation.
///
/// # Arguments
/// * `state` - The managed host state snapshot.
/// * `dpu_snapshot` - The DPU machine snapshot.
/// * `dpf_config` - DPF controller configuration.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
async fn handle_update_node_effect_annotation_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_config: &DpfConfig,
    next_state_resolver: &impl NextState,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let res = carbide_dpf::utils::update_dpu_node_maintenance_annotation(
        bmc_ip(&state.host_snapshot)?,
        &*dpf_config.kube_client_provider,
    )
    .await;

    if let Err(e) = res {
        tracing::error!("Error updating node effect annotation: {e:?}");
        return Err(StateHandlerError::DpfError(e));
    }

    let next_state = next_state_resolver.next_dpf_state(
        &state.managed_state,
        &dpu_snapshot.id,
        DpfState::WaitingForOsInstallToComplete,
    )?;
    Ok(StateHandlerOutcome::transition(next_state))
}

/// Handles the creation of a DPU device by registering it and transitioning to the WaitForDpuDeviceToReady state.
///
/// # Arguments
/// * `state` - Host and DPU managed state snapshot.
/// * `dpu_snapshot` - DPU machine state snapshot.
/// * `dpf_config` - DPF controller configuration.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
async fn handle_create_dpu_device(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_config: &DpfConfig,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let serial_number = dpu_snapshot
        .hardware_info
        .as_ref()
        .and_then(|x| x.dmi_data.as_ref())
        .map(|x| x.product_serial.as_str())
        .unwrap_or_default();

    carbide_dpf::utils::create_dpu_device(
        &dpu_snapshot.id,
        bmc_ip(dpu_snapshot)?,
        bmc_ip(&state.host_snapshot)?,
        serial_number,
        &*dpf_config.kube_client_provider,
    )
    .await?;

    let next_state = DpuInitState::DpfStates {
        state: DpfState::DpuDeviceCreated,
    }
    .next_state(&state.managed_state, &dpu_snapshot.id)?;

    Ok(StateHandlerOutcome::transition(next_state))
}

/// Polls to check if the DPU device is ready and transitions to DpuDeviceCreated or waits if not ready.
///
/// # Arguments
/// * `state` - Host and DPU managed state snapshot.
/// * `dpu_snapshot` - DPU machine state snapshot.
/// * `dpf_config` - DPF controller configuration.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
async fn handle_wait_for_dpu_device_to_ready_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
    dpf_config: &DpfConfig,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let is_ready = carbide_dpf::utils::check_if_dpu_device_is_ready(
        &dpu_snapshot.id,
        &*dpf_config.kube_client_provider,
    )
    .await?;
    if is_ready {
        let next_state = DpuInitState::DpfStates {
            state: DpfState::DpuDeviceReady,
        }
        .next_state(&state.managed_state, &dpu_snapshot.id)?;
        Ok(StateHandlerOutcome::transition(next_state))
    } else {
        Ok(StateHandlerOutcome::wait(format!(
            "Waiting for DPU device {} to be ready",
            dpu_snapshot.id
        )))
    }
}

/// Handles the state where a DPU device is marked as ready.
/// If all DPUs are synchronized in readiness, transitions to the UpdateNodeEffectAnnotation state.
/// Otherwise, waits until all DPUs are ready for the host.
///
/// # Arguments
/// * `state` - The managed host and DPU state snapshot.
/// * `dpu_snapshot` - The current DPU machine state snapshot.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
pub fn handle_dpu_device_ready_state(
    state: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if state.managed_state.all_dpu_states_in_sync()? {
        let next_state = DpuInitState::DpfStates {
            state: DpfState::UpdateNodeEffectAnnotation,
        }
        .next_state_with_all_dpus_updated(&state.managed_state)?;
        Ok(StateHandlerOutcome::transition(next_state))
    } else {
        Ok(StateHandlerOutcome::wait(format!(
            "Waiting for all dpus to be ready for host {}",
            state.host_snapshot.id
        )))
    }
}

/// Marks the DPU device as created and, if all DPUs are in sync, transitions to node creation.
/// If not, waits for the rest of the DPUs to finish initialization.
///
/// # Arguments
/// * `state` - Host and DPU managed state snapshot.
/// * `dpu_snapshot` - The current DPU machine state snapshot.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
fn handle_dpu_device_created_state(
    state: &ManagedHostStateSnapshot,
    dpu_snapshot: &Machine,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if state.managed_state.all_dpu_states_in_sync()? {
        let next_state = DpuInitState::DpfStates {
            state: DpfState::CreateDpuNode,
        }
        .next_state(&state.managed_state, &dpu_snapshot.id)?;
        Ok(StateHandlerOutcome::transition(next_state))
    } else {
        Ok(StateHandlerOutcome::wait(format!(
            "Waiting for all dpus to be created and come in Ready state for host {}",
            state.host_snapshot.id
        )))
    }
}

/// Handles the creation of the DPU node (in Kubernetes) for all DPUs associated with this host.
/// Waits if DPU list is empty. Otherwise, transitions to effect annotation state.
///
/// # Arguments
/// * `state` - Host and DPU managed state snapshot.
/// * `dpf_config` - DPF controller configuration.
///
/// # Returns
/// * `Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError>`
async fn handle_create_dpu_node_state(
    state: &ManagedHostStateSnapshot,
    dpf_config: &DpfConfig,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let dpu_machine_ids = state
        .dpu_snapshots
        .iter()
        .map(|dpu| &dpu.id)
        .collect::<Vec<&MachineId>>();

    if dpu_machine_ids.is_empty() {
        return Ok(StateHandlerOutcome::wait(format!(
            "Waiting for dpus to be associated with host {}",
            state.host_snapshot.id
        )));
    }
    carbide_dpf::utils::create_dpu_node(
        bmc_ip(&state.host_snapshot)?,
        &dpu_machine_ids,
        &*dpf_config.kube_client_provider,
    )
    .await?;

    let next_state = DpuInitState::DpfStates {
        state: DpfState::WaitForDpuDeviceToReady,
    }
    .next_state_with_all_dpus_updated(&state.managed_state)?;
    Ok(StateHandlerOutcome::transition(next_state))
}
