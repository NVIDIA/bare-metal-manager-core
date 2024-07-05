/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! State Handler implementation for Machines

use std::{collections::HashMap, task::Poll};

use chrono::{DateTime, Duration, Utc};
use config_version::ConfigVersion;
use eyre::eyre;
use futures::TryFutureExt;
use libredfish::{
    model::task::{Task, TaskState},
    Boot, PowerState, Redfish, SystemPowerControl,
};
use tokio::fs::File;

use forge_secrets::credentials::{BmcCredentialType, CredentialKey};

use crate::{
    cfg::{DpuComponent, DpuComponentUpdate, DpuDesc, DpuModel},
    db::{
        ib_partition,
        instance::{DeleteInstance, Instance, InstanceId},
        machine::Machine,
        machine_interface::MachineInterface,
        machine_topology::MachineTopology,
    },
    ib::{self, types::IBNetwork, DEFAULT_IB_FABRIC_NAME},
    measured_boot::{
        dto::records::{MeasurementBundleState, MeasurementMachineState},
        model::machine::{get_measurement_bundle_state, get_measurement_machine_state},
    },
    model::{
        instance::{
            config::infiniband::InstanceIbInterfaceConfig,
            snapshot::InstanceSnapshot,
            status::infiniband::{
                InstanceIbInterfaceStatusObservation, InstanceInfinibandStatusObservation,
            },
        },
        machine::{
            get_display_ids,
            machine_id::MachineId,
            network::HealthStatus,
            BmcFirmwareUpdateSubstate, CleanupState, DpuDiscoveringState, FailureCause,
            FailureDetails, FailureSource, InstanceNextStateResolver, InstanceState, LockdownInfo,
            LockdownMode::{self, Enable},
            LockdownState, MachineLastRebootRequestedMode, MachineNextStateResolver,
            MachineSnapshot, MachineState, ManagedHostState, ManagedHostStateSnapshot,
            MeasuringState, NextReprovisionState, ReprovisionRequest, ReprovisionState, RetryInfo,
            UefiSetupInfo, UefiSetupState,
        },
    },
    redfish::{
        build_redfish_client_from_machine_snapshot, host_power_control, poll_redfish_job,
        RedfishClientCreationError,
    },
    state_controller::{
        machine::context::MachineStateHandlerContextObjects,
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
            StateHandlerOutcome, StateHandlerServices,
        },
    },
};

/// Reachability params to check if DPU is up or not.
#[derive(Copy, Clone, Debug)]
pub struct ReachabilityParams {
    pub dpu_wait_time: chrono::Duration,
    pub power_down_wait: chrono::Duration,
    pub failure_retry_time: chrono::Duration,
}

/// Parameters used by the HostStateMachineHandler.
#[derive(Copy, Clone, Debug)]
pub struct HostHandlerParams {
    pub attestation_enabled: bool,
    pub reachability_params: ReachabilityParams,
}

/// The actual Machine State handler
#[derive(Debug, Clone)]
pub struct MachineStateHandler {
    host_handler: HostMachineStateHandler,
    pub dpu_handler: DpuMachineStateHandler,
    instance_handler: InstanceStateHandler,
    dpu_up_threshold: chrono::Duration,
    /// Reachability params to check if DPU is up or not
    reachability_params: ReachabilityParams,
}

impl MachineStateHandler {
    pub fn new(
        dpu_up_threshold: chrono::Duration,
        dpu_nic_firmware_initial_update_enabled: bool,
        dpu_nic_firmware_reprovision_update_enabled: bool,
        dpu_models: HashMap<DpuModel, DpuDesc>,
        reachability_params: ReachabilityParams,
        attestation_enabled: bool,
    ) -> Self {
        MachineStateHandler {
            dpu_up_threshold,
            host_handler: HostMachineStateHandler::new(HostHandlerParams {
                attestation_enabled,
                reachability_params,
            }),
            dpu_handler: DpuMachineStateHandler::new(
                dpu_nic_firmware_initial_update_enabled,
                dpu_models,
                reachability_params,
            ),
            instance_handler: InstanceStateHandler::new(
                dpu_nic_firmware_reprovision_update_enabled,
                reachability_params,
            ),
            reachability_params,
        }
    }

    fn record_metrics(
        &self,
        state: &mut ManagedHostStateSnapshot,
        ctx: &mut StateHandlerContext<MachineStateHandlerContextObjects>,
    ) {
        ctx.metrics.dpu_firmware_version = state.dpu_snapshots[0]
            .hardware_info
            .as_ref()
            .and_then(|hi| hi.dpu_info.as_ref().map(|di| di.firmware_version.clone()));
        ctx.metrics.machine_inventory_component_versions.extend(
            state.dpu_snapshots[0]
                .inventory
                .clone()
                .components
                .into_iter()
                .map(|mut component| {
                    // Remove the URL field for metrics purposes. We don't want to report different metrics
                    // just because the URL field in components differ. Only name and version are important
                    component.url = String::new();
                    component
                }),
        );

        // Update DPU network health Prometheus metrics
        ctx.metrics.dpu_healthy = state.dpu_snapshots[0].has_healthy_network();
        if let Some(observation) = state.dpu_snapshots[0].network_status_observation.as_ref() {
            ctx.metrics.agent_version = observation.agent_version.clone();
            ctx.metrics.dpu_up =
                Utc::now().signed_duration_since(observation.observed_at) <= self.dpu_up_threshold;
            for failed in &observation.health_status.failed {
                ctx.metrics.failed_dpu_healthchecks.insert(failed.clone());
            }

            ctx.metrics.machine_id = Some(observation.machine_id.clone());
            ctx.metrics.client_certificate_expiry = observation.client_certificate_expiry;
        }
    }

    async fn attempt_state_transition(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<'_, ManagedHostState>,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let managed_state = &state.managed_state;

        // If it's been more than 5 minutes since DPU reported status, consider it unhealthy
        for dpu_snapshot in &state.dpu_snapshots {
            if dpu_snapshot.has_healthy_network() {
                if let Some(mut observation) =
                    dpu_snapshot.network_status_observation.clone().take()
                {
                    let observed_at = observation.observed_at;
                    let since_last_seen = Utc::now().signed_duration_since(observed_at);
                    if since_last_seen > self.dpu_up_threshold {
                        let message = format!("Last seen over {} ago", self.dpu_up_threshold);
                        observation.health_status = HealthStatus {
                            is_healthy: false,
                            passed: vec![],
                            failed: vec!["HeartbeatTimeout".to_string()],
                            message: Some(message.clone()),
                        };
                        observation.observed_at = Utc::now();
                        let dpu_machine_id = &dpu_snapshot.machine_id;
                        Machine::update_network_status_observation(
                            txn,
                            dpu_machine_id,
                            &observation,
                        )
                        .await?;

                        let health_report = health_report::HealthReport {
                            source: "forge-dpu-agent".to_string(),
                            observed_at: Some(chrono::Utc::now()),
                            successes: vec![],
                            alerts: vec![health_report::HealthProbeAlert {
                                id: "HeartbeatTimeout".parse().expect("Probe ID is valid"),
                                in_alert_since: Some(chrono::Utc::now()),
                                message,
                                tenant_message: None,
                                classifications: vec![health_report::HealthAlertClassification::prevent_host_state_changes()],
                            }],
                        };
                        Machine::update_dpu_agent_health_report(
                            txn,
                            dpu_machine_id,
                            &health_report,
                        )
                        .await?;

                        tracing::warn!(
                        host_machine_id = %host_machine_id,
                        dpu_machine_id = %dpu_machine_id,
                        last_seen = %observed_at,
                        "DPU is not sending network status observations, marking unhealthy");
                        // The next iteration will run with the now unhealthy network
                        return Ok(StateHandlerOutcome::DoNothing);
                    }
                }
            }
        }

        // TODO: multidpu: Check for all DPUs
        if let Some(reprov_request) = &state.dpu_snapshots[0].reprovision_requested {
            // Reprovision is started and user requested for restart of reprovision.
            if reprov_request.started_at.is_some()
                && dpu_reprovision_restart_requested_after_state_transition(
                    state.host_snapshot.current.version,
                    reprov_request.restart_reprovision_requested_at,
                )
            {
                if let Some(next_state) = self
                    .restart_dpu_reprovision(
                        managed_state,
                        state,
                        ctx,
                        txn,
                        host_machine_id,
                        reprov_request,
                    )
                    .await?
                {
                    return Ok(StateHandlerOutcome::Transition(next_state));
                }
            }
        }

        // Don't update failed state failure cause everytime. Record first failure cause only,
        // otherwise first failure cause will be overwritten.
        if !matches!(managed_state, ManagedHostState::Failed { .. }) {
            if let Some((machine_id, details)) = get_failed_state(state) {
                tracing::error!(
                    %machine_id,
                    "ManagedHost {}/{} (failed machine: {}) is moved to Failed state with cause: {:?}",
                    state.host_snapshot.machine_id,
                    get_display_ids(&state.dpu_snapshots),
                    machine_id,
                    details
                );
                let next_state = ManagedHostState::Failed {
                    details,
                    machine_id,
                    retry_count: 0,
                };
                return Ok(StateHandlerOutcome::Transition(next_state));
            }
        }

        match &managed_state {
            ManagedHostState::DpuDiscoveringState { .. } => {
                self.dpu_handler
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await
            }
            ManagedHostState::DPUNotReady { .. } => {
                self.dpu_handler
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await
            }

            ManagedHostState::HostNotReady { .. } => {
                self.host_handler
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await
            }

            ManagedHostState::Ready => {
                // Check if DPU reprovisioning is requested
                // TODO: multidpu: Check for all DPUs
                if let Some(reprovisioning_requested) =
                    dpu_reprovisioning_needed(&state.dpu_snapshots[0])
                {
                    handler_restart_dpu(&state.dpu_snapshots[0], ctx.services, txn).await?;
                    Machine::update_dpu_reprovision_start_time(
                        &state.dpu_snapshots[0].machine_id,
                        txn,
                    )
                    .await?;
                    let next_state = ManagedHostState::DPUReprovision {
                        reprovision_state: if reprovisioning_requested.update_firmware {
                            ReprovisionState::FirmwareUpgrade
                        } else {
                            set_managed_host_topology_update_needed(txn, state).await?;
                            ReprovisionState::WaitingForNetworkInstall
                        },
                    };
                    return Ok(StateHandlerOutcome::Transition(next_state));
                }

                // Check to see if measurement bundle states changed while
                // the host has been sitting in Ready state -- it may need
                // to be transitioned away from Ready.
                if self.host_handler.host_handler_params.attestation_enabled {
                    if let Some(next_state) =
                        handle_measuring_state(Err(managed_state), state, txn).await?
                    {
                        return Ok(StateHandlerOutcome::Transition(next_state));
                    }
                }

                // Check if instance to be created.
                if state.instance.is_some() {
                    // Instance is requested by user. Let's configure it.

                    // TODO: multidpu: Check for all DPUs
                    // Switch to using the network we just created for the tenant
                    for dpu_snapshot in &state.dpu_snapshots {
                        let (mut netconf, version) = dpu_snapshot.network_config.clone().take();
                        netconf.use_admin_network = Some(false);
                        Machine::try_update_network_config(
                            txn,
                            &dpu_snapshot.machine_id,
                            version,
                            &netconf,
                        )
                        .await?;
                    }

                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkConfig,
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                } else {
                    Ok(StateHandlerOutcome::DoNothing)
                }
            }

            ManagedHostState::Assigned { instance_state: _ } => {
                // Process changes needed for instance.
                self.instance_handler
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await
            }

            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                match cleanup_state {
                    CleanupState::HostCleanup => {
                        if !cleanedup_after_state_transition(
                            state.host_snapshot.current.version,
                            state.host_snapshot.last_cleanup_time,
                        ) {
                            let status = trigger_reboot_if_needed(
                                &state.host_snapshot,
                                state,
                                None,
                                &self.reachability_params,
                                ctx.services,
                                txn,
                            )
                            .await?;
                            return Ok(StateHandlerOutcome::Wait(status.status));
                        }

                        // Reboot host
                        handler_host_power_control(
                            state,
                            ctx.services,
                            SystemPowerControl::ForceRestart,
                            txn,
                        )
                        .await?;

                        purge_machine_validation_results(
                            &state.host_snapshot.machine_id,
                            "CleanupState".to_string(),
                            txn,
                        )
                        .await?;

                        let current_machine_validation_id = uuid::Uuid::new_v4();

                        Machine::update_current_machine_validation_id(
                            &state.host_snapshot.machine_id,
                            current_machine_validation_id,
                            txn,
                        )
                        .await?;
                        let next_state = ManagedHostState::HostNotReady {
                            machine_state: MachineState::MachineValidating {
                                context: "CleanupState".to_string(),
                                id: current_machine_validation_id,
                                completed: 1,
                                total: 1,
                            },
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    }
                    CleanupState::DisableBIOSBMCLockdown => {
                        tracing::error!(
                            machine_id = %host_machine_id,
                            "DisableBIOSBMCLockdown state is not implemented. Machine stuck in unimplemented state.",
                        );
                        Err(StateHandlerError::InvalidHostState(
                            host_machine_id.clone(),
                            state.managed_state.clone(),
                        ))
                    }
                }
            }
            ManagedHostState::Created => {
                tracing::error!("Machine just created. We should not be here.");
                Err(StateHandlerError::InvalidHostState(
                    host_machine_id.clone(),
                    state.managed_state.clone(),
                ))
            }
            ManagedHostState::ForceDeletion => {
                // Just ignore. Delete is done directly in api.rs::admin_force_delete_machine.
                tracing::info!(
                    machine_id = %host_machine_id,
                    "Machine is marked for forced deletion. Ignoring.",
                );
                Ok(StateHandlerOutcome::Deleted)
            }
            ManagedHostState::Failed {
                details,
                machine_id,
                retry_count,
            } => {
                match details.cause {
                    // DPU discovery failed needs more logic to handle.
                    // DPU discovery can failed from multiple states init,
                    // waitingfornetworkinstall, reprov(waitingforfirmwareupgrade),
                    // reprov(waitingfornetworkinstall). Error handler must be aware of it and
                    // handle based on it.
                    // Another bigger problem is every discovery will need a
                    // fresh os install as scout is executed by cloud-init and it runs only
                    // once after os install. This has to be changed.
                    FailureCause::Discovery { .. } if machine_id.machine_type().is_host() => {
                        // If user manually reboots host, and discovery is successful then also it will come out
                        // of failed state.
                        if discovered_after_state_transition(
                            state.host_snapshot.current.version,
                            state.host_snapshot.last_discovery_time,
                        ) {
                            ctx.metrics
                                .machine_reboot_attempts_in_failed_during_discovery =
                                Some(*retry_count as u64);
                            // Anytime host discovery is successful, move to next state.
                            Machine::clear_failure_details(machine_id, txn).await?;
                            let next_state = handler_host_lockdown(txn, ctx, state).await?;
                            return Ok(StateHandlerOutcome::Transition(next_state));
                        }

                        // Wait till failure_retry_time is over except first time.
                        // First time, host is already up and reported that discovery is failed.
                        // Let's reboot now immediately.
                        if *retry_count == 0 {
                            handler_host_power_control(
                                state,
                                ctx.services,
                                SystemPowerControl::ForceRestart,
                                txn,
                            )
                            .await?;
                            let next_state = ManagedHostState::Failed {
                                retry_count: retry_count + 1,
                                details: details.clone(),
                                machine_id: machine_id.clone(),
                            };
                            return Ok(StateHandlerOutcome::Transition(next_state));
                        }

                        if trigger_reboot_if_needed(
                            &state.host_snapshot,
                            state,
                            Some(*retry_count as i64),
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?
                        .increase_retry_count
                        {
                            let next_state = ManagedHostState::Failed {
                                retry_count: retry_count + 1,
                                details: details.clone(),
                                machine_id: machine_id.clone(),
                            };
                            Ok(StateHandlerOutcome::Transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::DoNothing)
                        }
                    }
                    FailureCause::NVMECleanFailed { .. } if machine_id.machine_type().is_host() => {
                        if cleanedup_after_state_transition(
                            state.host_snapshot.current.version,
                            state.host_snapshot.last_cleanup_time,
                        ) && details.failed_at
                            < state.host_snapshot.last_cleanup_time.unwrap_or_default()
                        {
                            // Cleaned up successfully after a failure.
                            let next_state = ManagedHostState::WaitingForCleanup {
                                cleanup_state: CleanupState::HostCleanup,
                            };
                            Machine::clear_failure_details(machine_id, txn)
                                .await
                                .map_err(StateHandlerError::from)?;
                            return Ok(StateHandlerOutcome::Transition(next_state));
                        }

                        if trigger_reboot_if_needed(
                            &state.host_snapshot,
                            state,
                            Some(*retry_count as i64),
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?
                        .increase_retry_count
                        {
                            let next_state = ManagedHostState::Failed {
                                retry_count: retry_count + 1,
                                details: details.clone(),
                                machine_id: machine_id.clone(),
                            };
                            Ok(StateHandlerOutcome::Transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::DoNothing)
                        }
                    }
                    // FailureCause::MeasurementsRetired happens when a machine matches
                    // a retired bundle. Since retired bundles can have their state changed,
                    // and since there's always the potential for bundle management to
                    // happen behind the scenes otherwise, lets re-check for changes here.
                    FailureCause::MeasurementsRetired { .. }
                        if machine_id.machine_type().is_host() =>
                    {
                        if let Some(next_state) =
                            handle_measuring_state(Err(managed_state), state, txn).await?
                        {
                            Ok(StateHandlerOutcome::Transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::DoNothing)
                        }
                    }
                    // FailureCause::MeasurementsRevoked happens when a machine matches
                    // a revoked bundle. Now, revoked bundles cannot be reactivated, however,
                    // still check to see if there is a potential avenue for recovery
                    // here (e.g. a new, active bundle that has a more specific match than
                    // the revoked bundle, or potentially the revoked bundle being deleted
                    // and a new bundle being created, etc).
                    FailureCause::MeasurementsRevoked { .. }
                        if machine_id.machine_type().is_host() =>
                    {
                        if let Some(next_state) =
                            handle_measuring_state(Err(managed_state), state, txn).await?
                        {
                            Ok(StateHandlerOutcome::Transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::DoNothing)
                        }
                    }
                    _ => {
                        // Do nothing.
                        // Handle error cause and decide how to recover if possible.
                        tracing::error!(
                            %machine_id,
                            "ManagedHost {} is in Failed state with machine/cause {}/{}. Failed at: {}, Ignoring.",
                            host_machine_id,
                            machine_id,
                            details.cause,
                            details.failed_at,
                        );
                        // TODO: Should this be StateHandlerError::ManualInterventionRequired ?
                        Ok(StateHandlerOutcome::DoNothing)
                    }
                }
            }
            ManagedHostState::DPUReprovision { reprovision_state } => {
                if let Some(next_state) = handle_dpu_reprovision(
                    reprovision_state,
                    state,
                    &self.reachability_params,
                    ctx.services,
                    txn,
                    &MachineNextStateResolver,
                )
                .await?
                {
                    Ok(StateHandlerOutcome::Transition(next_state))
                } else {
                    Ok(StateHandlerOutcome::DoNothing)
                }
            }
            // ManagedHostState::Measuring is introduced into the flow when
            // attestation_enabled is set to true (defaults to false), and
            // is injected right after post-discovery reboot, and right before
            // the machine goes to Ready.
            ManagedHostState::Measuring { measuring_state } => {
                if let Some(next_state) =
                    handle_measuring_state(Ok(measuring_state), state, txn).await?
                {
                    Ok(StateHandlerOutcome::Transition(next_state))
                } else {
                    Ok(StateHandlerOutcome::Wait(
                        match measuring_state {
                            MeasuringState::WaitingForMeasurements => {
                                "Waiting for machine to send measurement report"
                            }
                            MeasuringState::PendingBundle => {
                                "Waiting for matching measurement bundle for machine profile"
                            }
                        }
                        .to_string(),
                    ))
                }
            }
        }
    }

    async fn restart_dpu_reprovision(
        &self,
        managed_state: &ManagedHostState,
        state: &ManagedHostStateSnapshot,
        ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        host_machine_id: &MachineId,
        reprov_request: &ReprovisionRequest,
    ) -> Result<Option<ManagedHostState>, StateHandlerError> {
        let mut next_state = None;
        match managed_state {
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision { .. },
            } => {
                // User approval must have received, otherwise reprovision has not
                // started.
                if let Err(err) = handler_host_power_control(
                    state,
                    ctx.services,
                    SystemPowerControl::ForceRestart,
                    txn,
                )
                .await
                {
                    tracing::error!(%host_machine_id, "Host reboot failed with error: {err}");
                }

                next_state = Some(ManagedHostState::Assigned {
                    instance_state: InstanceState::DPUReprovision {
                        // FIXME: if reprov initiated by admincli, ignore the feature flag.
                        reprovision_state: if reprov_request.update_firmware
                            && self
                                .instance_handler
                                .dpu_nic_firmware_reprovision_update_enabled
                        {
                            ReprovisionState::FirmwareUpgrade
                        } else {
                            set_managed_host_topology_update_needed(txn, state).await?;
                            ReprovisionState::WaitingForNetworkInstall
                        },
                    },
                });
            }
            ManagedHostState::DPUReprovision { .. } => {
                next_state = Some(ManagedHostState::DPUReprovision {
                    reprovision_state: if reprov_request.update_firmware {
                        ReprovisionState::FirmwareUpgrade
                    } else {
                        set_managed_host_topology_update_needed(txn, state).await?;
                        ReprovisionState::WaitingForNetworkInstall
                    },
                });
            }
            _ => {}
        };

        // TODO: multidpu: Check for all DPUs
        if next_state.is_some() {
            handler_restart_dpu(&state.dpu_snapshots[0], ctx.services, txn).await?;
            return Ok(next_state);
        }

        Ok(None)
    }
}

/// This function checks if reprovisioning is requested of a given DPU or not.
/// It also returns if firmware upgrade is needed.
fn dpu_reprovisioning_needed(dpu_snapshot: &MachineSnapshot) -> Option<ReprovisionRequest> {
    dpu_snapshot.reprovision_requested.clone()
}

// Function to wait for some time in state machine.
fn wait(basetime: &DateTime<Utc>, wait_time: Duration) -> bool {
    let expected_time = *basetime + wait_time;
    let current_time = Utc::now();

    current_time < expected_time
}

/// if dpu_agent has responded health after dpu is rebooted, return true.
fn dpus_up(state: &ManagedHostStateSnapshot) -> bool {
    for dpu_snapshot in &state.dpu_snapshots {
        let observation_time = dpu_snapshot
            .network_status_observation
            .as_ref()
            .map(|o| o.observed_at)
            .unwrap_or(DateTime::<Utc>::MIN_UTC);
        let state_change_time = state.host_snapshot.current.version.timestamp();

        if observation_time < state_change_time {
            return false;
        }
    }

    true
}

fn is_dpu_up_and_network_ready(state: &ManagedHostStateSnapshot) -> bool {
    if !dpus_up(state) {
        return false;
    }

    if !is_network_ready(&state.dpu_snapshots) {
        return false;
    }

    true
}

#[async_trait::async_trait]
impl StateHandler for MachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        if state.dpu_snapshots.is_empty() {
            return Err(StateHandlerError::GenericError(eyre!(
                "No DPU snapshot found."
            )));
        }
        self.record_metrics(state, ctx);
        self.attempt_state_transition(host_machine_id, state, controller_state, txn, ctx)
            .await
    }
}

/// handle_measuring_state handles state machine workflow for the
/// Measuring state, its corresponding substates, and measurement
/// related FailureCauses. This is achieved by passing in a Result
/// that contains either the MeasuringState or FailureCause.
async fn handle_measuring_state(
    result_state: Result<&MeasuringState, &ManagedHostState>,
    state: &ManagedHostStateSnapshot,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Option<ManagedHostState>, StateHandlerError> {
    let machine_id = &state.host_snapshot.machine_id;
    let machine_state = get_measurement_machine_state(txn, machine_id.clone())
        .await
        .map_err(StateHandlerError::GenericError)?;

    match result_state {
        Ok(measuring_state) => {
            match measuring_state {
                // In this state, the machine has been discovered, and the
                // API is now waiting for a measurement report, which is up
                // to Scout to send (as part of reacting to an Action::Measure
                // response from the API).
                //
                // Once a measurement report is received, it will be verified
                // (where if that fails, will move to ManagedHostState::Failed
                // with a MeasurementsFailedSignatureCheck reason), and matched
                // against a bundle.
                //
                // If no match is found, then the machine will hang out in
                // MeasuringState::PendingBundle.
                MeasuringState::WaitingForMeasurements => {
                    Ok(match machine_state {
                        // "Discovered" is the MeasurementMachineState equivalent of
                        // "no measurements have been sent yet". If that's the case,
                        // then continue waiting for measurements.
                        MeasurementMachineState::Discovered => None,
                        MeasurementMachineState::PendingBundle => {
                            Some(ManagedHostState::Measuring {
                                measuring_state: MeasuringState::PendingBundle,
                            })
                        }
                        MeasurementMachineState::Measured => Some(ManagedHostState::Ready),
                        MeasurementMachineState::MeasuringFailed => {
                            Some(ManagedHostState::Failed {
                                details: FailureDetails {
                                    cause: get_measurement_failure_cause(txn, machine_id).await?,
                                    failed_at: chrono::Utc::now(),
                                    source: FailureSource::StateMachine,
                                },
                                machine_id: machine_id.clone(),
                                retry_count: 0,
                            })
                        }
                    })
                }
                // In this state, a measurement report of PCR values has been
                // received (and verified), but the values don't match a bundle
                // yet. Check to see if they match one now (which happens via
                // bundle promotion). If not, keep on waiting.
                MeasuringState::PendingBundle => {
                    Ok(match machine_state {
                        // "PendingBundle" is the current state, so if this is returned,
                        // just keep on waiting for a matching bundle.
                        MeasurementMachineState::PendingBundle => None,
                        // "Discovered" is the MeasurementMachineState equivalent of
                        // "no measurements have been sent yet". If this is happens,
                        // it means measurements must have been wiped, so lets transition
                        // *back* to WaitingForMeasurements (which will tell the API to
                        // ask Scout for measurements again).
                        MeasurementMachineState::Discovered => Some(ManagedHostState::Measuring {
                            measuring_state: MeasuringState::WaitingForMeasurements,
                        }),
                        MeasurementMachineState::Measured => Some(ManagedHostState::Ready),
                        MeasurementMachineState::MeasuringFailed => {
                            Some(ManagedHostState::Failed {
                                details: FailureDetails {
                                    cause: get_measurement_failure_cause(txn, machine_id).await?,
                                    failed_at: chrono::Utc::now(),
                                    source: FailureSource::StateMachine,
                                },
                                machine_id: machine_id.clone(),
                                retry_count: 0,
                            })
                        }
                    })
                }
            }
        }
        Err(managed_host_state) => {
            match managed_host_state {
                ManagedHostState::Ready => Ok(match machine_state {
                    // If there are no longer measurements reported
                    // for the machine, then send it back to WaitingForMeasurements.
                    MeasurementMachineState::Discovered => {
                        Some(ManagedHostState::Measuring {
                            measuring_state: MeasuringState::WaitingForMeasurements,
                        })
                    }
                    // If the machine is now pending a bundle, then send it
                    // over to PendingBundle.
                    MeasurementMachineState::PendingBundle => {
                        Some(ManagedHostState::Measuring {
                            measuring_state: MeasuringState::PendingBundle,
                        })
                    }
                    // If the machine now has an active/happy bundle match,
                    // then lets move it on to Ready!
                    MeasurementMachineState::Measured => None,
                    // If the machine is in MeasuringFailed, lets see which one.
                    MeasurementMachineState::MeasuringFailed => {
                        Some(ManagedHostState::Failed {
                            details: FailureDetails {
                                cause: get_measurement_failure_cause(txn, machine_id).await?,
                                failed_at: chrono::Utc::now(),
                                source: FailureSource::StateMachine,
                            },
                            machine_id: machine_id.clone(),
                            retry_count: 0,
                        })
                    }
                }),
                ManagedHostState::Failed { details, .. } => match details.cause {
                    // In this state, the machine is matching retired measurements,
                    // so see if that's still the case. If not, transition to
                    // whatever the next state is.
                    FailureCause::MeasurementsRetired { .. } => {
                        Ok(match machine_state {
                            // If there are no longer measurements reported
                            // for the machine, then send it back to WaitingForMeasurements.
                            MeasurementMachineState::Discovered => {
                                Some(ManagedHostState::Measuring {
                                    measuring_state: MeasuringState::WaitingForMeasurements,
                                })
                            }
                            // If the machine is now pending a bundle, then send it
                            // over to PendingBundle.
                            MeasurementMachineState::PendingBundle => {
                                Some(ManagedHostState::Measuring {
                                    measuring_state: MeasuringState::PendingBundle,
                                })
                            }
                            // If the machine now has an active/happy bundle match,
                            // then lets move it on to Ready!
                            MeasurementMachineState::Measured => Some(ManagedHostState::Ready),
                            // If the machine is still in MeasuringFailed, lets
                            // see if its still MeasurementsRetired (in which case, no
                            // change), or if it needs to be moved to MeasurementsRevoked.
                            MeasurementMachineState::MeasuringFailed => {
                                let failure_cause =
                                    get_measurement_failure_cause(txn, machine_id).await?;
                                match failure_cause {
                                    // No state change, still retired!
                                    FailureCause::MeasurementsRetired { .. } => None,
                                    // State change, going to revoked!
                                    FailureCause::MeasurementsRevoked { .. } => {
                                        Some(ManagedHostState::Failed {
                                            details: FailureDetails {
                                                cause: failure_cause,
                                                failed_at: chrono::Utc::now(),
                                                source: FailureSource::StateMachine,
                                            },
                                            machine_id: machine_id.clone(),
                                            retry_count: 0,
                                        })
                                    }
                                    _ => {
                                        return Err(StateHandlerError::InvalidState(
                                            "unexpected measurement failure cause returned"
                                                .to_string(),
                                        ))
                                    }
                                }
                            }
                        })
                    }
                    // In this state, the machine is matching revoked measurements,
                    // so see if that's still the case. If not, transition to
                    // whatever the next state is.
                    FailureCause::MeasurementsRevoked { .. } => {
                        Ok(match machine_state {
                            // If there are no longer measurements reported
                            // for the machine, then send it back to WaitingForMeasurements.
                            MeasurementMachineState::Discovered => {
                                Some(ManagedHostState::Measuring {
                                    measuring_state: MeasuringState::WaitingForMeasurements,
                                })
                            }
                            // If the machine is now pending a bundle, then send it
                            // over to PendingBundle.
                            MeasurementMachineState::PendingBundle => {
                                Some(ManagedHostState::Measuring {
                                    measuring_state: MeasuringState::PendingBundle,
                                })
                            }
                            // If the machine now has an active/happy bundle match,
                            // then lets move it on to Ready!
                            MeasurementMachineState::Measured => Some(ManagedHostState::Ready),
                            // If the machine is still in MeasuringFailed, lets
                            // see if its still MeasurementsRetired (in which case, no
                            // change), or if it needs to be moved to MeasurementsRevoked.
                            MeasurementMachineState::MeasuringFailed => {
                                let failure_cause =
                                    get_measurement_failure_cause(txn, machine_id).await?;
                                match failure_cause {
                                    // No state change, still revoked!
                                    FailureCause::MeasurementsRevoked { .. } => None,
                                    // State change, going to retired!
                                    FailureCause::MeasurementsRetired { .. } => {
                                        Some(ManagedHostState::Failed {
                                            details: FailureDetails {
                                                cause: failure_cause,
                                                failed_at: chrono::Utc::now(),
                                                source: FailureSource::StateMachine,
                                            },
                                            machine_id: machine_id.clone(),
                                            retry_count: 0,
                                        })
                                    }
                                    _ => {
                                        return Err(StateHandlerError::InvalidState(
                                            "unexpected measurement failure cause returned"
                                                .to_string(),
                                        ))
                                    }
                                }
                            }
                        })
                    }
                    // If an unexpected FailureCase is provided here, yell.
                    _ => Err(StateHandlerError::InvalidState(
                        "measurement handling of FailureCause expecting MeasurementsRetired or MeasurementsRevoked"
                            .to_string(),
                    )),
                },
                // If an unexpected ManagedHostState is provided here, yell.
                _ => Err(StateHandlerError::InvalidState(
                    "measurement handling of ManagedHostState expecting Ready or Failed".to_string(),
                )),
            }
        }
    }
}

/// get_measurement_failure_cause gets the currently associated
/// measurement bundle for a given machine ID (if one exists), and
/// maps the state of the bundle to a FailureCause.
///
/// This is intended to be used when a machine is in MeasuringFailed,
/// and we want to dig into the corresponding bundle state to see why
/// it failed (e.g. retired or revoked).
///
/// If a bundle is not associated, or the associated bundle is not
/// in a retired or revoked state, then this will return an error.
///
/// TODO(chet): There's probably a world where the bundle state
/// could be stored in the journal entry itself (so there's no need
/// for a subsequent query), or a world where I introduce some
/// ComposedState type of thing where I can join across the journal
/// and bundle to do a single query + return a single ComposedState
/// that has everything I want.
async fn get_measurement_failure_cause(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
) -> Result<FailureCause, StateHandlerError> {
    let state = get_measurement_bundle_state(txn, machine_id)
        .await
        .map_err(StateHandlerError::GenericError)?
        .ok_or(StateHandlerError::MissingData {
            object_id: machine_id.to_string(),
            missing: "expected bundle reference from journal for failed measurements",
        })?;

    let failure_cause = match state {
        MeasurementBundleState::Retired => FailureCause::MeasurementsRetired {
            err: "measurements matched retired bundle".to_string(),
        },
        MeasurementBundleState::Revoked => FailureCause::MeasurementsRevoked {
            err: "measurements matched revoked bundle".to_string(),
        },
        _ => {
            return Err(StateHandlerError::MissingData {
                object_id: machine_id.to_string(),
                missing: "expected retired or revoked bundle for failure cause",
            });
        }
    };

    Ok(failure_cause)
}

/// Handle workflow of DPU reprovision
async fn handle_dpu_reprovision(
    reprovision_state: &ReprovisionState,
    state: &ManagedHostStateSnapshot,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    next_state_resolver: &impl NextReprovisionState,
) -> Result<Option<ManagedHostState>, StateHandlerError> {
    // TODO: multidpu: Check for all DPUs
    match reprovision_state {
        ReprovisionState::FirmwareUpgrade => {
            // Firmware upgrade is going on.
            if !rebooted(&state.dpu_snapshots[0]) {
                trigger_reboot_if_needed(
                    &state.dpu_snapshots[0],
                    state,
                    None,
                    reachability_params,
                    services,
                    txn,
                )
                .await?;
                return Ok(None);
            }

            handler_host_power_control(state, services, SystemPowerControl::ForceOff, txn).await?;
            set_managed_host_topology_update_needed(txn, state).await?;
            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
        ReprovisionState::PowerDown => {
            let basetime = state
                .host_snapshot
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time)
                .unwrap_or(state.host_snapshot.current.version.timestamp());

            if wait(&basetime, reachability_params.power_down_wait) {
                return Ok(None);
            }

            let redfish_client = build_redfish_client_from_machine_snapshot(
                &state.host_snapshot,
                &services.redfish_client_pool,
                txn,
            )
            .await?;
            let power_state = host_power_state(redfish_client.as_ref()).await?;

            // Host is not powered-off yet. Try again.
            if power_state != libredfish::PowerState::Off {
                tracing::error!(
                    "Machine {} is still not power-off state. Turning off for host again.",
                    state.host_snapshot.machine_id
                );
                handler_host_power_control(state, services, SystemPowerControl::ForceOff, txn)
                    .await?;

                return Ok(None);
            }
            handler_host_power_control(state, services, SystemPowerControl::On, txn).await?;
            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
        ReprovisionState::WaitingForNetworkInstall => {
            if (try_wait_for_dpu_discovery_and_reboot(state, reachability_params, services, txn)
                .await?)
                .is_pending()
            {
                return Ok(None);
            }

            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
        ReprovisionState::BufferTime => {
            // This state just waits for some time to avoid race condition where
            // dpu_agent sends heartbeat just before DPU goes down. A few microseconds
            // gap can cause host to restart before DPU comes up. This will fail Host
            // DHCP.
            if wait(
                &state.host_snapshot.current.version.timestamp(),
                reachability_params.dpu_wait_time,
            ) {
                return Ok(None);
            }
            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
        ReprovisionState::WaitingForNetworkConfig => {
            if !is_dpu_up_and_network_ready(state) {
                return Ok(None);
            }

            // Clear reprovisioning state.
            for dpu_snapshot in &state.dpu_snapshots {
                Machine::clear_dpu_reprovisioning_request(txn, &dpu_snapshot.machine_id, false)
                    .await
                    .map_err(StateHandlerError::from)?;
            }

            handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn)
                .await?;

            // We need to wait for the host to reboot and submit it's new Hardware information in
            // case of Ready.
            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
    }
}

/// This function waits for DPU to finish discovery and reboots it.
async fn try_wait_for_dpu_discovery_and_reboot(
    state: &ManagedHostStateSnapshot,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<Poll<()>, StateHandlerError> {
    // We are waiting for the `DiscoveryCompleted` RPC call to update the
    // `last_discovery_time` timestamp.
    // This indicates that all forge-scout actions have succeeded.
    // TODO: multidpu: Check for all DPUs
    if !discovered_after_state_transition(
        state.dpu_snapshots[0].current.version,
        state.dpu_snapshots[0].last_discovery_time,
    ) {
        let _status = trigger_reboot_if_needed(
            &state.dpu_snapshots[0],
            state,
            None,
            reachability_params,
            services,
            txn,
        )
        .await?;
        // TODO propagate the status.status message to a StateHandlerOutcome::Wait
        return Ok(Poll::Pending);
    }

    handler_restart_dpu(&state.dpu_snapshots[0], services, txn).await?;

    Ok(Poll::Ready(()))
}

async fn set_managed_host_topology_update_needed(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &ManagedHostStateSnapshot,
) -> Result<(), StateHandlerError> {
    //Update it for host and DPU both.
    for dpu_snapshot in &state.dpu_snapshots {
        MachineTopology::set_topology_update_needed(txn, &dpu_snapshot.machine_id, true).await?;
    }
    MachineTopology::set_topology_update_needed(txn, &state.host_snapshot.machine_id, true).await?;
    Ok(())
}

/// This function returns failure cause for both host and dpu.
fn get_failed_state(state: &ManagedHostStateSnapshot) -> Option<(MachineId, FailureDetails)> {
    // TODO: multidpu: Check for all DPUs
    // TODO: This might return HashMap<dpu_id, failure> to handle failure from all dpus.
    // Return updated state only for errors which should cause machine to move into failed
    // state.
    if state.host_snapshot.failure_details.cause != FailureCause::NoError {
        Some((
            state.host_snapshot.machine_id.clone(),
            state.host_snapshot.failure_details.clone(),
        ))
    } else if state.dpu_snapshots[0].failure_details.cause != FailureCause::NoError {
        Some((
            state.dpu_snapshots[0].machine_id.clone(),
            state.dpu_snapshots[0].failure_details.clone(),
        ))
    } else {
        None
    }
}

/// A `StateHandler` implementation for DPU machines
#[derive(Debug, Clone)]
pub struct DpuMachineStateHandler {
    dpu_nic_firmware_initial_update_enabled: bool,
    dpu_models: HashMap<DpuModel, DpuDesc>,
    reachability_params: ReachabilityParams,
}

impl DpuMachineStateHandler {
    pub fn new(
        dpu_nic_firmware_initial_update_enabled: bool,
        dpu_models: HashMap<DpuModel, DpuDesc>,
        reachability_params: ReachabilityParams,
    ) -> Self {
        DpuMachineStateHandler {
            dpu_nic_firmware_initial_update_enabled,
            dpu_models,
            reachability_params,
        }
    }
    /// Return `DpuModel` if the explored endpoint is a DPU
    pub fn identify_dpu(&self, state: &mut ManagedHostStateSnapshot) -> DpuModel {
        // TODO: multidpu: Check for all DPUs
        let model = state.dpu_snapshots[0]
            .hardware_info
            .as_ref()
            .and_then(|hi| {
                hi.dpu_info
                    .as_ref()
                    .map(|di| di.part_description.to_string())
            })
            .unwrap_or("".to_string());
        match model.to_lowercase() {
            value if value.contains("bluefield 2") => DpuModel::BlueField2,
            value if value.contains("bluefield 3") => DpuModel::BlueField3,
            _ => DpuModel::Unknown,
        }
    }

    async fn component_update(
        &self,
        redfish: &dyn Redfish,
        component: DpuComponent,
        component_value: &DpuComponentUpdate,
    ) -> Result<Option<Task>, StateHandlerError> {
        let redfish_component_name = match component {
            // Note: DPU uses different name for BMC Firmware as
            // BF2: 6d53cf4d_BMC_Firmware
            // BF3: BMC_Firmware
            DpuComponent::Bmc => "BMC_Firmware",
            DpuComponent::Uefi => "DPU_UEFI",
            DpuComponent::Cec => "Bluefield_FW_ERoT",
        };
        let inventories = redfish.get_software_inventories().await.map_err(|e| {
            StateHandlerError::RedfishError {
                operation: "get_software_inventories",
                error: e,
            }
        })?;

        let inventory_id = inventories
            .iter()
            .find(|i| i.contains(redfish_component_name))
            .ok_or(StateHandlerError::FirmwareUpdateError(eyre!(
                "No inventory found that matches: {}",
                redfish_component_name
            )))?;

        let inventory = match redfish.get_firmware(inventory_id).await {
            Ok(inventory) => inventory,
            Err(e) => {
                tracing::error!("redfish command get_firmware error {}", e.to_string());
                return Err(StateHandlerError::RedfishError {
                    operation: "get_firmware",
                    error: e,
                });
            }
        };

        if inventory.version.is_none() {
            let msg = format!("Unknown {:?} version", component);
            tracing::error!(msg);
            return Err(StateHandlerError::FirmwareUpdateError(eyre!(msg)));
        };

        if component_value.version.is_some() {
            let cur_version = inventory
                .version
                .unwrap_or("0".to_string())
                .to_lowercase()
                .replace("bf-", "");
            let update_version = component_value.version.as_ref().unwrap();

            match version_compare::compare_to(
                cur_version.clone(),
                update_version,
                version_compare::Cmp::Ge,
            ) {
                Ok(update_is_not_needed) => {
                    if update_is_not_needed {
                        return Ok(None);
                    }
                }
                Err(e) => {
                    return Err(StateHandlerError::FirmwareUpdateError(eyre!(
                        "Could not compare firmware versions (cur_version: {cur_version}, update_version: {update_version}): {e:#?}",
                    )));
                }
            };
        };

        let update_path = &component_value.path;
        let update_file = File::open(update_path).await.map_err(|e| {
            StateHandlerError::FirmwareUpdateError(eyre!(
                "Failed to open {:?} path {} with error {}",
                component,
                update_path,
                e.to_string()
            ))
        })?;

        match redfish.update_firmware(update_file).await {
            Ok(task) => Ok(Some(task)),
            Err(e) => {
                tracing::error!("redfish command update_firmware error {}", e.to_string());
                Err(StateHandlerError::RedfishError {
                    operation: "update_firmware",
                    error: e,
                })
            }
        }
    }

    fn get_discovery_failure(&self, msg: String, machine_id: &MachineId) -> ManagedHostState {
        tracing::error!(msg);
        let failure_details = FailureDetails {
            cause: FailureCause::Discovery { err: msg },
            failed_at: chrono::Utc::now(),
            source: FailureSource::StateMachine,
        };

        ManagedHostState::Failed {
            details: failure_details,
            machine_id: machine_id.clone(),
            retry_count: 0,
        }
    }
}

#[async_trait::async_trait]
impl StateHandler for DpuMachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        // TODO: multidpu: Check for all DPUs
        let dpu_machine_id = &state.dpu_snapshots[0].machine_id.clone();
        match &state.managed_state {
            ManagedHostState::DpuDiscoveringState {
                discovering_state: DpuDiscoveringState::Initializing,
            } => {
                let next_state = ManagedHostState::DpuDiscoveringState {
                    discovering_state: DpuDiscoveringState::Configuring,
                };
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            ManagedHostState::DpuDiscoveringState {
                discovering_state:
                    DpuDiscoveringState::BmcFirmwareUpdate {
                        substate: BmcFirmwareUpdateSubstate::HostPowerOff,
                    },
            } => {
                let ip = state.host_snapshot.bmc_info.ip.clone();
                let host_client = build_redfish_client_from_machine_snapshot(
                    &state.host_snapshot,
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await?;

                match host_client.get_power_state().await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get_power_state",
                        error: e,
                    }
                })? {
                    PowerState::Off => {
                        host_client
                            .power(SystemPowerControl::On)
                            .await
                            .map_err(|e| StateHandlerError::RedfishError {
                                operation: "host_power_on",
                                error: e,
                            })?;
                        let next_state = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                substate: BmcFirmwareUpdateSubstate::Reboot { count: 0 },
                            },
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    }
                    _ => Ok(StateHandlerOutcome::Wait(format!(
                        "Waiting to host {:?} power off",
                        ip
                    ))),
                }
            }
            ManagedHostState::DpuDiscoveringState {
                discovering_state:
                    DpuDiscoveringState::BmcFirmwareUpdate {
                        substate:
                            BmcFirmwareUpdateSubstate::WaitForUpdateCompletion {
                                firmware_type,
                                task_id,
                            },
                    },
            } => {
                let dpu_redfish_client = build_redfish_client_from_machine_snapshot(
                    &state.dpu_snapshots[0],
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await?;

                let task = dpu_redfish_client.get_task(task_id).await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get_task",
                        error: e,
                    }
                })?;

                tracing::info!("{:?} FW update task: {:#?}", firmware_type, task);

                match task.task_state {
                    Some(TaskState::Completed) => {
                        if *firmware_type == DpuComponent::Cec {
                            // For Cec firmware update need also to reboot a host
                            let host_redfish_client = build_redfish_client_from_machine_snapshot(
                                &state.host_snapshot,
                                &ctx.services.redfish_client_pool,
                                txn,
                            )
                            .await?;

                            host_redfish_client
                                .power(SystemPowerControl::ForceOff)
                                .await
                                .map_err(|e| StateHandlerError::RedfishError {
                                    operation: "host_power_off",
                                    error: e,
                                })?;
                            let next_state = ManagedHostState::DpuDiscoveringState {
                                discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                    substate: BmcFirmwareUpdateSubstate::HostPowerOff,
                                },
                            };
                            return Ok(StateHandlerOutcome::Transition(next_state));
                        }

                        dpu_redfish_client.bmc_reset().await.map_err(|e| {
                            StateHandlerError::RedfishError {
                                operation: "bmc_reset",
                                error: e,
                            }
                        })?;
                        let next_state = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                substate: BmcFirmwareUpdateSubstate::Reboot { count: 0 },
                            },
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    }
                    Some(TaskState::Exception) => {
                        let msg = format!(
                            "Failed to update FW:  {:#?}",
                            task.messages
                                .last()
                                .map_or("".to_string(), |m| m.message.clone())
                        );
                        let next_state = self.get_discovery_failure(msg, dpu_machine_id);
                        Ok(StateHandlerOutcome::Transition(next_state))
                    }
                    Some(_) => {
                        // TODO: Are any of these states an error? Or we're waiting for something
                        Ok(StateHandlerOutcome::DoNothing)
                    }
                    None => Err(StateHandlerError::GenericError(eyre!(
                        "No task state field in task: {:#?}",
                        task
                    ))),
                }
            }
            ManagedHostState::DpuDiscoveringState {
                discovering_state:
                    DpuDiscoveringState::BmcFirmwareUpdate {
                        substate: BmcFirmwareUpdateSubstate::Reboot { count },
                    },
            } => {
                match build_redfish_client_from_machine_snapshot(
                    &state.dpu_snapshots[0],
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await
                {
                    Ok(_client) => {
                        let next_state = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::Configuring {},
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    }
                    Err(_e) => {
                        let next_state = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                substate: BmcFirmwareUpdateSubstate::Reboot { count: count + 1 },
                            },
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    }
                }
            }
            ManagedHostState::DpuDiscoveringState {
                discovering_state: DpuDiscoveringState::Configuring,
            } => {
                let dpu_redfish_client_result = build_redfish_client_from_machine_snapshot(
                    &state.dpu_snapshots[0],
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await;

                let dpu_redfish_client = match dpu_redfish_client_result {
                    Ok(redfish_client) => redfish_client,
                    Err(e) => {
                        let msg = format!("Failed to instantiate redfish client: {}", e);
                        let next_state = self.get_discovery_failure(msg, dpu_machine_id);
                        return Ok(StateHandlerOutcome::Transition(next_state));
                    }
                };

                let dpu_model = self.identify_dpu(state);
                if let Some(dpu_desc) = self.dpu_models.get(&dpu_model) {
                    if dpu_desc.component_update.is_some() {
                        let dpu_component_update = dpu_desc.component_update.as_ref().unwrap();
                        for dpu_component in DpuComponent::iter() {
                            if let Some(dpu_component_value) =
                                dpu_component_update.get(&dpu_component)
                            {
                                let task = self
                                    .component_update(
                                        &*dpu_redfish_client,
                                        dpu_component,
                                        dpu_component_value,
                                    )
                                    .await?;
                                if task.is_some() {
                                    let next_state = ManagedHostState::DpuDiscoveringState {
                                        discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                            substate:
                                                BmcFirmwareUpdateSubstate::WaitForUpdateCompletion {
                                                    firmware_type: dpu_component,
                                                    task_id: task.unwrap().id,
                                                },
                                        },
                                    };
                                    return Ok(StateHandlerOutcome::Transition(next_state));
                                };
                            }
                        }
                    }
                }

                if let Err(e) = ctx
                    .services
                    .redfish_client_pool
                    .uefi_setup(dpu_redfish_client.as_ref(), true)
                    .await
                {
                    tracing::error!(%e, "Failed to run uefi_setup call");
                    return Err(StateHandlerError::RedfishClientCreationError(e));
                }

                if let Err(e) = dpu_redfish_client.forge_setup().await {
                    tracing::error!(%e, "Failed to run forge_setup call");
                    return Err(StateHandlerError::RedfishError {
                        operation: "forge_setup",
                        error: e,
                    });
                }

                if let Err(e) = dpu_redfish_client.disable_secure_boot().await {
                    tracing::error!(%e, "Failed to run disable_secure_boot call");
                    return Err(StateHandlerError::RedfishError {
                        operation: "disable_secure_boot",
                        error: e,
                    });
                }

                // If we have OOB mac - set explicitly to boot from OOB mac,
                // otherwise set boot to HttpBoot
                if let Some(oob_mac) = state.dpu_snapshots[0]
                    .hardware_info
                    .as_ref()
                    .and_then(|h| h.network_interfaces.first().map(|n| n.mac_address.clone()))
                {
                    let oob_boot_pattern = format!(
                        "UEFI HTTPv4 (MAC:{})",
                        oob_mac.replace(':', "").to_uppercase()
                    );
                    let boot_order = dpu_redfish_client
                        .get_system()
                        .map_err(|e| StateHandlerError::RedfishError {
                            operation: "get_system",
                            error: e,
                        })
                        .await?
                        .boot
                        .boot_order;

                    let mut new_boot_order: Vec<String> = Vec::new();
                    let mut found = false;

                    for member in boot_order {
                        let b = dpu_redfish_client
                            .get_boot_option(member.as_str())
                            .map_err(|e| StateHandlerError::RedfishError {
                                operation: "get_boot_option",
                                error: e,
                            })
                            .await?;
                        if b.display_name
                            .to_uppercase()
                            .starts_with(oob_boot_pattern.as_str())
                        {
                            found = true;
                            new_boot_order.insert(0, b.id);
                        } else {
                            new_boot_order.push(b.id);
                        }
                    }

                    // If we couldn't find boot order by patter, still try to boot from UEFI http.
                    if !found {
                        dpu_redfish_client
                            .boot_once(Boot::UefiHttp)
                            .map_err(|e| StateHandlerError::RedfishError {
                                operation: "boot_once",
                                error: e,
                            })
                            .await?;
                    } else {
                        dpu_redfish_client
                            .change_boot_order(new_boot_order)
                            .map_err(|e| StateHandlerError::RedfishError {
                                operation: "change_boot_order",
                                error: e,
                            })
                            .await?;
                    }
                } else {
                    dpu_redfish_client
                        .boot_once(Boot::UefiHttp)
                        .map_err(|e| StateHandlerError::RedfishError {
                            operation: "boot_once",
                            error: e,
                        })
                        .await?;
                }

                if let Err(e) = dpu_redfish_client
                    .power(SystemPowerControl::ForceRestart)
                    .await
                {
                    tracing::error!(%e, "Failed to reboot a DPU");
                    return Err(StateHandlerError::RedfishError {
                        operation: "reboot",
                        error: e,
                    });
                }

                let next_state = ManagedHostState::DPUNotReady {
                    machine_state: MachineState::Init,
                };
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::Init,
            } => {
                // initial restart, firmware update and scout is run, first reboot of dpu discovery
                let dpu_discovery_poll = try_wait_for_dpu_discovery_and_reboot(
                    state,
                    &self.reachability_params,
                    ctx.services,
                    txn,
                )
                .await?;
                if dpu_discovery_poll.is_pending() {
                    return Ok(StateHandlerOutcome::Wait(
                        "Waiting for DPU discovery and reboot".to_string(),
                    ));
                }

                tracing::debug!(
                    "ManagedHostState::DPUNotReady::Init: firmware update enabled = {}",
                    self.dpu_nic_firmware_initial_update_enabled
                );

                let next_state = if self.dpu_nic_firmware_initial_update_enabled {
                    // the initial topology may be based on a different firmware version.  allow it to be
                    // updated once the reboot completes and sends new data.
                    // TODO: multidpu: Check for all DPUs
                    MachineTopology::set_topology_update_needed(
                        txn,
                        &state.dpu_snapshots[0].machine_id,
                        true,
                    )
                    .await?;
                    ManagedHostState::DPUNotReady {
                        machine_state: MachineState::WaitingForNetworkInstall,
                    }
                } else {
                    ManagedHostState::DPUNotReady {
                        machine_state: MachineState::WaitingForNetworkConfig,
                    }
                };
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::WaitingForNetworkInstall,
            } => {
                // rebooted from the init state, where firmware is updated and scout is running.
                // TODO: multidpu: Check for all DPUs
                if !rebooted(&state.dpu_snapshots[0]) {
                    let status = trigger_reboot_if_needed(
                        &state.dpu_snapshots[0],
                        state,
                        None,
                        &self.reachability_params,
                        ctx.services,
                        txn,
                    )
                    .await?;
                    return Ok(StateHandlerOutcome::Wait(status.status));
                }

                // hbn needs a restart to be able to come online, second reboot of dpu discovery
                handler_restart_dpu(&state.dpu_snapshots[0], ctx.services, txn).await?;

                let next_state = ManagedHostState::DPUNotReady {
                    machine_state: MachineState::WaitingForNetworkConfig,
                };
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::WaitingForNetworkConfig,
            } => {
                if !is_network_ready(&state.dpu_snapshots) {
                    // TODO: Make is_network_ready give us more details as a string
                    return Ok(StateHandlerOutcome::Wait(
                        "Waiting for DPU agent to apply network config and report healthy network"
                            .to_string(),
                    ));
                }

                if let Err(e) = handler_host_power_control(
                    state,
                    ctx.services,
                    SystemPowerControl::ForceRestart,
                    txn,
                )
                .await
                {
                    tracing::error!("Error while rebooting host with site default password. {e}");
                    // TODO: Return the error to make it visible to SRE?
                }

                let next_state = ManagedHostState::HostNotReady {
                    machine_state: MachineState::WaitingForPlatformConfiguration,
                };
                Ok(StateHandlerOutcome::Transition(next_state))
            }
            state => {
                tracing::warn!(machine_id = %host_machine_id, ?state, "Unhandled State for DPU machine");
                Err(StateHandlerError::InvalidHostState(
                    dpu_machine_id.clone(),
                    state.clone(),
                ))
            }
        }
    }
}

fn get_reboot_cycle(
    next_potential_reboot_time: DateTime<Utc>,
    entered_state_at: DateTime<Utc>,
    wait_period: Duration,
) -> Result<i64, StateHandlerError> {
    if next_potential_reboot_time <= entered_state_at {
        return Err(
            StateHandlerError::GenericError(
                eyre::eyre!("Poorly configured paramters: next_potential_reboot_time: {}, entered_state_at: {}, wait_period: {}",
                    next_potential_reboot_time,
                    entered_state_at,
                    wait_period.num_minutes()
                )
            )
        );
    }

    let cycle = next_potential_reboot_time - entered_state_at;

    // Although trigger_reboot_if_needed makes sure to not send wait_period as 0, but still if some other
    // function calls get_reboot_cycle, this function must not panic, so setting it min 1 minute
    // here as well.
    Ok(cycle.num_minutes() / wait_period.num_minutes().max(1))
}

struct RebootStatus {
    increase_retry_count: bool, // the vague previous return value
    status: String,             // what we did or are waiting for
}

/// In case machine does not come up until a specified duration, this function tries to reboot
/// it again. The reboot continues till 6 hours only. After that this function gives up.
async fn trigger_reboot_if_needed(
    target: &MachineSnapshot,
    state: &ManagedHostStateSnapshot,
    retry_count: Option<i64>,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<RebootStatus, StateHandlerError> {
    let Some(last_reboot_requested) = &target.last_reboot_requested else {
        return Ok(RebootStatus {
            increase_retry_count: false,
            status: "No pending reboot. Will keep waiting.".to_string(),
        });
    };
    let host = &state.host_snapshot;
    if let MachineLastRebootRequestedMode::PowerOff = last_reboot_requested.mode {
        // PowerOn the host.
        tracing::info!(
            "Machine {} is in power-off state. Turning on for host: {}",
            target.machine_id,
            host.machine_id,
        );
        let basetime = host
            .last_reboot_requested
            .as_ref()
            .map(|x| x.time)
            .unwrap_or(host.current.version.timestamp());

        if wait(&basetime, reachability_params.power_down_wait) {
            return Ok(RebootStatus {
                increase_retry_count: false,
                status: format!(
                    "Waiting for host to power off. Next check at {}",
                    basetime + reachability_params.power_down_wait
                ),
            });
        }

        let redfish_client =
            build_redfish_client_from_machine_snapshot(host, &services.redfish_client_pool, txn)
                .await?;

        let power_state = host_power_state(redfish_client.as_ref()).await?;

        // If power-off done, power-on now.
        // If host is not powered-off yet, try again.
        let action = if power_state == libredfish::PowerState::Off {
            SystemPowerControl::On
        } else {
            tracing::error!(
                "Machine {} is still not power-off state. Turning off again for host: {}",
                target.machine_id,
                host.machine_id,
            );
            SystemPowerControl::ForceOff
        };

        tracing::trace!(machine_id=%target.machine_id, "Redfish setting host power state to {action}");
        handler_host_power_control(state, services, action, txn).await?;
        return Ok(RebootStatus {
            increase_retry_count: false,
            status: format!("Set power state to {action} using Redfish API"),
        });
    }

    let wait_period = reachability_params
        .failure_retry_time
        .max(Duration::minutes(1));

    let next_potential_reboot_time = last_reboot_requested.time + wait_period;
    let current_time = Utc::now();
    let entered_state_at = target.current.version.timestamp();
    let time_elapsed_since_state_change = (current_time - entered_state_at).num_minutes();
    // Let's stop at 15 cycles of reboot.
    let max_retry_duration = Duration::minutes(wait_period.num_minutes() * 15);

    let should_try = if let Some(retry_count) = retry_count {
        retry_count < 15
    } else {
        entered_state_at + max_retry_duration > current_time
    };

    // We can try reboot only upto 15 cycles from state change.
    if should_try {
        // A cycle is done but host has not responded yet. Let's try a reboot.
        if next_potential_reboot_time < current_time {
            // Find the cycle.
            // We are trying to reboot 3 times and power down/up on 4th cycle.
            let cycle = match retry_count {
                Some(x) => x,
                None => {
                    get_reboot_cycle(next_potential_reboot_time, entered_state_at, wait_period)?
                }
            };

            let status = if cycle % 4 == 0 {
                // PowerDown
                // DPU or host, in both cases power down is triggered from host.
                let action = SystemPowerControl::ForceOff;
                handler_host_power_control(state, services, action, txn).await?;
                format!(
                    "Has not come up after {} minutes, trying ForceOff, cycle: {cycle}",
                    time_elapsed_since_state_change,
                )
            } else {
                // Reboot
                if target.machine_id.machine_type().is_dpu() {
                    handler_restart_dpu(target, services, txn).await?;
                } else {
                    handler_host_power_control(
                        state,
                        services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;
                }
                format!(
                    "Has not come up after {} minutes. Rebooting again, cycle: {cycle}.",
                    time_elapsed_since_state_change
                )
            };
            Ok(RebootStatus {
                increase_retry_count: true,
                status,
            })
        } else {
            Ok(RebootStatus {
                increase_retry_count: false,
                status: format!("Will attempt next reboot at {next_potential_reboot_time}"),
            })
        }
    } else {
        let h = (current_time - entered_state_at).num_hours();
        Err(StateHandlerError::ManualInterventionRequired(format!(
            "Machine has not responded after {h} hours."
        )))
    }
}

/// This function waits until target machine is up or not. It relies on scout to identify if
/// machine has come up or not after reboot.
// True if machine is rebooted after state change.
fn rebooted(target: &MachineSnapshot) -> bool {
    target.last_reboot_time.unwrap_or_default() > target.current.version.timestamp()
}

fn machine_validation_completed(target: &MachineSnapshot) -> bool {
    target.last_machine_validation_time.unwrap_or_default() > target.current.version.timestamp()
}
// Was machine rebooted after state change?
fn discovered_after_state_transition(
    version: ConfigVersion,
    last_discovery_time: Option<DateTime<Utc>>,
) -> bool {
    last_discovery_time.unwrap_or_default() > version.timestamp()
}

// Was DPU reprov restart requested after state change
fn dpu_reprovision_restart_requested_after_state_transition(
    version: ConfigVersion,
    reprov_restart_requested_at: DateTime<Utc>,
) -> bool {
    reprov_restart_requested_at > version.timestamp()
}

fn cleanedup_after_state_transition(
    version: ConfigVersion,
    last_cleanup_time: Option<DateTime<Utc>>,
) -> bool {
    last_cleanup_time.unwrap_or_default() > version.timestamp()
}

/// A `StateHandler` implementation for host machines
#[derive(Debug, Clone)]
pub struct HostMachineStateHandler {
    host_handler_params: HostHandlerParams,
}

impl HostMachineStateHandler {
    pub fn new(host_handler_params: HostHandlerParams) -> Self {
        Self {
            host_handler_params,
        }
    }
}

/// 1. Has the network config version that the host wants been applied by DPU?
/// 2. Is HBN reporting the network is healthy?
fn is_network_ready(dpu_snapshots: &[MachineSnapshot]) -> bool {
    for dpu_snapshot in dpu_snapshots {
        let dpu_expected_version = dpu_snapshot.network_config.version;
        let dpu_observation = dpu_snapshot.network_status_observation.as_ref();
        let dpu_observed_version: ConfigVersion = match dpu_observation {
            None => {
                return false;
            }
            Some(network_status) => match network_status.network_config_version {
                None => {
                    return false;
                }
                Some(version) => version,
            },
        };

        if dpu_expected_version != dpu_observed_version || !dpu_snapshot.has_healthy_network() {
            return false;
        }
    }

    true
}

async fn handler_host_lockdown(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    state: &mut ManagedHostStateSnapshot,
) -> Result<ManagedHostState, StateHandlerError> {
    // Enable Bios/BMC lockdown now.
    lockdown_host(txn, state, ctx.services).await?;

    Ok(ManagedHostState::HostNotReady {
        machine_state: MachineState::WaitingForLockdown {
            lockdown_info: LockdownInfo {
                state: LockdownState::TimeWaitForDPUDown,
                mode: Enable,
            },
        },
    })
}

/// TODO: we need to handle the case where the job is deleted for some reason
async fn handle_host_uefi_setup(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    state: &mut ManagedHostStateSnapshot,
    uefi_setup_info: UefiSetupInfo,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let redfish_client = build_redfish_client_from_machine_snapshot(
        &state.host_snapshot,
        &ctx.services.redfish_client_pool,
        txn,
    )
    .await?;

    match uefi_setup_info.uefi_setup_state.clone() {
        UefiSetupState::SetUefiPassword => {
            /*
            TODO: re-enable setting the host uefi password once we clear the password as part of a force-delete
            let job_id = set_host_uefi_password(
                redfish_client.as_ref(),
                ctx.services.redfish_client_pool.clone(),
            )
            .await
            .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("{}", e)))?;

            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: job_id,
                            uefi_setup_state: UefiSetupState::WaitForPasswordJobScheduled,
                        },
                    },
                },
            ))
            */
            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: None,
                            uefi_setup_state: UefiSetupState::WaitForPasswordJobScheduled,
                        },
                    },
                },
            ))
        }
        UefiSetupState::WaitForPasswordJobScheduled => {
            if let Some(job_id) = uefi_setup_info.uefi_password_jid.clone() {
                if !poll_redfish_job(
                    redfish_client.as_ref(),
                    job_id.clone(),
                    libredfish::JobState::Scheduled,
                )
                .await
                .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("{}", e)))?
                {
                    return Ok(StateHandlerOutcome::Wait(format!(
                        "waiting for job {:#?} to complete",
                        job_id
                    )));
                }
            }

            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: uefi_setup_info.uefi_password_jid.clone(),
                            uefi_setup_state: UefiSetupState::PowercycleHost,
                        },
                    },
                },
            ))
        }
        UefiSetupState::PowercycleHost => {
            /*
            TODO: re-enable setting the host uefi password once we clear the password as part of a force-delete
            let redfish_client = build_redfish_client_from_machine_snapshot(
                &state.host_snapshot,
                &ctx.services.redfish_client_pool,
                txn,
            )
            .await?;

            host_power_control(
                redfish_client.as_ref(),
                &state.host_snapshot,
                SystemPowerControl::ForceRestart,
                ctx.services.ipmi_tool.clone(),
                txn,
            )
            .await
            .map_err(|e| {
                StateHandlerError::GenericError(eyre!("handler_host_power_control failed: {}", e))
            })?;
            */

            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: uefi_setup_info.uefi_password_jid.clone(),
                            uefi_setup_state: UefiSetupState::WaitForPasswordJobCompletion,
                        },
                    },
                },
            ))
        }
        UefiSetupState::WaitForPasswordJobCompletion => {
            if let Some(job_id) = uefi_setup_info.uefi_password_jid.clone() {
                let redfish_client = build_redfish_client_from_machine_snapshot(
                    &state.host_snapshot,
                    &ctx.services.redfish_client_pool,
                    txn,
                )
                .await?;
                if !poll_redfish_job(
                    redfish_client.as_ref(),
                    job_id.clone(),
                    libredfish::JobState::Completed,
                )
                .await
                .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("{}", e)))?
                {
                    return Ok(StateHandlerOutcome::Wait(format!(
                        "waiting for job {:#?} to complete",
                        job_id
                    )));
                }
            }

            /*
            TODO: re-enable setting the host uefi password once we clear the password as part of a force-delete
            state.host_snapshot.bios_password_set_time = Some(chrono::offset::Utc::now());
            Machine::update_bios_password_set(&state.host_snapshot.machine_id, txn)
                .await
                .map_err(|e| {
                    StateHandlerError::GenericError(eyre!(
                        "update_host_bios_password_set failed: {}",
                        e
                    ))
                })?;
            */

            Ok(StateHandlerOutcome::Transition(
                ManagedHostState::HostNotReady {
                    machine_state: MachineState::UefiSetup {
                        uefi_setup_info: UefiSetupInfo {
                            uefi_password_jid: uefi_setup_info.uefi_password_jid.clone(),
                            uefi_setup_state: UefiSetupState::LockdownHost,
                        },
                    },
                },
            ))
        }
        UefiSetupState::LockdownHost => Ok(StateHandlerOutcome::Transition(
            handler_host_lockdown(txn, ctx, state).await.map_err(|e| {
                StateHandlerError::GenericError(eyre!("handle_host_lockdown failed: {}", e))
            })?,
        )),
    }
}

#[async_trait::async_trait]
impl StateHandler for HostMachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        if let ManagedHostState::HostNotReady { machine_state } = &state.managed_state {
            match machine_state {
                MachineState::Init => Err(StateHandlerError::InvalidHostState(
                    host_machine_id.clone(),
                    state.managed_state.clone(),
                )),
                MachineState::WaitingForNetworkConfig => {
                    tracing::warn!(
                        machine_id = %host_machine_id,
                        "Invalid State WaitingForNetworkConfig for Host Machine",
                    );
                    Err(StateHandlerError::InvalidHostState(
                        host_machine_id.clone(),
                        state.managed_state.clone(),
                    ))
                }
                MachineState::WaitingForPlatformConfiguration => {
                    let next_state = ManagedHostState::HostNotReady {
                        machine_state: MachineState::WaitingForDiscovery,
                    };

                    tracing::info!(
                        machine_id = %host_machine_id,
                        "Starting UEFI / BMC setup");

                    match build_redfish_client_from_machine_snapshot(
                        &state.host_snapshot,
                        &ctx.services.redfish_client_pool,
                        txn,
                    )
                    .await
                    {
                        Ok(redfish_client) => {
                            redfish_client.forge_setup().await.map_err(|e| {
                                StateHandlerError::RedfishError {
                                    operation: "forge_setup",
                                    error: e,
                                }
                            })?;

                            // Rely on the next_state being WaitingForDiscovery which performs a
                            // reboot of the host to pick up the changes
                            Ok(StateHandlerOutcome::Transition(next_state))
                        }
                        Err(RedfishClientCreationError::MissingBmcEndpoint(_)) => {
                            tracing::warn!(
                                machine_id = %host_machine_id,
                                "Machine does not have BMC information, skipping UEFI / BMC setup");

                            Ok(StateHandlerOutcome::Transition(next_state))
                        }
                        Err(e) => {
                            tracing::warn!(
                                machine_id = %host_machine_id,
                                "Unable to connect to Redfish API for UEFI / BMC setup: {:?}", e);

                            Err(e.into())
                        }
                    }
                }
                MachineState::WaitingForDiscovery => {
                    if !discovered_after_state_transition(
                        state.host_snapshot.current.version,
                        state.host_snapshot.last_discovery_time,
                    ) {
                        tracing::trace!(
                            "Waiting for forge-scout to report host online. \
                                         Host last seen {:?}, must come after DPU's {}",
                            state.host_snapshot.last_discovery_time,
                            state.host_snapshot.current.version.timestamp()
                        );
                        let status = trigger_reboot_if_needed(
                            &state.host_snapshot,
                            state,
                            None,
                            &self.host_handler_params.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;
                        return Ok(StateHandlerOutcome::Wait(status.status));
                    }

                    Ok(StateHandlerOutcome::Transition(
                        ManagedHostState::HostNotReady {
                            machine_state: MachineState::UefiSetup {
                                uefi_setup_info: UefiSetupInfo {
                                    uefi_password_jid: None,
                                    uefi_setup_state: UefiSetupState::SetUefiPassword,
                                },
                            },
                        },
                    ))
                }
                MachineState::UefiSetup { uefi_setup_info } => {
                    Ok(handle_host_uefi_setup(txn, ctx, state, uefi_setup_info.clone()).await?)
                }
                MachineState::WaitingForLockdown { lockdown_info } => {
                    match lockdown_info.state {
                        LockdownState::TimeWaitForDPUDown => {
                            // Lets wait for some time before checking if DPU is up or not.
                            // Waiting is needed because DPU takes some time to go down. If we check DPU
                            // reachability before it goes down, it will give us wrong result.
                            if wait(
                                &state.host_snapshot.current.version.timestamp(),
                                self.host_handler_params.reachability_params.dpu_wait_time,
                            ) {
                                Ok(StateHandlerOutcome::Wait(format!(
                                    "Forced wait of {} for DPU to power down",
                                    self.host_handler_params.reachability_params.dpu_wait_time
                                )))
                            } else {
                                let next_state = ManagedHostState::HostNotReady {
                                    machine_state: MachineState::WaitingForLockdown {
                                        lockdown_info: LockdownInfo {
                                            state: LockdownState::WaitForDPUUp,
                                            mode: lockdown_info.mode.clone(),
                                        },
                                    },
                                };
                                Ok(StateHandlerOutcome::Transition(next_state))
                            }
                        }
                        LockdownState::WaitForDPUUp => {
                            // Has forge-dpu-agent reported state? That means DPU is up.
                            if dpus_up(state) {
                                // reboot host
                                // When forge changes BIOS params (for lockdown enable/disable both), host does a power cycle.
                                // During power cycle, DPU also reboots. Now DPU and Host are coming up together. Since DPU is not ready yet,
                                // it does not forward DHCP discover from host and host goes into failure mode and stops sending further
                                // DHCP Discover. A second reboot starts DHCP cycle again when DPU is already up.

                                handler_host_power_control(
                                    state,
                                    ctx.services,
                                    SystemPowerControl::ForceRestart,
                                    txn,
                                )
                                .await?;
                                if LockdownMode::Enable == lockdown_info.mode {
                                    purge_machine_validation_results(
                                        &state.host_snapshot.machine_id,
                                        "Discovery".to_string(),
                                        txn,
                                    )
                                    .await?;
                                    let current_machine_validation_id = uuid::Uuid::new_v4();

                                    Machine::update_current_machine_validation_id(
                                        &state.host_snapshot.machine_id,
                                        current_machine_validation_id,
                                        txn,
                                    )
                                    .await?;
                                    let next_state = ManagedHostState::HostNotReady {
                                        machine_state: MachineState::MachineValidating {
                                            context: "Discovery".to_string(),
                                            id: current_machine_validation_id,
                                            completed: 1,
                                            total: 1,
                                        },
                                    };
                                    Ok(StateHandlerOutcome::Transition(next_state))
                                } else {
                                    // We have not implemented LockdownMode::Disabled. This is a kind of placeholder for it, but we never needed it.
                                    Ok(StateHandlerOutcome::DoNothing)
                                }
                            } else {
                                Ok(StateHandlerOutcome::Wait("Waiting for DPU to report UP by sending a network status observation".to_string()))
                            }
                        }
                    }
                }
                MachineState::Discovered => {
                    // Check if machine is rebooted. If yes, move to Ready state
                    // or Measuring state, depending on if machine attestation
                    // is enabled or not.
                    if rebooted(&state.host_snapshot) {
                        let next_state = if self.host_handler_params.attestation_enabled {
                            ManagedHostState::Measuring {
                                measuring_state: MeasuringState::WaitingForMeasurements,
                            }
                        } else {
                            ManagedHostState::Ready
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    } else {
                        let status = trigger_reboot_if_needed(
                            &state.host_snapshot,
                            state,
                            None,
                            &self.host_handler_params.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;
                        Ok(StateHandlerOutcome::Wait(status.status))
                    }
                }
                MachineState::WaitingForNetworkInstall => {
                    tracing::warn!(
                        "Invalid State WaitingForNetworkConfig for Host Machine {}",
                        host_machine_id
                    );
                    Err(StateHandlerError::InvalidHostState(
                        host_machine_id.clone(),
                        state.managed_state.clone(),
                    ))
                }
                MachineState::MachineValidating {
                    context,
                    id,
                    completed,
                    total,
                } => {
                    tracing::info!(
                        "context = {} id = {} completed = {} total = {}",
                        context,
                        id,
                        completed,
                        total
                    );
                    // Host validation completed
                    if machine_validation_completed(&state.host_snapshot) {
                        if state.host_snapshot.failure_details.cause == FailureCause::NoError {
                            tracing::info!(
                                "{} machine validation completed",
                                state.host_snapshot.machine_id
                            );
                            handler_host_power_control(
                                state,
                                ctx.services,
                                SystemPowerControl::ForceRestart,
                                txn,
                            )
                            .await?;
                            return Ok(StateHandlerOutcome::Transition(
                                ManagedHostState::HostNotReady {
                                    machine_state: MachineState::Discovered,
                                },
                            ));
                        } else {
                            tracing::info!(
                                "{} machine validation failed",
                                state.host_snapshot.machine_id
                            );
                            return Ok(StateHandlerOutcome::Transition(ManagedHostState::Failed {
                                details: state.host_snapshot.failure_details.clone(),
                                machine_id: state.host_snapshot.machine_id.clone(),
                                retry_count: 0,
                            }));
                        }
                    } else {
                        tracing::info!(
                            "{} machine validation failed",
                            state.host_snapshot.machine_id
                        );
                    }
                    Ok(StateHandlerOutcome::DoNothing)
                }
            }
        } else {
            Err(StateHandlerError::InvalidHostState(
                host_machine_id.clone(),
                state.managed_state.clone(),
            ))
        }
    }
}

/// A `StateHandler` implementation for instances
#[derive(Debug, Clone)]
pub struct InstanceStateHandler {
    dpu_nic_firmware_reprovision_update_enabled: bool,
    reachability_params: ReachabilityParams,
}

impl InstanceStateHandler {
    pub fn new(
        dpu_nic_firmware_reprovision_update_enabled: bool,
        reachability_params: ReachabilityParams,
    ) -> Self {
        InstanceStateHandler {
            dpu_nic_firmware_reprovision_update_enabled,
            reachability_params,
        }
    }
}

#[async_trait::async_trait]
impl StateHandler for InstanceStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
        let Some(ref instance) = state.instance else {
            return Err(StateHandlerError::GenericError(eyre!(
                "Instance is empty at this point. Cleanup is needed for host: {}.",
                host_machine_id
            )));
        };

        if let ManagedHostState::Assigned { instance_state } = &state.managed_state {
            match instance_state {
                InstanceState::Init => {
                    // we should not be here. This state to be used if state machine has not
                    // picked instance creation and user asked for status.
                    Err(StateHandlerError::InvalidHostState(
                        host_machine_id.clone(),
                        state.managed_state.clone(),
                    ))
                }
                InstanceState::WaitingForNetworkConfig => {
                    // It should be first state to process here.
                    // Wait for instance network config to be applied
                    // Reboot host and moved to Ready.

                    // TODO GK if delete_requested skip this whole step,
                    // reboot and jump to BootingWithDiscoveryImage

                    // Check DPU network config has been applied
                    if !is_network_ready(&state.dpu_snapshots) {
                        return Ok(StateHandlerOutcome::Wait(
                            "Waiting for DPU agent to apply network config and report healthy network"
                                .to_string(),
                        ));
                    }
                    // Check instance network config has been applied
                    let expected = &instance.network_config_version;
                    let actual = match &instance.observations.network {
                        None => {
                            return Ok(StateHandlerOutcome::Wait(
                                "Waiting for DPU agent to apply initial network config".to_string(),
                            ));
                        }
                        Some(network_status) => &network_status.config_version,
                    };
                    if expected != actual {
                        return Ok(StateHandlerOutcome::Wait(
                            "Waiting for DPU agent to apply most recent network config".to_string(),
                        ));
                    }

                    bind_ib_ports(
                        ctx.services,
                        txn,
                        instance.instance_id,
                        instance.config.infiniband.ib_interfaces.clone(),
                    )
                    .await?;

                    record_infiniband_status_observation(
                        ctx.services,
                        txn,
                        instance,
                        instance.config.infiniband.ib_interfaces.clone(),
                    )
                    .await?;

                    // Reboot host
                    handler_host_power_control(
                        state,
                        ctx.services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;

                    // Instance is ready.
                    // We can not determine if machine is rebooted successfully or not. Just leave
                    // it like this and declare Instance Ready.
                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::Ready,
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::Ready => {
                    // Machine is up after reboot. Hurray. Instance is up.

                    // Wait for user's approval. Once user approves for dpu
                    // reprovision/update firmware, trigger it.
                    // TODO: multidpu: Check for all DPUs
                    let reprov_needed = if let Some(reprovisioning_requested) =
                        dpu_reprovisioning_needed(&state.dpu_snapshots[0])
                    {
                        reprovisioning_requested.user_approval_received
                    } else {
                        false
                    };

                    if instance.delete_requested || reprov_needed {
                        if reprov_needed {
                            // User won't be allowed to clear reprovisioning flag after this.
                            Machine::update_dpu_reprovision_start_time(
                                &state.dpu_snapshots[0].machine_id,
                                txn,
                            )
                            .await?;
                        }

                        // Reboot host. Host will boot with carbide discovery image now. Changes
                        // are done in get_pxe_instructions api.
                        // User will loose all access to instance now.
                        if let Err(err) = handler_host_power_control(
                            state,
                            ctx.services,
                            SystemPowerControl::ForceRestart,
                            txn,
                        )
                        .await
                        {
                            // Fix: 4647451
                            // No need to return if reboot fails. The managedhost will move to next
                            // state (BootingWithDiscoveryImage) and recovery code will try to
                            // reboot after certain time, if machine does not respond.
                            tracing::error!(%host_machine_id, "Host reboot failed with error: {err}");
                        }

                        let next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::BootingWithDiscoveryImage {
                                retry: RetryInfo { count: 0 },
                            },
                        };
                        Ok(StateHandlerOutcome::Transition(next_state))
                    } else {
                        record_infiniband_status_observation(
                            ctx.services,
                            txn,
                            instance,
                            instance.config.infiniband.ib_interfaces.clone(),
                        )
                        .await?;
                        Ok(StateHandlerOutcome::DoNothing)
                    }
                }
                InstanceState::BootingWithDiscoveryImage { retry } => {
                    if !rebooted(&state.host_snapshot) {
                        let status = trigger_reboot_if_needed(
                            &state.host_snapshot,
                            state,
                            // can't send 0. 0 will force power-off as cycle calculator.
                            Some(retry.count as i64 + 1),
                            &self.reachability_params,
                            ctx.services,
                            txn,
                        )
                        .await?;

                        let st = if status.increase_retry_count {
                            let next_state = ManagedHostState::Assigned {
                                instance_state: InstanceState::BootingWithDiscoveryImage {
                                    retry: RetryInfo {
                                        count: retry.count + 1,
                                    },
                                },
                            };
                            StateHandlerOutcome::Transition(next_state)
                        } else {
                            StateHandlerOutcome::Wait(status.status)
                        };
                        return Ok(st);
                    }

                    // Now retry_count won't exceed a limit. Function trigger_reboot_if_needed does
                    // not reboot a machine after 6 hrs, so this counter won't increase at all
                    // after 6 hours.
                    ctx.metrics
                        .machine_reboot_attempts_in_booting_with_discovery_image =
                        Some(retry.count + 1);

                    // In case state is triggered for delete instance handling, follow that path.
                    if instance.delete_requested {
                        let next_state = ManagedHostState::Assigned {
                            instance_state: InstanceState::SwitchToAdminNetwork,
                        };
                        return Ok(StateHandlerOutcome::Transition(next_state));
                    }

                    // If we are here, DPU reprov MUST have been be requested.
                    // TODO: multidpu: Check for all DPUs
                    if let Some(reprovisioning_requested) =
                        dpu_reprovisioning_needed(&state.dpu_snapshots[0])
                    {
                        // If we are here, it is definitely because user has already given
                        // approval, but a repeat check doesn't harm anyway.
                        if reprovisioning_requested.user_approval_received {
                            handler_restart_dpu(&state.dpu_snapshots[0], ctx.services, txn).await?;
                            let next_state = ManagedHostState::Assigned {
                                instance_state: InstanceState::DPUReprovision {
                                    reprovision_state: if reprovisioning_requested.update_firmware
                                        && self.dpu_nic_firmware_reprovision_update_enabled
                                    {
                                        ReprovisionState::FirmwareUpgrade
                                    } else {
                                        set_managed_host_topology_update_needed(txn, state).await?;
                                        ReprovisionState::WaitingForNetworkInstall
                                    },
                                },
                            };
                            Ok(StateHandlerOutcome::Transition(next_state))
                        } else {
                            Ok(StateHandlerOutcome::Wait(
                                "Waiting for user approval for DPU reprovision".to_string(),
                            ))
                        }
                    } else {
                        // TODO what do we do here? Is this unreachable?
                        Ok(StateHandlerOutcome::DoNothing)
                    }
                }

                InstanceState::SwitchToAdminNetwork => {
                    // Tenant is gone and so is their network, switch back to admin network
                    for dpu_snapshot in &state.dpu_snapshots {
                        let (mut netconf, version) = dpu_snapshot.network_config.clone().take();
                        netconf.use_admin_network = Some(true);
                        Machine::try_update_network_config(
                            txn,
                            &dpu_snapshot.machine_id,
                            version,
                            &netconf,
                        )
                        .await?;
                    }

                    let next_state = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkReconfig,
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::WaitingForNetworkReconfig => {
                    // Has forge-dpu-agent written the network config?
                    if !is_network_ready(&state.dpu_snapshots) {
                        return Ok(StateHandlerOutcome::Wait(
                            "Waiting for DPU agent to apply network config and report healthy network"
                                .to_string(),
                        ));
                    }

                    unbind_ib_ports(
                        ctx.services,
                        txn,
                        instance.instance_id,
                        instance.config.infiniband.ib_interfaces.clone(),
                    )
                    .await?;

                    // Delete from database now. Once done, reboot and move to next state.
                    DeleteInstance {
                        instance_id: instance.instance_id,
                    }
                    .delete(txn)
                    .await
                    .map_err(|err| StateHandlerError::GenericError(err.into()))?;

                    // TODO: TPM cleanup
                    // Reboot host
                    handler_host_power_control(
                        state,
                        ctx.services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;

                    let next_state = ManagedHostState::WaitingForCleanup {
                        cleanup_state: CleanupState::HostCleanup,
                    };
                    Ok(StateHandlerOutcome::Transition(next_state))
                }
                InstanceState::DPUReprovision { reprovision_state } => {
                    match handle_dpu_reprovision(
                        reprovision_state,
                        state,
                        &self.reachability_params,
                        ctx.services,
                        txn,
                        &InstanceNextStateResolver,
                    )
                    .await?
                    {
                        Some(next_state) => Ok(StateHandlerOutcome::Transition(next_state)),
                        None => {
                            // TODO handle_dpu_reprovision should return StateHandlerOutcome
                            // so that we can be specific here
                            Ok(StateHandlerOutcome::Wait(
                                "Waiting for DPU reprovision".to_string(),
                            ))
                        }
                    }
                }
            }
        } else {
            // We are not in Assigned state. Should this be Err(StateHandlerError::InvalidHostState)?
            Ok(StateHandlerOutcome::DoNothing)
        }
    }
}

async fn record_infiniband_status_observation(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance: &InstanceSnapshot,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<ib_partition::IBPartitionId, Vec<String>>::new();

    for ib in &ib_interfaces {
        let guid = ib.guid.clone().ok_or(StateHandlerError::MissingData {
            object_id: instance.instance_id.to_string(),
            missing: "GUID of IB Port",
        })?;

        ibconf.entry(ib.ib_partition_id).or_default().push(guid);
    }

    if ibconf.is_empty() {
        // Update an empty record for ib.
        let status = InstanceInfinibandStatusObservation {
            config_version: instance.ib_config_version,
            ib_interfaces: vec![],
            observed_at: Utc::now(),
        };
        Instance::update_infiniband_status_observation(txn, instance.instance_id, &status).await?;

        return Ok(());
    }

    let ib_fabric = services
        .ib_fabric_manager
        .connect(DEFAULT_IB_FABRIC_NAME)
        .await
        .map_err(|x| {
            StateHandlerError::IBFabricError(format!("Failed to connect to fabric manager: {x}"))
        })?;

    let mut ib_interfaces_status = Vec::with_capacity(ib_interfaces.len());

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            ib_partition::IBPartitionIdKeyedObjectFilter::One(k),
            ib_partition::IBPartitionSearchConfig {
                include_history: false,
            },
        )
        .await?;

        let ibpartition = ib_partitions
            .first()
            .ok_or(StateHandlerError::MissingData {
                object_id: k.to_string(),
                missing: "ib_partition not found",
            })?;

        // Get the status of ports from UFM, and persist it as observed status.
        let filter = ib::Filter {
            guids: Some(v),
            pkey: ibpartition.config.pkey,
        };
        let ports = ib_fabric
            .find_ib_port(Some(filter))
            .await
            .map_err(|err| StateHandlerError::GenericError(err.into()))?;

        ib_interfaces_status.extend(
            ports
                .iter()
                .map(InstanceIbInterfaceStatusObservation::from)
                .collect::<Vec<_>>(),
        );
    }

    if ib_interfaces.len() != ib_interfaces_status.len() {
        return Err(StateHandlerError::InvalidState(format!(
            "{} infiniband interfaces with {} statuses",
            ib_interfaces.len(),
            ib_interfaces_status.len()
        )));
    }

    let status = InstanceInfinibandStatusObservation {
        config_version: instance.ib_config_version,
        ib_interfaces: ib_interfaces_status,
        observed_at: Utc::now(),
    };
    Instance::update_infiniband_status_observation(txn, instance.instance_id, &status).await?;

    Ok(())
}

async fn bind_ib_ports(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: InstanceId,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<ib_partition::IBPartitionId, Vec<String>>::new();
    for ib in ib_interfaces {
        let guid = ib.guid.ok_or(StateHandlerError::MissingData {
            object_id: instance_id.to_string(),
            missing: "GUID of IB Port",
        })?;

        ibconf.entry(ib.ib_partition_id).or_default().push(guid);
    }

    if ibconf.is_empty() {
        return Ok(());
    }

    let ib_fabric = services
        .ib_fabric_manager
        .connect(DEFAULT_IB_FABRIC_NAME)
        .await
        .map_err(|_| StateHandlerError::IBFabricError("can not get IB fabric".to_string()))?;

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            ib_partition::IBPartitionIdKeyedObjectFilter::One(k),
            ib_partition::IBPartitionSearchConfig {
                include_history: false,
            },
        )
        .await?;

        let ibpartition = ib_partitions
            .first()
            .ok_or(StateHandlerError::MissingData {
                object_id: k.to_string(),
                missing: "ib_partition not found",
            })?;

        ib_fabric
            .bind_ib_ports(IBNetwork::from(ibpartition), v)
            .await
            .map_err(|_| StateHandlerError::IBFabricError("bind_ib_ports".to_string()))?;
    }

    Ok(())
}

async fn unbind_ib_ports(
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: InstanceId,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<ib_partition::IBPartitionId, Vec<String>>::new();

    for ib in ib_interfaces {
        let guid = ib.guid.ok_or(StateHandlerError::MissingData {
            object_id: instance_id.to_string(),
            missing: "GUID of IB Port",
        })?;
        ibconf.entry(ib.ib_partition_id).or_default().push(guid);
    }

    if ibconf.is_empty() {
        return Ok(());
    }

    let ib_fabric = services
        .ib_fabric_manager
        .connect(DEFAULT_IB_FABRIC_NAME)
        .await
        .map_err(|_| StateHandlerError::IBFabricError("can not get IB fabric".to_string()))?;

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            ib_partition::IBPartitionIdKeyedObjectFilter::One(k),
            ib_partition::IBPartitionSearchConfig {
                include_history: false,
            },
        )
        .await?;

        let ibpartition = ib_partitions
            .first()
            .ok_or(StateHandlerError::MissingData {
                object_id: k.to_string(),
                missing: "ib_partition not found",
            })?;
        let pkey = ibpartition
            .config
            .pkey
            .ok_or(StateHandlerError::MissingData {
                object_id: ibpartition.id.to_string(),
                missing: "ib_partition pkey",
            })?;

        ib_fabric
            .unbind_ib_ports(pkey, v)
            .await
            .map_err(|_| StateHandlerError::IBFabricError("unbind_ib_ports".to_string()))?;
    }

    Ok(())
}

/// Issues a reboot request command to a host or DPU
async fn handler_restart_dpu(
    machine_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StateHandlerError> {
    restart_dpu(machine_snapshot, services, txn).await?;

    Machine::update_reboot_requested_time(
        &machine_snapshot.machine_id,
        txn,
        crate::model::machine::MachineLastRebootRequestedMode::Reboot,
    )
    .await
    .map_err(|err| err.into())
    //handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn).await
}

async fn purge_machine_validation_results(
    _machine_id: &MachineId,
    _context: String,
    _txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StateHandlerError> {
    // MachineValidationResult::delete_by_context(txn, context, machine_id).await?;
    Ok(())
}

async fn host_power_state(
    redfish_client: &dyn Redfish,
) -> Result<libredfish::PowerState, StateHandlerError> {
    redfish_client
        .get_power_state()
        .await
        .map_err(|e| StateHandlerError::RedfishError {
            operation: "get_power_state",
            error: e,
        })
}

pub async fn handler_host_power_control(
    managedhost_snapshot: &ManagedHostStateSnapshot,
    services: &StateHandlerServices,
    action: SystemPowerControl,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StateHandlerError> {
    let redfish_client = build_redfish_client_from_machine_snapshot(
        &managedhost_snapshot.host_snapshot,
        &services.redfish_client_pool,
        txn,
    )
    .await?;

    host_power_control(
        redfish_client.as_ref(),
        &managedhost_snapshot.host_snapshot,
        action,
        services.ipmi_tool.clone(),
        txn,
    )
    .await
    .map_err(|e| {
        StateHandlerError::GenericError(eyre!("handler_host_power_control failed: {}", e))
    })?;

    // If host is forcedOff/On, it will impact DPU also. So DPU timestamp should also be updated
    // here.
    if action == SystemPowerControl::ForceOff || action == SystemPowerControl::On {
        for dpu_snapshot in &managedhost_snapshot.dpu_snapshots {
            Machine::update_reboot_requested_time(&dpu_snapshot.machine_id, txn, action.into())
                .await?;
        }
    }

    Ok(())
}

async fn restart_dpu(
    machine_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StateHandlerError> {
    let maybe_ip =
        machine_snapshot
            .bmc_info
            .ip
            .clone()
            .ok_or_else(|| StateHandlerError::MissingData {
                object_id: machine_snapshot.machine_id.to_string(),
                missing: "bmc_info.ip",
            })?;

    let ip = maybe_ip
        .parse()
        .map_err(|_| StateHandlerError::MissingData {
            object_id: machine_snapshot.machine_id.to_string(),
            missing: "bmc_info.ip is not an ip address",
        })?;

    let machine_interface_target =
        MachineInterface::find_by_ip(txn, ip)
            .await?
            .ok_or_else(|| StateHandlerError::MissingData {
                object_id: machine_snapshot.machine_id.to_string(),
                missing: "machine interface for bmc_info.ip",
            })?;

    let credential_key = CredentialKey::BmcCredentials {
        // TODO(ajf): Change this to Forge Admin user once site explorer
        // ensures it exist, credentials are done by mac address
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: machine_interface_target.mac_address,
        },
    };

    services
        .ipmi_tool
        .restart(&machine_snapshot.machine_id, ip, true, credential_key)
        .await
        .map_err(|e: eyre::ErrReport| {
            StateHandlerError::GenericError(eyre!("IPMI failed to restart machine: {}", e))
        })?;

    Ok(())
}

/// Issues a lockdown and reboot request command to a host.
async fn lockdown_host(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &ManagedHostStateSnapshot,
    services: &StateHandlerServices,
) -> Result<(), StateHandlerError> {
    let host_snapshot = &state.host_snapshot;
    let redfish_client = build_redfish_client_from_machine_snapshot(
        host_snapshot,
        &services.redfish_client_pool,
        txn,
    )
    .await?;

    // the forge_setup call includes the equivalent of these calls internally in libredfish
    // - serial setup (bios, bmc)
    // - tpm clear (bios)
    // - boot once to pxe
    redfish_client
        .forge_setup()
        .await
        .map_err(|e| StateHandlerError::RedfishError {
            operation: "forge_setup",
            error: e,
        })?;

    redfish_client
        .lockdown(libredfish::EnabledDisabled::Enabled)
        .await
        .map_err(|e| StateHandlerError::RedfishError {
            operation: "lockdown",
            error: e,
        })?;

    tracing::info!("Forcing restart");

    handler_host_power_control(state, services, SystemPowerControl::ForceRestart, txn).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_cycle_1() {
        let state_change_time =
            chrono::DateTime::<Utc>::from_str("2024-01-30T11:26:18.261228950+00:00").unwrap();

        let expected_time = state_change_time + Duration::minutes(30);
        let wait_period = Duration::minutes(30);

        let cycle = get_reboot_cycle(expected_time, state_change_time, wait_period).unwrap();
        assert_eq!(cycle, 1);
    }

    #[test]
    fn test_cycle_2() {
        let state_change_time =
            chrono::DateTime::<Utc>::from_str("2024-01-30T11:26:18.261228950+00:00").unwrap();

        let expected_time = state_change_time + Duration::minutes(70);
        let wait_period = Duration::minutes(30);

        let cycle = get_reboot_cycle(expected_time, state_change_time, wait_period).unwrap();
        assert_eq!(cycle, 2);
    }

    #[test]
    fn test_cycle_3() {
        let state_change_time =
            chrono::DateTime::<Utc>::from_str("2024-01-30T11:26:18.261228950+00:00").unwrap();

        let expected_time = state_change_time + Duration::minutes(121);
        let wait_period = Duration::minutes(30);

        let cycle = get_reboot_cycle(expected_time, state_change_time, wait_period).unwrap();
        assert_eq!(cycle, 4);
    }

    #[test]
    fn test_cycle_4() {
        let state_change_time =
            chrono::DateTime::<Utc>::from_str("2024-01-30T11:26:18.261228950+00:00").unwrap();

        let expected_time = state_change_time + Duration::minutes(30);
        let wait_period = Duration::minutes(0);

        let cycle = get_reboot_cycle(expected_time, state_change_time, wait_period).unwrap();
        assert_eq!(cycle, 30);
    }
}
