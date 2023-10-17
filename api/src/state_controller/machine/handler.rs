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
use eyre::eyre;

use crate::{
    db::{
        ib_partition,
        instance::{
            status::infiniband::update_instance_infiniband_status_observation, DeleteInstance,
        },
        machine::Machine,
        machine_topology::MachineTopology,
    },
    ib,
    ib::types::IBNetwork,
    model::{
        config_version::ConfigVersion,
        instance::config::infiniband::InstanceIbInterfaceConfig,
        instance::snapshot::InstanceSnapshot,
        instance::status::infiniband::{
            InstanceIbInterfaceStatusObservation, InstanceInfinibandStatusObservation,
        },
        machine::{
            machine_id::MachineId,
            network::HealthStatus,
            CleanupState, FailureCause, FailureDetails, InstanceNextStateResolver, InstanceState,
            LockdownInfo,
            LockdownMode::{self, Enable},
            LockdownState, MachineNextStateResolver, MachineSnapshot, MachineState,
            ManagedHostState, ManagedHostStateSnapshot, NextReprovisionState, ReprovisionRequest,
            ReprovisionState,
        },
    },
    redfish::RedfishCredentialType,
    state_controller::{
        machine::metrics::MachineMetrics,
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
        },
    },
};

/// The actual Machine State handler
#[derive(Debug)]
pub struct MachineStateHandler {
    host_handler: HostMachineStateHandler,
    dpu_handler: DpuMachineStateHandler,
    instance_handler: InstanceStateHandler,
    dpu_up_threshold: chrono::Duration,
}

impl MachineStateHandler {
    pub fn new(dpu_up_threshold: chrono::Duration) -> Self {
        MachineStateHandler {
            dpu_up_threshold,
            host_handler: Default::default(),
            dpu_handler: Default::default(),
            instance_handler: Default::default(),
        }
    }
}

/// Conveninence function for the tests
impl Default for MachineStateHandler {
    fn default() -> Self {
        Self::new(chrono::Duration::minutes(5))
    }
}

/// This function checks if reprovisoning is requested of a given DPU or not.
/// It also returns if firmware upgrade is needed.
fn dpu_reprovisioning_needed(dpu_snapshot: &MachineSnapshot) -> Option<ReprovisionRequest> {
    dpu_snapshot.reprovision_requested.clone()
}

// Function to wait for some time in state machine.
fn wait(state: &ManagedHostStateSnapshot, wait_time: Duration) -> bool {
    // Lets wait for some time before checking if DPU is up or not.
    // Waiting is needed because DPU takes some time to go down. If we check DPU
    // reachability before it goes down, it will give us wrong result.
    let expected_time = state.host_snapshot.current.version.timestamp() + wait_time;
    let current_time = Utc::now();

    current_time < expected_time
}

/// if dpu_agent has responded health after dpu is rebooted, return true.
fn is_dpu_up(state: &ManagedHostStateSnapshot) -> bool {
    let observation_time = state
        .dpu_snapshot
        .network_status_observation
        .as_ref()
        .map(|o| o.observed_at)
        .unwrap_or(DateTime::<Utc>::MIN_UTC);
    let state_change_time = state.host_snapshot.current.version.timestamp();

    observation_time >= state_change_time
}

fn is_dpu_up_and_network_ready(state: &ManagedHostStateSnapshot) -> bool {
    if !is_dpu_up(state) {
        return false;
    }

    if !is_network_ready(&state.dpu_snapshot) {
        return false;
    }

    true
}

#[async_trait::async_trait]
impl StateHandler for MachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ObjectMetrics = MachineMetrics;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        metrics: &mut Self::ObjectMetrics,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let managed_state = &state.managed_state;

        metrics.dpu_firmware_version = state
            .dpu_snapshot
            .hardware_info
            .as_ref()
            .and_then(|hi| hi.dpu_info.as_ref().map(|di| di.firmware_version.clone()));

        // Update DPU network health Prometheus metrics
        metrics.dpu_healthy = state.dpu_snapshot.has_healthy_network();
        if let Some(observation) = state.dpu_snapshot.network_status_observation.as_ref() {
            metrics.agent_version = observation.agent_version.clone();
            metrics.dpu_up =
                Utc::now().signed_duration_since(observation.observed_at) <= self.dpu_up_threshold;
            for failed in &observation.health_status.failed {
                metrics.failed_dpu_healthchecks.insert(failed.clone());
            }
        }

        // If it's been more than 5 minutes since DPU reported status, consider it unhealthy
        if state.dpu_snapshot.has_healthy_network() {
            if let Some(mut observation) =
                state.dpu_snapshot.network_status_observation.clone().take()
            {
                let observed_at = observation.observed_at;
                let since_last_seen = Utc::now().signed_duration_since(observed_at);
                if since_last_seen > self.dpu_up_threshold {
                    observation.health_status = HealthStatus {
                        is_healthy: false,
                        passed: vec![],
                        failed: vec!["HeartbeatTimeout".to_string()],
                        message: Some(format!("Last seen over {} ago", self.dpu_up_threshold)),
                    };
                    observation.observed_at = Utc::now();
                    let dpu_machine_id = &state.dpu_snapshot.machine_id;
                    Machine::update_network_status_observation(txn, dpu_machine_id, &observation)
                        .await?;
                    tracing::warn!(
                        host_machine_id = %host_machine_id,
                        dpu_machine_id = %dpu_machine_id,
                        last_seen = %observed_at,
                        "DPU is not sending network status observations, marking unhealthy");
                    // The next iteration will run with the now unhealthy network
                    return Ok(());
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
                    state.dpu_snapshot.machine_id,
                    machine_id,
                    details
                );
                *controller_state.modify() = ManagedHostState::Failed {
                    details,
                    machine_id,
                };
                return Ok(());
            }
        }

        match &managed_state {
            ManagedHostState::DPUNotReady { .. } => {
                self.dpu_handler
                    .handle_object_state(
                        host_machine_id,
                        state,
                        controller_state,
                        txn,
                        metrics,
                        ctx,
                    )
                    .await?;
            }

            ManagedHostState::HostNotReady { .. } => {
                self.host_handler
                    .handle_object_state(
                        host_machine_id,
                        state,
                        controller_state,
                        txn,
                        metrics,
                        ctx,
                    )
                    .await?;
            }

            ManagedHostState::Ready => {
                // Check if DPU reprovisioing is requested
                if let Some(reprovisioning_requested) =
                    dpu_reprovisioning_needed(&state.dpu_snapshot)
                {
                    restart_machine(&state.dpu_snapshot, ctx).await?;
                    *controller_state.modify() = ManagedHostState::DPUReprovision {
                        reprovision_state: if reprovisioning_requested.update_firmware {
                            ReprovisionState::FirmwareUpgrade
                        } else {
                            set_managed_host_topology_update_needed(txn, state).await?;
                            ReprovisionState::WaitingForNetworkInstall
                        },
                    };

                    return Ok(());
                }

                // Check if instance to be created.
                if state.instance.is_some() {
                    // Instance is requested by user. Let's configure it.

                    // Switch to using the network we just created for the tenant
                    let (mut netconf, version) = state.dpu_snapshot.network_config.clone().take();
                    netconf.use_admin_network = Some(false);
                    Machine::try_update_network_config(
                        txn,
                        &state.dpu_snapshot.machine_id,
                        version,
                        &netconf,
                    )
                    .await?;

                    *controller_state.modify() = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkConfig,
                    };
                }
            }

            ManagedHostState::Assigned { instance_state: _ } => {
                // Process changes needed for instance.
                self.instance_handler
                    .handle_object_state(
                        host_machine_id,
                        state,
                        controller_state,
                        txn,
                        metrics,
                        ctx,
                    )
                    .await?;
            }

            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                match cleanup_state {
                    CleanupState::HostCleanup => {
                        if !cleanedup_after_state_transition(
                            state.host_snapshot.current.version,
                            state.host_snapshot.last_cleanup_time,
                        )
                        .await?
                        {
                            return Ok(());
                        }

                        // Reboot host
                        restart_machine(&state.host_snapshot, ctx).await?;

                        *controller_state.modify() = ManagedHostState::HostNotReady {
                            machine_state: MachineState::Discovered,
                        };
                    }
                    CleanupState::DisableBIOSBMCLockdown => {
                        tracing::error!(
                            machine_id = %host_machine_id,
                            "DisableBIOSBMCLockdown state is not implemented. Machine stuck in unimplemented state.",
                        );
                    }
                }
            }
            ManagedHostState::Created => {
                tracing::error!("Machine just created. We should not be here.");
            }
            ManagedHostState::ForceDeletion => {
                // Just ignore.
                tracing::info!(
                    machine_id = %host_machine_id,
                    "Machine is marked for forced deletion. Ignoring.",
                );
            }
            ManagedHostState::Failed {
                details,
                machine_id,
            } => {
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
            }

            ManagedHostState::DPUReprovision { reprovision_state } => {
                if let Some(new_state) = handle_dpu_reprovision(
                    reprovision_state,
                    state,
                    ctx,
                    txn,
                    &MachineNextStateResolver,
                )
                .await?
                {
                    *controller_state.modify() = new_state;
                }
            }
        }

        Ok(())
    }
}

/// Handle workflow of DPU reprovision
async fn handle_dpu_reprovision(
    reprovision_state: &ReprovisionState,
    state: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_>,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    next_state_resolver: &impl NextReprovisionState,
) -> Result<Option<ManagedHostState>, StateHandlerError> {
    match reprovision_state {
        ReprovisionState::FirmwareUpgrade => {
            // Firmware upgrade is going on.
            if !rebooted(
                state.dpu_snapshot.current.version,
                state.dpu_snapshot.last_reboot_time,
            )
            .await?
            {
                return Ok(None);
            }

            restart_machine(&state.dpu_snapshot, ctx).await?;
            set_managed_host_topology_update_needed(txn, state).await?;
            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
        ReprovisionState::WaitingForNetworkInstall => {
            if (try_wait_for_dpu_discovery_and_reboot(state, ctx).await?).is_pending() {
                return Ok(None);
            }

            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
        ReprovisionState::BufferTime => {
            // This state just waits for some time to avoid race condition where
            // dpu_agent sends heartbeat just before DPU goes down. A few microseconds
            // gap can cause host to restart before DPU comes up. This will fail Host
            // DHCP.
            // TODO: Reduce this duration to 2 mins.
            if wait(state, ctx.services.reachability_params.dpu_wait_time) {
                return Ok(None);
            }
            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
        ReprovisionState::WaitingForNetworkConfig => {
            if !is_dpu_up_and_network_ready(state) {
                return Ok(None);
            }

            // Clear reprovisioning state.
            Machine::clear_reprovisioning_request(txn, &state.dpu_snapshot.machine_id)
                .await
                .map_err(StateHandlerError::from)?;
            restart_host(&state.host_snapshot, ctx).await?;

            // We need to wait for the host to reboot and submit it's new Hardware information in
            // case of Ready.
            Ok(Some(next_state_resolver.next_state(reprovision_state)))
        }
    }
}

/// This function waits for DPU to finish discovery and reboots it.
async fn try_wait_for_dpu_discovery_and_reboot(
    state: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_>,
) -> Result<Poll<()>, StateHandlerError> {
    // We are waiting for the `DiscoveryCompleted` RPC call to update the
    // `last_discovery_time` timestamp.
    // This indicates that all forge-scout actions have succeeded.
    if !discovered_after_state_transition(
        state.dpu_snapshot.current.version,
        state.dpu_snapshot.last_discovery_time,
    )
    .await?
    {
        return Ok(Poll::Pending);
    }

    restart_machine(&state.dpu_snapshot, ctx).await?;

    Ok(Poll::Ready(()))
}

async fn set_managed_host_topology_update_needed(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    state: &ManagedHostStateSnapshot,
) -> Result<(), StateHandlerError> {
    //Update it for host and DPU both.
    MachineTopology::set_topology_update_needed(txn, &state.dpu_snapshot.machine_id, true).await?;
    MachineTopology::set_topology_update_needed(txn, &state.host_snapshot.machine_id, true).await?;
    Ok(())
}

/// This function returns failure cause for both host and dpu.
fn get_failed_state(state: &ManagedHostStateSnapshot) -> Option<(MachineId, FailureDetails)> {
    // Return updated state only for errors which should cause machine to move into failed
    // state.
    if state.host_snapshot.failure_details.cause != FailureCause::NoError {
        Some((
            state.host_snapshot.machine_id.clone(),
            state.host_snapshot.failure_details.clone(),
        ))
    } else if state.dpu_snapshot.failure_details.cause != FailureCause::NoError {
        Some((
            state.dpu_snapshot.machine_id.clone(),
            state.dpu_snapshot.failure_details.clone(),
        ))
    } else {
        None
    }
}

/// A `StateHandler` implementation for DPU machines
#[derive(Debug, Default)]
pub struct DpuMachineStateHandler {}

#[async_trait::async_trait]
impl StateHandler for DpuMachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ObjectMetrics = MachineMetrics;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _metrics: &mut Self::ObjectMetrics,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        match &state.managed_state {
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::Init,
            } => {
                // initial restart, firmware update and scout is run, first reboot of dpu discovery
                if (try_wait_for_dpu_discovery_and_reboot(state, ctx).await?).is_pending() {
                    return Ok(());
                }

                // the initial topology may be based on a different firmware version.  allow it to be
                // updated once the reboot completes and sends new data.
                MachineTopology::set_topology_update_needed(
                    txn,
                    &state.dpu_snapshot.machine_id,
                    true,
                )
                .await?;

                *controller_state.modify() = ManagedHostState::DPUNotReady {
                    machine_state: MachineState::WaitingForNetworkInstall,
                };
            }
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::WaitingForNetworkInstall,
            } => {
                if !rebooted(
                    // rebooted from the init state, where firmware is updated and scout is run
                    state.dpu_snapshot.current.version,
                    state.dpu_snapshot.last_reboot_time,
                )
                .await?
                {
                    return Ok(());
                }

                // hbn needs a restart to be able to come online, second reboot of dpu discovery
                restart_machine(&state.dpu_snapshot, ctx).await?;

                *controller_state.modify() = ManagedHostState::DPUNotReady {
                    machine_state: MachineState::WaitingForNetworkConfig,
                };
            }
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::WaitingForNetworkConfig,
            } => {
                if !is_network_ready(&state.dpu_snapshot) {
                    return Ok(());
                }

                *controller_state.modify() = ManagedHostState::HostNotReady {
                    machine_state: MachineState::WaitingForDiscovery,
                };
            }
            state => {
                tracing::warn!(machine_id = %host_machine_id, ?state, "Unhandled State for DPU machine");
            }
        }

        Ok(())
    }
}

pub async fn rebooted(
    version: ConfigVersion,
    last_reboot_time: Option<DateTime<Utc>>,
) -> Result<bool, StateHandlerError> {
    if last_reboot_time.unwrap_or_default() > version.timestamp() {
        // Machine is rebooted after state change.
        return Ok(true);
    }

    Ok(false)
}

pub async fn discovered_after_state_transition(
    version: ConfigVersion,
    last_discovery_time: Option<DateTime<Utc>>,
) -> Result<bool, StateHandlerError> {
    if last_discovery_time.unwrap_or_default() > version.timestamp() {
        // Machine is rebooted after state change.
        return Ok(true);
    }

    Ok(false)
}

pub async fn cleanedup_after_state_transition(
    version: ConfigVersion,
    last_cleanup_time: Option<DateTime<Utc>>,
) -> Result<bool, StateHandlerError> {
    if last_cleanup_time.unwrap_or_default() > version.timestamp() {
        // Machine is rebooted after state change.
        return Ok(true);
    }

    Ok(false)
}

/// A `StateHandler` implementation for host machines
#[derive(Debug, Default)]
pub struct HostMachineStateHandler {}

/// 1. Has the network config version that the host wants been applied by DPU?
/// 2. Is HBN reporting the network is healthy?
fn is_network_ready(dpu_snapshot: &MachineSnapshot) -> bool {
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

    (dpu_expected_version == dpu_observed_version) && dpu_snapshot.has_healthy_network()
}

#[async_trait::async_trait]
impl StateHandler for HostMachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ObjectMetrics = MachineMetrics;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _metrics: &mut Self::ObjectMetrics,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        if let ManagedHostState::HostNotReady { machine_state } = &state.managed_state {
            match machine_state {
                MachineState::Init => {
                    return Err(StateHandlerError::InvalidHostState(
                        host_machine_id.clone(),
                        state.managed_state.clone(),
                    ));
                }
                MachineState::WaitingForNetworkConfig => {
                    tracing::warn!(
                        machine_id = %host_machine_id,
                        "Invalid State WaitingForNetworkConfig for Host Machine",
                    );
                }
                MachineState::WaitingForDiscovery => {
                    if !discovered_after_state_transition(
                        state.dpu_snapshot.current.version,
                        state.host_snapshot.last_discovery_time,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                    // Enable Bios/BMC lockdown now.
                    lockdown_host(&state.host_snapshot, ctx, true).await?;

                    *controller_state.modify() = ManagedHostState::HostNotReady {
                        machine_state: MachineState::WaitingForLockdown {
                            lockdown_info: LockdownInfo {
                                state: LockdownState::TimeWaitForDPUDown,
                                mode: Enable,
                            },
                        },
                    };
                }

                MachineState::Discovered => {
                    // Check if machine is rebooted. If yes, move to Ready state.
                    if !rebooted(
                        state.dpu_snapshot.current.version,
                        state.host_snapshot.last_reboot_time,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                    // Machine is ready for Instance Creation.
                    *controller_state.modify() = ManagedHostState::Ready;
                }

                MachineState::WaitingForLockdown { lockdown_info } => {
                    match lockdown_info.state {
                        LockdownState::TimeWaitForDPUDown => {
                            // Lets wait for some time before checking if DPU is up or not.
                            // Waiting is needed because DPU takes some time to go down. If we check DPU
                            // reachability before it goes down, it will give us wrong result.
                            if !wait(state, ctx.services.reachability_params.dpu_wait_time) {
                                *controller_state.modify() = ManagedHostState::HostNotReady {
                                    machine_state: MachineState::WaitingForLockdown {
                                        lockdown_info: LockdownInfo {
                                            state: LockdownState::WaitForDPUUp,
                                            mode: lockdown_info.mode.clone(),
                                        },
                                    },
                                };
                            }
                        }
                        LockdownState::WaitForDPUUp => {
                            // Has forge-dpu-agent reported state? That means DPU is up.
                            if is_dpu_up(state) {
                                // reboot host
                                // When forge changes BIOS params (for lockdown enable/disable both), host does a power cycle.
                                // During power cycle, DPU also reboots. Now DPU and Host are coming up together. Since DPU is not ready yet,
                                // it does not forward DHCP discover from host and host goes into failure mode and stops sending further
                                // DHCP Discover. A second reboot starts DHCP cycle again when DPU is already up.
                                restart_machine(&state.host_snapshot, ctx).await?;
                                if LockdownMode::Enable == lockdown_info.mode {
                                    *controller_state.modify() = ManagedHostState::HostNotReady {
                                        machine_state: MachineState::Discovered,
                                    };
                                }
                            }
                        }
                    }
                }
                MachineState::WaitingForNetworkInstall => {
                    tracing::warn!(
                        "Invalid State WaitingForNetworkConfig for Host Machine {}",
                        host_machine_id
                    );
                }
            }
        }

        Ok(())
    }
}

/// A `StateHandler` implementation for instances
#[derive(Debug, Default)]
pub struct InstanceStateHandler {}

#[async_trait::async_trait]
impl StateHandler for InstanceStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;
    type ObjectMetrics = MachineMetrics;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _metrics: &mut Self::ObjectMetrics,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let Some(ref instance) = state.instance else {
            return Err(StateHandlerError::GenericError(eyre!("Instance is empty at this point. Cleanup is needed for host: {}.", host_machine_id)));
        };

        if let ManagedHostState::Assigned { instance_state } = &state.managed_state {
            match instance_state {
                InstanceState::Init => {
                    // we should not be here. This state to be used if state machine has not
                    // picked instance creation and user asked for status.
                }
                InstanceState::WaitingForNetworkConfig => {
                    // It should be first state to process here.
                    // Wait for instance network config to be applied
                    // Reboot host and moved to Ready.

                    // TODO GK if delete_requested skip this whole step,
                    // reboot and jump to BootingWithDiscoveryImage

                    // Check DPU network config has been applied
                    if !is_network_ready(&state.dpu_snapshot) {
                        return Ok(());
                    }
                    // Check instance network config has been applied
                    let expected = &instance.network_config_version;
                    let actual = match &instance.observations.network {
                        None => {
                            return Ok(());
                        }
                        Some(network_status) => &network_status.config_version,
                    };
                    if expected != actual {
                        return Ok(());
                    }

                    bind_ib_ports(
                        ctx,
                        txn,
                        instance.instance_id,
                        instance.config.infiniband.ib_interfaces.clone(),
                    )
                    .await?;

                    record_infiniband_status_observation(
                        ctx,
                        txn,
                        instance,
                        instance.config.infiniband.ib_interfaces.clone(),
                    )
                    .await?;

                    // Reboot host
                    restart_machine(&state.host_snapshot, ctx).await?;

                    // Instance is ready.
                    // We can not determine if machine is rebooted successfully or not. Just leave
                    // it like this and declare Instance Ready.
                    *controller_state.modify() = ManagedHostState::Assigned {
                        instance_state: InstanceState::Ready,
                    };
                }
                InstanceState::Ready => {
                    // Machine is up after reboot. Hurray. Instance is up.
                    if instance.delete_requested {
                        // Reboot host. Host will boot with carbide discovery image now. Changes
                        // are done in get_pxe_instructions api.
                        // User will loose all access to instance now.
                        restart_machine(&state.host_snapshot, ctx).await?;

                        *controller_state.modify() = ManagedHostState::Assigned {
                            instance_state: InstanceState::BootingWithDiscoveryImage,
                        };
                    } else {
                        record_infiniband_status_observation(
                            ctx,
                            txn,
                            instance,
                            instance.config.infiniband.ib_interfaces.clone(),
                        )
                        .await?;

                        // Check if DPU reprovisioing is requested
                        if let Some(reprovisioning_requested) =
                            dpu_reprovisioning_needed(&state.dpu_snapshot)
                        {
                            // TODO: Replace with type safe enum.
                            // TODO: If initiator is admin_cli, start re-provisioning immediately,
                            // else wait for user's approval.
                            if !reprovisioning_requested.initiator.contains("Automatic") {
                                restart_machine(&state.dpu_snapshot, ctx).await?;
                                *controller_state.modify() = ManagedHostState::Assigned {
                                    instance_state: InstanceState::DPUReprovision {
                                        reprovision_state: if reprovisioning_requested
                                            .update_firmware
                                        {
                                            ReprovisionState::FirmwareUpgrade
                                        } else {
                                            set_managed_host_topology_update_needed(txn, state)
                                                .await?;
                                            ReprovisionState::WaitingForNetworkInstall
                                        },
                                    },
                                };
                            } else {
                                //TODO: This block to be removed once Automatic reprovision is
                                //implemented.

                                // Clear reprovisioning state.
                                Machine::clear_reprovisioning_request(
                                    txn,
                                    &state.dpu_snapshot.machine_id,
                                )
                                .await
                                .map_err(StateHandlerError::from)?;
                            }

                            return Ok(());
                        }
                    }
                }
                InstanceState::BootingWithDiscoveryImage => {
                    if !rebooted(
                        state.dpu_snapshot.current.version,
                        state.host_snapshot.last_reboot_time,
                    )
                    .await?
                    {
                        return Ok(());
                    }

                    *controller_state.modify() = ManagedHostState::Assigned {
                        instance_state: InstanceState::SwitchToAdminNetwork,
                    };
                }
                InstanceState::SwitchToAdminNetwork => {
                    // Tenant is gone and so is their network, switch back to admin network
                    let (mut netconf, version) = state.dpu_snapshot.network_config.clone().take();
                    netconf.use_admin_network = Some(true);
                    Machine::try_update_network_config(
                        txn,
                        &state.dpu_snapshot.machine_id,
                        version,
                        &netconf,
                    )
                    .await?;

                    *controller_state.modify() = ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkReconfig,
                    }
                }
                InstanceState::WaitingForNetworkReconfig => {
                    // Has forge-dpu-agent written the network config?
                    if !is_network_ready(&state.dpu_snapshot) {
                        return Ok(());
                    }

                    unbind_ib_ports(
                        ctx,
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
                    restart_machine(&state.host_snapshot, ctx).await?;

                    *controller_state.modify() = ManagedHostState::WaitingForCleanup {
                        cleanup_state: CleanupState::HostCleanup,
                    };
                }
                InstanceState::DPUReprovision { reprovision_state } => {
                    if let Some(new_state) = handle_dpu_reprovision(
                        reprovision_state,
                        state,
                        ctx,
                        txn,
                        &InstanceNextStateResolver,
                    )
                    .await?
                    {
                        *controller_state.modify() = new_state;
                    }
                }
            }
        }

        Ok(())
    }
}

async fn record_infiniband_status_observation(
    ctx: &StateHandlerContext<'_>,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance: &InstanceSnapshot,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<uuid::Uuid, Vec<String>>::new();

    for ib in &ib_interfaces {
        let guid = ib.guid.clone().ok_or(StateHandlerError::MissingData {
            object_id: instance.instance_id.to_string(),
            missing: "GUID of IB Port",
        })?;

        ibconf
            .entry(ib.ib_partition_id)
            .or_insert(Vec::new())
            .push(guid);
    }

    let mut ib_interfaces_status = Vec::with_capacity(ib_interfaces.len());

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            crate::db::UuidKeyedObjectFilter::One(k),
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
            pkey: ibpartition.config.pkey.map(|pkey| pkey as i32),
        };
        let ports = ctx
            .services
            .ib_fabric_manager
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
        return Err(StateHandlerError::MissingData {
            object_id: instance.instance_id.to_string(),
            missing: "number of infiniband interfaces mismatched",
        });
    }

    let status = InstanceInfinibandStatusObservation {
        config_version: instance.ib_config_version,
        ib_interfaces: ib_interfaces_status,
        observed_at: Utc::now(),
    };
    update_instance_infiniband_status_observation(txn, instance.instance_id, &status).await?;

    Ok(())
}

async fn bind_ib_ports(
    ctx: &StateHandlerContext<'_>,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: uuid::Uuid,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<uuid::Uuid, Vec<String>>::new();

    for ib in ib_interfaces {
        let guid = ib.guid.ok_or(StateHandlerError::MissingData {
            object_id: instance_id.to_string(),
            missing: "GUID of IB Port",
        })?;

        ibconf
            .entry(ib.ib_partition_id)
            .or_insert(Vec::new())
            .push(guid);
    }

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            crate::db::UuidKeyedObjectFilter::One(k),
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

        ctx.services
            .ib_fabric_manager
            .bind_ib_ports(IBNetwork::from(ibpartition), v)
            .await
            .map_err(|_| StateHandlerError::IBFabricError("bind_ib_ports".to_string()))?;
    }

    Ok(())
}

async fn unbind_ib_ports(
    ctx: &StateHandlerContext<'_>,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    instance_id: uuid::Uuid,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<uuid::Uuid, Vec<String>>::new();

    for ib in ib_interfaces {
        let guid = ib.guid.ok_or(StateHandlerError::MissingData {
            object_id: instance_id.to_string(),
            missing: "GUID of IB Port",
        })?;
        ibconf
            .entry(ib.ib_partition_id)
            .or_insert(Vec::new())
            .push(guid);
    }

    for (k, v) in ibconf {
        let ib_partitions = ib_partition::IBPartition::find(
            txn,
            crate::db::UuidKeyedObjectFilter::One(k),
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

        ctx.services
            .ib_fabric_manager
            .unbind_ib_ports(pkey as i32, v)
            .await
            .map_err(|_| StateHandlerError::IBFabricError("unbind_ib_ports".to_string()))?;
    }

    Ok(())
}

/// Issues a reboot request command to a host or DPU
async fn restart_machine(
    machine_snapshot: &MachineSnapshot,
    ctx: &StateHandlerContext<'_>,
) -> Result<(), StateHandlerError> {
    if machine_snapshot.machine_id.machine_type().is_dpu() {
        restart_dpu(machine_snapshot, ctx).await
    } else {
        restart_host(machine_snapshot, ctx).await
    }
}

async fn restart_host(
    machine_snapshot: &MachineSnapshot,
    ctx: &StateHandlerContext<'_>,
) -> Result<(), StateHandlerError> {
    let bmc_ip =
        machine_snapshot
            .bmc_info
            .ip
            .as_deref()
            .ok_or_else(|| StateHandlerError::MissingData {
                object_id: machine_snapshot.machine_id.to_string(),
                missing: "bmc_info.ip",
            })?;
    let is_lenovo = machine_snapshot.bmc_vendor.is_lenovo();

    let client = ctx
        .services
        .redfish_client_pool
        .create_client(
            bmc_ip,
            None,
            RedfishCredentialType::Machine {
                machine_id: machine_snapshot.machine_id.to_string(),
            },
        )
        .await?;

    // Since libredfish calls are thread blocking and we are inside an async function,
    // we have to delegate the actual call into a threadpool
    tokio::task::spawn_blocking(move || {
        if is_lenovo {
            // Lenovos prepend the users OS to the boot order once it is installed and this cleans up the mess
            client.boot_once(libredfish::Boot::Pxe)?;
        }
        client.power(libredfish::SystemPowerControl::ForceRestart)
    })
    .await
    .map_err(|e| {
        StateHandlerError::GenericError(eyre!("Failed redfish ForceRestart subtask: {}", e))
    })?
    .map_err(|e| StateHandlerError::RedfishError {
        operation: "restart",
        error: e,
    })?;

    Ok(())
}

async fn restart_dpu(
    machine_snapshot: &MachineSnapshot,
    ctx: &StateHandlerContext<'_>,
) -> Result<(), StateHandlerError> {
    let bmc_ip =
        machine_snapshot
            .bmc_info
            .ip
            .clone()
            .ok_or_else(|| StateHandlerError::MissingData {
                object_id: machine_snapshot.machine_id.to_string(),
                missing: "bmc_info.ip",
            })?;

    ctx.services
        .ipmi_tool
        .restart(&machine_snapshot.machine_id, bmc_ip)
        .await
        .map_err(|e: eyre::ErrReport| {
            StateHandlerError::GenericError(eyre!("Failed to restart machine: {}", e))
        })?;

    Ok(())
}

/// Issues a lockdown and reboot request command to a host.
async fn lockdown_host(
    machine_snapshot: &MachineSnapshot,
    ctx: &StateHandlerContext<'_>,
    enable: bool,
) -> Result<(), StateHandlerError> {
    let bmc_ip =
        machine_snapshot
            .bmc_info
            .ip
            .as_deref()
            .ok_or_else(|| StateHandlerError::MissingData {
                object_id: machine_snapshot.machine_id.to_string(),
                missing: "bmc_info.ip",
            })?;

    let client = ctx
        .services
        .redfish_client_pool
        .create_client(
            bmc_ip,
            None,
            RedfishCredentialType::Machine {
                machine_id: machine_snapshot.machine_id.to_string(),
            },
        )
        .await?;

    // Since libredfish calls are thread blocking and we are inside an async function,
    // we have to delegate the actual call into a threadpool
    tokio::task::spawn_blocking(move || {
        if enable {
            // the forge_setup call includes the equivalent of these calls internally in libredfish
            // 1. serial setup (bios, bmc)
            // 2. tpm clear (bios)
            // 3. lockdown (bios, bmc)
            // 4. boot once to pxe
            client.forge_setup()?;
        }
        client.power(libredfish::SystemPowerControl::ForceRestart)
    })
    .await
    .map_err(|e| {
        StateHandlerError::GenericError(eyre!("Failed redfish ForceRestart subtask: {}", e))
    })?
    .map_err(|e| StateHandlerError::RedfishError {
        operation: "lockdown",
        error: e,
    })?;

    Ok(())
}
