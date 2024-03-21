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
use forge_secrets::credentials::{CredentialKey, CredentialType};
use libredfish::{model::task::TaskState, Redfish, SystemPowerControl};
use tokio::fs::File;

use crate::{
    cfg::DpuFwUpdateConfig,
    db::{
        bmc_metadata::UserRoles,
        ib_partition,
        instance::{DeleteInstance, Instance},
        machine::{Machine, MachineSearchConfig},
        machine_topology::MachineTopology,
    },
    ib::{self, types::IBNetwork, DEFAULT_IB_FABRIC_NAME},
    model::{
        config_version::ConfigVersion,
        instance::{
            config::infiniband::InstanceIbInterfaceConfig,
            snapshot::InstanceSnapshot,
            status::infiniband::{
                InstanceIbInterfaceStatusObservation, InstanceInfinibandStatusObservation,
            },
        },
        machine::{
            machine_id::MachineId,
            network::HealthStatus,
            BmcFirmwareUpdateSubstate, CleanupState, DpuDiscoveringState, FailureCause,
            FailureDetails, FailureSource, FirmwareType, InstanceNextStateResolver, InstanceState,
            LockdownInfo,
            LockdownMode::{self, Enable},
            LockdownState, MachineLastRebootRequestedMode, MachineNextStateResolver,
            MachineSnapshot, MachineState, ManagedHostState, ManagedHostStateSnapshot,
            NextReprovisionState, ReprovisionRequest, ReprovisionState, RetryInfo,
        },
    },
    redfish::RedfishClientCreationError,
    state_controller::{
        machine::context::MachineStateHandlerContextObjects,
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
            StateHandlerServices,
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

/// The actual Machine State handler
#[derive(Debug)]
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
        dpu_fw_update_config: DpuFwUpdateConfig,
        reachability_params: ReachabilityParams,
    ) -> Self {
        MachineStateHandler {
            dpu_up_threshold,
            host_handler: HostMachineStateHandler::new(reachability_params),
            dpu_handler: DpuMachineStateHandler::new(
                dpu_nic_firmware_initial_update_enabled,
                dpu_fw_update_config,
                reachability_params,
            ),
            instance_handler: InstanceStateHandler::new(
                dpu_nic_firmware_reprovision_update_enabled,
                reachability_params,
            ),
            reachability_params,
        }
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
    type ContextObjects = MachineStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<(), StateHandlerError> {
        let managed_state = &state.managed_state;

        ctx.metrics.dpu_firmware_version = state
            .dpu_snapshot
            .hardware_info
            .as_ref()
            .and_then(|hi| hi.dpu_info.as_ref().map(|di| di.firmware_version.clone()));

        // Update DPU network health Prometheus metrics
        ctx.metrics.dpu_healthy = state.dpu_snapshot.has_healthy_network();
        if let Some(observation) = state.dpu_snapshot.network_status_observation.as_ref() {
            ctx.metrics.agent_version = observation.agent_version.clone();
            ctx.metrics.dpu_up =
                Utc::now().signed_duration_since(observation.observed_at) <= self.dpu_up_threshold;
            for failed in &observation.health_status.failed {
                ctx.metrics.failed_dpu_healthchecks.insert(failed.clone());
            }

            ctx.metrics.machine_id = Some(observation.machine_id.clone());
            ctx.metrics.client_certificate_expiry = observation.client_certificate_expiry;
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
                    retry_count: 0,
                };
                return Ok(());
            }
        }

        match &managed_state {
            ManagedHostState::DpuDiscoveringState { .. } => {
                self.dpu_handler
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await?;
            }
            ManagedHostState::DPUNotReady { .. } => {
                self.dpu_handler
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await?;
            }

            ManagedHostState::HostNotReady { .. } => {
                self.host_handler
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await?;
            }

            ManagedHostState::Ready => {
                // Check if DPU reprovisioing is requested
                if let Some(reprovisioning_requested) =
                    dpu_reprovisioning_needed(&state.dpu_snapshot)
                {
                    restart_machine(&state.dpu_snapshot, ctx.services, txn).await?;
                    Machine::update_dpu_reprovision_start_time(&state.dpu_snapshot.machine_id, txn)
                        .await?;
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
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
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
                            trigger_reboot_if_needed(
                                &state.host_snapshot,
                                &state.host_snapshot,
                                None,
                                &self.reachability_params,
                                ctx.services,
                                None,
                                txn,
                            )
                            .await?;
                            return Ok(());
                        }

                        // Reboot host
                        restart_machine(&state.host_snapshot, ctx.services, txn).await?;

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
                        )
                        .await?
                        {
                            ctx.metrics
                                .machine_reboot_attempts_in_failed_during_discovery =
                                Some(*retry_count as u64);
                            // Anytime host discovery is successful, move to next state.
                            Machine::clear_failure_details(machine_id, txn).await?;
                            let new_state =
                                handle_host_waitingfordiscovery(txn, ctx, state).await?;
                            *controller_state.modify() = new_state;
                            return Ok(());
                        }

                        // Wait till failure_retry_time is over except first time.
                        // First time, host is already up and reported that discovery is failed.
                        // Let's reboot now immediately.
                        if *retry_count == 0 {
                            restart_machine(&state.host_snapshot, ctx.services, txn).await?;
                            *controller_state.modify() = ManagedHostState::Failed {
                                retry_count: retry_count + 1,
                                details: details.clone(),
                                machine_id: machine_id.clone(),
                            };
                            return Ok(());
                        }

                        if trigger_reboot_if_needed(
                            &state.host_snapshot,
                            &state.host_snapshot,
                            Some(*retry_count as i64),
                            &self.reachability_params,
                            ctx.services,
                            None,
                            txn,
                        )
                        .await?
                        {
                            *controller_state.modify() = ManagedHostState::Failed {
                                retry_count: retry_count + 1,
                                details: details.clone(),
                                machine_id: machine_id.clone(),
                            };
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
                    }
                }
            }

            ManagedHostState::DPUReprovision { reprovision_state } => {
                if let Some(new_state) = handle_dpu_reprovision(
                    reprovision_state,
                    state,
                    &self.reachability_params,
                    ctx.services,
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
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    next_state_resolver: &impl NextReprovisionState,
) -> Result<Option<ManagedHostState>, StateHandlerError> {
    match reprovision_state {
        ReprovisionState::FirmwareUpgrade => {
            // Firmware upgrade is going on.
            if !rebooted(&state.dpu_snapshot).await? {
                trigger_reboot_if_needed(
                    &state.dpu_snapshot,
                    &state.host_snapshot,
                    None,
                    reachability_params,
                    services,
                    None,
                    txn,
                )
                .await?;
                return Ok(None);
            }

            host_power_control(
                &state.host_snapshot,
                services,
                SystemPowerControl::ForceOff,
                None,
                txn,
            )
            .await?;
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
            let power_state = host_power_state(&state.host_snapshot, services).await?;

            // Host is not powered-off yet. Try again.
            if power_state != libredfish::PowerState::Off {
                tracing::error!(
                    "Machine {} is still not power-off state. Turning off for host again.",
                    state.host_snapshot.machine_id
                );
                host_power_control(
                    &state.host_snapshot,
                    services,
                    SystemPowerControl::ForceOff,
                    None,
                    txn,
                )
                .await?;

                return Ok(None);
            }
            host_power_control(
                &state.host_snapshot,
                services,
                SystemPowerControl::On,
                None,
                txn,
            )
            .await?;
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
            Machine::clear_dpu_reprovisioning_request(txn, &state.dpu_snapshot.machine_id, false)
                .await
                .map_err(StateHandlerError::from)?;
            host_power_control(
                &state.host_snapshot,
                services,
                SystemPowerControl::ForceRestart,
                None,
                txn,
            )
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
    if !discovered_after_state_transition(
        state.dpu_snapshot.current.version,
        state.dpu_snapshot.last_discovery_time,
    )
    .await?
    {
        trigger_reboot_if_needed(
            &state.dpu_snapshot,
            &state.host_snapshot,
            None,
            reachability_params,
            services,
            Some(CredentialKey::DpuRedfish {
                credential_type: CredentialType::SiteDefault,
            }),
            txn,
        )
        .await?;
        return Ok(Poll::Pending);
    }

    restart_machine(&state.dpu_snapshot, services, txn).await?;

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
#[derive(Debug)]
pub struct DpuMachineStateHandler {
    dpu_nic_firmware_initial_update_enabled: bool,
    dpu_firmware_update_config: DpuFwUpdateConfig,
    reachability_params: ReachabilityParams,
}

// Minimal supported DPU BMC FW version, that is capable to do BMC FW update
const MIN_SUPPORTED_BMC_FW: &str = "23.07";

impl DpuMachineStateHandler {
    pub fn new(
        dpu_nic_firmware_initial_update_enabled: bool,
        dpu_firmware_update_config: DpuFwUpdateConfig,
        reachability_params: ReachabilityParams,
    ) -> Self {
        DpuMachineStateHandler {
            dpu_nic_firmware_initial_update_enabled,
            dpu_firmware_update_config,
            reachability_params,
        }
    }

    async fn redfish_check_fw_update_needed(
        &self,
        redfish: &dyn Redfish,
        firmware_type: &str,
        minimal_supported_version: Option<&str>,
        latest_available_version: &str,
    ) -> Result<bool, StateHandlerError> {
        // For BF2 BMC FW inventory has different name
        let inventories = redfish.get_software_inventories().await.map_err(|e| {
            StateHandlerError::RedfishError {
                operation: "get_software_inventories",
                error: e,
            }
        })?;
        let inventory_id = inventories
            .iter()
            .find(|i| i.contains(firmware_type))
            .ok_or(StateHandlerError::FirmwareUpdateError(eyre!(
                "No inventory found that matches: {}",
                firmware_type
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

        match inventory.version {
            Some(version_str) => {
                let version = version_str.to_uppercase().replace("BF-", "");

                if minimal_supported_version.is_some_and(|minimal_supported_version| {
                    version_compare::compare(version.as_str(), minimal_supported_version)
                        .is_ok_and(|c| c == version_compare::Cmp::Lt)
                }) {
                    let msg = format!(
                        "Current {} FW version: {}, minimal supported version: {}",
                        firmware_type,
                        version.as_str(),
                        minimal_supported_version.unwrap(),
                    );
                    tracing::error!(msg);
                    return Err(StateHandlerError::FirmwareUpdateError(eyre!(msg)));
                }
                tracing::debug!(
                    "Version: {}, latest available_version: {}",
                    version,
                    latest_available_version
                );
                Ok(version_compare::compare(version, latest_available_version)
                    .is_ok_and(|c| c == version_compare::Cmp::Lt))
            }
            None => {
                let msg = format!("Unknown {} FW version", firmware_type);
                tracing::error!(msg);
                Err(StateHandlerError::FirmwareUpdateError(eyre!(msg)))
            }
        }
    }

    async fn get_firmware_file(
        &self,
        bf_version: i32,
        fw_type: &str,
    ) -> Result<File, StateHandlerError> {
        let fw_location = self.dpu_firmware_update_config.firmware_location.clone();
        let fw_file: String = format!("{}/bf{}-{}.fwpkg", fw_location, bf_version, fw_type);
        File::open(fw_file).await.map_err(|e| {
            StateHandlerError::FirmwareUpdateError(eyre!(
                "Failed to read BMC FW file: {}",
                e.to_string()
            ))
        })
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
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<(), StateHandlerError> {
        let dpu_machine_id = &state.dpu_snapshot.machine_id.clone();
        match &state.managed_state {
            ManagedHostState::DpuDiscoveringState {
                discovering_state: DpuDiscoveringState::Initializing,
            } => {
                let client;
                let client_result = ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        state.dpu_snapshot.bmc_info.ip.as_ref().unwrap().as_str(),
                        state.dpu_snapshot.bmc_info.port,
                        CredentialKey::DpuRedfish {
                            credential_type: CredentialType::SiteDefault,
                        },
                    )
                    .await;

                match client_result {
                    Ok(redfish_client) => client = redfish_client,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to instantiate redfish client");
                        return Ok(());
                    }
                }

                if let Err(e) = ctx
                    .services
                    .redfish_client_pool
                    .create_forge_admin_user(client, dpu_machine_id.to_string())
                    .await
                {
                    let msg = format!("Failed to create forge_admin user: {}", e);
                    *controller_state.modify() = self.get_discovery_failure(msg, dpu_machine_id);
                    return Ok(());
                }

                *controller_state.modify() = ManagedHostState::DpuDiscoveringState {
                    discovering_state: DpuDiscoveringState::Configuring,
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
                let client = ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        state.dpu_snapshot.bmc_info.ip.as_ref().unwrap().as_str(),
                        None,
                        CredentialKey::DpuRedfish {
                            credential_type: CredentialType::Machine {
                                machine_id: dpu_machine_id.to_string(),
                            },
                        },
                    )
                    .await
                    .map_err(StateHandlerError::RedfishClientCreationError)?;

                let task = client.get_task(task_id).await.map_err(|e| {
                    StateHandlerError::RedfishError {
                        operation: "get_task",
                        error: e,
                    }
                })?;

                tracing::info!("{} FW update task: {:#?}", firmware_type, task);

                match task.task_state {
                    Some(TaskState::Completed) => {
                        if *firmware_type == FirmwareType::Cec {
                            // For Cec firmware update need also to reboot a host
                            let bmc_ip =
                                state.host_snapshot.bmc_info.ip.as_ref().ok_or_else(|| {
                                    StateHandlerError::RedfishClientCreationError(
                                        RedfishClientCreationError::MissingCredentials(eyre!(
                                            "No host BMC IP"
                                        )),
                                    )
                                })?;

                            // Use host client with site-default credentials.
                            // TODO: modify host_power_control to use site-default credentials and use that method.
                            let host_client = ctx
                                .services
                                .redfish_client_pool
                                .create_client(
                                    bmc_ip.as_str(),
                                    None,
                                    CredentialKey::HostRedfish {
                                        credential_type: CredentialType::SiteDefault,
                                    },
                                )
                                .await
                                .map_err(StateHandlerError::RedfishClientCreationError)?;
                            host_client
                                .power(SystemPowerControl::ForceRestart)
                                .await
                                .map_err(|e| StateHandlerError::RedfishError {
                                    operation: "host_reboot",
                                    error: e,
                                })?;
                        }
                        client
                            .bmc_reset()
                            .await
                            .map_err(|e| StateHandlerError::RedfishError {
                                operation: "bmc_reset",
                                error: e,
                            })?;
                        *controller_state.modify() = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                substate: BmcFirmwareUpdateSubstate::Reboot { count: 0 },
                            },
                        };

                        return Ok(());
                    }
                    Some(TaskState::Exception) => {
                        let msg = format!(
                            "Failed to update FW:  {:#?}",
                            task.messages
                                .last()
                                .map_or("".to_string(), |m| m.message.clone())
                        );
                        *controller_state.modify() =
                            self.get_discovery_failure(msg, dpu_machine_id);
                        return Ok(());
                    }
                    Some(_) => {}
                    None => {
                        return Err(StateHandlerError::GenericError(eyre!(
                            "No task state field in task: {:#?}",
                            task
                        )));
                    }
                }
            }
            ManagedHostState::DpuDiscoveringState {
                discovering_state:
                    DpuDiscoveringState::BmcFirmwareUpdate {
                        substate: BmcFirmwareUpdateSubstate::Reboot { count },
                    },
            } => {
                match ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        state.dpu_snapshot.bmc_info.ip.as_ref().unwrap().as_str(),
                        None,
                        CredentialKey::DpuRedfish {
                            credential_type: CredentialType::Machine {
                                machine_id: dpu_machine_id.to_string(),
                            },
                        },
                    )
                    .await
                {
                    Ok(_client) => {
                        *controller_state.modify() = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::Configuring {},
                        };
                    }
                    Err(_e) => {
                        *controller_state.modify() = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                substate: BmcFirmwareUpdateSubstate::Reboot { count: count + 1 },
                            },
                        };
                    }
                };

                return Ok(());
            }
            ManagedHostState::DpuDiscoveringState {
                discovering_state: DpuDiscoveringState::Configuring,
            } => {
                let client;
                let client_result = ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        state.dpu_snapshot.bmc_info.ip.as_ref().unwrap().as_str(),
                        state.dpu_snapshot.bmc_info.port,
                        CredentialKey::DpuRedfish {
                            credential_type: CredentialType::Machine {
                                machine_id: dpu_machine_id.to_string(),
                            },
                        },
                    )
                    .await;

                match client_result {
                    Ok(redfish_client) => client = redfish_client,
                    Err(e) => {
                        let msg = format!("Failed to instantiate redfish client: {}", e);
                        *controller_state.modify() =
                            self.get_discovery_failure(msg, dpu_machine_id);
                        return Ok(());
                    }
                }

                let model_description = state
                    .dpu_snapshot
                    .hardware_info
                    .as_ref()
                    .and_then(|hi| {
                        hi.dpu_info
                            .as_ref()
                            .map(|di| di.part_description.to_lowercase())
                    })
                    .unwrap_or("bluefield 3".to_string());

                let bf_version = if model_description.contains("bluefield 3") {
                    3
                } else {
                    2
                };

                let fw_update_version = if bf_version == 2 {
                    &self
                        .dpu_firmware_update_config
                        .dpu_bf2_bmc_firmware_update_version
                } else {
                    &self
                        .dpu_firmware_update_config
                        .dpu_bf3_bmc_firmware_update_version
                };

                if !fw_update_version.is_empty() {
                    let bmc_inventory = FirmwareType::Bmc.get_inventory_name();

                    let latest_bmc_fw_version = fw_update_version.get(bmc_inventory);

                    // Check and update Bmc FW
                    if latest_bmc_fw_version.is_some()
                        && self
                            .redfish_check_fw_update_needed(
                                &*client,
                                bmc_inventory,
                                Some(MIN_SUPPORTED_BMC_FW),
                                latest_bmc_fw_version.unwrap(),
                            )
                            .await?
                    {
                        let firmware_file = self.get_firmware_file(bf_version, "bmc").await?;

                        // TODO: Change to an error state or do some retries
                        let task = client.update_firmware(firmware_file).await.map_err(|e| {
                            StateHandlerError::RedfishError {
                                operation: "update_firmware",
                                error: e,
                            }
                        })?;
                        *controller_state.modify() = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                substate: BmcFirmwareUpdateSubstate::WaitForUpdateCompletion {
                                    firmware_type: FirmwareType::Bmc,
                                    task_id: task.id,
                                },
                            },
                        };
                        return Ok(());
                    }

                    let cec_inventory = FirmwareType::Cec.get_inventory_name();
                    let latest_cec_fw_version = fw_update_version.get(cec_inventory);

                    // Check and update Cec FW
                    if latest_cec_fw_version.is_some()
                        && self
                            .redfish_check_fw_update_needed(
                                &*client,
                                cec_inventory,
                                None,
                                latest_cec_fw_version.unwrap(),
                            )
                            .await?
                    {
                        let firmware_file = self.get_firmware_file(bf_version, "cec").await?;
                        let task = client.update_firmware(firmware_file).await.map_err(|e| {
                            StateHandlerError::RedfishError {
                                operation: "update_firmware",
                                error: e,
                            }
                        })?;
                        *controller_state.modify() = ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                                substate: BmcFirmwareUpdateSubstate::WaitForUpdateCompletion {
                                    firmware_type: FirmwareType::Cec,
                                    task_id: task.id,
                                },
                            },
                        };
                        return Ok(());
                    }
                }

                if let Err(e) = ctx
                    .services
                    .redfish_client_pool
                    .uefi_setup(client.as_ref())
                    .await
                {
                    let msg = format!("Failed to run uefi_setup call: {}", e);
                    *controller_state.modify() = self.get_discovery_failure(msg, dpu_machine_id);
                    return Ok(());
                }

                if let Err(e) = client.forge_setup().await {
                    let msg = format!("Failed to run forge_setup call: {}", e);
                    *controller_state.modify() = self.get_discovery_failure(msg, dpu_machine_id);
                    return Ok(());
                }

                if let Err(e) = client.power(SystemPowerControl::GracefulRestart).await {
                    let msg = format!("Failed to reboot a DPU: {}", e);
                    *controller_state.modify() = self.get_discovery_failure(msg, dpu_machine_id);
                    return Ok(());
                }

                *controller_state.modify() = ManagedHostState::DPUNotReady {
                    machine_state: MachineState::Init,
                };
                let host_machine_result = Machine::find_one(
                    &mut *txn,
                    &state.host_snapshot.machine_id,
                    MachineSearchConfig::default(),
                )
                .await;

                if let Ok(Some(host_machine)) = host_machine_result {
                    host_machine
                        .advance(
                            txn,
                            ManagedHostState::DPUNotReady {
                                machine_state: MachineState::Init,
                            },
                            Some(host_machine.current_version().increment()),
                        )
                        .await?;
                } else {
                    let msg = format!(
                        "Failed to find associated host: {}",
                        state.host_snapshot.machine_id
                    );
                    *controller_state.modify() = self.get_discovery_failure(msg, host_machine_id);
                }

                return Ok(());
            }
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::Init,
            } => {
                // initial restart, firmware update and scout is run, first reboot of dpu discovery
                if (try_wait_for_dpu_discovery_and_reboot(
                    state,
                    &self.reachability_params,
                    ctx.services,
                    txn,
                )
                .await?)
                    .is_pending()
                {
                    return Ok(());
                }

                tracing::debug!(
                    "ManagedHostState::DPUNotReady::Init: firmware update enabled = {}",
                    self.dpu_nic_firmware_initial_update_enabled
                );

                if self.dpu_nic_firmware_initial_update_enabled {
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
                } else {
                    *controller_state.modify() = ManagedHostState::DPUNotReady {
                        machine_state: MachineState::WaitingForNetworkConfig,
                    };
                }
            }
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::WaitingForNetworkInstall,
            } => {
                // rebooted from the init state, where firmware is updated and scout is running.
                if !rebooted(&state.dpu_snapshot).await? {
                    trigger_reboot_if_needed(
                        &state.dpu_snapshot,
                        &state.host_snapshot,
                        None,
                        &self.reachability_params,
                        ctx.services,
                        None,
                        txn,
                    )
                    .await?;
                    return Ok(());
                }

                // hbn needs a restart to be able to come online, second reboot of dpu discovery
                restart_machine(&state.dpu_snapshot, ctx.services, txn).await?;

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

                let key = CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                };
                if let Err(e) = host_power_control(
                    &state.host_snapshot,
                    ctx.services,
                    SystemPowerControl::ForceRestart,
                    Some(key),
                    txn,
                )
                .await
                {
                    tracing::error!("Error while rebooting host with site default password. {e}");
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

/// In case machine does not come up until a specified duration, this function tries to reboot
/// it again. The reboot continues till 6 hours only. After that this function gives up.
async fn trigger_reboot_if_needed(
    target: &MachineSnapshot,
    host: &MachineSnapshot,
    retry_count: Option<i64>,
    reachability_params: &ReachabilityParams,
    services: &StateHandlerServices,
    key: Option<CredentialKey>,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<bool, StateHandlerError> {
    let Some(last_reboot_requested) = &target.last_reboot_requested else {
        return Ok(false);
    };
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
            return Ok(false);
        }
        let power_state = host_power_state(host, services).await?;

        // Host is not powered-off yet, try again. If state is powered-off, power-on now.
        let action = if power_state == libredfish::PowerState::Off {
            SystemPowerControl::On
        } else {
            tracing::error!(
                "Machine {} is still not power-off state. Turning off for host: {} again.",
                target.machine_id,
                host.machine_id,
            );
            SystemPowerControl::ForceOff
        };

        host_power_control(host, services, action, key, txn).await?;
        Machine::update_reboot_requested_time(&target.machine_id, txn, action.into()).await?;
        return Ok(false);
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

            if cycle % 4 == 0 {
                // PowerDown
                // DPU or host, in both cases power down is triggered from host.
                tracing::info!(
                    "Machine {} has not come up after {} minutes. Trying Power-Toggle for host: {}, cycle: {cycle}",
                    target.machine_id,
                    time_elapsed_since_state_change,
                    host.machine_id,
                );
                let action = SystemPowerControl::ForceOff;
                host_power_control(host, services, action, key, txn).await?;
                // Update target machine also. In case of DPU, target machine is DPU. In case of
                // Host stuck, target machine is host. In case of host, this field will be updated
                // twice. Well, it should not harm much.
                Machine::update_reboot_requested_time(&target.machine_id, txn, action.into())
                    .await?;
            } else {
                // Reboot
                tracing::info!(
                    "Machine {} has not come up after {} minutes. Trying rebooting again, cycle: {cycle}.",
                    target.machine_id,
                    time_elapsed_since_state_change
                );
                restart_machine(target, services, txn).await?;
            }
            return Ok(true);
        }
    } else {
        tracing::warn!(
            "Machine {} has not responded yet after {} hours.",
            target.machine_id,
            (current_time - entered_state_at).num_hours()
        );
    }
    Ok(false)
}

/// This function waits until target machine is up or not. It relies on scout to identify if
/// machine has come up or not after reboot.
pub async fn rebooted(target: &MachineSnapshot) -> Result<bool, StateHandlerError> {
    if target.last_reboot_time.unwrap_or_default() > target.current.version.timestamp() {
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
#[derive(Debug)]
pub struct HostMachineStateHandler {
    reachability_params: ReachabilityParams,
}

impl HostMachineStateHandler {
    pub fn new(reachability_params: ReachabilityParams) -> Self {
        Self {
            reachability_params,
        }
    }
}

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

async fn handle_host_waitingfordiscovery(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    state: &mut ManagedHostStateSnapshot,
) -> Result<ManagedHostState, StateHandlerError> {
    // Enable Bios/BMC lockdown now.
    lockdown_host(txn, &state.host_snapshot, ctx.services, true).await?;

    Ok(ManagedHostState::HostNotReady {
        machine_state: MachineState::WaitingForLockdown {
            lockdown_info: LockdownInfo {
                state: LockdownState::TimeWaitForDPUDown,
                mode: Enable,
            },
        },
    })
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
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
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
                        trigger_reboot_if_needed(
                            &state.host_snapshot,
                            &state.host_snapshot,
                            None,
                            &self.reachability_params,
                            ctx.services,
                            Some(CredentialKey::HostRedfish {
                                credential_type: CredentialType::SiteDefault,
                            }),
                            txn,
                        )
                        .await?;
                        return Ok(());
                    }

                    let new_state = handle_host_waitingfordiscovery(txn, ctx, state).await?;
                    *controller_state.modify() = new_state;
                }

                MachineState::Discovered => {
                    // Check if machine is rebooted. If yes, move to Ready state.
                    if !rebooted(&state.host_snapshot).await? {
                        trigger_reboot_if_needed(
                            &state.host_snapshot,
                            &state.host_snapshot,
                            None,
                            &self.reachability_params,
                            ctx.services,
                            None,
                            txn,
                        )
                        .await?;
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
                            if !wait(
                                &state.host_snapshot.current.version.timestamp(),
                                self.reachability_params.dpu_wait_time,
                            ) {
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
                                restart_machine(&state.host_snapshot, ctx.services, txn).await?;
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
#[derive(Debug)]
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
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<(), StateHandlerError> {
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
                    restart_machine(&state.host_snapshot, ctx.services, txn).await?;

                    // Instance is ready.
                    // We can not determine if machine is rebooted successfully or not. Just leave
                    // it like this and declare Instance Ready.
                    *controller_state.modify() = ManagedHostState::Assigned {
                        instance_state: InstanceState::Ready,
                    };
                }
                InstanceState::Ready => {
                    // Machine is up after reboot. Hurray. Instance is up.

                    // Wait for user's approval. Once user approves for dpu
                    // reprovision/update firmware, trigger it.
                    let reprov_needed = if let Some(reprovisioning_requested) =
                        dpu_reprovisioning_needed(&state.dpu_snapshot)
                    {
                        reprovisioning_requested.user_approval_received
                    } else {
                        false
                    };

                    if instance.delete_requested || reprov_needed {
                        if reprov_needed {
                            // User won't be allowed to clear reprovisioning flag after this.
                            Machine::update_dpu_reprovision_start_time(
                                &state.dpu_snapshot.machine_id,
                                txn,
                            )
                            .await?;
                        }

                        // Reboot host. Host will boot with carbide discovery image now. Changes
                        // are done in get_pxe_instructions api.
                        // User will loose all access to instance now.
                        restart_machine(&state.host_snapshot, ctx.services, txn).await?;

                        *controller_state.modify() = ManagedHostState::Assigned {
                            instance_state: InstanceState::BootingWithDiscoveryImage {
                                retry: RetryInfo { count: 0 },
                            },
                        };
                    } else {
                        record_infiniband_status_observation(
                            ctx.services,
                            txn,
                            instance,
                            instance.config.infiniband.ib_interfaces.clone(),
                        )
                        .await?;
                    }
                }
                InstanceState::BootingWithDiscoveryImage { retry } => {
                    if !rebooted(&state.host_snapshot).await? {
                        if trigger_reboot_if_needed(
                            &state.host_snapshot,
                            &state.host_snapshot,
                            // can't send 0. 0 will force power-off as cycle calculator.
                            Some(retry.count as i64 + 1),
                            &self.reachability_params,
                            ctx.services,
                            None,
                            txn,
                        )
                        .await?
                        {
                            *controller_state.modify() = ManagedHostState::Assigned {
                                instance_state: InstanceState::BootingWithDiscoveryImage {
                                    retry: RetryInfo {
                                        count: retry.count + 1,
                                    },
                                },
                            };
                        }

                        return Ok(());
                    }

                    // Now retry_count won't exceed a limit. Function trigger_reboot_if_needed does
                    // not reboot a machine after 6 hrs, so this counter won't increase at all
                    // after 6 hours.
                    ctx.metrics
                        .machine_reboot_attempts_in_booting_with_discovery_image =
                        Some(retry.count + 1);

                    // In case state is triggered for delete instance handling, follow that path.
                    if instance.delete_requested {
                        *controller_state.modify() = ManagedHostState::Assigned {
                            instance_state: InstanceState::SwitchToAdminNetwork,
                        };

                        return Ok(());
                    }

                    // If we are here, DPU reprov MUST have been be requested.
                    if let Some(reprovisioning_requested) =
                        dpu_reprovisioning_needed(&state.dpu_snapshot)
                    {
                        // If we are here, it is definitely because user has already given
                        // approval, but a repeat check doesn't harm anyway.
                        if reprovisioning_requested.user_approval_received {
                            restart_machine(&state.dpu_snapshot, ctx.services, txn).await?;
                            *controller_state.modify() = ManagedHostState::Assigned {
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
                        }
                    }
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
                    restart_machine(&state.host_snapshot, ctx.services, txn).await?;

                    *controller_state.modify() = ManagedHostState::WaitingForCleanup {
                        cleanup_state: CleanupState::HostCleanup,
                    };
                }
                InstanceState::DPUReprovision { reprovision_state } => {
                    if let Some(new_state) = handle_dpu_reprovision(
                        reprovision_state,
                        state,
                        &self.reachability_params,
                        ctx.services,
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
    services: &StateHandlerServices,
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
    Instance::update_infiniband_status_observation(txn, instance.instance_id, &status).await?;

    Ok(())
}

async fn bind_ib_ports(
    services: &StateHandlerServices,
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
    instance_id: uuid::Uuid,
    ib_interfaces: Vec<InstanceIbInterfaceConfig>,
) -> Result<(), StateHandlerError> {
    let mut ibconf = HashMap::<uuid::Uuid, Vec<String>>::new();

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

        ib_fabric
            .unbind_ib_ports(pkey as i32, v)
            .await
            .map_err(|_| StateHandlerError::IBFabricError("unbind_ib_ports".to_string()))?;
    }

    Ok(())
}

/// Issues a reboot request command to a host or DPU
async fn restart_machine(
    machine_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StateHandlerError> {
    if machine_snapshot.machine_id.machine_type().is_dpu() {
        restart_dpu(machine_snapshot, services).await?;
        Machine::update_reboot_requested_time(
            &machine_snapshot.machine_id,
            txn,
            crate::model::machine::MachineLastRebootRequestedMode::Reboot,
        )
        .await?;
    } else {
        host_power_control(
            machine_snapshot,
            services,
            SystemPowerControl::ForceRestart,
            None,
            txn,
        )
        .await?;
    }

    Ok(())
}

async fn host_power_state(
    host_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
) -> Result<libredfish::PowerState, StateHandlerError> {
    let bmc_ip =
        host_snapshot
            .bmc_info
            .ip
            .as_deref()
            .ok_or_else(|| StateHandlerError::MissingData {
                object_id: host_snapshot.machine_id.to_string(),
                missing: "bmc_info.ip",
            })?;

    let client = services
        .redfish_client_pool
        .create_client(
            bmc_ip,
            host_snapshot.bmc_info.port,
            CredentialKey::Bmc {
                machine_id: host_snapshot.machine_id.to_string(),
                user_role: UserRoles::Administrator.to_string(),
            },
        )
        .await?;

    client
        .get_power_state()
        .await
        .map_err(|e| StateHandlerError::RedfishError {
            operation: "get_power_state",
            error: e,
        })
}

async fn host_power_control(
    machine_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
    action: SystemPowerControl,
    key: Option<CredentialKey>,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
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

    let key = key.unwrap_or(CredentialKey::Bmc {
        machine_id: machine_snapshot.machine_id.to_string(),
        user_role: UserRoles::Administrator.to_string(),
    });

    let client = services
        .redfish_client_pool
        .create_client(bmc_ip, machine_snapshot.bmc_info.port, key)
        .await?;

    if machine_snapshot.bmc_vendor.is_lenovo() || machine_snapshot.bmc_vendor.is_supermicro() {
        // Lenovos prepend the users OS to the boot order once it is installed and this cleans up the mess
        // Supermicro will bot the users OS if we don't do this
        client.boot_once(libredfish::Boot::Pxe).await.map_err(|e| {
            StateHandlerError::RedfishError {
                operation: "boot_once",
                error: e,
            }
        })?;
    }
    // vikings reboot their DPU's if redfish reset is used. \
    // ipmitool is verified to not cause it to reset, so we use it, hackily, here.
    if machine_snapshot.bmc_vendor.is_viking() {
        services
            .ipmi_tool
            .restart(&machine_snapshot.machine_id, bmc_ip.to_string(), false)
            .await
            .map_err(|e: eyre::ErrReport| {
                StateHandlerError::GenericError(eyre!("Failed to restart machine: {}", e))
            })?;
    } else {
        client
            .power(action)
            .await
            .map_err(|e| StateHandlerError::RedfishError {
                operation: "restart",
                error: e,
            })?;
    }
    Machine::update_reboot_requested_time(&machine_snapshot.machine_id, txn, action.into()).await?;

    Ok(())
}

async fn restart_dpu(
    machine_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
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

    services
        .ipmi_tool
        .restart(&machine_snapshot.machine_id, bmc_ip, true)
        .await
        .map_err(|e: eyre::ErrReport| {
            StateHandlerError::GenericError(eyre!("Failed to restart machine: {}", e))
        })?;

    Ok(())
}

/// Issues a lockdown and reboot request command to a host.
async fn lockdown_host(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_snapshot: &MachineSnapshot,
    services: &StateHandlerServices,
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

    let client = services
        .redfish_client_pool
        .create_client(
            bmc_ip,
            machine_snapshot.bmc_info.port,
            CredentialKey::Bmc {
                machine_id: machine_snapshot.machine_id.to_string(),
                user_role: UserRoles::Administrator.to_string(),
            },
        )
        .await?;

    if enable {
        // the forge_setup call includes the equivalent of these calls internally in libredfish
        // 1. serial setup (bios, bmc)
        // 2. tpm clear (bios)
        // 3. lockdown (bios, bmc)
        // 4. boot once to pxe
        client
            .forge_setup()
            .await
            .map_err(|e| StateHandlerError::RedfishError {
                operation: "lockdown",
                error: e,
            })?;
    }
    host_power_control(
        machine_snapshot,
        services,
        SystemPowerControl::ForceRestart,
        None,
        txn,
    )
    .await?;

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
