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

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use eyre::eyre;

use crate::{
    db::{
        ib_subnet,
        instance::{
            status::infiniband::update_instance_infiniband_status_observation, DeleteInstance,
        },
        machine::Machine,
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
            CleanupState, FailureCause, FailureDetails, InstanceState, LockdownInfo,
            LockdownMode::{self, Enable},
            LockdownState, MachineSnapshot, MachineState, ManagedHostState,
            ManagedHostStateSnapshot,
        },
    },
    redfish::RedfishCredentialType,
    state_controller::state_handler::{
        ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
    },
};

/// The actual Machine State handler
#[derive(Debug, Default)]
pub struct MachineStateHandler {
    host_handler: HostMachineStateHandler,
    dpu_handler: DpuMachineStateHandler,
    instance_handler: InstanceStateHandler,
}

#[async_trait::async_trait]
impl StateHandler for MachineStateHandler {
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type ObjectId = MachineId;

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let managed_state = &state.managed_state;

        // Don't update failed state failure cause everytime. Record first failure cause only,
        // otherwise first failure cause will be overwritten.
        if !matches!(managed_state, ManagedHostState::Failed { .. }) {
            if let Some((machine_id, details)) = get_failed_state(state) {
                tracing::error!(
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
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await?;
            }

            ManagedHostState::HostNotReady { .. } => {
                self.host_handler
                    .handle_object_state(host_machine_id, state, controller_state, txn, ctx)
                    .await?;
            }

            ManagedHostState::Ready => {
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
                            return Ok(());
                        }

                        // Reboot host
                        restart_machine(&state.host_snapshot, ctx).await?;

                        *controller_state.modify() = ManagedHostState::HostNotReady {
                            machine_state: MachineState::Discovered,
                        };
                    }
                    CleanupState::DisableBIOSBMCLockdown => {
                        tracing::error!("DisableBIOSBMCLockdown state is not implemented. Machine {} stuck in unimplemented state.", host_machine_id);
                    }
                }
            }
            ManagedHostState::Created => {
                tracing::error!("Machine just created. Er should not be here.");
            }
            ManagedHostState::ForceDeletion => {
                // Just ignore.
                tracing::info!(
                    "Machine {} is marked for forced deletion. Ignoring.",
                    host_machine_id
                );
            }
            ManagedHostState::Failed {
                details,
                machine_id,
            } => {
                // Do nothing.
                // Handle error cause and decide how to recover if possible.
                tracing::error!(
                    "ManagedHost {} is in Failed state with machine/cause {}/{}. Failed at: {}, Ignoring.",
                    host_machine_id,
                    machine_id,
                    details.cause,
                    details.failed_at,
                );
            }
        }

        Ok(())
    }
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

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        match &state.managed_state {
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::Init,
            } => {
                // We are waiting for the `DiscoveryCompleted` RPC call to update the
                // `last_discovery_time` timestamp.
                // This indicates that all forge-scout actions have succeeded.
                if !discovered_after_state_transition(
                    state.dpu_snapshot.current.version,
                    state.dpu_snapshot.last_discovery_time,
                )
                .await?
                {
                    return Ok(());
                }

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

                // Network config has been applied and network is good, move to next state
                *controller_state.modify() = ManagedHostState::HostNotReady {
                    machine_state: MachineState::WaitingForDiscovery,
                };
            }
            state => {
                tracing::warn!(
                    "Unhandled State {:?} for DPU machine {}",
                    state,
                    host_machine_id
                );
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

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
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
                        "Invalid State WaitingForNetworkConfig for Host Machine {}",
                        host_machine_id
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
                            let expected_time = state.dpu_snapshot.current.version.timestamp()
                                + ctx.services.reachability_params.dpu_wait_time;
                            let current_time = Utc::now();

                            if current_time >= expected_time {
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
                            let observation_time = state
                                .dpu_snapshot
                                .network_status_observation
                                .as_ref()
                                .map(|o| o.observed_at)
                                .unwrap_or(DateTime::<Utc>::MIN_UTC);
                            let state_change_time = state.host_snapshot.current.version.timestamp();
                            if observation_time >= state_change_time {
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

    async fn handle_object_state(
        &self,
        host_machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
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
            .entry(ib.ib_subnet_id)
            .or_insert(Vec::new())
            .push(guid);
    }

    let mut ib_interfaces_status = Vec::with_capacity(ib_interfaces.len());

    for (k, v) in ibconf {
        let ibsubnets = ib_subnet::IBSubnet::find(
            txn,
            crate::db::UuidKeyedObjectFilter::One(k),
            ib_subnet::IBSubnetSearchConfig {
                include_history: false,
            },
        )
        .await?;

        let ibsubnet = ibsubnets.first().ok_or(StateHandlerError::MissingData {
            object_id: k.to_string(),
            missing: "ib_subnet not found",
        })?;

        // Get the status of ports from UFM, and persist it as observed status.
        let filter = ib::Filter {
            guids: Some(v),
            pkey: ibsubnet.config.pkey.map(|pkey| pkey as i32),
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
            .entry(ib.ib_subnet_id)
            .or_insert(Vec::new())
            .push(guid);
    }

    for (k, v) in ibconf {
        let ibsubnets = ib_subnet::IBSubnet::find(
            txn,
            crate::db::UuidKeyedObjectFilter::One(k),
            ib_subnet::IBSubnetSearchConfig {
                include_history: false,
            },
        )
        .await?;

        let ibsubnet = ibsubnets.first().ok_or(StateHandlerError::MissingData {
            object_id: k.to_string(),
            missing: "ib_subnet not found",
        })?;

        ctx.services
            .ib_fabric_manager
            .bind_ib_ports(IBNetwork::from(ibsubnet), v)
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
            .entry(ib.ib_subnet_id)
            .or_insert(Vec::new())
            .push(guid);
    }

    for (k, v) in ibconf {
        let ibsubnets = ib_subnet::IBSubnet::find(
            txn,
            crate::db::UuidKeyedObjectFilter::One(k),
            ib_subnet::IBSubnetSearchConfig {
                include_history: false,
            },
        )
        .await?;

        let ibsubnet = ibsubnets.first().ok_or(StateHandlerError::MissingData {
            object_id: k.to_string(),
            missing: "ib_subnet not found",
        })?;
        let pkey = ibsubnet.config.pkey.ok_or(StateHandlerError::MissingData {
            object_id: ibsubnet.id.to_string(),
            missing: "ib_subnet pkey",
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
