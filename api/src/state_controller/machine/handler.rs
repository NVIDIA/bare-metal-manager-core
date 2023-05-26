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

use std::{net::IpAddr, task::Poll, time::SystemTime};

use chrono::{DateTime, Utc};
use eyre::eyre;
use rpc::{InstanceInterfaceStatusObservation, InstanceNetworkStatusObservation};

use crate::{
    db::{
        dpu_machine::DpuMachine, instance::DeleteInstance, machine::Machine,
        vpc_resource_leaf::VpcResourceLeaf,
    },
    kubernetes::{self, VpcApi},
    model::{
        config_version::ConfigVersion,
        instance::config::network::{InstanceNetworkConfig, InterfaceFunctionId},
        machine::{
            machine_id::MachineId,
            network::MachineNetworkStatusObservation,
            CleanupState, InstanceState, LockdownInfo,
            LockdownMode::{self, Enable},
            LockdownState, MachineSnapshot, MachineState, ManagedHostState,
            ManagedHostStateSnapshot,
        },
    },
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
                if let Some(instance) = state.instance.as_ref() {
                    // Instance is requested by user. Let's configure it.
                    // Create managed resources and move to Assigned: WaitingForNetworkConfig
                    if let Some(vpc_api) = ctx.services.vpc_api.as_ref() {
                        let _poll_status = kubernetes::create_managed_resource(
                            txn,
                            &state.dpu_snapshot.machine_id,
                            instance.config.network.clone(),
                            instance.instance_id,
                            vpc_api,
                        )
                        .await?;
                    }

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
        }

        Ok(())
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
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
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
                    machine_state: MachineState::WaitingForLeafCreation,
                };
            }
            ManagedHostState::DPUNotReady {
                machine_state: MachineState::WaitingForLeafCreation,
            } => {
                //TODO: In multi DPU setup, only one machine interface should be Primary per host.
                let host_address = state
                    .host_snapshot
                    .interfaces
                    .iter()
                    .filter(|x| x.is_primary)
                    .last()
                    .ok_or_else(|| StateHandlerError::MissingData {
                        object_id: host_machine_id.to_string(),
                        missing: "Host Interface",
                    })?
                    .ip_address;

                match ctx.services.vpc_api.as_ref() {
                    None => {
                        // New: Ethernet Virtualizer
                        // Has forge-dpu-agent written the network config?
                        if !has_applied_network_config(
                            &state.dpu_snapshot.network_config.version,
                            state.dpu_snapshot.network_status_observation.as_ref(),
                        ) {
                            return Ok(());
                        }
                    }
                    Some(vpc_api) => {
                        // Old: K8s VPC
                        // Create leaf and wait for it to get loopback ip.
                        if Poll::Pending
                            == create_leaf_and_wait_for_loopback_ip(
                                txn,
                                &state.dpu_snapshot.machine_id,
                                host_address,
                                vpc_api.as_ref(),
                            )
                            .await?
                        {
                            // No-one has written the network config. Stay in current state.
                            return Ok(());
                        }
                    }
                }

                // Network config has been applied, move to next state
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

/// Has the network config version that the host wants has been applied by DPU?
fn has_applied_network_config(
    dpu_expected_version: &ConfigVersion,
    dpu_observation: Option<&MachineNetworkStatusObservation>,
) -> bool {
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
    *dpu_expected_version == dpu_observed_version
}

pub async fn create_leaf_and_wait_for_loopback_ip(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    dpu_machine_id: &MachineId,
    host_address: IpAddr,
    vpc_api: &dyn VpcApi,
) -> Result<Poll<()>, StateHandlerError> {
    let dpu = DpuMachine::find_by_machine_id(txn, dpu_machine_id)
        .await
        .map_err(|err| StateHandlerError::GenericError(err.into()))?;
    match vpc_api.try_create_leaf(dpu, host_address).await? {
        Poll::Pending => Ok(Poll::Pending),
        Poll::Ready(ip_address) => {
            // Update loopback ip in table.
            let mut vpc_db_resource = VpcResourceLeaf::find(txn, dpu_machine_id)
                .await
                .map_err(|err| StateHandlerError::GenericError(err.into()))?;
            vpc_db_resource
                .update_loopback_ip_address(txn, ip_address)
                .await
                .map_err(|err| StateHandlerError::GenericError(err.into()))?;
            Ok(Poll::Ready(()))
        }
    }
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
                MachineState::WaitingForLeafCreation => {
                    tracing::warn!(
                        "Invalid State WaitingForLeafCreation for Host Machine {}",
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
                            let checker = ctx.services.reachability_params.checker.build(
                                state.dpu_ssh_ip_address.ip(),
                                crate::reachability::ExpectedState::Alive,
                            );

                            // Wait until DPU is reachable (ping test)
                            if checker
                                .check_condition()
                                .await
                                .map_err(|e| StateHandlerError::GenericError(e.into()))?
                            {
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

async fn record_instance_network_observation(
    network_config: InstanceNetworkConfig,
    instance_id: uuid::Uuid,
    network_config_version: ConfigVersion,
    ctx: &mut StateHandlerContext<'_>,
) -> Result<(), StateHandlerError> {
    let mut iface_observations: Vec<InstanceInterfaceStatusObservation> =
        Vec::with_capacity(network_config.interfaces.len());
    for iface in network_config.interfaces.iter() {
        let addresses = iface
            .ip_addrs
            .iter()
            .map(|prefix_and_addr| prefix_and_addr.1.to_string())
            .collect();

        iface_observations.push(InstanceInterfaceStatusObservation {
            function_type: rpc::InterfaceFunctionType::from(iface.function_id.function_type())
                as i32,
            virtual_function_id: match iface.function_id {
                InterfaceFunctionId::Physical {} => None,
                InterfaceFunctionId::Virtual { id } => Some(id as u32),
            },
            mac_address: None,
            addresses,
        });
    }

    ctx.services
        .forge_api
        .record_observed_instance_network_status(tonic::Request::new(
            InstanceNetworkStatusObservation {
                instance_id: Some(instance_id.into()),
                config_version: network_config_version.version_string(),
                observed_at: Some(SystemTime::now().into()),
                interfaces: iface_observations,
                // TODO(k82cn): add IB interface observations.
                ib_interfaces: Vec::new(),
            },
        ))
        .await
        .map_err(|status| {
            StateHandlerError::GenericError(eyre!(<tonic::Status as Into<eyre::Report>>::into(
                status
            )))
        })?;

    Ok(())
}
///
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
                    // It should be first state to process here. Wait until managed resources
                    // are up. Reboot host and moved to Ready.

                    // Wait for instance network config to be applied

                    if let Some(vpc_api) = ctx.services.vpc_api.as_ref() {
                        // Old: K8s VPC

                        if kubernetes::create_managed_resource(
                            txn,
                            &state.dpu_snapshot.machine_id,
                            instance.config.network.clone(),
                            instance.instance_id,
                            vpc_api,
                        )
                        .await?
                        .is_pending()
                        {
                            return Ok(());
                        }
                        record_instance_network_observation(
                            instance.config.network.clone(),
                            instance.instance_id,
                            instance.network_config_version,
                            ctx,
                        )
                        .await?;
                    } else {
                        // New: Ethernet Virtualizer

                        // Check DPU network config has been applied
                        if !has_applied_network_config(
                            &state.dpu_snapshot.network_config.version,
                            state.dpu_snapshot.network_status_observation.as_ref(),
                        ) {
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
                    }

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
                    // Wait until deleted flag is set. If set, start deleting Managed resource.
                    // try_delete_managed_resources function is async. We have to move out of Ready
                    // state as soon as possible, to indicate that delete process is started. In next cycle, this function must return Poll::Ready if all managed resources are deleted, else keep retrying, but in next state.
                    if instance.delete_requested {
                        // Reboot host. Host will boot with carbide discovery image now. Changes
                        // are done in get_pxe_instructions api.
                        // User will loose all access to instance now.
                        restart_machine(&state.host_snapshot, ctx).await?;

                        *controller_state.modify() = ManagedHostState::Assigned {
                            instance_state: InstanceState::BootingWithDiscoveryImage,
                        };
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
                    if let Some(vpc_api) = ctx.services.vpc_api.as_ref() {
                        let _ = vpc_api
                            .try_delete_managed_resources(instance.instance_id)
                            .await?;
                    }

                    *controller_state.modify() = ManagedHostState::Assigned {
                        instance_state: InstanceState::DeletingManagedResource,
                    };
                }
                InstanceState::DeletingManagedResource => {
                    // Wait until Managed resources are deleted now.
                    if let Some(vpc_api) = ctx.services.vpc_api.as_ref() {
                        if vpc_api
                            .try_delete_managed_resources(instance.instance_id)
                            .await?
                            .is_pending()
                        {
                            return Ok(());
                        }
                    }

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
                    if let Some(vpc_api) = ctx.services.vpc_api.as_ref() {
                        // Old: K8s VPC
                        if vpc_api
                            .try_monitor_leaf(&state.dpu_snapshot.machine_id)
                            .await?
                            .is_pending()
                        {
                            return Ok(());
                        }
                    }

                    if ctx.services.vpc_api.is_none() {
                        // New: Ethernet Virtualizer
                        // Has forge-dpu-agent written the network config?
                        if !has_applied_network_config(
                            &state.dpu_snapshot.network_config.version,
                            state.dpu_snapshot.network_status_observation.as_ref(),
                        ) {
                            return Ok(());
                        }
                    }

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

    let client = ctx
        .services
        .redfish_client_pool
        .create_client(&machine_snapshot.machine_id, bmc_ip, None)
        .await
        .map_err(|e| StateHandlerError::GenericError(e.into()))?;

    // Since libredfish calls are thread blocking and we are inside an async function,
    // we have to delegate the actual call into a threadpool
    tokio::task::spawn_blocking(move || client.power(libredfish::SystemPowerControl::ForceRestart))
        .await
        .map_err(|e| {
            StateHandlerError::GenericError(eyre!("Failed redfish ForceRestart subtask: {}", e))
        })?
        .map_err(|e| StateHandlerError::GenericError(eyre!("Failed to restart machine: {}", e)))?;

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
        .create_client(&machine_snapshot.machine_id, bmc_ip, None)
        .await
        .map_err(|e| StateHandlerError::GenericError(e.into()))?;

    // Since libredfish calls are thread blocking and we are inside an async function,
    // we have to delegate the actual call into a threadpool
    tokio::task::spawn_blocking(move || {
        if enable {
            client.lockdown(libredfish::EnabledDisabled::Enabled)?;
            // TODO: TPM cleanup
        }
        client.power(libredfish::SystemPowerControl::ForceRestart)
    })
    .await
    .map_err(|e| {
        StateHandlerError::GenericError(eyre!("Failed redfish ForceRestart subtask: {}", e))
    })?
    .map_err(|e| {
        StateHandlerError::GenericError(eyre!(
            "Failed to restart machine during lockdown handling: {}",
            e
        ))
    })?;

    Ok(())
}
