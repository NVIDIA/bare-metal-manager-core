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

use std::{
    collections::{hash_map::RandomState, HashMap},
    net::IpAddr,
    task::Poll,
    time::SystemTime,
};

use chrono::{DateTime, Utc};
use eyre::eyre;
use rpc::{InstanceInterfaceStatusObservation, InstanceNetworkStatusObservation};
use sqlx::Postgres;

use crate::{
    db::{
        dpu_machine::DpuMachine, instance::DeleteInstance, instance_address::InstanceAddress,
        machine_interface::MachineInterface, vpc_resource_leaf::VpcResourceLeaf,
    },
    kubernetes,
    model::{
        config_version::ConfigVersion,
        instance::config::network::{InstanceNetworkConfig, InterfaceFunctionId},
        machine::{
            machine_id::MachineId,
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
        machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let managed_state = &state.managed_state;

        match &managed_state {
            ManagedHostState::DPUNotReady { .. } => {
                self.dpu_handler
                    .handle_object_state(machine_id, state, controller_state, txn, ctx)
                    .await?;
            }

            ManagedHostState::HostNotReady { .. } => {
                self.host_handler
                    .handle_object_state(machine_id, state, controller_state, txn, ctx)
                    .await?;
            }

            ManagedHostState::Ready => {
                // Check if instance to be created.
                if let Some(instance) = state.instance.as_ref() {
                    // Instance is requested by user. Let's configure it.
                    // Create managed resources and move to Assigned: WaitingForNetworkConfig
                    let _poll_status = kubernetes::create_managed_resource(
                        txn,
                        machine_id,
                        instance.config.network.clone(),
                        instance.instance_id,
                        &ctx.services.vpc_api,
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
                    .handle_object_state(machine_id, state, controller_state, txn, ctx)
                    .await?;
            }

            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                let Some(ref host_snapshot) = state.host_snapshot else {
                    return Ok(());
                };

                match cleanup_state {
                    CleanupState::HostCleanup => {
                        if !cleanedup_after_state_transition(
                            host_snapshot.current.version,
                            host_snapshot.last_cleanup_time,
                        )
                        .await?
                        {
                            return Ok(());
                        }

                        // Reboot host
                        restart_machine(host_snapshot, ctx).await?;

                        *controller_state.modify() = ManagedHostState::HostNotReady {
                            machine_state: MachineState::Discovered,
                        };
                    }
                    CleanupState::DisableBIOSBMCLockdown => {
                        log::error!("DisableBIOSBMCLockdown state is not implemented. Machine {} stuck in unimplemented state.", machine_id);
                    }
                }
            }
            ManagedHostState::Created => {
                log::error!("Machine just created. Er should not be here.");
            }
            ManagedHostState::ForceDeletion => {
                // Just ignore.
                log::info!(
                    "Machine {} is marked for forced deletion. Ignoring.",
                    machine_id
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
        machine_id: &MachineId,
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
                // Create leaf and wait for it to get loopback ip.
                if Poll::Pending
                    == create_leaf_and_wait_for_loopback_ip(
                        txn,
                        &state.dpu_snapshot.machine_id,
                        ctx,
                    )
                    .await?
                {
                    return Ok(());
                }

                *controller_state.modify() = ManagedHostState::HostNotReady {
                    machine_state: MachineState::Init,
                };
            }
            state => {
                log::warn!("Unhandled State {:?} for DPU machine {}", state, machine_id);
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

pub async fn create_leaf_and_wait_for_loopback_ip(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    dpu_machine_id: &MachineId,
    ctx: &mut StateHandlerContext<'_>,
) -> Result<Poll<()>, StateHandlerError> {
    let dpu = DpuMachine::find_by_machine_id(txn, dpu_machine_id)
        .await
        .map_err(|err| StateHandlerError::GenericError(err.into()))?;
    match ctx.services.vpc_api.try_create_leaf(dpu).await? {
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
        machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let managed_state = &state.managed_state;
        if let ManagedHostState::HostNotReady {
            machine_state: MachineState::Init,
        } = &managed_state
        {
            // At this stage, no host machine is created. Only source of truth is
            // machine_interface.
            // If IP allocated => DHCP done and host is powered-on.
            // try_updating_leaf.
            let Some(machine_interface) = MachineInterface::find_host_primary_interface_by_dpu_id(txn, machine_id).await? else {
                    log::info!("Still host interface is not created for dpu_id: {}.", machine_id);
                    return Ok(());
            };

            // Find associated machine_interface with host where dpu id = machine_id;
            let ip_address = match machine_interface.addresses().last() {
                Some(address) => match address.address.ip() {
                    IpAddr::V4(addr) => addr,
                    x => {
                        return Err(StateHandlerError::GenericError(eyre!(
                            "Invalid address {:?} for machine: {}",
                            x,
                            machine_id
                        )));
                    }
                },
                None => {
                    // Not an error for this scenario.
                    log::info!("Still host IP is not allocated to dpu_id: {}.", machine_id);
                    return Ok(());
                }
            };
            if ctx
                .services
                .vpc_api
                .try_update_leaf(machine_id, ip_address)
                .await?
                .is_pending()
            {
                return Ok(());
            }
            *controller_state.modify() = ManagedHostState::HostNotReady {
                machine_state: MachineState::WaitingForDiscovery,
            };
            return Ok(());
        }

        let Some(ref host_snapshot) = state.host_snapshot else {
            // But in any other state, except WaitingForDiscovery, host snapshot is mandatory. Raise Error.
            if let ManagedHostState::HostNotReady { machine_state: MachineState::WaitingForDiscovery} = &managed_state {
                return Ok(());
            }
            return Err(StateHandlerError::HostSnapshotMissing(
                machine_id.clone(),
                managed_state.clone(),
            ));
        };

        if let ManagedHostState::HostNotReady { machine_state } = &managed_state {
            match machine_state {
                MachineState::Init => {}
                MachineState::WaitingForLeafCreation => {
                    log::warn!(
                        "Invalid State WaitingForLeafCreation for Host Machine {}",
                        machine_id
                    );
                }
                MachineState::WaitingForDiscovery => {
                    if !discovered_after_state_transition(
                        state.dpu_snapshot.current.version,
                        host_snapshot.last_discovery_time,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                    // Enable Bios/BMC lockdown now.
                    lockdown_host(host_snapshot, ctx, true).await?;

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
                        host_snapshot.last_reboot_time,
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
                                restart_machine(host_snapshot, ctx).await?;
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
    txn: &mut sqlx::Transaction<'_, Postgres>,
    ctx: &mut StateHandlerContext<'_>,
) -> Result<(), StateHandlerError> {
    let ip_details: HashMap<uuid::Uuid, IpAddr, RandomState> = HashMap::from_iter(
        InstanceAddress::get_allocated_address(txn, instance_id)
            .await
            .map_err(|e| StateHandlerError::GenericError(e.into()))?
            .into_iter()
            .map(|x| (x.segment_id, x.address.ip())),
    );

    let mut iface_observations: Vec<InstanceInterfaceStatusObservation> =
        Vec::with_capacity(network_config.interfaces.len());
    for iface in network_config.interfaces.iter() {
        let address = ip_details.get(&iface.network_segment_id);

        let address = match address {
            Some(address) => address,
            None => {
                let error = format!(
                    "Failed to retrieve Ip Address for instance {} and function ID {:?}",
                    instance_id, iface.function_id
                );
                return Err(StateHandlerError::GenericError(eyre!(error)));
            }
        };

        iface_observations.push(InstanceInterfaceStatusObservation {
            function_type: rpc::InterfaceFunctionType::from(iface.function_id.function_type())
                as i32,
            virtual_function_id: match iface.function_id {
                InterfaceFunctionId::PhysicalFunctionId {} => None,
                InterfaceFunctionId::VirtualFunctionId { id } => Some(id as u32),
            },
            mac_address: None,
            addresses: vec![address.to_string()],
        });
    }

    ctx.services
        .forge_api
        .record_observed_instance_network_status(tonic::Request::new(
            InstanceNetworkStatusObservation {
                instance_id: Some(instance_id.into()),
                config_version: network_config_version.to_version_string(),
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
        machine_id: &MachineId,
        state: &mut ManagedHostStateSnapshot,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let Some(ref host_snapshot) = state.host_snapshot else {
            return Ok(());
        };

        let Some(ref instance) = state.instance else {
            return Err(StateHandlerError::GenericError(eyre!("Instance is empty at this point. Cleanup is needed for dpu: {}.", machine_id)));
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
                    if kubernetes::create_managed_resource(
                        txn,
                        machine_id,
                        instance.config.network.clone(),
                        instance.instance_id,
                        &ctx.services.vpc_api.clone(),
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
                        txn,
                        ctx,
                    )
                    .await?;

                    // Reboot host
                    restart_machine(host_snapshot, ctx).await?;

                    // Instance is ready.
                    // We can not determine if machine is rebooted successfully or not. Just leave
                    // it like this and declare Instance Ready.
                    *controller_state.modify() = ManagedHostState::Assigned {
                        instance_state: InstanceState::Ready,
                    };
                }
                InstanceState::Ready => {
                    // Machine is up after reboot. Hurrey. Instance is up.
                    // Wait until deleted flag is set. If set, start deleting Managed resource.
                    // try_delete_managed_resources function is async. We have to move out of Ready
                    // state as soon as possible, to indicate that delete process is started. In next cycle, this function must return Poll::Ready if all managed resources are deleted, else keep retrying, but in next state.
                    if instance.delete_requested {
                        // Reboot host. Host will boot with carbide discovery image now. Changes
                        // are done in get_pxe_instructions api.
                        // User will loose all access to instance now.
                        restart_machine(host_snapshot, ctx).await?;

                        *controller_state.modify() = ManagedHostState::Assigned {
                            instance_state: InstanceState::BootingWithDiscoveryImage,
                        };
                    }
                }
                InstanceState::BootingWithDiscoveryImage => {
                    if !rebooted(
                        state.dpu_snapshot.current.version,
                        host_snapshot.last_reboot_time,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                    let _ = ctx
                        .services
                        .vpc_api
                        .try_delete_managed_resources(instance.instance_id)
                        .await?;

                    *controller_state.modify() = ManagedHostState::Assigned {
                        instance_state: InstanceState::DeletingManagedResource,
                    };
                }
                InstanceState::DeletingManagedResource => {
                    // Wait until Managed resources are deleted now.
                    if let Poll::Ready(()) = ctx
                        .services
                        .vpc_api
                        .try_delete_managed_resources(instance.instance_id)
                        .await?
                    {
                        *controller_state.modify() = ManagedHostState::Assigned {
                            instance_state: InstanceState::WaitingForNetworkReconfig,
                        };
                    }
                }
                InstanceState::WaitingForNetworkReconfig => {
                    // Managed resources are deleted, now wait until admin network is reconfigured on dpu.
                    if ctx
                        .services
                        .vpc_api
                        .try_monitor_leaf(machine_id)
                        .await?
                        .is_pending()
                    {
                        return Ok(());
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
                    restart_machine(host_snapshot, ctx).await?;

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
    tokio::task::spawn_blocking(move || {
        client.boot_once(libredfish::Boot::Pxe)?;
        client.power(libredfish::SystemPowerControl::ForceRestart)
    })
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
    .map_err(|e| StateHandlerError::GenericError(eyre!("Failed to restart machine: {}", e)))?;

    Ok(())
}
