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

//! State Controller IO implementation for Machines

use config_version::{ConfigVersion, Versioned};

use crate::{
    db::{host_machine::HostMachine, machine::Machine, DatabaseError},
    model::controller_outcome::PersistentStateHandlerOutcome,
    model::machine::{
        machine_id::MachineId, DpuDiscoveringState, InstanceState, MachineState, ManagedHostState,
        ManagedHostStateSnapshot, MeasuringState,
    },
    state_controller::{
        io::StateControllerIO,
        machine::{context::MachineStateHandlerContextObjects, metrics::MachineMetricsEmitter},
        snapshot_loader::{DbSnapshotLoader, MachineStateSnapshotLoader, SnapshotLoaderError},
    },
};

/// State Controller IO implementation for Machines
#[derive(Default, Debug)]
pub struct MachineStateControllerIO {
    snapshot_loader: DbSnapshotLoader,
}

#[async_trait::async_trait]
impl StateControllerIO for MachineStateControllerIO {
    type ObjectId = MachineId;
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type MetricsEmitter = MachineMetricsEmitter;
    type ContextObjects = MachineStateHandlerContextObjects;

    const DB_LOCK_NAME: &'static str = "machine_state_controller_lock";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "machine_state_controller";

    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError> {
        Ok(crate::db::host_machine::HostMachine::list_active_ids(txn)
            .await
            .map_err(|x| SnapshotLoaderError::GenericError(x.into()))?)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        machine_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        self.snapshot_loader
            .load_machine_snapshot(txn, machine_id)
            .await
    }

    async fn load_controller_state(
        &self,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, SnapshotLoaderError> {
        let current = state.host_snapshot.current.clone();

        Ok(Versioned::new(current.state, current.version))
    }

    async fn persist_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        _old_version: ConfigVersion,
        new_state: Self::ControllerState,
    ) -> Result<(), SnapshotLoaderError> {
        HostMachine::update_state(txn, object_id, new_state)
            .await
            .map_err(|err| SnapshotLoaderError::GenericError(err.into()))?;

        Ok(())
    }

    async fn persist_outcome(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        Machine::update_controller_state_outcome(txn, object_id, outcome).await
    }

    fn metric_state_names(state: &ManagedHostState) -> (&'static str, &'static str) {
        use crate::model::machine::{CleanupState, InstanceState, MachineState};

        fn machine_state_name(machine_state: &MachineState) -> &'static str {
            match machine_state {
                MachineState::Init => "init",
                MachineState::WaitingForNetworkInstall => "waitingfornetworkinstall",
                MachineState::WaitingForNetworkConfig => "waitingfornetworkconfig",
                MachineState::UefiSetup { .. } => "uefisetup",
                MachineState::WaitingForDiscovery => "waitingfordiscovery",
                MachineState::Discovered => "discovered",
                MachineState::WaitingForLockdown { .. } => "waitingforlockdown",
            }
        }

        fn discovering_state_name(discovering_state: &DpuDiscoveringState) -> &'static str {
            match discovering_state {
                DpuDiscoveringState::Initializing => "dpuinitializing",
                DpuDiscoveringState::Configuring => "dpuconfiguring",
                DpuDiscoveringState::BmcFirmwareUpdate { .. } => "dpubmcfirmwareupdate",
            }
        }

        fn instance_state_name(instance_state: &InstanceState) -> &'static str {
            match instance_state {
                InstanceState::Init => "init",
                InstanceState::WaitingForNetworkConfig => "waitingfornetworkconfig",
                InstanceState::Ready => "ready",
                InstanceState::BootingWithDiscoveryImage { .. } => "bootingwithdiscoveryimage",
                InstanceState::SwitchToAdminNetwork => "switchtoadminnetwork",
                InstanceState::WaitingForNetworkReconfig => "waitingfornetworkreconfig",
                InstanceState::DPUReprovision { .. } => "dpureprovisioning",
            }
        }

        fn measuring_state_name(measuring_state: &MeasuringState) -> &'static str {
            match measuring_state {
                MeasuringState::WaitingForMeasurements => "waitingformeasurements",
                MeasuringState::PendingBundle => "pendingbundle",
            }
        }

        fn cleanup_state_name(cleanup_state: &CleanupState) -> &'static str {
            match cleanup_state {
                CleanupState::HostCleanup => "hostcleanup",
                CleanupState::DisableBIOSBMCLockdown => "disablebmclockdown",
            }
        }

        match state {
            ManagedHostState::DpuDiscoveringState { discovering_state } => {
                ("dpudiscovering", discovering_state_name(discovering_state))
            }
            ManagedHostState::DPUNotReady { machine_state } => {
                ("dpunotready", machine_state_name(machine_state))
            }
            ManagedHostState::HostNotReady { machine_state } => {
                ("hostnotready", machine_state_name(machine_state))
            }
            ManagedHostState::Ready => ("ready", ""),
            ManagedHostState::Assigned { instance_state } => {
                ("assigned", instance_state_name(instance_state))
            }
            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                ("waitingforcleanup", cleanup_state_name(cleanup_state))
            }
            ManagedHostState::Created => ("created", ""),
            ManagedHostState::ForceDeletion => ("forcedeletion", ""),
            ManagedHostState::Failed { .. } => ("failed", ""),
            ManagedHostState::DPUReprovision { .. } => ("reprovisioning", ""),
            ManagedHostState::Measuring { measuring_state } => {
                ("measuring", measuring_state_name(measuring_state))
            }
        }
    }

    fn time_in_state_above_sla(state: &Versioned<Self::ControllerState>) -> bool {
        let time_in_state = chrono::Utc::now()
            .signed_duration_since(state.version.timestamp())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

        match &state.value {
            ManagedHostState::DpuDiscoveringState { discovering_state } => {
                match discovering_state {
                    DpuDiscoveringState::Initializing | DpuDiscoveringState::Configuring => {
                        time_in_state > std::time::Duration::from_secs(30 * 60)
                    }
                    DpuDiscoveringState::BmcFirmwareUpdate { .. } => {
                        time_in_state > std::time::Duration::from_secs(30 * 60)
                    }
                }
            }
            ManagedHostState::DPUNotReady { machine_state } => {
                // Init has no SLA since starting discovery requires a manual action
                match machine_state {
                    MachineState::Init => false,
                    MachineState::WaitingForDiscovery => false,
                    _ => time_in_state > std::time::Duration::from_secs(30 * 60),
                }
            }
            ManagedHostState::HostNotReady { machine_state } => match machine_state {
                MachineState::Init => false,
                MachineState::WaitingForDiscovery => false,
                _ => time_in_state > std::time::Duration::from_secs(30 * 60),
            },
            ManagedHostState::Ready => false,
            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::Ready => false,
                InstanceState::BootingWithDiscoveryImage { retry } if retry.count > 0 => {
                    // Since retries happen after 30min, the occurence of any retry means we exhausted the SLA
                    true
                }
                _ => time_in_state > std::time::Duration::from_secs(30 * 60),
            },
            ManagedHostState::WaitingForCleanup { .. } => {
                time_in_state > std::time::Duration::from_secs(30 * 60)
            }
            ManagedHostState::Created => time_in_state > std::time::Duration::from_secs(30 * 60),
            ManagedHostState::ForceDeletion => {
                time_in_state > std::time::Duration::from_secs(30 * 60)
            }
            ManagedHostState::Failed { .. } => true,
            ManagedHostState::DPUReprovision { .. } => {
                time_in_state > std::time::Duration::from_secs(30 * 60)
            }
            ManagedHostState::Measuring { measuring_state } => match measuring_state {
                // The API shouldn't be waiting for measurements for long. As soon
                // as it transitions into this state, Scout should get an Action::Measure
                // action, and it should pretty quickly send measurements in (~seconds).
                MeasuringState::WaitingForMeasurements => {
                    time_in_state > std::time::Duration::from_secs(30 * 60)
                }
                // If the machine is waiting for a matching bundle, this could
                // take a bit, since it means either auto-bundle generation OR
                // manual bundle generation needs to happen. In the case of new
                // turn ups, this could take hours or even days (e.g. if new gear
                // is sitting there).
                MeasuringState::PendingBundle => false,
            },
        }
    }
}
