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

use crate::{
    db::host_machine::HostMachine,
    model::{
        config_version::{ConfigVersion, Versioned},
        machine::{machine_id::MachineId, ManagedHostState, ManagedHostStateSnapshot},
    },
    state_controller::{
        controller::StateControllerIO,
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

    fn db_lock_name() -> &'static str {
        "machine_state_controller_lock"
    }

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
        let current = state.dpu_snapshot.current.clone();

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

    fn metric_state_names(state: &ManagedHostState) -> (&'static str, &'static str) {
        use crate::model::machine::{CleanupState, InstanceState, MachineState};

        fn machine_state_name(machine_state: &MachineState) -> &'static str {
            match machine_state {
                MachineState::Init => "init",
                MachineState::WaitingForNetworkConfig => "waitingfornetworkconfig",
                MachineState::WaitingForLeafCreation => "waitingforleafcreation",
                MachineState::WaitingForDiscovery => "waitingfordiscovery",
                MachineState::Discovered => "discovered",
                MachineState::WaitingForLockdown { .. } => "waitingforlockdown",
            }
        }

        fn instance_state_name(instance_state: &InstanceState) -> &'static str {
            match instance_state {
                InstanceState::Init => "init",
                InstanceState::WaitingForNetworkConfig => "waitingfornetworkconfig",
                InstanceState::Ready => "ready",
                InstanceState::BootingWithDiscoveryImage => "bootingwithdiscoveryimage",
                InstanceState::SwitchToAdminNetwork => "switchtoadminnetwork",
                InstanceState::WaitingForNetworkReconfig => "waitingfornetworkreconfig",
            }
        }

        fn cleanup_state_name(cleanup_state: &CleanupState) -> &'static str {
            match cleanup_state {
                CleanupState::HostCleanup => "hostcleanup",
                CleanupState::DisableBIOSBMCLockdown => "disablebmclockdown",
            }
        }

        match state {
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
        }
    }
}
