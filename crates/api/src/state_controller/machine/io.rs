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

use carbide_uuid::machine::MachineId;
use config_version::{ConfigVersion, Versioned};
use db::{self, DatabaseError};
use model::StateSla;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    self, DpuDiscoveringState, DpuInitState, HostHealthConfig, MachineValidatingState,
    ManagedHostState, ManagedHostStateSnapshot, MeasuringState, ValidationState,
};
use sqlx::PgConnection;

use crate::state_controller::io::StateControllerIO;
use crate::state_controller::machine::context::MachineStateHandlerContextObjects;
use crate::state_controller::machine::metrics::MachineMetricsEmitter;

// This should be updated on each new model introdunction
pub const CURRENT_STATE_MODEL_VERSION: i16 = 2;

/// State Controller IO implementation for Machines
#[derive(Default, Debug)]
pub struct MachineStateControllerIO {
    pub host_health: HostHealthConfig,
}

#[async_trait::async_trait]
impl StateControllerIO for MachineStateControllerIO {
    type ObjectId = MachineId;
    type State = ManagedHostStateSnapshot;
    type ControllerState = ManagedHostState;
    type MetricsEmitter = MachineMetricsEmitter;
    type ContextObjects = MachineStateHandlerContextObjects;

    const DB_ITERATION_ID_TABLE_NAME: &'static str = "machine_state_controller_iteration_ids";
    const DB_QUEUED_OBJECTS_TABLE_NAME: &'static str = "machine_state_controller_queued_objects";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "machine_state_controller";

    async fn list_objects(
        &self,
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        Ok(db::machine::find_machine_ids(
            txn,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        machine_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        let mut retstate = db::managed_host::load_snapshot(
            txn,
            machine_id,
            model::machine::LoadSnapshotOptions {
                include_history: false,
                include_instance_data: true,
                host_health_config: self.host_health,
            },
        )
        .await?;

        if let Some(retstate) = retstate.as_mut() {
            let dpa_snapshots = db::dpa_interface::find_by_machine_id(txn, machine_id).await?;
            retstate.dpa_interface_snapshots = dpa_snapshots;
        };

        return Ok(retstate);
    }

    async fn load_controller_state(
        &self,
        _txn: &mut PgConnection,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, DatabaseError> {
        let current = state.host_snapshot.state.clone();

        Ok(Versioned::new(current.value, current.version))
    }

    async fn persist_controller_state(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        _old_version: ConfigVersion,
        new_state: &Self::ControllerState,
    ) -> Result<(), DatabaseError> {
        db::machine::update_state(txn, object_id, new_state).await
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        db::machine::update_controller_state_outcome(txn, object_id, outcome).await
    }

    fn metric_state_names(state: &ManagedHostState) -> (&'static str, &'static str) {
        use model::machine::{CleanupState, InstanceState, MachineState};

        fn dpuinit_state_name(dpu_state: &DpuInitState) -> &'static str {
            match dpu_state {
                DpuInitState::InstallDpuOs { .. } => "installdpuos",
                DpuInitState::Init => "init",
                DpuInitState::WaitingForNetworkInstall => "waitingfornetworkinstall",
                DpuInitState::WaitingForNetworkConfig => "waitingfornetworkconfig",
                DpuInitState::WaitingForPlatformConfiguration => "waitingforplatformconfiguration",
                DpuInitState::PollingBiosSetup => "pollingbiossetup",
                DpuInitState::WaitingForPlatformPowercycle { .. } => "waitingforplatformpowercycle",
                DpuInitState::DpfStates { .. } => "dpfstates",
            }
        }

        fn machine_state_name(machine_state: &MachineState) -> &'static str {
            match machine_state {
                MachineState::Init => "init",
                MachineState::WaitingForPlatformConfiguration => "waitingforplatformconfiguration",
                MachineState::PollingBiosSetup => "pollingbiossetup",
                MachineState::SetBootOrder { .. } => "setbootorder",
                MachineState::UefiSetup { .. } => "uefisetup",
                MachineState::WaitingForDiscovery => "waitingfordiscovery",
                MachineState::Discovered { .. } => "discovered",
                MachineState::WaitingForLockdown { .. } => "waitingforlockdown",
                MachineState::EnableIpmiOverLan => "enableipmioverlan",
                MachineState::Measuring { .. } => "machinestatemeasuring",
            }
        }

        fn discovering_state_name(discovering_state: &DpuDiscoveringState) -> &'static str {
            match discovering_state {
                DpuDiscoveringState::Initializing => "dpuinitializing",
                DpuDiscoveringState::Configuring => "dpuconfiguring",
                DpuDiscoveringState::DisableSecureBoot { .. } => "disablesecureboot",
                DpuDiscoveringState::EnableSecureBoot { .. } => "enablesecureboot",
                DpuDiscoveringState::SetUefiHttpBoot => "setuefihttpboot",
                DpuDiscoveringState::RebootAllDPUS => "rebootalldpus",
                DpuDiscoveringState::EnableRshim => "enablershim",
            }
        }

        fn instance_state_name(instance_state: &InstanceState) -> &'static str {
            match instance_state {
                InstanceState::Init => "init",
                InstanceState::WaitingForNetworkSegmentToBeReady => {
                    "waitingfornetworksegmenttobeready"
                }
                InstanceState::WaitingForNetworkConfig => "waitingfornetworkconfig",
                InstanceState::WaitingForStorageConfig => "waitingforstorageconfig",
                InstanceState::WaitingForExtensionServicesConfig => {
                    "waitingforextensionservicesconfig"
                }
                InstanceState::WaitingForRebootToReady => "waitingforreboottoready",
                InstanceState::Ready => "ready",
                InstanceState::BootingWithDiscoveryImage { .. } => "bootingwithdiscoveryimage",
                InstanceState::SwitchToAdminNetwork => "switchtoadminnetwork",
                InstanceState::WaitingForNetworkReconfig => "waitingfornetworkreconfig",
                InstanceState::DPUReprovision { .. } => "dpureprovisioning",
                InstanceState::Failed { .. } => "failed",
                InstanceState::HostReprovision { .. } => "hostreprovisioning",
                InstanceState::NetworkConfigUpdate { .. } => "networkconfigupdate",
                InstanceState::WaitingForDpusToUp => "waitingfordpustoup",
                InstanceState::HostPlatformConfiguration { .. } => "hostplatformconfiguration",
                InstanceState::DpaProvisioning => "dpaprovisioning",
                InstanceState::WaitingForDpaToBeReady => "waitingfordpatobeready",
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
                CleanupState::Init => "init",
                CleanupState::SecureEraseBoss { .. } => "secureeraseboss",
                CleanupState::HostCleanup { .. } => "hostcleanup",
                CleanupState::CreateBossVolume { .. } => "createbossvolume",
                CleanupState::DisableBIOSBMCLockdown => "disablebmclockdown",
            }
        }

        fn machine_validation_state_name(
            validation_state: &MachineValidatingState,
        ) -> &'static str {
            match validation_state {
                MachineValidatingState::MachineValidating { .. } => "machinevalidating",
                MachineValidatingState::RebootHost { .. } => "reboothost",
            }
        }
        match state {
            ManagedHostState::DpuDiscoveringState { dpu_states } => {
                // Min state indicates the least processed DPU. The state machine is blocked
                // becasue of this.
                let dpu_state = dpu_states.states.values().min();
                let Some(dpu_state) = dpu_state else {
                    return ("unknown", "dpu");
                };
                ("dpudiscovering", discovering_state_name(dpu_state))
            }
            ManagedHostState::DPUInit { dpu_states } => {
                // Min state indicates the least processed DPU. The state machine is blocked
                // becasue of this.
                let dpu_state = dpu_states.states.values().min();
                let Some(dpu_state) = dpu_state else {
                    return ("unknown", "dpu");
                };
                ("dpunotready", dpuinit_state_name(dpu_state))
            }
            ManagedHostState::HostInit { machine_state } => {
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
            ManagedHostState::HostReprovision { .. } => ("hostreprovisioning", ""),
            ManagedHostState::Measuring { measuring_state } => {
                ("measuring", measuring_state_name(measuring_state))
            }
            ManagedHostState::PostAssignedMeasuring { measuring_state } => (
                "postassignedmeasuring",
                measuring_state_name(measuring_state),
            ),
            ManagedHostState::BomValidating {
                bom_validating_state,
            } => match bom_validating_state {
                machine::BomValidating::MatchingSku(_) => ("bomvalidating", "matchingsku"),
                machine::BomValidating::UpdatingInventory(_) => {
                    ("bomvalidating", "updatinginventory")
                }
                machine::BomValidating::VerifyingSku(_) => ("bomvalidating", "verifyingsku"),
                machine::BomValidating::SkuVerificationFailed(_) => {
                    ("bomvalidating", "skuverificationfailed")
                }
                machine::BomValidating::WaitingForSkuAssignment(_) => {
                    ("bomvalidating", "waitingforskuassignment")
                }
                machine::BomValidating::SkuMissing(_) => ("bomvalidating", "skumissing"),
            },
            ManagedHostState::Validation { validation_state } => match validation_state {
                ValidationState::MachineValidation { machine_validation } => (
                    "validation",
                    machine_validation_state_name(machine_validation),
                ),
            },
        }
    }

    fn state_sla(state: &Versioned<Self::ControllerState>) -> StateSla {
        machine::state_sla(&state.value, &state.version)
    }
}
