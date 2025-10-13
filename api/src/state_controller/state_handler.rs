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
use std::collections::HashMap;
use std::sync::Arc;

use forge_uuid::machine::MachineId;
use libredfish::RedfishError;
use model::controller_outcome::{PersistentSourceReference, PersistentStateHandlerOutcome};
use model::machine::{
    DpuDiscoveringState, DpuDiscoveringStates, DpuInitNextStateResolver, DpuInitState,
    DpuInitStates, DpuReprovisionStates, HostReprovisionState, InstallDpuOsState,
    InstanceNextStateResolver, InstanceState, Machine, MachineNextStateResolver, MachineState,
    ManagedHostState, ManagedHostStateSnapshot, ReprovisionState,
};
use model::power_manager::PowerOptions;
use model::resource_pool::ResourcePoolError;
use model::resource_pool::common::IbPools;
use mqttea::MqtteaClient;
use sqlx::PgConnection;

use crate::cfg::file::CarbideConfig;
use crate::db::DatabaseError;
use crate::ib::IBFabricManager;
use crate::ipmitool::IPMITool;
use crate::redfish::{RedfishClientCreationError, RedfishClientPool};
use crate::storage::{NvmeshClientPool, StorageError};

/// Services that are accessible to the `StateHandler`
pub struct StateHandlerServices {
    /// A database connection pool that can be used for additional queries
    pub pool: sqlx::PgPool,

    /// API for interaction with Libredfish
    pub redfish_client_pool: Arc<dyn RedfishClientPool>,

    /// API for interaction with Forge IBFabricManager
    pub ib_fabric_manager: Arc<dyn IBFabricManager>,

    /// API for interaction with NVMesh storage cluster
    pub nvmesh_client_pool: Arc<dyn NvmeshClientPool>,

    /// Resource pools for ib pkey allocation/release.
    pub ib_pools: IbPools,

    /// An implementation of the IPMITool that understands how to reboot a machine
    pub ipmi_tool: Arc<dyn IPMITool>,

    /// Access to the site config
    pub site_config: Arc<CarbideConfig>,

    pub mqtt_client: Option<Arc<MqtteaClient>>,
}

/// The collection of generic objects which are referenced in StateHandlerContext
pub trait StateHandlerContextObjects: Send + Sync + 'static {
    /// The type that can hold metrics specific to a single object.
    ///
    /// These metrics can be produced by code inside the state handler by writing
    /// them to `ObjectMetrics`.
    /// After state has been processed for all all objects, the various metrics
    /// are merged into an `IterationMetrics` object.
    type ObjectMetrics: std::fmt::Debug + Default + Send + Sync + 'static;
}

/// Context parameter passed to `StateHandler`
pub struct StateHandlerContext<'a, T: StateHandlerContextObjects> {
    /// Services that are available to the `StateHandler`
    pub services: &'a Arc<StateHandlerServices>,
    /// Metrics that are produced as a result of acting on an object
    pub metrics: &'a mut T::ObjectMetrics,
    /// Power Options.
    pub power_options: Option<PowerOptions>,
}

/// Defines a function that will be called to determine the next step in
/// an objects lifecycle.
///
/// The function retrieves the full Object state as loaded from the database
/// as input, and can take any decisions to advance the Object state.
#[async_trait::async_trait]
pub trait StateHandler: std::fmt::Debug + Send + Sync + 'static {
    type ObjectId: Clone + std::fmt::Display + std::fmt::Debug;
    type State;
    type ControllerState;
    type ContextObjects: StateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        state: &mut Self::State,
        controller_state: &Self::ControllerState,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError>;
}

/// References the source code that lead to the result
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SourceReference {
    pub file: &'static str,
    pub line: u32,
}

impl From<&SourceReference> for PersistentSourceReference {
    fn from(value: &SourceReference) -> Self {
        Self {
            file: value.file.to_string(),
            line: value.line,
        }
    }
}

pub enum StateHandlerOutcome<S> {
    Wait {
        /// The reason we're waiting
        reason: String,
        source_ref: SourceReference,
    },
    Transition {
        /// The state we are transitioning to
        next_state: S,
        source_ref: SourceReference,
    },
    DoNothing {
        source_ref: SourceReference,
    }, // Nothing to do. Typically in Ready or Assigned/Ready
    Deleted {
        _source_ref: SourceReference,
    }, // The object was removed from the database
}

macro_rules! source_ref {
    () => {
        crate::state_controller::state_handler::SourceReference {
            file: file!(),
            line: line!(),
        }
    };
}
pub(crate) use source_ref;

macro_rules! do_nothing {
    () => {
        StateHandlerOutcome::DoNothing {
            source_ref: crate::state_controller::state_handler::source_ref!(),
        }
    };
}

macro_rules! transition {
    ($next_state:expr) => {
        StateHandlerOutcome::Transition {
            next_state: $next_state,
            source_ref: crate::state_controller::state_handler::source_ref!(),
        }
    };
}

macro_rules! wait {
    ($reason:expr) => {
        StateHandlerOutcome::Wait {
            reason: $reason,
            source_ref: crate::state_controller::state_handler::source_ref!(),
        }
    };
}

macro_rules! deleted {
    () => {
        StateHandlerOutcome::Deleted {
            _source_ref: crate::state_controller::state_handler::source_ref!(),
        }
    };
}

pub(crate) use {deleted, do_nothing, transition, wait};

impl<S> std::fmt::Display for StateHandlerOutcome<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use StateHandlerOutcome::*;
        let msg = match self {
            Wait { reason, .. } => reason.as_str(),
            Transition { .. } => "Transition to next state",
            DoNothing { .. } => "Do nothing",
            Deleted { .. } => "Deleted",
        };
        write!(f, "{msg}")
    }
}

#[derive(Debug)]
pub enum MeasuringProblem {
    NoEkCertVerificationStatusFound(String),
}

impl std::fmt::Display for MeasuringProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            MeasuringProblem::NoEkCertVerificationStatusFound(info) => {
                write!(f, "NoEkCertVerificationStatusFound - {info}")
            }
        }
    }
}

/// Error type for handling a Machine State
#[derive(Debug, thiserror::Error)]
pub enum StateHandlerError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Failed to advance state: {0}")]
    GenericError(eyre::Report),
    #[error("State for object {object_id} can not be advanced. Missing data: {missing}")]
    MissingData {
        object_id: String,
        missing: &'static str,
    },
    #[error("{0}")]
    DBError(#[from] DatabaseError),

    #[error("Error releasing from resource pool: {0}")]
    PoolReleaseError(#[from] ResourcePoolError),

    #[error("Invalid host state {1} for DPU {0}.")]
    InvalidHostState(MachineId, Box<ManagedHostState>),

    #[error("Failed to execute \"{operation}\" on IB fabric manager: {error}")]
    IBFabricError {
        operation: String,
        error: eyre::Report,
    },

    #[error("Storage error {0}")]
    StorageError(#[from] StorageError),

    #[error("Failed to create redfish client: {0}")]
    RedfishClientCreationError(#[from] RedfishClientCreationError),

    #[error("The state handler for object {object_id} in state \"{state}\" timed out")]
    Timeout { object_id: String, state: String },

    #[error("Failed redfish operation: {operation}. Details: {error}")]
    RedfishError {
        operation: &'static str,
        error: RedfishError,
    },

    #[error("Failed to update firmware: {0}")]
    FirmwareUpdateError(eyre::Report),

    #[error("Manual intervention required. Cannot make progress. {0}")]
    ManualInterventionRequired(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Dpu: {0} is missing from states.")]
    MissingDpuFromState(MachineId),

    #[error("State will not be advanced due to health probe alert")]
    HealthProbeAlert,

    #[error(
        "The object is in the state for longer than defined by the SLA. Handler outcome: {handler_outcome}"
    )]
    TimeInStateAboveSla { handler_outcome: String },

    #[error("Problem with measured boot: {0}")]
    MeasuringError(MeasuringProblem),

    #[error("Resource {resource} cleanup error: {error}")]
    ResourceCleanupError {
        resource: &'static str,
        error: String,
    },
}

impl StateHandlerError {
    /// Returns the label that will be used to identify the error in metrics
    ///
    /// This will be a simplified description of the error, to avoid having too
    /// many metric dimensions.
    pub fn metric_label(&self) -> &'static str {
        match self {
            StateHandlerError::TransactionError(_) => "transaction_error",
            StateHandlerError::GenericError(_) => "generic_error",
            StateHandlerError::FirmwareUpdateError(_) => "firware_update_error",
            StateHandlerError::MissingData { .. } => "missing_data",
            StateHandlerError::DBError(_) => "db_error",
            StateHandlerError::Timeout { .. } => "timeout",
            StateHandlerError::PoolReleaseError(_) => "pool_release_error",
            StateHandlerError::InvalidHostState(_, _) => "invalid_host_state",
            StateHandlerError::IBFabricError { .. } => "ib_fabric_error",
            StateHandlerError::StorageError(_) => "storage_error",
            StateHandlerError::InvalidState(_) => "invalid_state",
            StateHandlerError::RedfishClientCreationError(_) => "redfish_client_creation_error",
            StateHandlerError::RedfishError { operation, .. } => match *operation {
                "restart" => "redfish_restart_error",
                "lockdown" => "redfish_lockdown_error",
                _ => "redfish_other_error",
            },
            StateHandlerError::ManualInterventionRequired(_) => "manual_intervention_required",
            StateHandlerError::MissingDpuFromState(_) => "missing_dpu_from_managedhost_state",
            StateHandlerError::HealthProbeAlert => "health_probe_alert",
            StateHandlerError::TimeInStateAboveSla { .. } => "time_in_state_above_sla",
            StateHandlerError::MeasuringError(problem) => match problem {
                MeasuringProblem::NoEkCertVerificationStatusFound(_) => {
                    "no_ek_cert_verification_status_found"
                }
            },
            StateHandlerError::ResourceCleanupError { resource, .. } => match *resource {
                "VpcLoopbackIp" => "vpcloopback_release_failed",
                "network_segment" => "network_segment_cleanup_failed",
                _ => "resource_cleanup_failed",
            },
        }
    }
}

/// A `StateHandler` implementation which does nothing
pub struct NoopStateHandler<I, S, CS, CO> {
    _phantom_data: std::marker::PhantomData<Option<(I, S, CS, CO)>>,
}

impl<I, S, CS, CO> std::fmt::Debug for NoopStateHandler<I, S, CS, CO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopStateHandler").finish()
    }
}

impl<I, S, CS, CO> Default for NoopStateHandler<I, S, CS, CO> {
    fn default() -> Self {
        Self {
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<
    I: Clone + std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    S: Send + Sync + 'static,
    CS: Send + Sync + 'static,
    CO: StateHandlerContextObjects,
> StateHandler for NoopStateHandler<I, S, CS, CO>
{
    type State = S;
    type ControllerState = CS;
    type ObjectId = I;
    type ContextObjects = CO;

    async fn handle_object_state(
        &self,
        _object_id: &Self::ObjectId,
        _state: &mut Self::State,
        _controller_state: &Self::ControllerState,
        _txn: &mut PgConnection,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError> {
        Ok(do_nothing!())
    }
}

pub trait FromStateHandlerResult<S> {
    fn from_result(r: Result<&StateHandlerOutcome<S>, &StateHandlerError>) -> Self;
}

impl<S> FromStateHandlerResult<S> for PersistentStateHandlerOutcome {
    fn from_result(
        r: Result<&StateHandlerOutcome<S>, &StateHandlerError>,
    ) -> PersistentStateHandlerOutcome {
        match r {
            Ok(StateHandlerOutcome::Wait { reason, source_ref }) => {
                PersistentStateHandlerOutcome::Wait {
                    reason: reason.clone(),
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::Transition { source_ref, .. }) => {
                PersistentStateHandlerOutcome::Transition {
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::DoNothing { source_ref }) => {
                PersistentStateHandlerOutcome::DoNothing {
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::Deleted { .. }) => unreachable!(),
            Err(err) => PersistentStateHandlerOutcome::Error {
                err: err.to_string(),
                // TODO: Make it possible to determine where errors are generated
                source_ref: None,
            },
        }
    }
}

pub trait NextState {
    fn next_bfb_install_state(
        &self,
        current_state: &ManagedHostState,
        install_os_substate: &InstallDpuOsState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError>;

    fn next_state(
        &self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
        host_snapshot: &Machine,
    ) -> Result<ManagedHostState, StateHandlerError>;

    fn next_state_with_all_dpus_updated(
        &self,
        state: &ManagedHostStateSnapshot,
        current_reprovision_state: &ReprovisionState,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let dpu_ids_for_reprov =
            // EnumIter conflicts with Itertool, don't know why?
            itertools::Itertools::collect_vec(state.dpu_snapshots.iter().filter_map(|x| {
                if x.reprovision_requested.is_some() {
                    Some(&x.id)
                } else {
                    None
                }
            }));

        let all_machine_ids =
            itertools::Itertools::collect_vec(state.dpu_snapshots.iter().map(|x| &x.id));

        match current_reprovision_state {
            ReprovisionState::BmcFirmwareUpgrade { .. } => ReprovisionState::FirmwareUpgrade
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    // Mark all DPUs in PowerDown state.
                    dpu_ids_for_reprov,
                ),
            ReprovisionState::FirmwareUpgrade => ReprovisionState::WaitingForNetworkInstall
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    // Mark all DPUs in PowerDown state.
                    all_machine_ids,
                ),
            ReprovisionState::WaitingForNetworkInstall => ReprovisionState::PoweringOffHost
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    all_machine_ids,
                ),
            ReprovisionState::PoweringOffHost => ReprovisionState::PowerDown
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    // Mark all DPUs in PowerDown state.
                    all_machine_ids,
                ),
            ReprovisionState::PowerDown => ReprovisionState::VerifyFirmareVersions
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    // Move only DPUs in WaitingForNetworkInstall for which reprovision is
                    // triggered.
                    dpu_ids_for_reprov,
                ),
            ReprovisionState::BufferTime => ReprovisionState::VerifyFirmareVersions
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    dpu_ids_for_reprov,
                ),
            ReprovisionState::WaitingForNetworkConfig => ReprovisionState::RebootHostBmc
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    all_machine_ids,
                ),
            ReprovisionState::RebootHostBmc => ReprovisionState::RebootHost
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    all_machine_ids,
                ),
            _ => Err(StateHandlerError::InvalidState(format!(
                "Unhandled {current_reprovision_state} state for all dpu handling."
            ))),
        }
    }
}

pub trait DpuDiscoveringStateHelper {
    fn next_state(
        self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError>;
}

impl DpuDiscoveringStateHelper for DpuDiscoveringState {
    fn next_state(
        self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::DpuDiscoveringState { dpu_states } => {
                let mut states = dpu_states.states.clone();
                let entry = states.entry(*dpu_id).or_insert(self.clone());
                *entry = self;

                Ok(ManagedHostState::DpuDiscoveringState {
                    dpu_states: DpuDiscoveringStates { states },
                })
            }
            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to DpuDiscoveringState::next_state.".to_string(),
            )),
        }
    }
}

pub trait DpuInitStateHelper {
    fn next_state(
        self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError>;

    fn next_state_with_all_dpus_updated(
        self,
        current_state: &ManagedHostState,
    ) -> Result<ManagedHostState, StateHandlerError>;
}

impl DpuInitStateHelper for DpuInitState {
    fn next_state(
        self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::DPUInit { dpu_states } => {
                let mut states = dpu_states.states.clone();
                let entry = states.entry(*dpu_id).or_insert(self.clone());
                *entry = self;

                Ok(ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates { states },
                })
            }

            ManagedHostState::DpuDiscoveringState { dpu_states } => {
                // All DPUs must be moved to same DPUInit state.
                let states = dpu_states
                    .states
                    .keys()
                    .map(|x| (*x, self.clone()))
                    .collect::<HashMap<MachineId, DpuInitState>>();
                Ok(ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates { states },
                })
            }

            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to DpuNotReady::next_state.".to_string(),
            )),
        }
    }

    fn next_state_with_all_dpus_updated(
        self,
        current_state: &ManagedHostState,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::DPUInit { dpu_states } => {
                let states = dpu_states
                    .states
                    .keys()
                    .map(|x| (*x, self.clone()))
                    .collect::<HashMap<MachineId, DpuInitState>>();

                Ok(ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates { states },
                })
            }
            ManagedHostState::DpuDiscoveringState { dpu_states } => {
                // All DPUs must be moved to same DPUInit state.
                let states = dpu_states
                    .states
                    .keys()
                    .map(|x| (*x, DpuInitState::Init))
                    .collect::<HashMap<MachineId, DpuInitState>>();
                Ok(ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates { states },
                })
            }
            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to DpuNotReady::next_state_all_dpu.".to_string(),
            )),
        }
    }
}

impl NextState for MachineNextStateResolver {
    fn next_state(
        &self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
        _host_snapshot: &Machine,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let reprovision_state = current_state
            .as_reprovision_state(dpu_id)
            .ok_or_else(|| StateHandlerError::MissingDpuFromState(*dpu_id))?;

        let mut dpu_states = match current_state {
            ManagedHostState::DPUReprovision { dpu_states } => dpu_states.states.clone(),
            _ => {
                return Err(StateHandlerError::InvalidState(format!(
                    "Unhandled {current_state} state for Machine handling."
                )));
            }
        };

        match reprovision_state {
            ReprovisionState::RebootHost => Ok(ManagedHostState::HostInit {
                machine_state: MachineState::Discovered {
                    skip_reboot_wait: false,
                },
            }),
            ReprovisionState::VerifyFirmareVersions => {
                dpu_states.insert(*dpu_id, ReprovisionState::WaitingForNetworkConfig);
                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states: dpu_states },
                })
            }
            _ => Err(StateHandlerError::InvalidState(format!(
                "Unhandled {reprovision_state} state for Non-Instance handling."
            ))),
        }
    }

    fn next_bfb_install_state(
        &self,
        current_state: &ManagedHostState,
        install_os_substate: &InstallDpuOsState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let mut dpu_states = match current_state {
            ManagedHostState::DPUReprovision { dpu_states } => dpu_states.states.clone(),
            _ => {
                return Err(StateHandlerError::InvalidState(format!(
                    "Unhandled {current_state} state for Non-Instance handling."
                )));
            }
        };
        match install_os_substate {
            InstallDpuOsState::Completed => {
                dpu_states.insert(*dpu_id, ReprovisionState::WaitingForNetworkInstall);
                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states: dpu_states },
                })
            }
            _ => {
                dpu_states.insert(
                    *dpu_id,
                    ReprovisionState::InstallDpuOs {
                        substate: install_os_substate.clone(),
                    },
                );
                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states: dpu_states },
                })
            }
        }
    }
}

impl NextState for InstanceNextStateResolver {
    fn next_state(
        &self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
        host_snapshot: &Machine,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let reprovision_state = current_state
            .as_reprovision_state(dpu_id)
            .ok_or_else(|| StateHandlerError::MissingDpuFromState(*dpu_id))?;

        let mut dpu_states = match current_state {
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision { dpu_states },
            } => dpu_states.states.clone(),
            _ => {
                return Err(StateHandlerError::InvalidState(format!(
                    "Unhandled {current_state} state for Instance handling."
                )));
            }
        };

        match reprovision_state {
            ReprovisionState::RebootHost => {
                if host_snapshot.host_reprovision_requested.is_some() {
                    Ok(ManagedHostState::Assigned {
                        instance_state: InstanceState::HostReprovision {
                            reprovision_state: HostReprovisionState::CheckingFirmware,
                        },
                    })
                } else {
                    Ok(ManagedHostState::Assigned {
                        instance_state: InstanceState::Ready,
                    })
                }
            }
            ReprovisionState::VerifyFirmareVersions => {
                dpu_states.insert(*dpu_id, ReprovisionState::WaitingForNetworkConfig);
                Ok(ManagedHostState::Assigned {
                    instance_state: InstanceState::DPUReprovision {
                        dpu_states: DpuReprovisionStates { states: dpu_states },
                    },
                })
            }
            _ => Err(StateHandlerError::InvalidState(format!(
                "Unhandled {reprovision_state} state for Instance handling."
            ))),
        }
    }

    fn next_bfb_install_state(
        &self,
        current_state: &ManagedHostState,
        install_os_substate: &InstallDpuOsState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let mut dpu_states = match current_state {
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision { dpu_states },
            } => dpu_states.states.clone(),
            _ => {
                return Err(StateHandlerError::InvalidState(format!(
                    "Unhandled {current_state} state for Instance handling."
                )));
            }
        };
        match install_os_substate {
            InstallDpuOsState::Completed => {
                dpu_states.insert(*dpu_id, ReprovisionState::WaitingForNetworkInstall);
                Ok(ManagedHostState::Assigned {
                    instance_state: InstanceState::DPUReprovision {
                        dpu_states: DpuReprovisionStates { states: dpu_states },
                    },
                })
            }
            _ => {
                dpu_states.insert(
                    *dpu_id,
                    ReprovisionState::InstallDpuOs {
                        substate: install_os_substate.clone(),
                    },
                );
                Ok(ManagedHostState::Assigned {
                    instance_state: InstanceState::DPUReprovision {
                        dpu_states: DpuReprovisionStates { states: dpu_states },
                    },
                })
            }
        }
    }
}

impl NextState for DpuInitNextStateResolver {
    fn next_state(
        &self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
        _host_snapshot: &Machine,
    ) -> Result<ManagedHostState, StateHandlerError> {
        DpuInitState::Init.next_state(current_state, dpu_id)
    }

    fn next_bfb_install_state(
        &self,
        current_state: &ManagedHostState,
        install_os_substate: &InstallDpuOsState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match install_os_substate {
            // Move to DpuInit state
            InstallDpuOsState::Completed => DpuInitState::Init.next_state(current_state, dpu_id),
            _ => Ok(DpuInitState::InstallDpuOs {
                substate: install_os_substate.clone(),
            }
            .next_state(current_state, dpu_id)?),
        }
    }
}

pub(crate) trait ReprovisionStateHelper {
    fn next_state_with_all_dpus_updated(
        self,
        current_state: &ManagedHostState,
        dpu_snapshots: &[Machine],
        dpu_ids_to_process: Vec<&MachineId>,
    ) -> Result<ManagedHostState, StateHandlerError>;
}

impl ReprovisionStateHelper for ReprovisionState {
    // This is normal case when user wants to reprovision only one DPU. In this condition, this
    // function will update state only for those DPU for which reprovision is triggered. Reset will
    // be updated as NotUnderReprovision state.
    fn next_state_with_all_dpus_updated(
        self,
        current_state: &ManagedHostState,
        dpu_snapshots: &[Machine],
        dpu_ids_to_process: Vec<&MachineId>,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::Ready => {
                let states = dpu_snapshots
                    .iter()
                    .map(|x| {
                        (
                            x.id,
                            if dpu_ids_to_process.contains(&&x.id) {
                                self.clone()
                            } else {
                                ReprovisionState::NotUnderReprovision
                            },
                        )
                    })
                    .collect::<HashMap<MachineId, ReprovisionState>>();

                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states },
                })
            }
            ManagedHostState::DPUReprovision { dpu_states: _ } => {
                let states = dpu_snapshots
                    .iter()
                    .map(|x| {
                        (
                            x.id,
                            if dpu_ids_to_process.contains(&&x.id) {
                                self.clone()
                            } else {
                                ReprovisionState::NotUnderReprovision
                            },
                        )
                    })
                    .collect::<HashMap<MachineId, ReprovisionState>>();
                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states },
                })
            }
            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::DPUReprovision { .. }
                | InstanceState::BootingWithDiscoveryImage { .. }
                | InstanceState::Failed { .. } => {
                    let states = dpu_snapshots
                        .iter()
                        .map(|x| {
                            (
                                x.id,
                                if dpu_ids_to_process.contains(&&x.id) {
                                    self.clone()
                                } else {
                                    ReprovisionState::NotUnderReprovision
                                },
                            )
                        })
                        .collect::<HashMap<MachineId, ReprovisionState>>();

                    Ok(ManagedHostState::Assigned {
                        instance_state: InstanceState::DPUReprovision {
                            dpu_states: DpuReprovisionStates { states },
                        },
                    })
                }

                _ => Err(StateHandlerError::InvalidState(format!(
                    "Invalid State {current_state:?} passed to Reprovision::Assigned::next_state_with_all_dpus."
                ))),
            },
            _ => Err(StateHandlerError::InvalidState(format!(
                "Invalid State {current_state:?} passed to Reprovision::next_state_with_all_dpus."
            ))),
        }
    }
}

pub trait ManagedHostStateHelper {
    fn all_dpu_states_in_sync(&self) -> Result<bool, StateHandlerError>;
}

impl ManagedHostStateHelper for ManagedHostState {
    fn all_dpu_states_in_sync(&self) -> Result<bool, StateHandlerError> {
        match self {
            // Don't now why but if I use itertools::Itertools in header, EnumIter creates problem.
            ManagedHostState::DpuDiscoveringState { dpu_states } => all_equal(
                &itertools::Itertools::collect_vec(dpu_states.states.values()),
            ),
            ManagedHostState::DPUInit { dpu_states } => all_equal(
                &itertools::Itertools::collect_vec(dpu_states.states.values()),
            ),
            // TODO: multidpu: reprovision state handling.
            _ => Ok(true),
        }
    }
}

pub fn all_equal<A>(states: &[A]) -> Result<bool, StateHandlerError>
where
    A: PartialEq,
{
    let Some(first) = states.first() else {
        return Err(StateHandlerError::MissingData {
            object_id: "NA".to_string(),
            missing: "DPU states.",
        });
    };

    Ok(states.iter().all(|x| x == first))
}
