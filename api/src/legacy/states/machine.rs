/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgRow, FromRow, Postgres, Row, Transaction};

use crate::{
    db::{machine::Machine, DatabaseError},
    model::machine::{
        self as new_machine, machine_id::MachineId, CleanupState, DpuDiscoveringState,
        DpuInitState, FailureDetails, LockdownInfo, ManagedHostState as NewManagedHostState,
        MeasuringState, ReprovisionState, RetryInfo, UefiSetupInfo,
    },
    state_controller::machine::io::CURRENT_STATE_MODEL_VERSION,
    CarbideError, CarbideResult,
};

struct OldMachine {
    controller_state: ManagedHostStateV1,
}

impl<'r> FromRow<'r, PgRow> for OldMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<ManagedHostStateV1> =
            row.try_get("controller_state")?;

        Ok(OldMachine {
            controller_state: controller_state.0,
        })
    }
}

/// Possible Machine state-machine implementation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
/// Possible ManagedHost state-machine implementation
/// Only DPU machine field in DB will contain state. Host will be empty. DPU state field will be
/// used to derive state for DPU and Host both.
pub enum ManagedHostStateV1 {
    /// Dpu was discovered by a site-explorer and is being configuring via redfish.
    DpuDiscoveringState {
        discovering_state: DpuDiscoveringState,
    },
    /// DPU is not yet ready.
    DPUNotReady {
        machine_state: MachineState,
    },
    /// DPU is ready, Host is not yet Ready.
    HostNotReady {
        machine_state: MachineState,
    },
    /// Host is Ready for instance creation.
    Ready,
    /// Host is assigned to an Instance.
    Assigned {
        instance_state: InstanceState,
    },
    /// Some cleanup is going on.
    WaitingForCleanup {
        cleanup_state: CleanupState,
    },
    /// Intermediate state for machine to be created.
    /// This state is not processed anywhere. Correct state is updated immediately.
    Created,
    /// A forced deletion process has been triggered by the admin CLI
    /// State controller will no longer manage the Machine
    ForceDeletion,

    /// Machine moved to failed state. Recovery will be based on FailedCause
    Failed {
        details: FailureDetails,
        machine_id: MachineId,
        #[serde(default)]
        retry_count: u32,
    },

    DPUReprovision {
        reprovision_state: ReprovisionState,
    },
    Measuring {
        measuring_state: MeasuringState,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum MachineState {
    Init,
    WaitingForPlatformConfiguration,
    WaitingForNetworkInstall,
    WaitingForNetworkConfig,
    UefiSetup {
        uefi_setup_info: UefiSetupInfo,
    },
    WaitingForDiscovery,
    Discovered,
    /// Lockdown handling.
    WaitingForLockdown {
        lockdown_info: LockdownInfo,
    },
    MachineValidating {
        context: String,
        id: uuid::Uuid,
        completed: usize,
        total: usize,
    },
}

/// Possible Instance state-machine implementation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum InstanceState {
    Init, // Instance is created but not picked by state machine yet.
    WaitingForNetworkConfig,
    Ready,
    BootingWithDiscoveryImage {
        #[serde(default)]
        retry: RetryInfo,
    },
    SwitchToAdminNetwork,
    WaitingForNetworkReconfig,
    DPUReprovision {
        reprovision_state: ReprovisionState,
    },
}

pub async fn start_migration(db_pool: sqlx::PgPool) -> eyre::Result<()> {
    crate::legacy::states::machine::migrate_machines(db_pool.clone())
        .await
        .map_err(|e| e.into())
}

pub async fn migrate_machines(db: sqlx::PgPool) -> CarbideResult<()> {
    tracing::info!("Trying to migrate machines to new state model.");

    let migrate_from = CURRENT_STATE_MODEL_VERSION - 1;
    let migrate_to = CURRENT_STATE_MODEL_VERSION;

    let mut txn = db.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin discover_machine",
            e,
        ))
    })?;

    let all_hosts = Machine::get_host_machine_ids_for_state_model_version(&mut txn, migrate_from)
        .await
        .map_err(CarbideError::from)?;

    _ = txn.rollback().await;

    for host_id in &all_hosts {
        tracing::info!(%host_id, "Trying to migrate host to version {migrate_to}");
        let mut txn = db.begin().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "begin discover_machine",
                e,
            ))
        })?;

        if let Err(err) = migrate_machine_to_v2(&mut txn, host_id, migrate_to).await {
            tracing::error!(%host_id, "Migration failed. Err: {:?}", err);
            _ = txn.rollback().await;
        } else {
            tracing::info!(%host_id, "Migration successful.");
            _ = txn.commit().await;
        }
    }
    tracing::info!("Finished migrating machines to new state model.");
    Ok(())
}

impl TryFrom<MachineState> for new_machine::MachineState {
    type Error = CarbideError;

    fn try_from(value: MachineState) -> Result<Self, Self::Error> {
        Ok(match value {
            MachineState::Init => new_machine::MachineState::Init,
            MachineState::UefiSetup { uefi_setup_info } => {
                new_machine::MachineState::UefiSetup { uefi_setup_info }
            }
            MachineState::WaitingForDiscovery => new_machine::MachineState::WaitingForDiscovery,
            MachineState::WaitingForPlatformConfiguration => {
                new_machine::MachineState::WaitingForPlatformConfiguration
            }
            MachineState::Discovered => new_machine::MachineState::Discovered,
            MachineState::WaitingForLockdown { lockdown_info } => {
                new_machine::MachineState::WaitingForLockdown { lockdown_info }
            }
            MachineState::MachineValidating {
                context,
                id,
                completed,
                total,
            } => new_machine::MachineState::MachineValidating {
                context,
                id,
                completed,
                total,
            },
            _ => {
                return Err(CarbideError::GenericError(format!(
                    "Invalid machine state for host: {:?}",
                    value
                )))
            }
        })
    }
}

impl InstanceState {
    fn to_new_instance_state(&self, dpu_ids: &[MachineId]) -> new_machine::InstanceState {
        match self {
            InstanceState::Init => new_machine::InstanceState::Init,
            InstanceState::WaitingForNetworkConfig => {
                new_machine::InstanceState::WaitingForNetworkConfig
            }
            InstanceState::Ready => new_machine::InstanceState::Ready,
            InstanceState::BootingWithDiscoveryImage { retry } => {
                new_machine::InstanceState::BootingWithDiscoveryImage {
                    retry: retry.clone(),
                }
            }
            InstanceState::SwitchToAdminNetwork => new_machine::InstanceState::SwitchToAdminNetwork,
            InstanceState::WaitingForNetworkReconfig => {
                new_machine::InstanceState::WaitingForNetworkReconfig
            }
            InstanceState::DPUReprovision { reprovision_state } => {
                new_machine::InstanceState::DPUReprovision {
                    dpu_states: new_machine::DpuReprovisionStates {
                        states: dpu_ids
                            .iter()
                            .map(|x| (x.clone(), reprovision_state.clone()))
                            .collect::<HashMap<MachineId, ReprovisionState>>(),
                    },
                }
            }
        }
    }
}

// Carbide couldn't load machine from db using new state model. It should be old states.
// It needs migration.
async fn migrate_machine_to_v2(
    txn: &mut Transaction<'_, Postgres>,
    host_id: &MachineId,
    migrate_version: i16,
) -> CarbideResult<()> {
    let query = "SELECT controller_state FROM machines WHERE id=$1";
    let old_machine = sqlx::query_as::<_, OldMachine>(query)
        .bind(host_id.to_string())
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "migration fetch", e))?;

    let dpus = Machine::find_dpu_machine_ids_by_host_machine_id(txn, host_id).await?;
    let new_state = match &old_machine.controller_state {
        ManagedHostStateV1::DpuDiscoveringState { discovering_state } => {
            NewManagedHostState::DpuDiscoveringState {
                dpu_states: crate::model::machine::DpuDiscoveringStates {
                    states: dpus
                        .clone()
                        .into_iter()
                        .map(|dpu_id| (dpu_id, discovering_state.clone()))
                        .collect::<HashMap<MachineId, DpuDiscoveringState>>(),
                },
            }
        }
        ManagedHostStateV1::DPUNotReady { machine_state } => {
            let dpu_init_state = match machine_state {
                MachineState::Init => DpuInitState::Init,
                MachineState::WaitingForNetworkConfig => DpuInitState::WaitingForNetworkConfig,
                MachineState::WaitingForNetworkInstall => DpuInitState::WaitingForNetworkInstall,
                MachineState::WaitingForPlatformConfiguration => {
                    DpuInitState::WaitingForPlatformConfiguration
                }
                _ => {
                    return Err(CarbideError::GenericError(format!(
                        "State: {:?} is not correct for DPU for host: {}.",
                        machine_state, host_id
                    )))
                }
            };

            NewManagedHostState::DPUInit {
                dpu_states: crate::model::machine::DpuInitStates {
                    states: dpus
                        .clone()
                        .into_iter()
                        .map(|dpu_id| (dpu_id, dpu_init_state.clone()))
                        .collect::<HashMap<MachineId, DpuInitState>>(),
                },
            }
        }
        ManagedHostStateV1::HostNotReady { machine_state } => NewManagedHostState::HostInit {
            machine_state: machine_state.clone().try_into()?,
        },

        ManagedHostStateV1::Assigned { instance_state } => NewManagedHostState::Assigned {
            instance_state: instance_state.to_new_instance_state(&dpus),
        },
        ManagedHostStateV1::DPUReprovision { reprovision_state } => {
            NewManagedHostState::DPUReprovision {
                dpu_states: new_machine::DpuReprovisionStates {
                    states: dpus
                        .clone()
                        .into_iter()
                        .map(|dpu_id| (dpu_id, reprovision_state.clone()))
                        .collect::<HashMap<MachineId, ReprovisionState>>(),
                },
            }
        }
        // These states have same json so parsing with new ManagedHostState must work.
        ManagedHostStateV1::Ready => NewManagedHostState::Ready,
        ManagedHostStateV1::ForceDeletion => NewManagedHostState::ForceDeletion,
        ManagedHostStateV1::Failed {
            details,
            machine_id,
            retry_count,
        } => NewManagedHostState::Failed {
            details: details.clone(),
            machine_id: machine_id.clone(),
            retry_count: *retry_count,
        },
        ManagedHostStateV1::Measuring { measuring_state } => NewManagedHostState::Measuring {
            measuring_state: measuring_state.clone(),
        },
        ManagedHostStateV1::WaitingForCleanup { cleanup_state } => {
            NewManagedHostState::WaitingForCleanup {
                cleanup_state: cleanup_state.clone(),
            }
        }
        ManagedHostStateV1::Created => NewManagedHostState::Created,
    };

    Machine::update_state_with_state_model_version_update(
        txn,
        host_id,
        &dpus,
        new_state,
        migrate_version,
    )
    .await?;

    Ok(())
}
