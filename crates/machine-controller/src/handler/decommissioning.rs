/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use carbide_secrets::credentials::CredentialKey;
use carbide_uuid::machine::MachineId;
use chrono::{Duration, Utc};
use libredfish::model::task::TaskState;
use libredfish::model::update_service::TransferProtocolType;
use libredfish::{EnabledDisabled, JobState, RedfishError, SystemPowerControl};
use model::bmc_suppression::{BmcSuppressionSubsystem, NewBmcSuppression};
use model::dpa_interface::{DpaInterfaceControllerState, DpaInterfaceType, DpaLockMode};
use model::machine::{
    DecommissioningState, DeconfiguringDpuState, DeconfiguringHostState, InstallDpuOsState,
    InstallingVanillaBfbState, ManagedHostState, ManagedHostStateSnapshot,
    VerifyingDhcpReleaseState,
};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use std::collections::{HashMap, HashSet};

use crate::context::MachineStateHandlerContextObjects;
use crate::dpf::{DpfOperations, dpf_dpudevices_and_dpunode_crs_noexist};
use crate::redfish::host_power_control;

fn deconfiguring(state: DeconfiguringHostState) -> ManagedHostState {
    ManagedHostState::Decommissioning {
        decommissioning_state: DecommissioningState::DeconfiguringHost {
            deconfiguring_state: state,
        },
    }
}

fn deconfiguring_dpus(dpu_states: HashMap<MachineId, DeconfiguringDpuState>) -> ManagedHostState {
    ManagedHostState::Decommissioning {
        decommissioning_state: DecommissioningState::DeconfiguringDpus { dpu_states },
    }
}

fn installing_vanilla_bfb(installing_state: InstallingVanillaBfbState) -> ManagedHostState {
    ManagedHostState::Decommissioning {
        decommissioning_state: DecommissioningState::InstallingVanillaBfb { installing_state },
    }
}

fn initial_bfb_install_state(state: &ManagedHostStateSnapshot) -> InstallingVanillaBfbState {
    InstallingVanillaBfbState::Installing {
        dpu_states: state
            .dpu_snapshots
            .iter()
            .map(|dpu| (dpu.id, InstallDpuOsState::InstallingBFB))
            .collect(),
    }
}

fn enter_bfb_install(state: &ManagedHostStateSnapshot) -> ManagedHostState {
    let installing_state = if state.host_snapshot.config.dpf.used_for_ingestion {
        InstallingVanillaBfbState::DeletingFromDpf
    } else {
        initial_bfb_install_state(state)
    };
    installing_vanilla_bfb(installing_state)
}

fn verifying_dhcp_release(verifying_state: VerifyingDhcpReleaseState) -> ManagedHostState {
    ManagedHostState::Decommissioning {
        decommissioning_state: DecommissioningState::VerifyingDhcpRelease { verifying_state },
    }
}

pub(super) async fn handle_preparing(
    state: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let machine_id = state.host_snapshot.id;
    let mut bmc_mac_addresses = Vec::with_capacity(state.dpu_snapshots.len() + 1);
    for machine in std::iter::once(&state.host_snapshot).chain(&state.dpu_snapshots) {
        let bmc_mac_address =
            machine
                .status
                .bmc_info
                .mac
                .ok_or_else(|| StateHandlerError::MissingData {
                    object_id: machine.id.to_string(),
                    missing: "bmc_mac",
                })?;
        bmc_mac_addresses.push(bmc_mac_address);
    }

    let mut txn = ctx.services.db_pool.begin().await?;
    let mut all_suppressions_acknowledged = true;
    for bmc_mac_address in bmc_mac_addresses {
        let suppression = db::bmc_suppression::upsert(
            &mut txn,
            &NewBmcSuppression {
                bmc_mac_address,
                subsystem: BmcSuppressionSubsystem::SiteExplorer,
                reason: format!("managed host {machine_id} is being decommissioned"),
            },
        )
        .await?;
        all_suppressions_acknowledged &= suppression.acknowledged_at.is_some();
    }

    let outcome = if all_suppressions_acknowledged {
        StateHandlerOutcome::transition(ManagedHostState::Decommissioning {
            decommissioning_state: DecommissioningState::DeconfiguringHost {
                deconfiguring_state: DeconfiguringHostState::DisableLockdown,
            },
        })
    } else {
        StateHandlerOutcome::do_nothing()
    };

    Ok(outcome.with_txn(txn))
}

pub(super) async fn handle_deconfiguring_host(
    deconfiguring_state: &DeconfiguringHostState,
    state: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let machine = &state.host_snapshot;
    let redfish_client = ctx
        .services
        .create_redfish_client_from_machine(machine)
        .await?;

    match deconfiguring_state {
        DeconfiguringHostState::DisableLockdown => {
            match redfish_client.lockdown_bmc(EnabledDisabled::Disabled).await {
                Ok(()) | Err(RedfishError::NotSupported(_)) => {}
                Err(error) => {
                    return Err(StateHandlerError::GenericError(eyre::eyre!(
                        "failed to disable host BMC lockdown: {error}"
                    )));
                }
            }

            let next = if machine.bmc_vendor().is_supermicro() {
                DeconfiguringHostState::RebootAfterLockdown
            } else {
                DeconfiguringHostState::ClearUefiPassword
            };
            Ok(StateHandlerOutcome::transition(deconfiguring(next)))
        }
        DeconfiguringHostState::RebootAfterLockdown => {
            host_power_control(
                redfish_client.as_ref(),
                machine,
                SystemPowerControl::ForceRestart,
                ctx,
            )
            .await
            .map_err(|error| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "failed to reboot host after disabling BMC lockdown: {error}"
                ))
            })?;
            Ok(StateHandlerOutcome::transition(deconfiguring(
                DeconfiguringHostState::ClearUefiPassword,
            )))
        }
        DeconfiguringHostState::ClearUefiPassword => {
            if machine.bios_password_set_time.is_none() {
                return Ok(StateHandlerOutcome::transition(deconfiguring(
                    DeconfiguringHostState::ClearSuperNicLockdown,
                )));
            }

            let bmc_mac =
                machine
                    .status
                    .bmc_info
                    .mac
                    .ok_or_else(|| StateHandlerError::MissingData {
                        object_id: machine.id.to_string(),
                        missing: "bmc_mac",
                    })?;
            let mut conn = ctx.services.db_pool.acquire().await?;
            let status = db::credential_rotation::device_rotation_status(
                &mut conn,
                db::credential_rotation::CredentialRotationType::HostUefi,
                bmc_mac,
            )
            .await?
            .ok_or_else(|| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "host UEFI credential version is not recorded for {bmc_mac}"
                ))
            })?;
            let version = status.current_version.ok_or_else(|| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "host UEFI credential version is not established for {bmc_mac}"
                ))
            })?;
            let version = u32::try_from(version).map_err(|error| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "invalid host UEFI credential version {version}: {error}"
                ))
            })?;
            drop(conn);

            let key = CredentialKey::host_uefi_site_default(version);
            let credentials = ctx
                .services
                .redfish_client_pool
                .credential_reader()
                .get_credentials(&key)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to read host UEFI credential: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "host UEFI credential {key:?} is not set"
                    ))
                })?;

            let job_id = ctx
                .services
                .redfish_client_pool
                .clear_host_uefi_password(redfish_client.as_ref(), credentials)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to clear host UEFI password: {error}"
                    ))
                })?;

            let next = match job_id {
                Some(job_id) => DeconfiguringHostState::WaitForUefiPasswordJobScheduled { job_id },
                None => DeconfiguringHostState::ClearSuperNicLockdown,
            };
            Ok(StateHandlerOutcome::transition(deconfiguring(next)))
        }
        DeconfiguringHostState::WaitForUefiPasswordJobScheduled { job_id } => {
            let job_state = redfish_client
                .get_job_state(job_id)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to read UEFI password job {job_id}: {error}"
                    ))
                })?;
            if !matches!(job_state, JobState::Scheduled) {
                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for UEFI password job {job_id} to be scheduled; current state: {job_state:?}"
                )));
            }
            Ok(StateHandlerOutcome::transition(deconfiguring(
                DeconfiguringHostState::RebootAfterUefiPassword {
                    job_id: job_id.clone(),
                },
            )))
        }
        DeconfiguringHostState::RebootAfterUefiPassword { job_id } => {
            host_power_control(
                redfish_client.as_ref(),
                machine,
                SystemPowerControl::ForceRestart,
                ctx,
            )
            .await
            .map_err(|error| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "failed to reboot host for UEFI password job {job_id}: {error}"
                ))
            })?;
            Ok(StateHandlerOutcome::transition(deconfiguring(
                DeconfiguringHostState::WaitForUefiPasswordJobCompletion {
                    job_id: job_id.clone(),
                },
            )))
        }
        DeconfiguringHostState::WaitForUefiPasswordJobCompletion { job_id } => {
            let job_state = redfish_client
                .get_job_state(job_id)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to read UEFI password job {job_id}: {error}"
                    ))
                })?;
            if !matches!(job_state, JobState::Completed) {
                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for UEFI password job {job_id} to complete; current state: {job_state:?}"
                )));
            }
            let mut txn = ctx.services.db_pool.begin().await?;
            db::machine::clear_bios_password_set_time(&machine.id, &mut txn).await?;
            Ok(StateHandlerOutcome::transition(deconfiguring(
                DeconfiguringHostState::ClearSuperNicLockdown,
            ))
            .with_txn(txn))
        }
        DeconfiguringHostState::ClearSuperNicLockdown => {
            let super_nics = state
                .dpa_interface_snapshots
                .iter()
                .filter(|interface| interface.interface_type == DpaInterfaceType::Svpc)
                .collect::<Vec<_>>();
            if super_nics.is_empty() {
                return Ok(StateHandlerOutcome::transition(deconfiguring(
                    DeconfiguringHostState::ResetUefiSettings,
                )));
            }

            let mut txn = ctx.services.db_pool.begin().await?;
            for interface in super_nics {
                db::dpa_interface::try_update_controller_state(
                    &mut txn,
                    interface.id,
                    interface.controller_state.version,
                    interface.controller_state.version.increment(),
                    &DpaInterfaceControllerState::Unlocking,
                )
                .await?;
            }
            Ok(StateHandlerOutcome::transition(deconfiguring(
                DeconfiguringHostState::WaitForSuperNicLockdown,
            ))
            .with_txn(txn))
        }
        DeconfiguringHostState::WaitForSuperNicLockdown => {
            let unlocked = state
                .dpa_interface_snapshots
                .iter()
                .filter(|interface| interface.interface_type == DpaInterfaceType::Svpc)
                .all(|interface| {
                    interface
                        .card_state
                        .as_ref()
                        .and_then(|card| card.lockmode.clone())
                        == Some(DpaLockMode::Unlocked)
                });
            if !unlocked {
                return Ok(StateHandlerOutcome::wait(
                    "waiting for all SuperNICs to report unlocked".to_string(),
                ));
            }
            Ok(StateHandlerOutcome::transition(deconfiguring(
                DeconfiguringHostState::ResetUefiSettings,
            )))
        }
        DeconfiguringHostState::ResetUefiSettings => {
            redfish_client.reset_bios().await.map_err(|error| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "failed to reset host UEFI settings: {error}"
                ))
            })?;
            Ok(StateHandlerOutcome::transition(deconfiguring(
                DeconfiguringHostState::RebootAfterUefiReset,
            )))
        }
        DeconfiguringHostState::RebootAfterUefiReset => {
            host_power_control(
                redfish_client.as_ref(),
                machine,
                SystemPowerControl::ForceRestart,
                ctx,
            )
            .await
            .map_err(|error| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "failed to reboot host after resetting UEFI settings: {error}"
                ))
            })?;
            Ok(StateHandlerOutcome::transition(
                ManagedHostState::Decommissioning {
                    decommissioning_state: DecommissioningState::DeconfiguringDpus {
                        dpu_states: state
                            .dpu_snapshots
                            .iter()
                            .map(|dpu| (dpu.id, DeconfiguringDpuState::ClearUefiPassword))
                            .collect(),
                    },
                },
            ))
        }
    }
}

pub(super) async fn handle_deconfiguring_dpus(
    dpu_states: &HashMap<MachineId, DeconfiguringDpuState>,
    state: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let Some((&dpu_id, dpu_state)) = dpu_states
        .iter()
        .find(|(_, dpu_state)| !matches!(dpu_state, DeconfiguringDpuState::Complete))
    else {
        return Ok(StateHandlerOutcome::transition(enter_bfb_install(state)));
    };
    let dpu = state
        .dpu_snapshots
        .iter()
        .find(|dpu| dpu.id == dpu_id)
        .ok_or_else(|| StateHandlerError::MissingData {
            object_id: state.host_snapshot.id.to_string(),
            missing: "dpu_snapshot",
        })?;
    let redfish_client = ctx.services.create_redfish_client_from_machine(dpu).await?;
    let mut next_states = dpu_states.clone();

    match dpu_state {
        DeconfiguringDpuState::ClearUefiPassword => {
            if dpu.bios_password_set_time.is_none() {
                next_states.insert(dpu_id, DeconfiguringDpuState::ResetUefiSettings);
                return Ok(StateHandlerOutcome::transition(deconfiguring_dpus(
                    next_states,
                )));
            }

            let bmc_mac =
                dpu.status
                    .bmc_info
                    .mac
                    .ok_or_else(|| StateHandlerError::MissingData {
                        object_id: dpu_id.to_string(),
                        missing: "bmc_mac",
                    })?;
            let mut conn = ctx.services.db_pool.acquire().await?;
            let status = db::credential_rotation::device_rotation_status(
                &mut conn,
                db::credential_rotation::CredentialRotationType::DpuUefi,
                bmc_mac,
            )
            .await?
            .ok_or_else(|| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "DPU UEFI credential version is not recorded for {bmc_mac}"
                ))
            })?;
            let version = status.current_version.ok_or_else(|| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "DPU UEFI credential version is not established for {bmc_mac}"
                ))
            })?;
            let version = u32::try_from(version).map_err(|error| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "invalid DPU UEFI credential version {version}: {error}"
                ))
            })?;
            drop(conn);

            let key = CredentialKey::dpu_uefi_site_default(version);
            let credentials = ctx
                .services
                .redfish_client_pool
                .credential_reader()
                .get_credentials(&key)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to read DPU UEFI credential: {error}"
                    ))
                })?
                .ok_or_else(|| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "DPU UEFI credential {key:?} is not set"
                    ))
                })?;
            let job_id = ctx
                .services
                .redfish_client_pool
                .clear_host_uefi_password(redfish_client.as_ref(), credentials)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to clear UEFI password on DPU {dpu_id}: {error}"
                    ))
                })?;
            next_states.insert(
                dpu_id,
                match job_id {
                    Some(job_id) => {
                        DeconfiguringDpuState::WaitForUefiPasswordJobScheduled { job_id }
                    }
                    None => DeconfiguringDpuState::ResetUefiSettings,
                },
            );
            Ok(StateHandlerOutcome::transition(deconfiguring_dpus(
                next_states,
            )))
        }
        DeconfiguringDpuState::WaitForUefiPasswordJobScheduled { job_id } => {
            let job_state = redfish_client
                .get_job_state(job_id)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to read DPU UEFI password job {job_id}: {error}"
                    ))
                })?;
            if !matches!(job_state, JobState::Scheduled) {
                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for DPU UEFI password job {job_id} to be scheduled; current state: {job_state:?}"
                )));
            }
            next_states.insert(
                dpu_id,
                DeconfiguringDpuState::RebootAfterUefiPassword {
                    job_id: job_id.clone(),
                },
            );
            Ok(StateHandlerOutcome::transition(deconfiguring_dpus(
                next_states,
            )))
        }
        DeconfiguringDpuState::RebootAfterUefiPassword { job_id } => {
            redfish_client
                .power(SystemPowerControl::ForceRestart)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to reboot DPU {dpu_id} for UEFI password job {job_id}: {error}"
                    ))
                })?;
            next_states.insert(
                dpu_id,
                DeconfiguringDpuState::WaitForUefiPasswordJobCompletion {
                    job_id: job_id.clone(),
                },
            );
            Ok(StateHandlerOutcome::transition(deconfiguring_dpus(
                next_states,
            )))
        }
        DeconfiguringDpuState::WaitForUefiPasswordJobCompletion { job_id } => {
            let job_state = redfish_client
                .get_job_state(job_id)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to read DPU UEFI password job {job_id}: {error}"
                    ))
                })?;
            if !matches!(job_state, JobState::Completed) {
                return Ok(StateHandlerOutcome::wait(format!(
                    "waiting for DPU UEFI password job {job_id} to complete; current state: {job_state:?}"
                )));
            }
            next_states.insert(dpu_id, DeconfiguringDpuState::ResetUefiSettings);
            let mut txn = ctx.services.db_pool.begin().await?;
            db::machine::clear_bios_password_set_time(&dpu_id, &mut txn).await?;
            Ok(StateHandlerOutcome::transition(deconfiguring_dpus(next_states)).with_txn(txn))
        }
        DeconfiguringDpuState::ResetUefiSettings => {
            redfish_client.reset_bios().await.map_err(|error| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "failed to reset UEFI settings on DPU {dpu_id}: {error}"
                ))
            })?;
            next_states.insert(dpu_id, DeconfiguringDpuState::RebootAfterUefiReset);
            Ok(StateHandlerOutcome::transition(deconfiguring_dpus(
                next_states,
            )))
        }
        DeconfiguringDpuState::RebootAfterUefiReset => {
            redfish_client
                .power(SystemPowerControl::ForceRestart)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to reboot DPU {dpu_id} after resetting UEFI settings: {error}"
                    ))
                })?;
            next_states.insert(dpu_id, DeconfiguringDpuState::Complete);
            if next_states
                .values()
                .all(|state| matches!(state, DeconfiguringDpuState::Complete))
            {
                Ok(StateHandlerOutcome::transition(enter_bfb_install(state)))
            } else {
                Ok(StateHandlerOutcome::transition(deconfiguring_dpus(
                    next_states,
                )))
            }
        }
        DeconfiguringDpuState::Complete => unreachable!("complete DPU states are skipped"),
    }
}

pub(super) async fn handle_installing_vanilla_bfb(
    installing_state: &InstallingVanillaBfbState,
    state: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    dpf_sdk: Option<&dyn DpfOperations>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match installing_state {
        InstallingVanillaBfbState::DeletingFromDpf => {
            let dpf_sdk = dpf_sdk.ok_or_else(|| {
                StateHandlerError::GenericError(eyre::eyre!(
                    "managed host {} was provisioned by DPF, but DPF is not configured",
                    state.host_snapshot.id
                ))
            })?;
            let host_dpf_id =
                state
                    .host_snapshot
                    .dpf_id()
                    .ok_or_else(|| StateHandlerError::MissingData {
                        object_id: state.host_snapshot.id.to_string(),
                        missing: "dpf_id",
                    })?;
            let dpu_dpf_ids = state
                .dpu_snapshots
                .iter()
                .map(|dpu| {
                    dpu.dpf_id().ok_or_else(|| StateHandlerError::MissingData {
                        object_id: dpu.id.to_string(),
                        missing: "dpf_id",
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            dpf_sdk
                .force_delete_host(&host_dpf_id, &dpu_dpf_ids)
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to delete managed host {} from DPF: {error}",
                        state.host_snapshot.id
                    ))
                })?;

            if !dpf_dpudevices_and_dpunode_crs_noexist(state, dpf_sdk)
                .await
                .map_err(|error| StateHandlerError::GenericError(error.into()))?
            {
                return Ok(StateHandlerOutcome::wait(
                    "waiting for managed host DPF resources to be deleted".to_string(),
                ));
            }

            Ok(StateHandlerOutcome::transition(installing_vanilla_bfb(
                initial_bfb_install_state(state),
            )))
        }
        InstallingVanillaBfbState::Installing { dpu_states } => {
            let Some((&dpu_id, dpu_state)) = dpu_states
                .iter()
                .find(|(_, dpu_state)| !matches!(dpu_state, InstallDpuOsState::Completed))
            else {
                return Ok(StateHandlerOutcome::transition(
                    ManagedHostState::Decommissioning {
                        decommissioning_state: DecommissioningState::VerifyingDhcpRelease {
                            verifying_state: VerifyingDhcpReleaseState::SuppressingDhcp,
                        },
                    },
                ));
            };
            let dpu = state
                .dpu_snapshots
                .iter()
                .find(|dpu| dpu.id == dpu_id)
                .ok_or_else(|| StateHandlerError::MissingData {
                    object_id: dpu_id.to_string(),
                    missing: "dpu_snapshot",
                })?;
            let redfish_client = ctx.services.create_redfish_client_from_machine(dpu).await?;
            let mut next_states = dpu_states.clone();

            match dpu_state {
                InstallDpuOsState::InstallingBFB => {
                    let task = redfish_client
                        .update_firmware_simple_update(
                            "carbide-pxe.forge//public/blobs/internal/aarch64/preingestion.bfb",
                            vec!["redfish/v1/UpdateService/FirmwareInventory/DPU_OS".to_string()],
                            TransferProtocolType::HTTP,
                        )
                        .await
                        .map_err(|error| {
                            StateHandlerError::GenericError(eyre::eyre!(
                                "failed to install vanilla BFB on DPU {dpu_id}: {error}"
                            ))
                        })?;
                    next_states.insert(
                        dpu_id,
                        InstallDpuOsState::WaitForInstallComplete {
                            task_id: task.id,
                            progress: "0".to_string(),
                        },
                    );
                    Ok(StateHandlerOutcome::transition(installing_vanilla_bfb(
                        InstallingVanillaBfbState::Installing {
                            dpu_states: next_states,
                        },
                    )))
                }
                InstallDpuOsState::WaitForInstallComplete { task_id, .. } => {
                    let task = redfish_client.get_task(task_id).await.map_err(|error| {
                        StateHandlerError::GenericError(eyre::eyre!(
                            "failed to verify vanilla BFB install task {task_id} on DPU {dpu_id}: {error}"
                        ))
                    })?;
                    match task.task_state {
                        Some(TaskState::Completed) => {
                            next_states.insert(dpu_id, InstallDpuOsState::Completed);
                            if next_states
                                .values()
                                .all(|state| matches!(state, InstallDpuOsState::Completed))
                            {
                                Ok(StateHandlerOutcome::transition(
                                    ManagedHostState::Decommissioning {
                                        decommissioning_state:
                                            DecommissioningState::VerifyingDhcpRelease {
                                                verifying_state:
                                                    VerifyingDhcpReleaseState::SuppressingDhcp,
                                            },
                                    },
                                ))
                            } else {
                                Ok(StateHandlerOutcome::transition(installing_vanilla_bfb(
                                    InstallingVanillaBfbState::Installing {
                                        dpu_states: next_states,
                                    },
                                )))
                            }
                        }
                        Some(TaskState::Running | TaskState::New | TaskState::Starting) => {
                            Ok(StateHandlerOutcome::wait(format!(
                                "waiting for vanilla BFB install on DPU {dpu_id} to complete: {}%",
                                task.percent_complete.unwrap_or_default()
                            )))
                        }
                        task_state => Err(StateHandlerError::GenericError(eyre::eyre!(
                            "vanilla BFB install task {task_id} on DPU {dpu_id} failed with state {task_state:?}"
                        ))),
                    }
                }
                InstallDpuOsState::InstallationError { msg } => {
                    Err(StateHandlerError::GenericError(eyre::eyre!(msg.clone())))
                }
                InstallDpuOsState::Completed => unreachable!("completed DPU states are skipped"),
            }
        }
    }
}

const DHCP_ACKNOWLEDGEMENT_TIMEOUT: Duration = Duration::minutes(30);

fn all_machines(
    state: &ManagedHostStateSnapshot,
) -> impl Iterator<Item = &model::machine::Machine> {
    std::iter::once(&state.host_snapshot).chain(&state.dpu_snapshots)
}

fn next_uncompleted_machine<'a>(
    state: &'a ManagedHostStateSnapshot,
    completed: &HashSet<MachineId>,
) -> Option<&'a model::machine::Machine> {
    all_machines(state).find(|machine| !completed.contains(&machine.id))
}

async fn all_dhcp_suppressions_acknowledged(
    state: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<bool, StateHandlerError> {
    for machine in all_machines(state) {
        let bmc_mac =
            machine
                .status
                .bmc_info
                .mac
                .ok_or_else(|| StateHandlerError::MissingData {
                    object_id: machine.id.to_string(),
                    missing: "bmc_mac",
                })?;
        let suppression = db::bmc_suppression::find(
            &ctx.services.db_pool,
            bmc_mac,
            BmcSuppressionSubsystem::Dhcp,
        )
        .await?;
        if suppression.is_none_or(|suppression| suppression.acknowledged_at.is_none()) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) async fn handle_verifying_dhcp_release(
    verifying_state: &VerifyingDhcpReleaseState,
    state: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match verifying_state {
        VerifyingDhcpReleaseState::SuppressingDhcp => {
            let mut txn = ctx.services.db_pool.begin().await?;
            for machine in all_machines(state) {
                let bmc_mac =
                    machine
                        .status
                        .bmc_info
                        .mac
                        .ok_or_else(|| StateHandlerError::MissingData {
                            object_id: machine.id.to_string(),
                            missing: "bmc_mac",
                        })?;
                db::bmc_suppression::upsert(
                    &mut txn,
                    &NewBmcSuppression {
                        bmc_mac_address: bmc_mac,
                        subsystem: BmcSuppressionSubsystem::Dhcp,
                        reason: format!(
                            "managed host {} has been decommissioned",
                            state.host_snapshot.id
                        ),
                    },
                )
                .await?;
            }
            Ok(StateHandlerOutcome::transition(verifying_dhcp_release(
                VerifyingDhcpReleaseState::ResettingBmcs {
                    completed: HashSet::new(),
                },
            ))
            .with_txn(txn))
        }
        VerifyingDhcpReleaseState::ResettingBmcs { completed } => {
            let Some(machine) = next_uncompleted_machine(state, completed) else {
                return Ok(StateHandlerOutcome::transition(verifying_dhcp_release(
                    VerifyingDhcpReleaseState::WaitingForAcknowledgement,
                )));
            };
            ctx.services
                .create_redfish_client_from_machine(machine)
                .await?
                .bmc_reset()
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to reset BMC for {}: {error}",
                        machine.id
                    ))
                })?;
            let mut completed = completed.clone();
            completed.insert(machine.id);
            Ok(StateHandlerOutcome::transition(verifying_dhcp_release(
                VerifyingDhcpReleaseState::ResettingBmcs { completed },
            )))
        }
        VerifyingDhcpReleaseState::WaitingForAcknowledgement => {
            if all_dhcp_suppressions_acknowledged(state, ctx).await? {
                return Ok(StateHandlerOutcome::transition(
                    ManagedHostState::Decommissioning {
                        decommissioning_state: DecommissioningState::Decommissioned,
                    },
                ));
            }
            if Utc::now() - state.host_snapshot.state.version.timestamp()
                < DHCP_ACKNOWLEDGEMENT_TIMEOUT
            {
                return Ok(StateHandlerOutcome::wait(
                    "waiting for DHCP suppression acknowledgement after BMC reset".to_string(),
                ));
            }
            Ok(StateHandlerOutcome::transition(verifying_dhcp_release(
                VerifyingDhcpReleaseState::FactoryResettingBmcs {
                    completed: HashSet::new(),
                },
            )))
        }
        VerifyingDhcpReleaseState::FactoryResettingBmcs { completed } => {
            let Some(machine) = next_uncompleted_machine(state, completed) else {
                return Ok(StateHandlerOutcome::transition(verifying_dhcp_release(
                    VerifyingDhcpReleaseState::WaitingForAcknowledgementAfterFactoryReset,
                )));
            };
            ctx.services
                .create_redfish_client_from_machine(machine)
                .await?
                .bmc_reset_to_defaults()
                .await
                .map_err(|error| {
                    StateHandlerError::GenericError(eyre::eyre!(
                        "failed to factory reset BMC for {}: {error}",
                        machine.id
                    ))
                })?;
            let mut completed = completed.clone();
            completed.insert(machine.id);
            Ok(StateHandlerOutcome::transition(verifying_dhcp_release(
                VerifyingDhcpReleaseState::FactoryResettingBmcs { completed },
            )))
        }
        VerifyingDhcpReleaseState::WaitingForAcknowledgementAfterFactoryReset => {
            if all_dhcp_suppressions_acknowledged(state, ctx).await? {
                return Ok(StateHandlerOutcome::transition(
                    ManagedHostState::Decommissioning {
                        decommissioning_state: DecommissioningState::Decommissioned,
                    },
                ));
            }
            if Utc::now() - state.host_snapshot.state.version.timestamp()
                < DHCP_ACKNOWLEDGEMENT_TIMEOUT
            {
                return Ok(StateHandlerOutcome::wait(
                    "waiting for DHCP suppression acknowledgement after BMC factory reset"
                        .to_string(),
                ));
            }
            Err(StateHandlerError::ManualInterventionRequired(format!(
                "DHCP suppression for managed host {} was not acknowledged within 30 minutes after BMC factory reset",
                state.host_snapshot.id
            )))
        }
    }
}
