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

//! Handler for [`ManagedHostState::Decommissioning`].

use std::str::FromStr;

use carbide_secrets::credentials::{BmcCredentialType, CredentialKey, CredentialWriter};
use carbide_uuid::machine::MachineId;
use db::dhcp_record as db_dhcp;
use db::machine as db_machine;
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthReport, HealthReportApplyMode,
};
use model::machine::{DecommissionState, ManagedHostState, ManagedHostStateSnapshot};
use state_controller::state_handler::{StateHandlerContext, StateHandlerError, StateHandlerOutcome};

use crate::context::MachineStateHandlerContextObjects;

pub(super) const DECOMMISSION_HEALTH_SOURCE: &str = "decommission";
const DECOMMISSION_PROBE_ID: &str = "DecommissionInProgress";

/// Top-level dispatcher for the `Decommissioning` state.
pub async fn handle_decommission(
    host_machine_id: &MachineId,
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let decommission_state = match &mh_snapshot.managed_state {
        ManagedHostState::Decommissioning { decommission_state } => decommission_state.clone(),
        _ => unreachable!("handle_decommission called with non-Decommissioning state"),
    };

    match decommission_state {
        DecommissionState::Init => handle_init(host_machine_id, mh_snapshot, ctx).await,
        DecommissionState::BmcResetToDefaults => {
            handle_bmc_reset(host_machine_id, mh_snapshot, ctx).await
        }
        DecommissionState::DpuBmcResetToDefaults => {
            handle_dpu_bmc_reset(host_machine_id, mh_snapshot, ctx).await
        }
        DecommissionState::DeleteCredentials => {
            handle_delete_credentials(host_machine_id, mh_snapshot, ctx).await
        }
        DecommissionState::MarkMacsIgnored => {
            handle_mark_macs_ignored(host_machine_id, mh_snapshot, ctx).await
        }
    }
}

/// `Init`: attach a `PreventAllocations` health alert, then advance to `BmcResetToDefaults`.
async fn handle_init(
    host_machine_id: &MachineId,
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    tracing::info!(
        machine_id = %host_machine_id,
        "Decommission Init: attaching PreventAllocations health alert",
    );

    let health_report = HealthReport {
        source: DECOMMISSION_HEALTH_SOURCE.to_string(),
        triggered_by: None,
        observed_at: Some(chrono::Utc::now()),
        alerts: vec![HealthProbeAlert {
            id: HealthProbeId::from_str(DECOMMISSION_PROBE_ID).expect("valid probe id"),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: "Machine is being decommissioned".to_string(),
            tenant_message: None,
            classifications: vec![HealthAlertClassification::prevent_allocations()],
        }],
        successes: vec![],
    };

    let mut txn = ctx.services.db_pool.begin().await?;

    db_machine::insert_health_report(
        &mut txn,
        host_machine_id,
        HealthReportApplyMode::Merge,
        &health_report,
        false,
    )
    .await?;

    // Also apply the alert to all DPU machines so none can be allocated.
    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
        db_machine::insert_health_report(
            &mut txn,
            &dpu_snapshot.id,
            HealthReportApplyMode::Merge,
            &health_report,
            false,
        )
        .await?;
    }

    let next_state = ManagedHostState::Decommissioning {
        decommission_state: DecommissionState::BmcResetToDefaults,
    };
    Ok(StateHandlerOutcome::transition(next_state).with_txn(txn))
}

/// `BmcResetToDefaults`: send `Manager.ResetToDefaults` to the host BMC.
///
/// If the BMC is unreachable or already reset, we log and continue rather than
/// blocking decommission indefinitely.
async fn handle_bmc_reset(
    host_machine_id: &MachineId,
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    tracing::info!(
        machine_id = %host_machine_id,
        "Decommission BmcResetToDefaults: resetting host BMC to factory defaults",
    );

    match ctx
        .services
        .create_redfish_client_from_machine(&mh_snapshot.host_snapshot)
        .await
    {
        Ok(redfish) => {
            if let Err(e) = redfish.bmc_reset_to_defaults().await {
                tracing::warn!(
                    machine_id = %host_machine_id,
                    error = %e,
                    "Host BMC reset to defaults failed; proceeding with decommission",
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                machine_id = %host_machine_id,
                error = %e,
                "Could not connect to host BMC for factory reset; proceeding with decommission",
            );
        }
    }

    Ok(StateHandlerOutcome::transition(ManagedHostState::Decommissioning {
        decommission_state: DecommissionState::DpuBmcResetToDefaults,
    }))
}

/// `DpuBmcResetToDefaults`: reset each attached DPU BMC to factory defaults.
async fn handle_dpu_bmc_reset(
    host_machine_id: &MachineId,
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    tracing::info!(
        machine_id = %host_machine_id,
        dpu_count = mh_snapshot.dpu_snapshots.len(),
        "Decommission DpuBmcResetToDefaults: resetting DPU BMCs to factory defaults",
    );

    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
        match ctx
            .services
            .create_redfish_client_from_machine(dpu_snapshot)
            .await
        {
            Ok(redfish) => {
                if let Err(e) = redfish.bmc_reset_to_defaults().await {
                    tracing::warn!(
                        machine_id = %host_machine_id,
                        dpu_machine_id = %dpu_snapshot.id,
                        error = %e,
                        "DPU BMC reset to defaults failed; proceeding with decommission",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    machine_id = %host_machine_id,
                    dpu_machine_id = %dpu_snapshot.id,
                    error = %e,
                    "Could not connect to DPU BMC for factory reset; proceeding with decommission",
                );
            }
        }
    }

    Ok(StateHandlerOutcome::transition(ManagedHostState::Decommissioning {
        decommission_state: DecommissionState::DeleteCredentials,
    }))
}

/// `DeleteCredentials`: remove per-machine secrets from the credential store.
///
/// Site-wide credentials (`SiteWideRoot`, `SiteDefault`) are intentionally
/// left intact — they are shared across all machines.
async fn handle_delete_credentials(
    host_machine_id: &MachineId,
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    tracing::info!(
        machine_id = %host_machine_id,
        "Decommission DeleteCredentials: removing per-machine credentials",
    );

    // Host BMC per-device credentials (keyed by BMC MAC).
    if let Some(bmc_mac) = mh_snapshot.host_snapshot.status.bmc_info.mac {
        for key in [
            CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot { bmc_mac_address: bmc_mac },
            },
            CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcForgeAdmin { bmc_mac_address: bmc_mac },
            },
        ] {
            if let Err(e) = ctx.services.credential_manager.delete_credentials(&key).await {
                tracing::warn!(
                    machine_id = %host_machine_id,
                    ?key,
                    error = %e,
                    "Failed to delete host BMC credential; continuing",
                );
            }
        }
    } else {
        tracing::warn!(
            machine_id = %host_machine_id,
            "Host BMC MAC not available; skipping BMC credential deletion",
        );
    }

    // Per-DPU credentials (keyed by DPU machine ID and DPU BMC MAC).
    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
        let dpu_id = dpu_snapshot.id;

        for key in [
            CredentialKey::DpuSsh { machine_id: dpu_id },
            CredentialKey::DpuHbn { machine_id: dpu_id },
        ] {
            if let Err(e) = ctx.services.credential_manager.delete_credentials(&key).await {
                tracing::warn!(
                    machine_id = %host_machine_id,
                    %dpu_id,
                    ?key,
                    error = %e,
                    "Failed to delete DPU credential; continuing",
                );
            }
        }

        if let Some(dpu_bmc_mac) = dpu_snapshot.status.bmc_info.mac {
            for key in [
                CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot {
                        bmc_mac_address: dpu_bmc_mac,
                    },
                },
                CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcForgeAdmin {
                        bmc_mac_address: dpu_bmc_mac,
                    },
                },
            ] {
                if let Err(e) = ctx.services.credential_manager.delete_credentials(&key).await {
                    tracing::warn!(
                        machine_id = %host_machine_id,
                        %dpu_id,
                        ?key,
                        error = %e,
                        "Failed to delete DPU BMC credential; continuing",
                    );
                }
            }
        }
    }

    Ok(StateHandlerOutcome::transition(ManagedHostState::Decommissioning {
        decommission_state: DecommissionState::MarkMacsIgnored,
    }))
}

/// `MarkMacsIgnored`: insert all BMC MAC addresses into the `ignored_macs` table so
/// the DHCP server stops issuing leases and NAKs any outstanding DHCPREQUEST.
///
/// This is the final step — after the DB write completes the machine is deleted.
async fn handle_mark_macs_ignored(
    host_machine_id: &MachineId,
    mh_snapshot: &ManagedHostStateSnapshot,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    tracing::info!(
        machine_id = %host_machine_id,
        "Decommission MarkMacsIgnored: marking BMC MACs as DHCP-ignored",
    );

    let mut txn = ctx.services.db_pool.begin().await?;

    if let Some(host_bmc_mac) = mh_snapshot.host_snapshot.status.bmc_info.mac {
        db_dhcp::ignore_mac(
            &mut txn,
            &host_bmc_mac,
            Some(host_machine_id),
            "decommissioned",
        )
        .await?;
    }

    for dpu_snapshot in &mh_snapshot.dpu_snapshots {
        if let Some(dpu_bmc_mac) = dpu_snapshot.status.bmc_info.mac {
            db_dhcp::ignore_mac(
                &mut txn,
                &dpu_bmc_mac,
                Some(&dpu_snapshot.id),
                "decommissioned",
            )
            .await?;
        }
    }

    Ok(StateHandlerOutcome::deleted().with_txn(txn))
}
