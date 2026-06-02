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

//! Handler for PowerShelfControllerState::Maintenance.

use carbide_rack::rack_manager_error;
use carbide_uuid::power_shelf::PowerShelfId;
use db::power_shelf as db_power_shelf;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, Credentials,
};
use librms::protos::rack_manager as rms;
use mac_address::MacAddress;
use model::power_shelf::{PowerShelf, PowerShelfControllerState, PowerShelfMaintenanceOperation};
use sqlx::PgPool;
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::PowerShelfStateHandlerContextObjects;

/// Default BMC HTTPS port used when populating `rms::Endpoint` for power
/// shelves. Mirrors the value used by `crate::rack::firmware_update`.
const POWER_SHELF_BMC_PORT: u32 = 443;

/// Handles the Maintenance state for a power shelf, dispatching on the
/// requested operation (`PowerOn` / `PowerOff`).
pub async fn handle_maintenance(
    power_shelf_id: &PowerShelfId,
    state: &mut PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    let operation = match &state.controller_state.value {
        PowerShelfControllerState::Maintenance { operation } => *operation,
        _ => unreachable!("handle_maintenance called with non-Maintenance state"),
    };

    match operation {
        PowerShelfMaintenanceOperation::PowerOn => {
            handle_power_on(power_shelf_id, state, ctx).await
        }
        PowerShelfMaintenanceOperation::PowerOff => {
            handle_power_off(power_shelf_id, state, ctx).await
        }
    }
}

async fn handle_power_on(
    power_shelf_id: &PowerShelfId,
    state: &mut PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    tracing::info!(
        power_shelf_id = %power_shelf_id,
        "PowerShelf maintenance: PowerOn"
    );
    invoke_rms_power_operation(
        power_shelf_id,
        state,
        ctx,
        rms::PowerOperation::On,
        "PowerOn",
    )
    .await
}

async fn handle_power_off(
    power_shelf_id: &PowerShelfId,
    state: &mut PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    tracing::info!(
        power_shelf_id = %power_shelf_id,
        "PowerShelf maintenance: PowerOff"
    );
    invoke_rms_power_operation(
        power_shelf_id,
        state,
        ctx,
        rms::PowerOperation::Off,
        "PowerOff",
    )
    .await
}

/// Common driver for RMS-backed power maintenance operations. Builds a
/// caller-supplied `NodeSet` with the power shelf's BMC connection details
/// and dispatches `BatchSetPowerState` against the configured
/// `RmsApi` client. Returns to `Ready` on success or transitions to `Error`
/// on failure. In both terminal cases the `power_shelf_maintenance_requested`
/// row is cleared so the controller does not re-enter `Maintenance` on the
/// next iteration.
async fn invoke_rms_power_operation(
    power_shelf_id: &PowerShelfId,
    state: &PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
    operation: rms::PowerOperation,
    operation_label: &'static str,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    let Some(rms_client) = ctx.services.rms_client.as_ref() else {
        return finish_maintenance_with_error(
            power_shelf_id,
            ctx,
            format!(
                "PowerShelf {} maintenance ({}): RMS client not configured",
                power_shelf_id, operation_label
            ),
        )
        .await;
    };

    let Some(rack_id) = state.rack_id.as_ref() else {
        return finish_maintenance_with_error(
            power_shelf_id,
            ctx,
            format!(
                "PowerShelf {} maintenance ({}): power shelf has no rack association",
                power_shelf_id, operation_label
            ),
        )
        .await;
    };

    let device = match build_power_shelf_node_info(
        power_shelf_id,
        state,
        rack_id.to_string(),
        &ctx.services.db_pool,
        ctx.services.credential_manager.as_ref(),
    )
    .await
    {
        Ok(device) => device,
        Err(cause) => {
            return finish_maintenance_with_error(
                power_shelf_id,
                ctx,
                format!(
                    "PowerShelf {} maintenance ({}): {}",
                    power_shelf_id, operation_label, cause
                ),
            )
            .await;
        }
    };

    let request = rms::BatchSetPowerStateRequest {
        nodes: Some(rms::NodeSet {
            nodes: vec![device],
        }),
        operation: operation as i32,
    };

    match rms_client.batch_set_power_state(request).await {
        Ok(response) => {
            let batch = response.response.unwrap_or_default();
            let stats = batch.stats.unwrap_or_default();

            if batch.status == rms::ReturnCode::Success as i32 && stats.failed_nodes == 0 {
                tracing::info!(
                    power_shelf_id = %power_shelf_id,
                    rack_id = %rack_id,
                    operation = operation_label,
                    successful_nodes = stats.successful_nodes,
                    "RMS BatchSetPowerState succeeded; returning PowerShelf to Ready"
                );
                let mut txn = ctx.services.db_pool.begin().await?;
                db_power_shelf::clear_power_shelf_maintenance_requested(&mut txn, *power_shelf_id)
                    .await?;
                return Ok(
                    StateHandlerOutcome::transition(PowerShelfControllerState::Ready).with_txn(txn),
                );
            }

            let node_error = batch
                .node_results
                .iter()
                .find(|result| {
                    result.status != rms::ReturnCode::Success as i32
                        || !result.error_message.is_empty()
                })
                .map(|result| {
                    if result.error_message.is_empty() {
                        format!("status={}", result.status)
                    } else {
                        result.error_message.clone()
                    }
                });
            let summary = if !batch.message.is_empty() {
                batch.message.clone()
            } else if let Some(error) = node_error.as_ref() {
                error.clone()
            } else {
                format!(
                    "batch status {}, failed_nodes {}",
                    batch.status, stats.failed_nodes,
                )
            };

            tracing::warn!(
                power_shelf_id = %power_shelf_id,
                rack_id = %rack_id,
                operation = operation_label,
                batch_status = batch.status,
                successful_nodes = stats.successful_nodes,
                failed_nodes = stats.failed_nodes,
                summary = %summary,
                "RMS BatchSetPowerState returned a non-success result",
            );
            let cause = format!(
                "PowerShelf {} maintenance ({}): RMS BatchSetPowerState failed: {}",
                power_shelf_id, operation_label, summary
            );
            finish_maintenance_with_error(power_shelf_id, ctx, cause).await
        }
        Err(error) => {
            let error = rack_manager_error("batch_set_power_state", error);
            let cause = format!(
                "PowerShelf {} maintenance ({}): RMS BatchSetPowerState failed: {}",
                power_shelf_id, operation_label, error
            );
            tracing::warn!(
                power_shelf_id = %power_shelf_id,
                rack_id = %rack_id,
                operation = operation_label,
                error = %error,
                "RMS BatchSetPowerState transport error",
            );
            finish_maintenance_with_error(power_shelf_id, ctx, cause).await
        }
    }
}

/// Build the `rms::NodeInfo` describing this power shelf for inclusion
/// in caller-supplied `NodeSet` requests from `Maintenance` and `Ready`.
/// Resolves the BMC IP from the database and BMC credentials via the
/// credential manager, since these RPCs require the BMC connection details
/// inline rather than relying on RMS's inventory.
pub(super) async fn build_power_shelf_node_info(
    power_shelf_id: &PowerShelfId,
    state: &PowerShelf,
    rack_id: String,
    db_pool: &PgPool,
    credential_manager: &dyn CredentialManager,
) -> Result<rms::NodeInfo, String> {
    let bmc_mac = state.bmc_mac_address.ok_or_else(|| {
        format!(
            "power shelf {} has no BMC MAC address recorded",
            power_shelf_id
        )
    })?;

    let bmc_ip = lookup_power_shelf_bmc_ip(db_pool, power_shelf_id, bmc_mac).await?;
    let credentials = lookup_bmc_credentials(credential_manager, bmc_mac).await?;

    Ok(rms::NodeInfo {
        node_id: power_shelf_id.to_string(),
        rack_id,
        r#type: Some(rms::NodeType::Powershelf as i32),
        bmc_endpoint: Some(rms::Endpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: bmc_ip,
                mac_address: bmc_mac.to_string(),
            }),
            port: POWER_SHELF_BMC_PORT,
            credentials: Some(credentials),
            dangerously_accept_invalid_certs: true,
        }),
        host_endpoint: None,
    })
}

/// Fetch the power shelf's BMC IP via the underlay machine_interfaces path.
async fn lookup_power_shelf_bmc_ip(
    db_pool: &PgPool,
    power_shelf_id: &PowerShelfId,
    bmc_mac: MacAddress,
) -> Result<String, String> {
    let rows = db_power_shelf::find_bmc_info_by_power_shelf_ids(db_pool, &[*power_shelf_id])
        .await
        .map_err(|error| format!("failed to look up BMC info: {}", error))?;

    rows.into_iter()
        .find(|row| row.power_shelf_id == *power_shelf_id)
        .map(|row| row.pmc_ip.to_string())
        .ok_or_else(|| {
            format!(
                "no BMC IP found for power shelf {} (bmc_mac {})",
                power_shelf_id, bmc_mac
            )
        })
}

/// Resolve BMC root credentials for the given MAC, falling back to the
/// site-wide root credentials if no per-MAC override exists.
async fn lookup_bmc_credentials(
    credential_manager: &dyn CredentialManager,
    bmc_mac: MacAddress,
) -> Result<rms::Credentials, String> {
    let bmc_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: bmc_mac,
        },
    };
    let creds = match credential_manager.get_credentials(&bmc_key).await {
        Ok(Some(creds)) => Some(creds),
        Ok(None) => None,
        Err(error) => {
            return Err(format!(
                "failed to read BMC credentials for {}: {}",
                bmc_mac, error
            ));
        }
    };

    let creds = match creds {
        Some(creds) => creds,
        None => {
            let sitewide_key = CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::SiteWideRoot,
            };
            credential_manager
                .get_credentials(&sitewide_key)
                .await
                .map_err(|error| format!("failed to read site-wide BMC credentials: {}", error))?
                .ok_or_else(|| {
                    format!("no BMC credentials configured for {} or sitewide", bmc_mac)
                })?
        }
    };

    let Credentials::UsernamePassword { username, password } = creds;
    Ok(rms::Credentials {
        auth: Some(rms::credentials::Auth::UserPass(rms::UsernamePassword {
            username,
            password,
        })),
    })
}

/// Clear the pending maintenance request and transition to `Error` with the
/// given cause. Clearing the request is what breaks the
/// `Error -> Ready -> Maintenance -> Error` loop on persistent failures and
/// forces the operator to explicitly re-request maintenance to retry.
async fn finish_maintenance_with_error(
    power_shelf_id: &PowerShelfId,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
    cause: String,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    let mut txn = ctx.services.db_pool.begin().await?;
    db_power_shelf::clear_power_shelf_maintenance_requested(&mut txn, *power_shelf_id).await?;
    Ok(StateHandlerOutcome::transition(PowerShelfControllerState::Error { cause }).with_txn(txn))
}
