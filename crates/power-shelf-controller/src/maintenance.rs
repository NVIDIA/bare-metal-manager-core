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

use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, Credentials,
};
use carbide_uuid::power_shelf::PowerShelfId;
use component_manager::power_shelf_manager::{
    PowerShelfComponentResult, PowerShelfEndpoint, PowerShelfVendor,
};
use db::power_shelf as db_power_shelf;
use mac_address::MacAddress;
use model::component_manager::PowerAction;
use model::power_shelf::{PowerShelf, PowerShelfControllerState, PowerShelfMaintenanceOperation};
use sqlx::PgPool;
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::PowerShelfStateHandlerContextObjects;
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
    invoke_power_operation(power_shelf_id, state, ctx, PowerAction::On, "PowerOn").await
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
    invoke_power_operation(
        power_shelf_id,
        state,
        ctx,
        PowerAction::ForceOff,
        "PowerOff",
    )
    .await
}

/// Common driver for component-manager-backed power maintenance operations.
/// Builds a `PowerShelfEndpoint` with the power shelf's BMC connection details
/// and dispatches `power_control` against the configured backend. Returns to
/// `Ready` on success or transitions to `Error` on failure. In both terminal
/// cases the `power_shelf_maintenance_requested` row is cleared so the
/// controller does not re-enter `Maintenance` on the next iteration.
async fn invoke_power_operation(
    power_shelf_id: &PowerShelfId,
    state: &PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
    action: PowerAction,
    operation_label: &'static str,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    let Some(component_manager) = ctx.services.component_manager.as_ref() else {
        return finish_maintenance_with_error(
            power_shelf_id,
            ctx,
            format!(
                "PowerShelf {} maintenance ({}): component manager not configured",
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

    let endpoint = match build_power_shelf_endpoint(
        power_shelf_id,
        state,
        &ctx.services.db_pool,
        ctx.services.credential_manager.as_ref(),
    )
    .await
    {
        Ok(endpoint) => endpoint,
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

    match component_manager
        .power_shelf
        .power_control(std::slice::from_ref(&endpoint), action)
        .await
    {
        Ok(results) => {
            let result = results
                .into_iter()
                .next()
                .unwrap_or(PowerShelfComponentResult {
                    pmc_mac: endpoint.pmc_mac,
                    success: false,
                    error: Some("component manager returned no result".into()),
                });

            if result.success {
                tracing::info!(
                    power_shelf_id = %power_shelf_id,
                    rack_id = %rack_id,
                    operation = operation_label,
                    backend = component_manager.power_shelf.name(),
                    "Power shelf power control succeeded; returning PowerShelf to Ready"
                );
                let mut txn = ctx.services.db_pool.begin().await?;
                db_power_shelf::clear_power_shelf_maintenance_requested(&mut txn, *power_shelf_id)
                    .await?;
                return Ok(
                    StateHandlerOutcome::transition(PowerShelfControllerState::Ready).with_txn(txn),
                );
            }

            let summary = result
                .error
                .unwrap_or_else(|| "power control failed".into());
            tracing::warn!(
                power_shelf_id = %power_shelf_id,
                rack_id = %rack_id,
                operation = operation_label,
                backend = component_manager.power_shelf.name(),
                summary = %summary,
                "Power shelf power control returned a non-success result",
            );
            let cause = format!(
                "PowerShelf {} maintenance ({}): power control failed: {}",
                power_shelf_id, operation_label, summary
            );
            finish_maintenance_with_error(power_shelf_id, ctx, cause).await
        }
        Err(error) => {
            let cause = format!(
                "PowerShelf {} maintenance ({}): power control failed: {}",
                power_shelf_id, operation_label, error
            );
            tracing::warn!(
                power_shelf_id = %power_shelf_id,
                rack_id = %rack_id,
                operation = operation_label,
                backend = component_manager.power_shelf.name(),
                error = %error,
                "Power shelf power control transport error",
            );
            finish_maintenance_with_error(power_shelf_id, ctx, cause).await
        }
    }
}

/// Build the `PowerShelfEndpoint` describing this power shelf for component
/// manager power operations. Resolves the BMC IP from the database and BMC
/// credentials via the credential manager.
pub(super) async fn build_power_shelf_endpoint(
    power_shelf_id: &PowerShelfId,
    state: &PowerShelf,
    db_pool: &PgPool,
    credential_manager: &dyn CredentialManager,
) -> Result<PowerShelfEndpoint, String> {
    let bmc_mac = state.bmc_mac_address.ok_or_else(|| {
        format!(
            "power shelf {} has no BMC MAC address recorded",
            power_shelf_id
        )
    })?;

    let bmc_ip = lookup_power_shelf_bmc_ip(db_pool, power_shelf_id, bmc_mac).await?;
    let credentials = lookup_bmc_credentials(credential_manager, bmc_mac).await?;

    Ok(PowerShelfEndpoint {
        pmc_ip: bmc_ip
            .parse()
            .map_err(|error| format!("invalid BMC IP {bmc_ip}: {error}"))?,
        pmc_mac: bmc_mac,
        pmc_vendor: PowerShelfVendor::DEFAULT,
        pmc_credentials: credentials,
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
) -> Result<Credentials, String> {
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

    match creds {
        Some(creds) => Ok(creds),
        None => {
            let sitewide_key = CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::SiteWideRoot,
            };
            credential_manager
                .get_credentials(&sitewide_key)
                .await
                .map_err(|error| format!("failed to read site-wide BMC credentials: {}", error))?
                .ok_or_else(|| format!("no BMC credentials configured for {} or sitewide", bmc_mac))
        }
    }
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
