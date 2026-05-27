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

//! Handler for PowerShelfControllerState::Ready.

use carbide_rack::rack_manager_error;
use carbide_uuid::power_shelf::PowerShelfId;
use db::power_shelf as db_power_shelf;
use librms::protos::rack_manager as rms;
use model::power_shelf::{PowerShelf, PowerShelfControllerState, PowerShelfStatus};
use sqlx::PgTransaction;
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::PowerShelfStateHandlerContextObjects;
use crate::maintenance::build_power_shelf_node_info;

/// Handles the Ready state for a power shelf.
///
/// If the power shelf is marked for deletion, transitions to `Deleting`.
/// If a maintenance request has been posted via
/// `power_shelf_maintenance_requested`, transitions to `Maintenance` with the
/// requested operation (PowerOn / PowerOff). Otherwise polls RMS for the
/// current power state (best-effort observation) and idles.
///
/// TODO: Implement PowerShelf monitoring (health checks, status updates,
/// power consumption / efficiency tracking).
pub async fn handle_ready(
    power_shelf_id: &PowerShelfId,
    state: &mut PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    if state.is_marked_as_deleted() {
        return Ok(StateHandlerOutcome::transition(
            PowerShelfControllerState::Deleting,
        ));
    }

    if let Some(req) = state.power_shelf_maintenance_requested.as_ref() {
        tracing::info!(
            operation = ?req.operation,
            initiator = %req.initiator,
            "PowerShelf maintenance requested; transitioning to Maintenance"
        );
        return Ok(StateHandlerOutcome::transition(
            PowerShelfControllerState::Maintenance {
                operation: req.operation,
            },
        ));
    }

    let txn = poll_rms_power_state(power_shelf_id, state, ctx).await;

    Ok(StateHandlerOutcome::do_nothing().with_txn_opt(txn))
}
///
/// On a successful response, the observed `pstate` for this power shelf is
/// persisted to the `power_shelves.status` column and the in-memory `state`
/// is updated to match. The returned `PgTransaction` (if any) carries that
/// status write so the caller can attach it to the `Ready` outcome and have
/// the state-controller framework commit it alongside the usual outcome
/// bookkeeping.
async fn poll_rms_power_state(
    power_shelf_id: &PowerShelfId,
    state: &mut PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Option<PgTransaction<'static>> {
    let Some(rms_client) = ctx.services.rms_client.as_ref() else {
        tracing::debug!(
            power_shelf_id = %power_shelf_id,
            "PowerShelf Ready: skipping RMS BatchGetPowerState; RMS client not configured",
        );
        return None;
    };

    let Some(rack_id) = state.rack_id.as_ref() else {
        tracing::debug!(
            power_shelf_id = %power_shelf_id,
            "PowerShelf Ready: skipping RMS BatchGetPowerState; power shelf has no rack association",
        );
        return None;
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
            tracing::debug!(
                power_shelf_id = %power_shelf_id,
                rack_id = %rack_id,
                cause = %cause,
                "PowerShelf Ready: skipping RMS BatchGetPowerState; unable to build NodeSet",
            );
            return None;
        }
    };

    let request = rms::BatchGetPowerStateRequest {
        nodes: Some(rms::NodeSet {
            nodes: vec![device],
        }),
    };

    let rack_id_str = rack_id.to_string();
    let response = match rms_client.batch_get_power_state(request).await {
        Ok(response) => response,
        Err(error) => {
            let error = rack_manager_error("batch_get_power_state", error);
            tracing::warn!(
                power_shelf_id = %power_shelf_id,
                rack_id = %rack_id_str,
                error = %error,
                "RMS BatchGetPowerState transport error",
            );
            return None;
        }
    };

    let batch = response.response.clone().unwrap_or_default();
    let stats = batch.stats.unwrap_or_default();
    if !(batch.status == rms::ReturnCode::Success as i32 && stats.failed_nodes == 0) {
        tracing::warn!(
            power_shelf_id = %power_shelf_id,
            rack_id = %rack_id_str,
            batch_status = batch.status,
            successful_nodes = stats.successful_nodes,
            failed_nodes = stats.failed_nodes,
            message = %batch.message,
            "RMS BatchGetPowerState returned non-Success result",
        );
        return None;
    }

    tracing::info!(
        power_shelf_id = %power_shelf_id,
        rack_id = %rack_id_str,
        successful_nodes = stats.successful_nodes,
        pstates = ?response
            .node_power_states
            .iter()
            .map(|node| (node.node_id.as_str(), node.pstate.as_str()))
            .collect::<Vec<_>>(),
        "RMS BatchGetPowerState succeeded",
    );

    persist_observed_power_state(power_shelf_id, state, ctx, &response.node_power_states).await
}

/// Look up the `NodePowerState` for this power shelf in the RMS response,
/// stamp the value into `state.status`, and persist it via
/// `db_power_shelf::update`. Returns the open `PgTransaction` so the caller
/// can attach it to the `Ready` outcome.
///
/// Status persistence is best-effort: if RMS did not echo a result for this
/// node, or if the DB write fails, the in-memory state is left untouched
/// and `None` is returned — `Ready` must stay in `Ready` regardless.
async fn persist_observed_power_state(
    power_shelf_id: &PowerShelfId,
    state: &mut PowerShelf,
    ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
    node_power_states: &[rms::NodePowerState],
) -> Option<PgTransaction<'static>> {
    let node_id = power_shelf_id.to_string();
    let Some(observed) = node_power_states
        .iter()
        .find(|node| node.node_id == node_id)
    else {
        tracing::debug!(
            power_shelf_id = %power_shelf_id,
            "RMS BatchGetPowerState: no NodePowerState echoed for this power shelf; skipping status update",
        );
        return None;
    };

    let new_power_state = observed.pstate.to_lowercase();
    let new_status = match state.status.as_ref() {
        Some(existing) => PowerShelfStatus {
            shelf_name: existing.shelf_name.clone(),
            power_state: new_power_state.clone(),
            health_status: existing.health_status.clone(),
        },
        None => PowerShelfStatus {
            shelf_name: state.config.name.clone(),
            power_state: new_power_state.clone(),
            health_status: String::new(),
        },
    };

    if state
        .status
        .as_ref()
        .is_some_and(|s| s.power_state == new_status.power_state)
    {
        tracing::debug!(
            power_shelf_id = %power_shelf_id,
            power_state = %new_status.power_state,
            "PowerShelf status power_state unchanged; skipping DB write",
        );
        return None;
    }

    let previous_status = state.status.replace(new_status);

    let mut txn = match ctx.services.db_pool.begin().await {
        Ok(txn) => txn,
        Err(error) => {
            state.status = previous_status;
            tracing::warn!(
                power_shelf_id = %power_shelf_id,
                error = %error,
                "PowerShelf Ready: failed to begin txn while persisting observed power state",
            );
            return None;
        }
    };

    if let Err(error) = db_power_shelf::update(state, &mut txn).await {
        state.status = previous_status;
        tracing::warn!(
            power_shelf_id = %power_shelf_id,
            error = %error,
            "PowerShelf Ready: failed to persist observed power state to DB",
        );
        return None;
    }

    tracing::info!(
        power_shelf_id = %power_shelf_id,
        power_state = %new_power_state,
        "PowerShelf Ready: persisted observed power state from RMS",
    );

    Some(txn)
}
