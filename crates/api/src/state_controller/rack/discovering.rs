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

//! Handler for RackState::Discovering.
//!
//! The rack waits in Discovering until all machines, switches, and power
//! shelves that belong to it (via `rack_id` FK) have reached their Ready
//! state. Once all devices are ready, reprovisioning is triggered and the
//! rack transitions to Maintenance.

use carbide_uuid::rack::{RackId, RackProfileId};
use db::{machine as db_machine, power_shelf as db_power_shelf, switch as db_switch};
use model::machine::machine_search_config::MachineSearchConfig;
use model::rack::{FirmwareUpgradeState, RackMaintenanceState, RackState};

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
pub async fn handle_discovering(
    id: &RackId,
    rack_profile_id: Option<&RackProfileId>,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    let capabilities = match super::resolve_capabilities(id, rack_profile_id, ctx) {
        Some(caps) => caps,
        None => {
            return Ok(StateHandlerOutcome::wait(
                "no or unknown rack_profile_id".into(),
            ));
        }
    };

    let mut txn = ctx.services.db_pool.begin().await?;

    let ready_compute = db_machine::find_machine_ids(
        txn.as_mut(),
        MachineSearchConfig {
            rack_id: Some(id.clone()),
            controller_state: Some("ready".into()),
            ..Default::default()
        },
    )
    .await?
    .len() as u32;
    let ready_switches = db_switch::find_ids(
        txn.as_mut(),
        model::switch::SwitchSearchFilter {
            rack_id: Some(id.clone()),
            controller_state: Some("ready".to_string()),
            ..Default::default()
        },
    )
    .await?
    .len() as u32;
    let ready_shelves = db_power_shelf::find_ids(
        txn.as_mut(),
        model::power_shelf::PowerShelfSearchFilter {
            rack_id: Some(id.clone()),
            controller_state: Some("ready".to_string()),
            ..Default::default()
        },
    )
    .await?
    .len() as u32;

    if ready_compute < capabilities.compute.count
        || ready_switches < capabilities.switch.count
        || ready_shelves < capabilities.power_shelf.count
    {
        return Ok(StateHandlerOutcome::wait(format!(
            "waiting for devices ready: compute={}/{}, switch={}/{}, power_shelf={}/{}",
            ready_compute,
            capabilities.compute.count,
            ready_switches,
            capabilities.switch.count,
            ready_shelves,
            capabilities.power_shelf.count,
        ))
        .with_txn(txn));
    }

    tracing::info!(
        "Rack {} all devices ready, transitioning to Maintenance",
        id
    );
    Ok(StateHandlerOutcome::transition(RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::Start,
        },
    }))
}
