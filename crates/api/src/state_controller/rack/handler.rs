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

use std::cmp::Ordering;

use carbide_uuid::rack::RackId;
use db::{
    expected_machine as db_expected_machine, expected_power_shelf as db_expected_power_shelf,
    expected_switch as db_expected_switch, rack as db_rack,
};
use model::machine::{LoadSnapshotOptions, ManagedHostState};
use model::power_shelf::PowerShelfControllerState;
use model::rack::{
    Rack, RackFirmwareUpgradeState, RackMaintenanceState, RackPowerState, RackReadyState,
    RackState, RackValidationState,
};
use model::switch::SwitchControllerState;
use sqlx::PgTransaction;

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

#[derive(Debug, Default, Clone)]
pub struct RackStateHandler {}

#[async_trait::async_trait]
impl StateHandler for RackStateHandler {
    type ObjectId = RackId;
    type State = Rack;
    type ControllerState = RackState;
    type ContextObjects = RackStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        id: &Self::ObjectId,
        state: &mut Rack,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
        let mut config = state.config.clone();
        let pending_txn: Option<PgTransaction>;
        tracing::info!("Rack {} is in state {}", id, controller_state.to_string());
        match controller_state {
            RackState::Expected => {
                // Validate expected device counts against the embedded rack type
                // definition. Racks without a definition stay parked in Expected
                // until one is set via add_expected_rack.
                if let Some(ref rack_type_def) = config.rack_type_definition {
                    let registered_compute = config.expected_compute_trays.len() as u32;
                    let registered_switches = config.expected_switches.len() as u32;
                    let registered_ps = config.expected_power_shelves.len() as u32;

                    if registered_compute != rack_type_def.expected_compute_trays {
                        tracing::info!(
                            "rack {} (type: {}) has {} of {} expected registered compute trays. waiting.",
                            id,
                            rack_type_def.name,
                            registered_compute,
                            rack_type_def.expected_compute_trays
                        );
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                    if registered_switches != rack_type_def.expected_switches {
                        tracing::info!(
                            "rack {} (type: {}) has {} of {} expected registered switches. waiting.",
                            id,
                            rack_type_def.name,
                            registered_switches,
                            rack_type_def.expected_switches
                        );
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                    if registered_ps != rack_type_def.expected_power_shelves {
                        tracing::info!(
                            "rack {} (type: {}) has {} of {} expected registered power shelves. waiting.",
                            id,
                            rack_type_def.name,
                            registered_ps,
                            rack_type_def.expected_power_shelves
                        );
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                } else {
                    // Racks without a rack_type_definition stay in Expected
                    // until one is set via add_expected_rack. This prevents
                    // auto-created racks from advancing before the expected
                    // device counts are known.
                    tracing::info!(
                        "rack {} has no rack_type_definition set, staying in Expected.",
                        id
                    );
                    return Ok(StateHandlerOutcome::do_nothing());
                }

                // Check if all expected machines have been explored and linked.
                let compute_done = match config
                    .expected_compute_trays
                    .len()
                    .cmp(&config.compute_trays.len())
                {
                    Ordering::Greater => {
                        let mut txn = ctx.services.db_pool.begin().await?;
                        for macaddr in config.expected_compute_trays.clone().as_slice() {
                            match db_expected_machine::find_one_linked(&mut txn, *macaddr).await {
                                Ok(machine) => {
                                    if let Some(machine_id) = machine.machine_id
                                        && !config.compute_trays.contains(&machine_id)
                                    {
                                        config.compute_trays.push(machine_id);
                                        db_rack::update(&mut txn, *id, &config).await?;
                                    }
                                }
                                Err(_) => {
                                    tracing::debug!(
                                        "rack {} expected compute tray {} not yet explored.",
                                        id,
                                        macaddr
                                    );
                                }
                            }
                        }
                        pending_txn = Some(txn);
                        false
                    }
                    Ordering::Less => {
                        tracing::info!(
                            "Rack {} has more compute trays discovered {} than expected {}",
                            id,
                            config.compute_trays.len(),
                            config.expected_compute_trays.len()
                        );
                        pending_txn = None;
                        true
                    }
                    Ordering::Equal => {
                        pending_txn = None;
                        true
                    }
                };

                // Check if all expected power shelves have been explored and linked.
                let ps_done = match config
                    .expected_power_shelves
                    .len()
                    .cmp(&config.power_shelves.len())
                {
                    Ordering::Greater => {
                        let mut ps_txn = ctx.services.db_pool.begin().await?;
                        let linked_power_shelves =
                            db_expected_power_shelf::find_all_linked(&mut ps_txn).await?;
                        for expected_mac in config.expected_power_shelves.iter() {
                            if let Some(linked) = linked_power_shelves.iter().find(|l| {
                                l.bmc_mac_address == *expected_mac && l.power_shelf_id.is_some()
                            }) {
                                let ps_id = linked.power_shelf_id.unwrap();
                                if !config.power_shelves.contains(&ps_id) {
                                    config.power_shelves.push(ps_id);
                                    db_rack::update(ps_txn.as_mut(), *id, &config).await?;
                                }
                            }
                        }
                        // Commit the power shelf txn separately since compute
                        // may have its own pending transaction.
                        ps_txn.commit().await?;
                        false
                    }
                    Ordering::Less => {
                        tracing::info!(
                            "Rack {} has more power shelves discovered {} than expected {}",
                            id,
                            config.power_shelves.len(),
                            config.expected_power_shelves.len()
                        );
                        true
                    }
                    Ordering::Equal => true,
                };

                // Check if all expected switches have been explored and linked.
                let switch_done = if config.expected_switches.is_empty() {
                    true
                } else {
                    let mut switch_txn = ctx.services.db_pool.begin().await?;
                    let linked_switches =
                        db_expected_switch::find_all_linked(&mut switch_txn).await?;
                    let discovered_count = config
                        .expected_switches
                        .iter()
                        .filter(|expected_mac| {
                            linked_switches.iter().any(|linked| {
                                linked.bmc_mac_address == **expected_mac
                                    && linked.switch_id.is_some()
                            })
                        })
                        .count();
                    discovered_count >= config.expected_switches.len()
                };

                if compute_done && ps_done && switch_done {
                    Ok(StateHandlerOutcome::transition(RackState::Discovering)
                        .with_txn_opt(pending_txn))
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn_opt(pending_txn))
                }
            }
            RackState::Discovering => {
                // Check if each compute machine has reached ManagedHostState::Ready.
                let mut txn = ctx.services.db_pool.begin().await?;
                for machine_id in config.compute_trays.iter() {
                    let mh_snapshot = db::managed_host::load_snapshot(
                        txn.as_mut(),
                        machine_id,
                        LoadSnapshotOptions {
                            include_history: false,
                            include_instance_data: false,
                            host_health_config: ctx.services.site_config.host_health,
                        },
                    )
                    .await?
                    .ok_or(StateHandlerError::MissingData {
                        object_id: machine_id.to_string(),
                        missing: "managed host not found",
                    })?;
                    if mh_snapshot.managed_state != ManagedHostState::Ready {
                        tracing::debug!(
                            "Rack {} has compute tray {} in {} state",
                            id,
                            machine_id,
                            mh_snapshot.managed_state
                        );
                        return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
                    }
                }

                // Check if each expected switch has reached SwitchControllerState::Ready.
                if !config.expected_switches.is_empty() {
                    let linked_switches = db_expected_switch::find_all_linked(txn.as_mut()).await?;
                    for expected_mac in config.expected_switches.iter() {
                        if let Some(linked) = linked_switches
                            .iter()
                            .find(|l| l.bmc_mac_address == *expected_mac && l.switch_id.is_some())
                        {
                            let switch_id = linked.switch_id.unwrap();
                            let switch = db::switch::find_by_id(txn.as_mut(), &switch_id)
                                .await?
                                .ok_or(StateHandlerError::MissingData {
                                    object_id: switch_id.to_string(),
                                    missing: "switch not found",
                                })?;
                            if *switch.controller_state != SwitchControllerState::Ready {
                                tracing::debug!(
                                    "Rack {} has switch {} in {:?} state",
                                    id,
                                    switch_id,
                                    *switch.controller_state
                                );
                                return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
                            }
                        } else {
                            tracing::debug!(
                                "Rack {} has expected switch {} not yet linked",
                                id,
                                expected_mac
                            );
                            return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
                        }
                    }
                }

                // Check if each expected power shelf has reached PowerShelfControllerState::Ready.
                for ps_id in config.power_shelves.iter() {
                    let power_shelf = db::power_shelf::find_by_id(txn.as_mut(), ps_id)
                        .await?
                        .ok_or(StateHandlerError::MissingData {
                            object_id: ps_id.to_string(),
                            missing: "power shelf not found",
                        })?;
                    if *power_shelf.controller_state != PowerShelfControllerState::Ready {
                        tracing::debug!(
                            "Rack {} has power shelf {} in {:?} state",
                            id,
                            ps_id,
                            *power_shelf.controller_state
                        );
                        return Ok(StateHandlerOutcome::do_nothing().with_txn(txn));
                    }
                }

                // All devices are ready, transition to firmware upgrade.
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    rack_maintenance: RackMaintenanceState::FirmwareUpgrade {
                        rack_firmware_upgrade: RackFirmwareUpgradeState::Compute,
                    },
                })
                .with_txn(txn))
            }
            RackState::Maintenance {
                rack_maintenance: maintenance,
            } => {
                match maintenance {
                    RackMaintenanceState::FirmwareUpgrade {
                        rack_firmware_upgrade,
                    } => {
                        match rack_firmware_upgrade {
                            RackFirmwareUpgradeState::Compute => {
                                //TODO add code here
                                return Ok(StateHandlerOutcome::transition(
                                    RackState::Maintenance {
                                        rack_maintenance: RackMaintenanceState::Completed,
                                    },
                                ));
                            }
                            RackFirmwareUpgradeState::Switch => {}
                            RackFirmwareUpgradeState::PowerShelf => {}
                            RackFirmwareUpgradeState::All => {
                                // we may most likely use this for rack manager to do the entire rack
                            }
                        }
                    }
                    RackMaintenanceState::RackValidation { rack_validation } => {
                        match rack_validation {
                            RackValidationState::Compute => {}
                            RackValidationState::Switch => {}
                            RackValidationState::Power => {}
                            RackValidationState::Nvlink => {}
                            RackValidationState::Topology => {}
                        }
                    }
                    RackMaintenanceState::PowerSequence { rack_power } => match rack_power {
                        RackPowerState::PoweringOn => {}
                        RackPowerState::PoweringOff => {}
                        RackPowerState::PowerReset => {}
                    },
                    RackMaintenanceState::Completed => {
                        return Ok(StateHandlerOutcome::transition(RackState::Ready {
                            rack_ready: RackReadyState::Full,
                        }));
                    }
                }
                Ok(StateHandlerOutcome::do_nothing())
            }
            RackState::Ready {
                rack_ready: ready_state,
            } => {
                match ready_state {
                    RackReadyState::Partial => {
                        // wait till rack is fully ready
                    }
                    RackReadyState::Full => {
                        return Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                            rack_maintenance: RackMaintenanceState::RackValidation {
                                rack_validation: RackValidationState::Topology,
                            },
                        }));
                    }
                }
                Ok(StateHandlerOutcome::do_nothing())
            }
            RackState::Deleting => Ok(StateHandlerOutcome::do_nothing()),
            RackState::Error { cause: log } => {
                // try to recover / auto-remediate
                tracing::error!("Rack {} is in error state {}", id, log);
                Ok(StateHandlerOutcome::do_nothing())
            }
            RackState::Unknown => Ok(StateHandlerOutcome::do_nothing()),
        }
    }
}
