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
    Rack, RackConfig, RackFirmwareUpgradeState, RackMaintenanceState, RackPowerState,
    RackReadyState, RackState, RackValidationState,
};
use model::rack_type::RackCapabilitiesSet;
use model::switch::SwitchControllerState;
use sqlx::{PgPool, PgTransaction};

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

#[derive(Debug, Default, Clone)]
pub struct RackStateHandler {}

/// adopt_dangling_devices finds expected devices that reference this rack_id
/// but haven't been added to the rack config yet, and adds them. Returns true
/// if any devices were adopted (config was changed).
pub(crate) async fn adopt_dangling_devices(
    pool: &PgPool,
    id: &RackId,
    config: &mut RackConfig,
) -> Result<bool, StateHandlerError> {
    let mut txn = pool.begin().await?;
    let mut changed = false;

    // Adopt expected machines with this rack_id.
    let expected_machines = db_expected_machine::find_all_by_rack_id(&mut txn, id).await?;
    for em in &expected_machines {
        if !config.expected_compute_trays.contains(&em.bmc_mac_address) {
            config.expected_compute_trays.push(em.bmc_mac_address);
            changed = true;
        }
    }

    // Adopt expected switches with this rack_id.
    let expected_switches = db_expected_switch::find_all_by_rack_id(&mut txn, id).await?;
    for es in &expected_switches {
        if !config.expected_switches.contains(&es.bmc_mac_address) {
            config.expected_switches.push(es.bmc_mac_address);
            changed = true;
        }
    }

    // Adopt expected power shelves with this rack_id.
    let expected_ps = db_expected_power_shelf::find_all_by_rack_id(&mut txn, id).await?;
    for eps in &expected_ps {
        if !config.expected_power_shelves.contains(&eps.bmc_mac_address) {
            config.expected_power_shelves.push(eps.bmc_mac_address);
            changed = true;
        }
    }

    if changed {
        db_rack::update(&mut txn, id, config).await?;
        txn.commit().await?;
    }

    Ok(changed)
}

/// validate_device_counts checks whether the registered device counts match
/// the rack capabilities. Returns true if all counts match.
pub(crate) fn validate_device_counts(
    id: &RackId,
    config: &RackConfig,
    capabilities: &RackCapabilitiesSet,
) -> bool {
    let registered_compute = config.expected_compute_trays.len() as u32;
    let registered_switches = config.expected_switches.len() as u32;
    let registered_ps = config.expected_power_shelves.len() as u32;

    if registered_compute != capabilities.compute.count {
        tracing::info!(
            "rack {} has {} of {} expected registered compute trays. waiting.",
            id,
            registered_compute,
            capabilities.compute.count
        );
        return false;
    }
    if registered_switches != capabilities.switch.count {
        tracing::info!(
            "rack {} has {} of {} expected registered switches. waiting.",
            id,
            registered_switches,
            capabilities.switch.count
        );
        return false;
    }
    if registered_ps != capabilities.power_shelf.count {
        tracing::info!(
            "rack {} has {} of {} expected registered power shelves. waiting.",
            id,
            registered_ps,
            capabilities.power_shelf.count
        );
        return false;
    }
    true
}

/// log_capability_hints logs debug messages about optional name/vendor matching
/// fields in the rack capabilities.
pub(crate) fn log_capability_hints(id: &RackId, capabilities: &RackCapabilitiesSet) {
    if let Some(ref name) = capabilities.compute.name {
        tracing::debug!(
            "rack {} would match compute model name '{}' if available.",
            id,
            name
        );
    }
    if let Some(ref vendor) = capabilities.compute.vendor {
        tracing::debug!(
            "rack {} would match compute vendor '{}' if available.",
            id,
            vendor
        );
    }
    if let Some(ref name) = capabilities.switch.name {
        tracing::debug!(
            "rack {} would match switch model name '{}' if available.",
            id,
            name
        );
    }
    if let Some(ref vendor) = capabilities.switch.vendor {
        tracing::debug!(
            "rack {} would match switch vendor '{}' if available.",
            id,
            vendor
        );
    }
    if let Some(ref name) = capabilities.power_shelf.name {
        tracing::debug!(
            "rack {} would match power shelf model name '{}' if available.",
            id,
            name
        );
    }
    if let Some(ref vendor) = capabilities.power_shelf.vendor {
        tracing::debug!(
            "rack {} would match power shelf vendor '{}' if available.",
            id,
            vendor
        );
    }
}

/// check_compute_linked checks whether all expected compute trays have been
/// explored and linked to actual machines. Returns (done, optional_txn).
pub(crate) async fn check_compute_linked(
    pool: &PgPool,
    id: &RackId,
    config: &mut RackConfig,
) -> Result<(bool, Option<PgTransaction<'static>>), StateHandlerError> {
    match config
        .expected_compute_trays
        .len()
        .cmp(&config.compute_trays.len())
    {
        Ordering::Greater => {
            let mut txn = pool.begin().await?;
            for macaddr in config.expected_compute_trays.clone().as_slice() {
                match db_expected_machine::find_one_linked(&mut txn, *macaddr).await {
                    Ok(machine) => {
                        if let Some(machine_id) = machine.machine_id
                            && !config.compute_trays.contains(&machine_id)
                        {
                            config.compute_trays.push(machine_id);
                            db_rack::update(&mut txn, id, config).await?;
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
            Ok((false, Some(txn)))
        }
        Ordering::Less => {
            tracing::info!(
                "Rack {} has more compute trays discovered {} than expected {}",
                id,
                config.compute_trays.len(),
                config.expected_compute_trays.len()
            );
            Ok((true, None))
        }
        Ordering::Equal => Ok((true, None)),
    }
}

/// check_power_shelves_linked checks whether all expected power shelves have
/// been explored and linked.
pub(crate) async fn check_power_shelves_linked(
    pool: &PgPool,
    id: &RackId,
    config: &mut RackConfig,
) -> Result<bool, StateHandlerError> {
    match config
        .expected_power_shelves
        .len()
        .cmp(&config.power_shelves.len())
    {
        Ordering::Greater => {
            let mut txn = pool.begin().await?;
            let linked = db_expected_power_shelf::find_all_linked(&mut txn).await?;
            for expected_mac in config.expected_power_shelves.iter() {
                if let Some(l) = linked
                    .iter()
                    .find(|l| l.bmc_mac_address == *expected_mac && l.power_shelf_id.is_some())
                {
                    let ps_id = l.power_shelf_id.unwrap();
                    if !config.power_shelves.contains(&ps_id) {
                        config.power_shelves.push(ps_id);
                        db_rack::update(txn.as_mut(), id, config).await?;
                    }
                }
            }
            txn.commit().await?;
            Ok(false)
        }
        Ordering::Less => {
            tracing::info!(
                "Rack {} has more power shelves discovered {} than expected {}",
                id,
                config.power_shelves.len(),
                config.expected_power_shelves.len()
            );
            Ok(true)
        }
        Ordering::Equal => Ok(true),
    }
}

/// check_switches_linked checks whether all expected switches have been
/// explored and linked.
pub(crate) async fn check_switches_linked(
    pool: &PgPool,
    config: &RackConfig,
) -> Result<bool, StateHandlerError> {
    if config.expected_switches.is_empty() {
        return Ok(true);
    }
    let mut txn = pool.begin().await?;
    let linked = db_expected_switch::find_all_linked(&mut txn).await?;
    let discovered_count = config
        .expected_switches
        .iter()
        .filter(|expected_mac| {
            linked
                .iter()
                .any(|l| l.bmc_mac_address == **expected_mac && l.switch_id.is_some())
        })
        .count();
    drop(txn);
    Ok(discovered_count >= config.expected_switches.len())
}

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
        tracing::info!("Rack {} is in state {}", id, controller_state.to_string());
        match controller_state {
            RackState::Expected => {
                // Racks without a rack_type stay parked in Expected until
                // an expected rack is created via add_expected_rack.
                let rack_type_name = match config.rack_type {
                    Some(ref name) => name.clone(),
                    None => {
                        tracing::info!("rack {} has no rack_type set, staying in Expected.", id);
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                };

                // Look up the capabilities from the config file.
                let capabilities = match ctx.services.site_config.rack_types.get(&rack_type_name) {
                    Some(caps) => caps.clone(),
                    None => {
                        tracing::error!(
                            "rack {} has rack_type '{}' but no matching definition in config. skipping.",
                            id,
                            rack_type_name
                        );
                        return Ok(StateHandlerOutcome::do_nothing());
                    }
                };

                // Adopt dangling expected devices that have this rack_id but
                // haven't been added to the rack config yet.
                if adopt_dangling_devices(&ctx.services.db_pool, id, &mut config).await? {
                    return Ok(StateHandlerOutcome::do_nothing());
                }

                log_capability_hints(id, &capabilities);

                // Validate expected device counts against the capabilities.
                if !validate_device_counts(id, &config, &capabilities) {
                    return Ok(StateHandlerOutcome::do_nothing());
                }

                // Check if all expected devices have been explored and linked.
                let (compute_done, pending_txn) =
                    check_compute_linked(&ctx.services.db_pool, id, &mut config).await?;
                let ps_done =
                    check_power_shelves_linked(&ctx.services.db_pool, id, &mut config).await?;
                let switch_done = check_switches_linked(&ctx.services.db_pool, &config).await?;

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
