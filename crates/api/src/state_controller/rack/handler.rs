/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::cmp::Ordering;

use carbide_uuid::rack::RackId;
use db::{expected_machine as db_expected_machine, rack as db_rack};
use model::machine::{LoadSnapshotOptions, ManagedHostState};
use model::rack::{
    Rack, RackFirmwareUpgradeState, RackMaintenanceState, RackPowerState, RackReadyState,
    RackState, RackValidationState,
};
use sqlx::PgTransaction;

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    StateHandlerOutcomeWithTransaction,
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
    ) -> Result<StateHandlerOutcomeWithTransaction<RackState>, StateHandlerError> {
        let mut config = state.config.clone();
        let pending_txn: Option<PgTransaction>;
        tracing::info!("Rack {} is in state {}", id, controller_state.to_string());
        match controller_state {
            RackState::Expected => {
                // check if all expected machines are explored
                let compute_done = match config
                    .expected_compute_trays
                    .len()
                    .cmp(&config.compute_trays.len())
                {
                    Ordering::Greater => {
                        // walk through each expected mac addr and check if they have been linked
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
                                    // do nothing since the bmc is not yet explored
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
                        // todo: walk through the list and check which compute tray got removed from expected list
                        // this will disassociate the compute tray from the rack.
                        // ideally the expected machine update api handler takes care of this.
                        pending_txn = None;
                        true
                    }
                    Ordering::Equal => {
                        // expected == explored
                        pending_txn = None;
                        true
                    }
                };
                // check if all expected power shelves showed up
                let ps_done = match config
                    .expected_power_shelves
                    .len()
                    .cmp(&config.power_shelves.len())
                {
                    Ordering::Greater => {
                        // todo: walk through power shelves and check if linked
                        false
                    }
                    Ordering::Less => {
                        tracing::info!(
                            "Rack {} has more power shelves discovered {} than expected {}",
                            id,
                            config.power_shelves.len(),
                            config.expected_power_shelves.len()
                        );
                        // todo: walk through the list and check which power shelf got removed from expected list
                        // this will disassociate the power shelf from the rack.
                        // ideally the expected ps update api handler does it and we never get here.
                        true
                    }
                    Ordering::Equal => true,
                };
                // todo: check if all expected nvswitches showed up
                //match config.expected_nvlink_switches.len().cmp(&config.nvlink_switches.len()) {}
                if compute_done && ps_done {
                    Ok(StateHandlerOutcome::transition(RackState::Discovering)
                        .with_txn(pending_txn))
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn(pending_txn))
                }
            }
            RackState::Discovering => {
                // check if each compute machine has reached ManagedHostState::Ready
                // we can then move all of them to firmware upgrade
                let mut txn = ctx.services.db_pool.begin().await?;
                for machine_id in config.compute_trays.iter() {
                    let mh_snapshot = db::managed_host::load_snapshot(
                        &mut txn,
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
                        return Ok(StateHandlerOutcome::do_nothing().with_txn(Some(txn)));
                    }
                }
                // todo: check nvlink switches
                // todo: check power shelves

                // todo: now once all are ready, push inventory to rack manager
                Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                    rack_maintenance: RackMaintenanceState::FirmwareUpgrade {
                        rack_firmware_upgrade: RackFirmwareUpgradeState::Compute,
                    },
                })
                .with_txn(Some(txn)))
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
                                )
                                .with_txn(None));
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
                        })
                        .with_txn(None));
                    }
                }
                Ok(StateHandlerOutcome::do_nothing().with_txn(None))
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
                        })
                        .with_txn(None));
                    }
                }
                Ok(StateHandlerOutcome::do_nothing().with_txn(None))
            }
            RackState::Deleting => Ok(StateHandlerOutcome::do_nothing().with_txn(None)),
            RackState::Error { cause: log } => {
                // try to recover / auto-remediate
                tracing::error!("Rack {} is in error state {}", id, log);
                Ok(StateHandlerOutcome::do_nothing().with_txn(None))
            }
            RackState::Unknown => Ok(StateHandlerOutcome::do_nothing().with_txn(None)),
        }
    }
}
