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

use db::{self};
use libredfish::SystemPowerControl;
use model::machine::{
    FailureCause, MachineState, MachineValidatingState, ManagedHostState, ManagedHostStateSnapshot,
    ValidationState,
};
use model::machine_validation::{MachineValidationState, MachineValidationStatus};
use sqlx::PgConnection;

use super::{HostHandlerParams, is_machine_validation_requested, machine_validation_completed};
use crate::state_controller::machine::context::MachineStateHandlerContextObjects;
use crate::state_controller::machine::handler::{
    handler_host_power_control, rebooted, trigger_reboot_if_needed,
};
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

pub(crate) async fn handle_machine_validation_state(
    txn: &mut PgConnection,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    machine_validation: &MachineValidatingState,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    match machine_validation {
        MachineValidatingState::RebootHost { validation_id } => {
            // Handle reboot host case
            handler_host_power_control(
                mh_snapshot,
                ctx.services,
                SystemPowerControl::ForceRestart,
                txn,
            )
            .await?;
            let machine_validation = db::machine_validation::find_by_id(txn, validation_id)
                .await
                .map_err(|err| StateHandlerError::GenericError(err.into()))?;
            let next_state = ManagedHostState::Validation {
                validation_state: ValidationState::MachineValidation {
                    machine_validation: MachineValidatingState::MachineValidating {
                        context: machine_validation.context.unwrap_or_default(),
                        id: *validation_id,
                        completed: 1,
                        total: 1,
                        is_enabled: host_handler_params.machine_validation_config.enabled,
                    },
                },
            };
            Ok(StateHandlerOutcome::transition(next_state))
        }
        MachineValidatingState::MachineValidating {
            context,
            id,
            completed,
            total,
            is_enabled,
        } => {
            tracing::trace!(
                "context = {} id = {} completed = {} total = {}, is_enabled = {} ",
                context,
                id,
                completed,
                total,
                is_enabled,
            );
            if !rebooted(&mh_snapshot.host_snapshot) {
                let status = trigger_reboot_if_needed(
                    &mh_snapshot.host_snapshot,
                    mh_snapshot,
                    None,
                    &host_handler_params.reachability_params,
                    ctx.services,
                    txn,
                )
                .await?;
                return Ok(StateHandlerOutcome::wait(status.status));
            }
            if !host_handler_params.machine_validation_config.enabled {
                tracing::info!("Skipping Machine Validation");
                let _ = db::machine_validation::mark_machine_validation_complete(
                    txn,
                    &mh_snapshot.host_snapshot.id,
                    id,
                    MachineValidationStatus {
                        state: MachineValidationState::Skipped,
                        ..MachineValidationStatus::default()
                    },
                )
                .await;
                let machine_validation = db::machine_validation::find_by_id(txn, id)
                    .await
                    .map_err(|err| StateHandlerError::GenericError(err.into()))?;
                *ctx.metrics
                    .last_machine_validation_list
                    .entry((
                        machine_validation.machine_id.to_string(),
                        machine_validation.context.unwrap_or_default(),
                    ))
                    .or_default() = 0_i32;
                return Ok(StateHandlerOutcome::transition(
                    ManagedHostState::HostInit {
                        machine_state: MachineState::Discovered {
                            // Since we're skipping machine validation, we don't need to
                            // wait on *another* reboot. We already waited for the prior
                            // reboot to complete above, so tell the Discovered state to
                            // skip it.
                            skip_reboot_wait: true,
                        },
                    },
                ));
            }
            // Host validation completed
            if machine_validation_completed(&mh_snapshot.host_snapshot) {
                if mh_snapshot.host_snapshot.failure_details.cause == FailureCause::NoError {
                    tracing::info!(
                        "{} machine validation completed",
                        mh_snapshot.host_snapshot.id
                    );
                    let machine_validation = db::machine_validation::find_by_id(txn, id)
                        .await
                        .map_err(|err| StateHandlerError::GenericError(err.into()))?;
                    let status = machine_validation.status.clone().unwrap_or_default();
                    *ctx.metrics
                        .last_machine_validation_list
                        .entry((
                            machine_validation.machine_id.to_string(),
                            machine_validation.context.clone().unwrap_or_default(),
                        ))
                        .or_default() = status.total - status.completed;
                    handler_host_power_control(
                        mh_snapshot,
                        ctx.services,
                        SystemPowerControl::ForceRestart,
                        txn,
                    )
                    .await?;
                    return Ok(StateHandlerOutcome::transition(
                        ManagedHostState::HostInit {
                            machine_state: MachineState::Discovered {
                                skip_reboot_wait: false,
                            },
                        },
                    ));
                } else {
                    tracing::info!("{} machine validation failed", mh_snapshot.host_snapshot.id);
                    return Ok(StateHandlerOutcome::transition(ManagedHostState::Failed {
                        details: mh_snapshot.host_snapshot.failure_details.clone(),
                        machine_id: mh_snapshot.host_snapshot.id,
                        retry_count: 0,
                    }));
                }
            }
            Ok(StateHandlerOutcome::do_nothing())
        }
    }
}

#[allow(txn_held_across_await)]
pub(crate) async fn handle_machine_validation_requested(
    txn: &mut PgConnection,
    mh_snapshot: &ManagedHostStateSnapshot,
    clear_failure_details: bool,
) -> Result<Option<StateHandlerOutcome<ManagedHostState>>, StateHandlerError> {
    if is_machine_validation_requested(mh_snapshot).await {
        if clear_failure_details {
            // Clear the error so that state machine doesnt get into loop
            db::machine::clear_failure_details(&mh_snapshot.host_snapshot.id, txn)
                .await
                .map_err(StateHandlerError::from)?;
        }
        let machine_validation =
            match db::machine_validation::find_active_machine_validation_by_machine_id(
                txn,
                &mh_snapshot.host_snapshot.id,
            )
            .await
            {
                Ok(data) => data,
                Err(e) => {
                    tracing::info!(
                        error = %e,
                        "find_active_machine_validation_by_machine_id"
                    );
                    db::machine::set_machine_validation_request(
                        txn,
                        &mh_snapshot.host_snapshot.id,
                        true,
                    )
                    .await
                    .map_err(StateHandlerError::from)?;
                    // Health Alert ?
                    // Rare screnario, if something googfed up in DB
                    return Ok(Some(StateHandlerOutcome::do_nothing()));
                }
            };

        let next_state = ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::RebootHost {
                    validation_id: machine_validation.id,
                },
            },
        };
        return Ok(Some(StateHandlerOutcome::transition(next_state)));
    }
    Ok(None)
}
