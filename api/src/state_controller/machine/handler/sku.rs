use chrono::Utc;
use health_report::HealthReport;

use super::{HostHandlerParams, discovered_after_state_transition};
use crate::{
    db::{self, machine_topology::MachineTopology, machine_validation::MachineValidation},
    model::{
        machine::{
            BomValidating, BomValidatingContext, MachineState, MachineValidatingState,
            ManagedHostState, ManagedHostStateSnapshot, ValidationState,
        },
        sku::diff_skus,
    },
    state_controller::state_handler::{StateHandlerError, StateHandlerOutcome},
};

fn get_machine_validation_context(state: &ManagedHostState) -> Option<String> {
    if let ManagedHostState::BomValidating {
        bom_validating_state,
    } = state
    {
        match bom_validating_state {
            BomValidating::MatchingSku(bom_validating_context)
            | BomValidating::UpdatingInventory(bom_validating_context)
            | BomValidating::VerifyingSku(bom_validating_context)
            | BomValidating::SkuVerificationFailed(bom_validating_context)
            | BomValidating::WaitingForSkuAssignment(bom_validating_context) => {
                bom_validating_context.machine_validation_context.clone()
            }
        }
    } else {
        None
    }
}

async fn match_sku_for_machine(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<Option<crate::model::sku::Sku>, StateHandlerError> {
    let sku_status = mh_snapshot.host_snapshot.hw_sku_status.as_ref();
    if sku_status.is_none()
        || sku_status.is_some_and(|ss| {
            ss.last_match_attempt.is_some_and(|t| {
                t < (Utc::now() - host_handler_params.bom_validation.find_match_interval)
            })
        })
    {
        db::machine::update_sku_status_last_match_attempt(txn, &mh_snapshot.host_snapshot.id)
            .await?;
        let machine_sku = db::sku::from_topology(txn, &mh_snapshot.host_snapshot.id).await?;
        return Ok(db::sku::find_matching(txn, &machine_sku).await?);
    }
    Ok(None)
}

pub(crate) async fn handle_bom_validation_requested(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<Option<StateHandlerOutcome<ManagedHostState>>, StateHandlerError> {
    if !host_handler_params.bom_validation.enabled {
        return Ok(None);
    }

    // If ignored_unassigned_machines is true, still try to find a matching SKU.
    if host_handler_params
        .bom_validation
        .ignore_unassigned_machines
        && mh_snapshot.host_snapshot.hw_sku.is_none()
    {
        if let Some(sku) = match_sku_for_machine(txn, host_handler_params, mh_snapshot).await? {
            tracing::info!(machine_id=%mh_snapshot.host_snapshot.id, sku_id=sku.id, "Possible SKU match found, attempting verification");
            // A possible match has been found but inventory may be out of date.  update the
            // machines inventory and do the match again
            return advance_to_updating_inventory(txn, mh_snapshot)
                .await
                .map(Some);
        }

        return Ok(None);
    }

    // if the sku was removed, move to waiting
    if mh_snapshot.host_snapshot.hw_sku.is_none() {
        tracing::info!(machine_id=%mh_snapshot.host_snapshot.id, sku_id=mh_snapshot.host_snapshot.hw_sku, "SKU unassigned");

        Ok(Some(StateHandlerOutcome::Transition(
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context: None,
                    },
                ),
            },
        )))
    } else if mh_snapshot
        .host_snapshot
        .hw_sku_status
        .as_ref()
        .is_some_and(|ss| {
            ss.verify_request_time
                .is_some_and(|t| t > mh_snapshot.host_snapshot.state.version.timestamp())
        })
    {
        tracing::info!(machine_id=%mh_snapshot.host_snapshot.id, sku_id=mh_snapshot.host_snapshot.hw_sku, "Verify SKU requested, attempting verification");

        advance_to_updating_inventory(txn, mh_snapshot)
            .await
            .map(Some)
    } else {
        Ok(None)
    }
}

async fn advance_to_updating_inventory(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let machine_validation_context =
        get_machine_validation_context(mh_snapshot.host_snapshot.current_state());

    MachineTopology::set_topology_update_needed(txn, &mh_snapshot.host_snapshot.id, true).await?;

    Ok(StateHandlerOutcome::Transition(
        ManagedHostState::BomValidating {
            bom_validating_state: BomValidating::UpdatingInventory(BomValidatingContext {
                machine_validation_context,
            }),
        },
    ))
}

async fn advance_to_waiting_for_sku_assignment(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mh_snapshot: &mut ManagedHostStateSnapshot,
    host_handler_params: &HostHandlerParams,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if host_handler_params
        .bom_validation
        .ignore_unassigned_machines
        && mh_snapshot.host_snapshot.hw_sku.is_none()
    {
        handle_bom_validation_disabled(txn, host_handler_params, mh_snapshot).await
    } else {
        let machine_validation_context =
            get_machine_validation_context(mh_snapshot.host_snapshot.current_state());

        Ok(StateHandlerOutcome::Transition(
            ManagedHostState::BomValidating {
                bom_validating_state: BomValidating::WaitingForSkuAssignment(
                    BomValidatingContext {
                        machine_validation_context,
                    },
                ),
            },
        ))
    }
}

async fn advance_to_machine_validating(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mh_snapshot: &mut ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    // transitioning to machine validating with a None context is a bug.
    let context = get_machine_validation_context(mh_snapshot.host_snapshot.current_state());

    let Some(context) = context else {
        tracing::info!("SKU verification complete; Skipping machine validation");
        return Ok(StateHandlerOutcome::Transition(
            ManagedHostState::HostInit {
                machine_state: MachineState::Discovered {
                    skip_reboot_wait: true,
                },
            },
        ));
    };
    let validation_id = MachineValidation::create_new_run(
        txn,
        &mh_snapshot.host_snapshot.id,
        context.clone(),
        crate::model::machine::MachineValidationFilter::default(),
    )
    .await?;
    Ok(StateHandlerOutcome::Transition(
        ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::RebootHost { validation_id },
            },
        },
    ))
}

async fn handle_bom_validation_disabled(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &mut ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    tracing::info!(bom_validation=?host_handler_params.bom_validation,
        machine_id=%mh_snapshot.host_snapshot.id,
        assigned_sku_id=%mh_snapshot.host_snapshot.hw_sku.as_deref().unwrap_or_default(),
        "Skipping SKU Validation due to configuration");

    let health_report = HealthReport::empty(HealthReport::SKU_VALIDATION_SOURCE.to_string());

    db::machine::update_sku_validation_health_report(
        txn,
        &mh_snapshot.host_snapshot.id,
        &health_report,
    )
    .await?;
    advance_to_machine_validating(txn, mh_snapshot).await
}

pub(crate) async fn handle_bom_validation_state(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &mut ManagedHostStateSnapshot,
    bom_validating_state: &BomValidating,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if !host_handler_params.bom_validation.enabled {
        return handle_bom_validation_disabled(txn, host_handler_params, mh_snapshot).await;
    }

    match bom_validating_state {
        BomValidating::MatchingSku(bom_validating_context) => {
            if mh_snapshot.host_snapshot.hw_sku.is_none() {
                if let Some(sku) =
                    match_sku_for_machine(txn, host_handler_params, mh_snapshot).await?
                {
                    db::machine::assign_sku(txn, &mh_snapshot.host_snapshot.id, &sku.id).await?;
                    // finding a match uses the same check as verifying the sku, so consider it verified.
                    advance_to_machine_validating(txn, mh_snapshot).await
                } else {
                    advance_to_waiting_for_sku_assignment(txn, mh_snapshot, host_handler_params)
                        .await
                }
            } else {
                Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::VerifyingSku(BomValidatingContext {
                            machine_validation_context: bom_validating_context
                                .machine_validation_context
                                .clone(),
                        }),
                    },
                ))
            }
        }
        BomValidating::UpdatingInventory(bom_validating_context) => {
            if !discovered_after_state_transition(
                mh_snapshot.host_snapshot.state.version,
                mh_snapshot.host_snapshot.last_discovery_time,
            ) {
                return Ok(StateHandlerOutcome::DoNothing);
            }

            if mh_snapshot.host_snapshot.hw_sku.is_none() {
                Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::MatchingSku(
                            bom_validating_context.clone(),
                        ),
                    },
                ))
            } else {
                Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::VerifyingSku(
                            bom_validating_context.clone(),
                        ),
                    },
                ))
            }
        }
        BomValidating::VerifyingSku(bom_validating_context) => {
            let Some(sku_id) = mh_snapshot.host_snapshot.hw_sku.clone() else {
                // the sku got removed before it could be verified.  start over
                return Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::MatchingSku(
                            bom_validating_context.clone(),
                        ),
                    },
                ));
            };

            let Some(expected_sku) = crate::db::sku::find(txn, &[sku_id.clone()]).await?.pop()
            else {
                return Err(StateHandlerError::MissingData {
                    object_id: sku_id,
                    missing: "Assigned SKU is missing",
                });
            };

            let actual_sku = crate::db::sku::from_topology_with_version(
                txn,
                &mh_snapshot.host_snapshot.id,
                expected_sku.schema_version,
            )
            .await?;

            let diffs = diff_skus(&actual_sku, &expected_sku);
            for diff in &diffs {
                tracing::error!(machine_id=%mh_snapshot.host_snapshot.id, "{}", diff);
            }

            if diffs.is_empty() {
                let health_report = HealthReport::sku_validation_success();

                db::machine::update_sku_validation_health_report(
                    txn,
                    &mh_snapshot.host_snapshot.id,
                    &health_report,
                )
                .await?;

                advance_to_machine_validating(txn, mh_snapshot).await
            } else {
                let health_report = HealthReport::sku_mismatch(diffs);
                db::machine::update_sku_validation_health_report(
                    txn,
                    &mh_snapshot.host_snapshot.id,
                    &health_report,
                )
                .await?;

                Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::SkuVerificationFailed(
                            bom_validating_context.clone(),
                        ),
                    },
                ))
            }
        }
        BomValidating::SkuVerificationFailed(bom_validating_context) => {
            if mh_snapshot.host_snapshot.hw_sku.is_none() {
                Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::WaitingForSkuAssignment(
                            bom_validating_context.clone(),
                        ),
                    },
                ))
            } else if mh_snapshot
                .host_snapshot
                .hw_sku_status
                .as_ref()
                .is_some_and(|ss| {
                    ss.verify_request_time
                        .is_some_and(|t| t > mh_snapshot.host_snapshot.state.version.timestamp())
                })
            {
                advance_to_updating_inventory(txn, mh_snapshot).await
            } else {
                Ok(StateHandlerOutcome::DoNothing)
            }
        }
        BomValidating::WaitingForSkuAssignment(_) => {
            if mh_snapshot.host_snapshot.hw_sku.is_some()
                || match_sku_for_machine(txn, host_handler_params, mh_snapshot)
                    .await?
                    .is_some()
            {
                advance_to_updating_inventory(txn, mh_snapshot).await
            } else if host_handler_params
                .bom_validation
                .ignore_unassigned_machines
            {
                handle_bom_validation_disabled(txn, host_handler_params, mh_snapshot).await
            } else {
                Ok(StateHandlerOutcome::DoNothing)
            }
        }
    }
}
