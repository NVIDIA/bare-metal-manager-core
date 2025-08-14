use chrono::Utc;
use health_report::HealthReport;
use sqlx::PgConnection;

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
    state_controller::state_handler::{
        StateHandlerError, StateHandlerOutcome, do_nothing, transition, wait,
    },
};

fn get_bom_validation_context(state: &ManagedHostState) -> BomValidatingContext {
    if let ManagedHostState::BomValidating {
        bom_validating_state,
    } = state
    {
        match bom_validating_state {
            BomValidating::MatchingSku(bom_validating_context)
            | BomValidating::UpdatingInventory(bom_validating_context)
            | BomValidating::VerifyingSku(bom_validating_context)
            | BomValidating::SkuVerificationFailed(bom_validating_context)
            | BomValidating::WaitingForSkuAssignment(bom_validating_context)
            | BomValidating::SkuMissing(bom_validating_context) => bom_validating_context.clone(),
        }
    } else {
        BomValidatingContext {
            machine_validation_context: None,
        }
    }
}

async fn clear_sku_validation_report(
    txn: &mut PgConnection,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<(), StateHandlerError> {
    let health_report = HealthReport::empty(HealthReport::SKU_VALIDATION_SOURCE.to_string());

    Ok(db::machine::update_sku_validation_health_report(
        txn,
        &mh_snapshot.host_snapshot.id,
        &health_report,
    )
    .await?)
}

async fn match_sku_for_machine(
    txn: &mut PgConnection,
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
        let machine_sku =
            db::sku::generate_sku_from_machine(txn, &mh_snapshot.host_snapshot.id).await?;
        let matching_sku = db::sku::find_matching(txn, &machine_sku).await?;
        if matching_sku.is_none() {
            // only update the last attempt if there is no match
            crate::db::machine::update_sku_status_last_match_attempt(
                txn,
                &mh_snapshot.host_snapshot.id,
            )
            .await?;
        }
        Ok(matching_sku)
    } else {
        Ok(None)
    }
}

async fn generate_missing_sku_for_machine(
    txn: &mut PgConnection,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> bool {
    if !host_handler_params.bom_validation.auto_generate_missing_sku {
        return false;
    }
    let Some(sku_id) = mh_snapshot.host_snapshot.hw_sku.as_ref() else {
        tracing::debug!(
            "No SKU assigned to machine {}",
            mh_snapshot.host_snapshot.id
        );
        return false;
    };

    // its unlikely we got here without a bmc mac
    let Some(bmc_mac_address) = mh_snapshot.host_snapshot.bmc_info.mac else {
        tracing::debug!("No bmc mac for machine {}", mh_snapshot.host_snapshot.id);
        return false;
    };

    // if there's no expected machine, no SKU in it, or the SKU doesn't match what's assigned to the machine, don't generate a SKU
    if db::expected_machine::ExpectedMachine::find_by_bmc_mac_address(txn, bmc_mac_address)
        .await
        .ok()
        .flatten()
        .is_none_or(|em| em.sku_id.as_ref().is_none_or(|id| id != sku_id))
    {
        tracing::debug!("No expected machine for bmc {}", bmc_mac_address);
        return false;
    }

    let sku_status = mh_snapshot.host_snapshot.hw_sku_status.as_ref();
    if sku_status.is_some_and(|ss| {
        ss.last_generate_attempt.is_some_and(|t| {
            t > (Utc::now()
                - host_handler_params
                    .bom_validation
                    .auto_generate_missing_sku_interval)
        })
    }) {
        tracing::info!(machine_id=%mh_snapshot.host_snapshot.id, "Last generation attempt is too recent");
        return false;
    }

    if let Err(e) = crate::db::machine::update_sku_status_last_generate_attempt(
        txn,
        &mh_snapshot.host_snapshot.id,
    )
    .await
    {
        tracing::error!(
            machine_id=%mh_snapshot.host_snapshot.id,
            error=%e,
            "Failed to get SKU status for machine",
        );
    } else {
        let generated_sku =
            match db::sku::generate_sku_from_machine(txn, &mh_snapshot.host_snapshot.id).await {
                Ok(mut sku) => {
                    sku.id = sku_id.clone();
                    sku
                }
                Err(e) => {
                    tracing::error!(
                        machine_id=%mh_snapshot.host_snapshot.id,
                        error=%e,
                        "Failed to generate SKU for machine",
                    );
                    return false;
                }
            };
        // Create checks for the existance of a duplicate SKU with a different name under a lock.
        if let Err(e) = db::sku::create(txn, &generated_sku).await {
            tracing::error!(
                machine_id=%mh_snapshot.host_snapshot.id,
                error=%e,
                "Failed to create generated SKU for machine",
            );
        }
    }
    true
}

pub(crate) async fn handle_bom_validation_requested(
    txn: &mut PgConnection,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<Option<StateHandlerOutcome<ManagedHostState>>, StateHandlerError> {
    if !host_handler_params.bom_validation.enabled {
        tracing::info!("BOM validation disabled");
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
        tracing::info!("ignoring unassigned machine");
        return Ok(None);
    }

    // if the sku was removed, move to waiting
    let Some(sku_id) = &mh_snapshot.host_snapshot.hw_sku else {
        tracing::info!(machine_id=%mh_snapshot.host_snapshot.id, sku_id=mh_snapshot.host_snapshot.hw_sku, "SKU unassigned");

        return advance_to_waiting_for_sku_assignment(txn, mh_snapshot, host_handler_params)
            .await
            .map(Some);
    };

    if let Some(verify_request_time) = mh_snapshot
        .host_snapshot
        .hw_sku_status
        .as_ref()
        .and_then(|ss| ss.verify_request_time)
    {
        if verify_request_time > mh_snapshot.host_snapshot.state.version.timestamp() {
            tracing::info!(machine_id=%mh_snapshot.host_snapshot.id, sku_id=mh_snapshot.host_snapshot.hw_sku, "Verify SKU requested, attempting verification");

            return advance_to_updating_inventory(txn, mh_snapshot)
                .await
                .map(Some);
        } else {
            tracing::info!(machine_id=%mh_snapshot.host_snapshot.id, sku_id=mh_snapshot.host_snapshot.hw_sku, "Verify SKU not requested");
        }
    }

    // if there is a request for verification pending
    if mh_snapshot
        .host_snapshot
        .hw_sku_status
        .as_ref()
        .is_some_and(|ss| {
            ss.verify_request_time
                .is_some_and(|t| t > mh_snapshot.host_snapshot.state.version.timestamp())
        })
    {
        tracing::info!(machine_id=%mh_snapshot.host_snapshot.id, sku_id=mh_snapshot.host_snapshot.hw_sku, "Verify SKU requested, attempting verification");

        return advance_to_updating_inventory(txn, mh_snapshot)
            .await
            .map(Some);
    }

    // check if the sku got deleted
    if db::sku::find(txn, &[sku_id.clone()]).await?.is_empty() {
        return advance_to_sku_missing(txn, mh_snapshot).await.map(Some);
    }

    Ok(None)
}

async fn advance_to_sku_missing(
    txn: &mut PgConnection,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let bom_validation_context =
        get_bom_validation_context(mh_snapshot.host_snapshot.current_state());
    let health_report = HealthReport::sku_missing(
        mh_snapshot
            .host_snapshot
            .hw_sku
            .as_deref()
            .unwrap_or_default(),
    );

    db::machine::update_sku_validation_health_report(
        txn,
        &mh_snapshot.host_snapshot.id,
        &health_report,
    )
    .await?;

    Ok(transition!(ManagedHostState::BomValidating {
        bom_validating_state: BomValidating::SkuMissing(bom_validation_context)
    }))
}

async fn advance_to_updating_inventory(
    txn: &mut PgConnection,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    let bom_validation_context =
        get_bom_validation_context(mh_snapshot.host_snapshot.current_state());

    MachineTopology::set_topology_update_needed(txn, &mh_snapshot.host_snapshot.id, true).await?;

    Ok(transition!(ManagedHostState::BomValidating {
        bom_validating_state: BomValidating::UpdatingInventory(bom_validation_context,),
    }))
}

async fn advance_to_waiting_for_sku_assignment(
    txn: &mut PgConnection,
    mh_snapshot: &ManagedHostStateSnapshot,
    host_handler_params: &HostHandlerParams,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if host_handler_params
        .bom_validation
        .ignore_unassigned_machines
        && mh_snapshot.host_snapshot.hw_sku.is_none()
    {
        handle_bom_validation_disabled(txn, host_handler_params, mh_snapshot).await
    } else {
        let bom_validation_context =
            get_bom_validation_context(mh_snapshot.host_snapshot.current_state());

        Ok(transition!(ManagedHostState::BomValidating {
            bom_validating_state: BomValidating::WaitingForSkuAssignment(bom_validation_context,),
        }))
    }
}

async fn advance_to_machine_validating(
    txn: &mut PgConnection,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    // transitioning to machine validating with a None context is a bug.
    let context = get_bom_validation_context(mh_snapshot.host_snapshot.current_state());

    let Some(context) = context.machine_validation_context else {
        tracing::info!("SKU verification complete; Skipping machine validation");
        return Ok(transition!(ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: true,
            },
        }));
    };
    let validation_id = MachineValidation::create_new_run(
        txn,
        &mh_snapshot.host_snapshot.id,
        context.clone(),
        crate::model::machine::MachineValidationFilter::default(),
    )
    .await?;
    Ok(transition!(ManagedHostState::Validation {
        validation_state: ValidationState::MachineValidation {
            machine_validation: MachineValidatingState::RebootHost { validation_id },
        },
    }))
}

async fn handle_bom_validation_disabled(
    txn: &mut PgConnection,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    tracing::info!(bom_validation=?host_handler_params.bom_validation,
        machine_id=%mh_snapshot.host_snapshot.id,
        assigned_sku_id=%mh_snapshot.host_snapshot.hw_sku.as_deref().unwrap_or_default(),
        "Skipping SKU Validation due to configuration");

    clear_sku_validation_report(txn, mh_snapshot).await?;

    advance_to_machine_validating(txn, mh_snapshot).await
}

pub(crate) async fn handle_bom_validation_state(
    txn: &mut PgConnection,
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
                Ok(transition!(ManagedHostState::BomValidating {
                    bom_validating_state: BomValidating::VerifyingSku(
                        bom_validating_context.clone()
                    ),
                }))
            }
        }
        BomValidating::UpdatingInventory(bom_validating_context) => {
            if !discovered_after_state_transition(
                mh_snapshot.host_snapshot.state.version,
                mh_snapshot.host_snapshot.last_discovery_time,
            ) {
                return Ok(do_nothing!());
            }

            if mh_snapshot.host_snapshot.hw_sku.is_none() {
                Ok(transition!(ManagedHostState::BomValidating {
                    bom_validating_state: BomValidating::MatchingSku(
                        bom_validating_context.clone(),
                    ),
                }))
            } else {
                Ok(transition!(ManagedHostState::BomValidating {
                    bom_validating_state: BomValidating::VerifyingSku(
                        bom_validating_context.clone(),
                    ),
                }))
            }
        }
        BomValidating::VerifyingSku(bom_validating_context) => {
            let Some(sku_id) = mh_snapshot.host_snapshot.hw_sku.clone() else {
                // the sku got removed before it could be verified.  start over
                return Ok(transition!(ManagedHostState::BomValidating {
                    bom_validating_state: BomValidating::MatchingSku(
                        bom_validating_context.clone(),
                    ),
                }));
            };

            let Some(expected_sku) = crate::db::sku::find(txn, &[sku_id.clone()]).await?.pop()
            else {
                return advance_to_sku_missing(txn, mh_snapshot).await;
            };

            let actual_sku = crate::db::sku::generate_sku_from_machine_at_version(
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

                Ok(transition!(ManagedHostState::BomValidating {
                    bom_validating_state: BomValidating::SkuVerificationFailed(
                        bom_validating_context.clone(),
                    ),
                }))
            }
        }
        BomValidating::SkuVerificationFailed(bom_validating_context) => {
            if mh_snapshot.host_snapshot.hw_sku.is_none() {
                Ok(transition!(ManagedHostState::BomValidating {
                    bom_validating_state: BomValidating::WaitingForSkuAssignment(
                        bom_validating_context.clone(),
                    ),
                }))
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
                Ok(do_nothing!())
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
                Ok(do_nothing!())
            }
        }
        BomValidating::SkuMissing(_) => {
            let outcome = if let Some(sku_id) = mh_snapshot.host_snapshot.hw_sku.clone() {
                if crate::db::sku::find(txn, &[sku_id]).await?.pop().is_some()
                    || generate_missing_sku_for_machine(txn, host_handler_params, mh_snapshot).await
                {
                    advance_to_updating_inventory(txn, mh_snapshot).await
                } else {
                    Ok(wait!(
                        "Assigned SKU does not exist.  Create the SKU or assign a different one"
                            .to_string()
                    ))
                }
            } else {
                advance_to_waiting_for_sku_assignment(txn, mh_snapshot, host_handler_params).await
            };

            // if leaving this state, clear the health report
            if matches!(outcome, Ok(StateHandlerOutcome::Transition { .. })) {
                clear_sku_validation_report(txn, mh_snapshot).await?;
            }
            outcome
        }
    }
}
