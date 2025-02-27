use health_report::HealthReport;

use super::{HostHandlerParams, discovered_after_state_transition};
use crate::{
    db::{self, machine_topology::MachineTopology, machine_validation::MachineValidation},
    model::{
        machine::{
            BomValidating, BomValidatingContext, MachineState, MachineValidationFilter,
            ManagedHostState, ManagedHostStateSnapshot,
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
            BomValidating::MatchingSku => Some("Discovery".to_string()),
            BomValidating::UpdatingInventory(bom_validating_context)
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

pub(crate) async fn handle_bom_validation_requested(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &ManagedHostStateSnapshot,
) -> Result<Option<StateHandlerOutcome<ManagedHostState>>, StateHandlerError> {
    if !host_handler_params.bom_validation.enabled
        || (host_handler_params
            .bom_validation
            .ignore_unassigned_machines
            && mh_snapshot.host_snapshot.hw_sku.is_none())
    {
        return Ok(None);
    }

    if mh_snapshot.host_snapshot.hw_sku.is_none() {
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

async fn advance_to_machine_validating(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mh_snapshot: &mut ManagedHostStateSnapshot,
    host_handler_params: &HostHandlerParams,
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
        MachineValidationFilter::default(),
    )
    .await?;
    Ok(StateHandlerOutcome::Transition(
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context,
                id: validation_id,
                completed: 1,
                total: 1,
                is_enabled: host_handler_params.machine_validation_config.enabled,
            },
        },
    ))
}

pub(crate) async fn handle_bom_validation_state(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    host_handler_params: &HostHandlerParams,
    mh_snapshot: &mut ManagedHostStateSnapshot,
    bom_validating_state: &BomValidating,
) -> Result<StateHandlerOutcome<ManagedHostState>, StateHandlerError> {
    if !host_handler_params.bom_validation.enabled
        || (host_handler_params
            .bom_validation
            .ignore_unassigned_machines
            && mh_snapshot.host_snapshot.hw_sku.is_none())
    {
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
        return advance_to_machine_validating(txn, mh_snapshot, host_handler_params).await;
    }

    match bom_validating_state {
        BomValidating::MatchingSku => {
            if mh_snapshot.host_snapshot.hw_sku.is_none() {
                // TODO.  New machines should attempt to find a sku that matches.
                // Currently this just sends the machine to WaitingForSkuAssignment
                // as if there is no match
                Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::WaitingForSkuAssignment(
                            BomValidatingContext {
                                machine_validation_context: Some("Discovery".to_string()),
                            },
                        ),
                    },
                ))
            } else {
                advance_to_updating_inventory(txn, mh_snapshot).await
            }
        }
        BomValidating::UpdatingInventory(bom_validating_context) => {
            if mh_snapshot.host_snapshot.hw_sku.is_none() {
                Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::WaitingForSkuAssignment(
                            bom_validating_context.clone(),
                        ),
                    },
                ))
            } else if discovered_after_state_transition(
                mh_snapshot.host_snapshot.state.version,
                mh_snapshot.host_snapshot.last_discovery_time,
            ) {
                Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::VerifyingSku(BomValidatingContext {
                            machine_validation_context: bom_validating_context
                                .machine_validation_context
                                .clone(),
                        }),
                    },
                ))
            } else {
                Ok(StateHandlerOutcome::DoNothing)
            }
        }
        BomValidating::VerifyingSku(bom_validating_context) => {
            let Some(sku_id) = mh_snapshot.host_snapshot.hw_sku.clone() else {
                return Ok(StateHandlerOutcome::Transition(
                    ManagedHostState::BomValidating {
                        bom_validating_state: BomValidating::WaitingForSkuAssignment(
                            bom_validating_context.clone(),
                        ),
                    },
                ));
            };

            let actual_sku =
                crate::db::sku::from_topology(txn, &mh_snapshot.host_snapshot.id).await?;
            let Some(expected_sku) = crate::db::sku::find(txn, &[sku_id.clone()]).await?.pop()
            else {
                return Err(StateHandlerError::MissingData {
                    object_id: sku_id,
                    missing: "Assigned SKU is missing",
                });
            };

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

                advance_to_machine_validating(txn, mh_snapshot, host_handler_params).await
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
            if mh_snapshot.host_snapshot.hw_sku.is_some() {
                advance_to_updating_inventory(txn, mh_snapshot).await
            } else {
                Ok(StateHandlerOutcome::DoNothing)
            }
        }
    }
}
