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
use ::rpc::forge::{self as rpc, GetMachineValidationExternalConfigResponse};
use carbide_machine_controller::config::machine_validation::{
    MachineValidationConfig, MachineValidationTestSelectionMode,
};
use carbide_uuid::machine_validation::{MachineValidationAttemptId, MachineValidationRunItemId};
use config_version::ConfigVersion;
use db::{self, machine_validation_suites};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    FailureCause, FailureDetails, FailureSource, MachineValidationContext, MachineValidationFilter,
    ManagedHostState, ValidationState,
};
use model::machine_validation::{
    MachineValidation, MachineValidationResult, MachineValidationState, MachineValidationStatus,
    MachineValidationTest as ModelMachineValidationTest,
    MachineValidationTestAddRequest as ModelTestAddRequest,
    MachineValidationTestUpdateRequest as ModelTestUpdateRequest,
    MachineValidationTestsGetRequest as ModelTestsGetRequest,
};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;
use crate::machine_validation::{
    MachineValidationCompleted, MachineValidationFailureCause, MachineValidationOutcome,
};

/// Temporary: when `true`, MV mutation handlers return `FailedPrecondition` and do not write to the DB.
///
/// **Why here and not only `internal_rbac_rules`?** Principal lists in `internal_rbac_rules` are
/// enforced only by `InternalRBACHandler`, which is **not** registered when
/// [`crate::cfg::file::CarbideConfig::bypass_rbac`] is `true` (see `crates/api/src/listener.rs`). In
/// that mode—common for local/dev—those rules never run, so tightening RBAC alone does not stop
/// clients from reaching these handlers and persisting. A check in the handler applies regardless
/// of `bypass_rbac`. Casbin may still apply separately; this guard is independent.
///
/// Remove or set `false` once add/update (and external-config update) paths are hardened.
const MACHINE_VALIDATION_MUTATION_NOOP: bool = true;

fn machine_validation_mutation_disabled_status() -> Status {
    Status::failed_precondition(
        "machine validation definition mutations are disabled until add/update paths are hardened",
    )
}

// machine has completed validation
pub(crate) async fn mark_machine_validation_complete(
    api: &Api,
    request: Request<rpc::MachineValidationCompletedRequest>,
) -> Result<Response<rpc::MachineValidationCompletedResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    // Extract and check
    let machine_id = convert_and_log_machine_id(req.machine_id.as_ref())?;

    // Extract and check UUID
    let Some(validation_id) = &req.validation_id else {
        return Err(CarbideError::MissingArgument("validation id").into());
    };

    let mut txn = api.txn_begin().await?;

    let machine = match db::machine::find_by_validation_id(&mut txn, validation_id).await? {
        Some(machine) => machine,
        None => {
            tracing::error!(machine_validation_id = %validation_id, "validation id not found");
            return Err(CarbideError::InvalidArgument("wrong validation ID".to_string()).into());
        }
    };

    if machine.id != machine_id {
        tracing::error!(machine_validation_id = %validation_id, machine_id = %machine_id, "Validation ID does not belong to provided Machine ID");
        return Err(CarbideError::InvalidArgument(
            "validation ID does not belong to provided machine ID".to_string(),
        )
        .into());
    }

    let mut state = MachineValidationState::Success;

    let machine_validation_error = req.machine_validation_error;
    if machine_validation_error.is_some() {
        state = MachineValidationState::Failed;
    }

    let validation_result_error =
        db::machine_validation_result::validate_current_context(&mut txn, validation_id).await?;
    if validation_result_error.is_some() {
        state = MachineValidationState::Failed;
    }

    let completed = db::machine_validation::mark_machine_validation_complete(
        &mut txn,
        &machine_id,
        validation_id,
        MachineValidationStatus {
            state,
            ..MachineValidationStatus::default()
        },
    )
    .await?;
    if !completed {
        tracing::info!(
            %machine_id,
            machine_validation_id = %validation_id,
            "machine validation completion ignored because run is no longer active"
        );
        txn.commit().await?;
        return Ok(Response::new(rpc::MachineValidationCompletedResponse {}));
    }

    // This call owns the run's active-to-terminal transition (checked above),
    // so it emits the run's one completion event -- after the commit below.
    let completion = completion_event(
        machine_id,
        *validation_id,
        machine_validation_error.as_deref(),
        validation_result_error.as_deref(),
    );

    if let Some(machine_validation_error) = machine_validation_error {
        db::machine::update_failure_details_by_machine_id(
            &machine_id,
            &mut txn,
            FailureDetails {
                cause: FailureCause::MachineValidation {
                    err: machine_validation_error.clone(),
                },
                failed_at: chrono::Utc::now(),
                source: FailureSource::Scout,
            },
        )
        .await?;

        // Update the Machine validation health report to include that the
        // validation failed
        let mut updated_validation_health_report = machine.machine_validation_health_report();
        updated_validation_health_report.observed_at = Some(chrono::Utc::now());
        updated_validation_health_report
            .alerts
            .push(health_report::HealthProbeAlert {
                // The shared cause vocabulary names this alert, so the label
                // and the alert id cannot drift apart.
                id: MachineValidationFailureCause::FailedValidationTestCompletion
                    .health_alert_id()
                    .expect("a failure cause always names its alert")
                    .parse()
                    .unwrap(),
                target: None,
                in_alert_since: Some(chrono::Utc::now()),
                message: format!(
                    "Validation test failed to run to completion:\n{machine_validation_error}"
                ),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_allocations(),
                ],
            });

        db::machine::update_machine_validation_health_report(
            &mut txn,
            &machine.id,
            &updated_validation_health_report,
        )
        .await?;
    }

    if let Some(error_message) = validation_result_error {
        db::machine::update_failure_details_by_machine_id(
            &machine_id,
            &mut txn,
            FailureDetails {
                cause: FailureCause::MachineValidation { err: error_message },
                failed_at: chrono::Utc::now(),
                source: FailureSource::Scout,
            },
        )
        .await?;
    }

    txn.commit().await?;

    carbide_instrument::emit(completion);
    Ok(Response::new(rpc::MachineValidationCompletedResponse {}))
}

/// The completion event for a run, from the two failure channels the handler
/// sees: a scout-reported run error means the run never completed its tests,
/// which takes precedence over a failed test found in the recorded results; a
/// run with neither passed. Both errors ride the log line when both are
/// present.
fn completion_event(
    machine_id: carbide_uuid::machine::MachineId,
    validation_id: carbide_uuid::machine_validation::MachineValidationId,
    machine_validation_error: Option<&str>,
    validation_result_error: Option<&str>,
) -> MachineValidationCompleted {
    let (outcome, cause) = match (machine_validation_error, validation_result_error) {
        (None, None) => (
            MachineValidationOutcome::Passed,
            MachineValidationFailureCause::None,
        ),
        (Some(_), _) => (
            MachineValidationOutcome::Failed,
            MachineValidationFailureCause::FailedValidationTestCompletion,
        ),
        (None, Some(_)) => (
            MachineValidationOutcome::Failed,
            MachineValidationFailureCause::FailedValidationTest,
        ),
    };
    let error = match (machine_validation_error, validation_result_error) {
        (Some(run_error), Some(test_error)) => format!("{run_error}; {test_error}"),
        (Some(error), None) | (None, Some(error)) => error.to_string(),
        (None, None) => String::new(),
    };
    MachineValidationCompleted {
        outcome,
        cause,
        machine_id,
        validation_id,
        error,
    }
}

pub(crate) async fn persist_validation_result(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationResultPostRequest>,
) -> Result<tonic::Response<()>, Status> {
    let Some(result) = request.into_inner().result else {
        return Err(CarbideError::InvalidArgument("validation result".to_string()).into());
    };

    let validation_result: MachineValidationResult = result.try_into()?;

    tracing::trace!(
        machine_validation_id = %validation_result.validation_id,
        "Received machine validation result"
    );

    let mut txn = api.txn_begin().await?;

    let machine = match db::machine::find_by_validation_id(
        &mut txn,
        &validation_result.validation_id,
    )
    .await?
    {
        Some(machine) => machine,
        None => {
            tracing::error!(machine_validation_id = %validation_result.validation_id, "validation id not found");
            return Err(CarbideError::InvalidArgument("wrong validation ID".to_string()).into());
        }
    };
    let machine_validation =
        db::machine_validation::find_by_id(&mut txn, &validation_result.validation_id).await?;
    if !db::machine_validation::is_active(&machine_validation) {
        tracing::info!(
            machine_validation_id = %validation_result.validation_id,
            machine_id = %machine.id,
            "machine validation result ignored because run is no longer active"
        );
        txn.commit().await?;
        return Ok(tonic::Response::new(()));
    }

    // Check state
    match machine.current_state() {
        ManagedHostState::Validation { validation_state } => {
            match validation_state {
                ValidationState::MachineValidation { .. } => {
                    tracing::info!(
                        machine_state = %machine.current_state(),
                        "Machine is in validation state",
                    );
                    //Continue to persist data
                }
            }
        }
        _ => {
            tracing::error!(
                machine_state = %machine.current_state(),
                "invalid host machine state",
            );
            return Err(
                CarbideError::InvalidArgument("wrong host machine state".to_string()).into(),
            );
        }
    }

    // Keep the durable run-item/attempt write ahead of the legacy projections.
    // A false return means this report is a replay of an already-terminal attempt.
    let first_terminal_report =
        db::machine_validation_execution::record_result(&mut txn, &validation_result).await?;
    if !first_terminal_report {
        tracing::info!(
            machine_validation_id = %validation_result.validation_id,
            machine_id = %machine.id,
            test_id = ?validation_result.test_id,
            "machine validation result ignored because attempt was already terminal"
        );
        txn.commit().await?;
        return Ok(tonic::Response::new(()));
    }

    // Update the Machine validation health report based on the result
    let mut updated_validation_health_report = machine.machine_validation_health_report();
    updated_validation_health_report.observed_at = Some(chrono::Utc::now());
    if validation_result.exit_code != 0 {
        updated_validation_health_report
            .alerts
            .push(health_report::HealthProbeAlert {
                id: "FailedValidationTest".parse().unwrap(),
                target: Some(validation_result.name.clone()),
                in_alert_since: Some(chrono::Utc::now()),
                message: format!(
                    "Failed validation test:\nName:{}\nCommand:{}\nArgs:{}",
                    validation_result.name, validation_result.command, validation_result.args
                ),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_allocations(),
                ],
            });
    }

    db::machine::update_machine_validation_health_report(
        &mut txn,
        &machine.id,
        &updated_validation_health_report,
    )
    .await?;

    db::machine_validation_result::create(validation_result, &mut txn).await?;
    txn.commit().await?;
    Ok(tonic::Response::new(()))
}

pub(crate) async fn get_machine_validation_results(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationGetRequest>,
) -> Result<tonic::Response<rpc::MachineValidationResultList>, Status> {
    log_request_data(&request);
    let req: rpc::MachineValidationGetRequest = request.into_inner();

    let machine_id = match req.machine_id {
        Some(id) => Some(convert_and_log_machine_id(Some(&id))?),
        None => None,
    };

    let validation_id = match req.validation_id {
        Some(id) => Some(id),
        None => {
            if machine_id.is_none() {
                return Err(CarbideError::MissingArgument(
                    "validation id or machine id is required",
                )
                .into());
            }
            None
        }
    };

    let mut db_reader = api.db_reader();
    let mut db_results: Vec<MachineValidationResult> = Vec::new();
    if let Some(machine_id) = machine_id.as_ref() {
        db_results = db::machine_validation_result::find_by_machine_id(
            &mut db_reader,
            machine_id,
            req.include_history,
        )
        .await?;

        if let Some(validation_id) = validation_id {
            db_results.retain(|x| x.validation_id == validation_id)
        }
    } else if let Some(validation_id) = validation_id {
        db_results = db::machine_validation_result::find_by_validation_id(
            &api.database_connection,
            &validation_id,
        )
        .await?;
    }

    let vec_rest = db_results
        .into_iter()
        .map(rpc::MachineValidationResult::from)
        .collect();

    Ok(tonic::Response::new(rpc::MachineValidationResultList {
        results: vec_rest,
    }))
}

pub(crate) async fn get_machine_validation_external_config(
    api: &Api,
    request: tonic::Request<rpc::GetMachineValidationExternalConfigRequest>,
) -> Result<tonic::Response<rpc::GetMachineValidationExternalConfigResponse>, Status> {
    log_request_data(&request);

    let req: rpc::GetMachineValidationExternalConfigRequest = request.into_inner();
    let ret =
        db::machine_validation_config::find_config_by_name(&api.database_connection, &req.name)
            .await?;

    Ok(tonic::Response::new(
        GetMachineValidationExternalConfigResponse {
            config: Some(rpc::MachineValidationExternalConfig::from(ret)),
        },
    ))
}

// The next three handlers share `MACHINE_VALIDATION_MUTATION_NOOP`. Handler no-op beats
// RBAC-only lockdown: `bypass_rbac` on `CarbideConfig` disables the internal RBAC layer entirely,
// so `internal_rbac_rules` are not consulted in that mode. Remove the no-op when safe.
pub(crate) async fn add_update_machine_validation_external_config(
    api: &Api,
    request: tonic::Request<rpc::AddUpdateMachineValidationExternalConfigRequest>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);
    if MACHINE_VALIDATION_MUTATION_NOOP {
        tracing::warn!("AddUpdateMachineValidationExternalConfig: rejecting mutation (no-op)");
        let _ = request.into_inner();
        return Err(machine_validation_mutation_disabled_status());
    }

    let mut txn = api.txn_begin().await?;

    let req: rpc::AddUpdateMachineValidationExternalConfigRequest = request.into_inner();

    let _ = db::machine_validation_config::create_or_update(
        &mut txn,
        &req.name,
        &req.description.unwrap_or_default(),
        &req.config,
    )
    .await;

    txn.commit().await?;
    Ok(tonic::Response::new(()))
}

pub(crate) async fn get_machine_validation_runs(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationRunListGetRequest>,
) -> Result<tonic::Response<rpc::MachineValidationRunList>, Status> {
    log_request_data(&request);
    let machine_validation_run_request: rpc::MachineValidationRunListGetRequest =
        request.into_inner();
    let mut db_reader = api.db_reader();
    let db_runs = match machine_validation_run_request.machine_id {
        Some(id) => {
            let machine_id = convert_and_log_machine_id(Some(&id))?;
            db::machine_validation::find(
                &mut db_reader,
                &machine_id,
                machine_validation_run_request.include_history,
            )
            .await
        }
        None => {
            tracing::info!("no machine ID");
            db::machine_validation::find_all(&api.database_connection).await
        }
    };
    let ret = db_runs
        .map(
            |runs: Vec<MachineValidation>| rpc::MachineValidationRunList {
                runs: runs
                    .into_iter()
                    .map(rpc::MachineValidationRun::from)
                    .collect(),
            },
        )
        .map(Response::new)?;

    Ok(ret)
}

pub(crate) async fn find_machine_validation_run_item_ids(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationRunItemSearchFilter>,
) -> Result<tonic::Response<rpc::MachineValidationRunItemIdList>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let validation_id = req
        .validation_id
        .as_ref()
        .ok_or(CarbideError::MissingArgument("validation id"))?;

    let mut db_reader = api.db_reader();
    let run_item_ids = db::machine_validation_execution::find_run_item_ids_by_run_id(
        &mut db_reader,
        validation_id,
    )
    .await?
    .into_iter()
    .map(|id| ::rpc::common::Uuid {
        value: id.to_string(),
    })
    .collect();

    Ok(tonic::Response::new(rpc::MachineValidationRunItemIdList {
        run_item_ids,
    }))
}

pub(crate) async fn find_machine_validation_run_items_by_ids(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationRunItemsByIdsRequest>,
) -> Result<tonic::Response<rpc::MachineValidationRunItemList>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if req.run_item_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} run_item_ids can be accepted"
        ))
        .into());
    } else if req.run_item_ids.is_empty() {
        return Err(CarbideError::InvalidArgument(
            "at least one run_item_id must be provided".to_string(),
        )
        .into());
    }

    let run_item_ids = req
        .run_item_ids
        .iter()
        .map(|id| {
            uuid::Uuid::try_from(id)
                .map(MachineValidationRunItemId::from)
                .map_err(CarbideError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut db_reader = api.db_reader();
    let run_items =
        db::machine_validation_execution::find_run_items_by_ids(&mut db_reader, &run_item_ids)
            .await?
            .into_iter()
            .map(rpc::MachineValidationRunItem::from)
            .collect();

    Ok(tonic::Response::new(rpc::MachineValidationRunItemList {
        run_items,
    }))
}

pub(crate) async fn get_machine_validation_attempt(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationAttemptGetRequest>,
) -> Result<tonic::Response<rpc::MachineValidationAttempt>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let attempt_id = req
        .attempt_id
        .as_ref()
        .ok_or(CarbideError::MissingArgument("attempt id"))?;
    let attempt_id = MachineValidationAttemptId::from(
        uuid::Uuid::try_from(attempt_id).map_err(CarbideError::from)?,
    );

    let attempt =
        db::machine_validation_execution::find_attempt_by_id(&api.database_connection, &attempt_id)
            .await?;

    Ok(tonic::Response::new(rpc::MachineValidationAttempt::from(
        attempt,
    )))
}

pub(crate) async fn heartbeat_machine_validation_run(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationHeartbeatRequest>,
) -> Result<tonic::Response<rpc::MachineValidationHeartbeatResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let validation_id = req
        .validation_id
        .as_ref()
        .ok_or(CarbideError::MissingArgument("validation id"))?;
    let mut test_id = None;
    let mut run_item_id = None;
    let mut attempt_id = None;
    match req.target {
        Some(rpc::machine_validation_heartbeat_request::Target::RunItemId(id)) => {
            run_item_id = Some(
                uuid::Uuid::try_from(&id)
                    .map(MachineValidationRunItemId::from)
                    .map_err(CarbideError::from)?,
            );
        }
        Some(rpc::machine_validation_heartbeat_request::Target::AttemptId(id)) => {
            attempt_id = Some(
                uuid::Uuid::try_from(&id)
                    .map(MachineValidationAttemptId::from)
                    .map_err(CarbideError::from)?,
            );
        }
        Some(rpc::machine_validation_heartbeat_request::Target::TestId(value)) => {
            test_id = Some(value);
        }
        None => {}
    }

    let mut txn = api.txn_begin().await?;
    let accepted = db::machine_validation_execution::record_heartbeat(
        &mut txn,
        validation_id,
        run_item_id.as_ref(),
        attempt_id.as_ref(),
        test_id.as_deref(),
        chrono::Utc::now(),
    )
    .await?;
    if accepted {
        txn.commit().await?;
    } else {
        txn.rollback().await?;
    }

    Ok(tonic::Response::new(
        rpc::MachineValidationHeartbeatResponse { accepted },
    ))
}

pub(crate) async fn on_demand_machine_validation(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationOnDemandRequest>,
) -> Result<tonic::Response<rpc::MachineValidationOnDemandResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let machine_id = convert_and_log_machine_id(req.machine_id.as_ref())?;

    match req.action() {
        rpc::machine_validation_on_demand_request::Action::Start => {
            let mut txn = api.txn_begin().await?;

            let machine = db::machine::find_one(
                &mut txn,
                &machine_id,
                MachineSearchConfig {
                    include_dpus: false,
                    ..MachineSearchConfig::default()
                },
            )
            .await?
            .ok_or_else(|| {
                CarbideError::InvalidArgument(format!("machine id {machine_id} not found"))
            })?;
            if machine
                .on_demand_machine_validation_request
                .unwrap_or_default()
            {
                let msg =
                    format!("On demand machine validation for {machine_id} is already scheduled.");
                tracing::error!(
                    %machine_id,
                    "On-demand machine validation is already scheduled"
                );
                return Err(CarbideError::InvalidArgument(msg).into());
            }
            // Check state
            match machine.current_state() {
                ManagedHostState::Ready | ManagedHostState::Failed { .. } => {
                    if machine
                        .on_demand_machine_validation_request
                        .unwrap_or(false)
                    {
                        // If triggere
                        let msg = format!(
                            "On demand machine validation for {machine_id} is already scheduled."
                        );
                        tracing::error!(
                            %machine_id,
                            "On-demand machine validation is already scheduled"
                        );
                        return Err(CarbideError::InvalidArgument(msg).into());
                    }
                    let allowed_tests: Vec<String> = req
                        .allowed_tests
                        .into_iter()
                        .map(|t| t.to_ascii_lowercase())
                        .collect();
                    let validation_id = db::machine_validation::create_new_run(
                        &mut txn,
                        &machine_id,
                        MachineValidationContext::OnDemand,
                        MachineValidationFilter {
                            tags: req.tags,
                            allowed_tests,
                            run_unverfied_tests: Some(req.run_unverfied_tests),
                            contexts: Some(req.contexts),
                        },
                    )
                    .await?;
                    tracing::trace!(
                        machine_validation_id = %validation_id,
                        "Created on-demand machine validation run"
                    );

                    // Update machine_validation_request.
                    db::machine::set_machine_validation_request(&mut txn, &machine_id, true)
                        .await?;

                    txn.commit().await?;

                    Ok(tonic::Response::new(
                        rpc::MachineValidationOnDemandResponse {
                            validation_id: Some(validation_id),
                        },
                    ))
                }
                _ => {
                    let msg = format!(
                        "On demand machine validation requires the machine to be in the {} state.  It is currently in state: {}",
                        ManagedHostState::Ready,
                        machine.current_state()
                    );
                    tracing::warn!(
                        %machine_id,
                        required_state = %ManagedHostState::Ready,
                        machine_state = %machine.current_state(),
                        "On-demand machine validation requires a different machine state"
                    );
                    Err(CarbideError::InvalidArgument(msg).into())
                }
            }
        }
        rpc::machine_validation_on_demand_request::Action::Stop => {
            Err(CarbideError::InvalidArgument(
                "cannot stop an on-demand validation request".to_string(),
            )
            .into())
        }
    }
}

pub(crate) async fn get_machine_validation_external_configs(
    api: &Api,
    request: tonic::Request<rpc::GetMachineValidationExternalConfigsRequest>,
) -> Result<tonic::Response<rpc::GetMachineValidationExternalConfigsResponse>, Status> {
    log_request_data(&request);

    let ret = db::machine_validation_config::find_configs(&api.database_connection).await?;
    Ok(tonic::Response::new(
        rpc::GetMachineValidationExternalConfigsResponse {
            configs: ret
                .into_iter()
                .map(rpc::MachineValidationExternalConfig::from)
                .collect(),
        },
    ))
}

pub(crate) async fn remove_machine_validation_external_config(
    api: &Api,
    request: tonic::Request<rpc::RemoveMachineValidationExternalConfigRequest>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let _ = db::machine_validation_config::remove_config(&mut txn, &req.name).await?;
    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

pub(crate) async fn update_machine_validation_test(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationTestUpdateRequest>,
) -> Result<tonic::Response<rpc::MachineValidationTestAddUpdateResponse>, Status> {
    log_request_data(&request);
    if MACHINE_VALIDATION_MUTATION_NOOP {
        tracing::warn!("UpdateMachineValidationTest: rejecting mutation (no-op)");
        let _ = request.into_inner();
        return Err(machine_validation_mutation_disabled_status());
    }

    let req = request.into_inner();
    let mut txn = api.txn_begin().await?;

    // let existing = machine_validation_suites::find(
    //     &mut txn,
    //     rpc::MachineValidationTestsGetRequest {
    //         test_id: Some(req.test_id.clone()),
    //         version: Some(req.version.clone()),
    //         ..rpc::MachineValidationTestsGetRequest::default()
    //     },
    // )
    // .await
    // .map_err(CarbideError::from)?;
    // if existing[0].read_only {
    //     return Err(Status::invalid_argument(
    //         "Cannot modify read-only test cases",
    //     ));
    // }
    let model_req: ModelTestUpdateRequest = req.clone().into();
    let test_id = machine_validation_suites::update(&mut txn, model_req).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(
        rpc::MachineValidationTestAddUpdateResponse {
            test_id,
            version: req.version,
        },
    ))
}

pub(crate) async fn add_machine_validation_test(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationTestAddRequest>,
) -> Result<tonic::Response<rpc::MachineValidationTestAddUpdateResponse>, Status> {
    log_request_data(&request);
    if MACHINE_VALIDATION_MUTATION_NOOP {
        tracing::warn!("AddMachineValidationTest: rejecting mutation (no-op)");
        let _ = request.into_inner();
        return Err(machine_validation_mutation_disabled_status());
    }

    let req = request.into_inner();
    let mut txn = api.txn_begin().await?;

    let model_req: ModelTestAddRequest = req.into();
    let tests = machine_validation_suites::find(
        &mut txn,
        ModelTestsGetRequest {
            test_id: Some(machine_validation_suites::generate_test_id(&model_req.name)),
            ..ModelTestsGetRequest::default()
        },
    )
    .await?;
    if !tests.is_empty() {
        return Err(CarbideError::InvalidArgument("name already exists".to_string()).into());
    }
    let version = ConfigVersion::initial();
    let test_id = machine_validation_suites::save(&mut txn, model_req, version).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(
        rpc::MachineValidationTestAddUpdateResponse {
            test_id,
            version: version.version_string(),
        },
    ))
}

pub(crate) async fn get_machine_validation_tests(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationTestsGetRequest>,
) -> Result<tonic::Response<rpc::MachineValidationTestsGetResponse>, Status> {
    log_request_data(&request);
    let req: ModelTestsGetRequest = request.into_inner().into();

    let tests = machine_validation_suites::find(&api.database_connection, req).await?;

    Ok(tonic::Response::new(
        rpc::MachineValidationTestsGetResponse {
            tests: tests
                .into_iter()
                .map(rpc::MachineValidationTest::from)
                .collect(),
        },
    ))
}

pub(crate) async fn machine_validation_test_verfied(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationTestVerfiedRequest>,
) -> Result<tonic::Response<rpc::MachineValidationTestVerfiedResponse>, Status> {
    let req = request.into_inner();
    let mut txn = api.txn_begin().await?;

    let existing = machine_validation_suites::find(
        &mut txn,
        ModelTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            version: Some(req.version.clone()),
            ..ModelTestsGetRequest::default()
        },
    )
    .await?;
    let _ = machine_validation_suites::mark_verified(&mut txn, req.test_id, existing[0].version)
        .await?;

    txn.commit().await?;

    Ok(tonic::Response::new(
        rpc::MachineValidationTestVerfiedResponse {
            message: "Success".to_string(),
        },
    ))
}
pub(crate) async fn machine_validation_test_next_version(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationTestNextVersionRequest>,
) -> Result<tonic::Response<rpc::MachineValidationTestNextVersionResponse>, Status> {
    let req = request.into_inner();
    let mut txn = api.txn_begin().await?;

    let existing = machine_validation_suites::find(
        &mut txn,
        ModelTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            ..ModelTestsGetRequest::default()
        },
    )
    .await?;
    let (test_id, next_version) = machine_validation_suites::clone(&mut txn, &existing[0]).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(
        rpc::MachineValidationTestNextVersionResponse {
            test_id,
            version: next_version.version_string(),
        },
    ))
}

pub(crate) async fn machine_validation_test_enable_disable_test(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationTestEnableDisableTestRequest>,
) -> Result<tonic::Response<rpc::MachineValidationTestEnableDisableTestResponse>, Status> {
    let req = request.into_inner();
    let mut txn = api.txn_begin().await?;

    let existing = machine_validation_suites::find(
        &mut txn,
        ModelTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            version: Some(req.version.clone()),
            ..ModelTestsGetRequest::default()
        },
    )
    .await?;
    let _ = machine_validation_suites::enable_disable(
        &mut txn,
        req.test_id,
        existing[0].version,
        req.is_enabled,
        existing[0].verified,
    )
    .await?;

    txn.commit().await?;

    Ok(tonic::Response::new(
        rpc::MachineValidationTestEnableDisableTestResponse {
            message: "Success".to_string(),
        },
    ))
}

pub(crate) async fn update_machine_validation_run(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationRunRequest>,
) -> Result<tonic::Response<rpc::MachineValidationRunResponse>, Status> {
    let req = request.into_inner();
    let mut txn = api.txn_begin().await?;

    let validation_id = req
        .validation_id
        .ok_or(CarbideError::MissingArgument("validation id"))?;
    let selected_tests = req
        .selected_tests
        .into_iter()
        .map(ModelMachineValidationTest::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let total = req
        .total
        .try_into()
        .map_err(|_e| CarbideError::InvalidArgument("total".to_string()))?;
    let total_len =
        usize::try_from(total).map_err(|_e| CarbideError::InvalidArgument("total".to_string()))?;

    if !selected_tests.is_empty() && total_len != selected_tests.len() {
        return Err(CarbideError::InvalidArgument(
            "total must match selected_tests length".to_string(),
        )
        .into());
    }

    db::machine_validation::update_run(
        &mut txn,
        &validation_id,
        total,
        req.duration_to_complete.unwrap_or_default().seconds,
    )
    .await?;

    if !selected_tests.is_empty() {
        let machine_validation =
            db::machine_validation::find_by_id(&mut txn, &validation_id).await?;
        db::machine_validation_execution::materialize_run_plan(
            &mut txn,
            &validation_id,
            machine_validation.context.as_deref().unwrap_or_default(),
            &selected_tests,
        )
        .await?;
    }

    txn.commit().await?;

    Ok(tonic::Response::new(rpc::MachineValidationRunResponse {
        message: "Success".to_string(),
    }))
}

pub async fn apply_config_on_startup(
    api: &Api,
    config: &MachineValidationConfig,
) -> Result<(), CarbideError> {
    let mut txn = api.txn_begin().await?;

    // Get all tests from DB
    let tests = machine_validation_suites::find(&mut txn, ModelTestsGetRequest::default()).await?;

    // Create a set of test IDs from config for efficient lookup
    let config_test_ids: std::collections::HashSet<_> =
        config.tests.iter().map(|t| &t.id).collect();

    match config.test_selection_mode {
        // Only update tests specified in tests config
        MachineValidationTestSelectionMode::Default => {
            // Only update tests specified in config
            for test_config in &config.tests {
                if let Some(test) = tests.iter().find(|t| t.test_id == test_config.id) {
                    tracing::info!(
                        test_id = %test.test_id,
                        enable = test_config.enable,
                        "Updating test to state from config",
                    );

                    machine_validation_suites::enable_disable(
                        &mut txn,
                        test.test_id.clone(),
                        test.version,
                        test_config.enable,
                        test.verified,
                    )
                    .await?;
                }
            }
        }
        // Enables all tests in DB, but allows config overrides
        MachineValidationTestSelectionMode::EnableAll => {
            // First enable all tests
            for test in &tests {
                let should_override = config_test_ids.contains(&test.test_id);
                let enable_state = if should_override {
                    // If test is in config, use config's enable state
                    config
                        .tests
                        .iter()
                        .find(|t| t.id == test.test_id)
                        .map(|t| t.enable)
                        .unwrap_or(true)
                } else {
                    // If test is not in config, enable it
                    true
                };

                tracing::info!(
                    test_id = %test.test_id,
                    test_enable_state = enable_state,
                    "Setting test to state (EnableAll mode)",
                );

                machine_validation_suites::enable_disable(
                    &mut txn,
                    test.test_id.clone(),
                    test.version,
                    enable_state,
                    test.verified,
                )
                .await?;
            }
        }
        // Disables all tests in DB, but allows config overrides
        MachineValidationTestSelectionMode::DisableAll => {
            // First disable all tests
            for test in &tests {
                let should_override = config_test_ids.contains(&test.test_id);
                let enable_state = if should_override {
                    // If test is in config, use config's enable state
                    config
                        .tests
                        .iter()
                        .find(|t| t.id == test.test_id)
                        .map(|t| t.enable)
                        .unwrap_or(false)
                } else {
                    // If test is not in config, disable it
                    false
                };

                tracing::info!(
                    test_id = %test.test_id,
                    test_enable_state = enable_state,
                    "Setting test to state (DisableAll mode)",
                );

                machine_validation_suites::enable_disable(
                    &mut txn,
                    test.test_id.clone(),
                    test.version,
                    enable_state,
                    test.verified,
                )
                .await?;
            }
        }
    }

    txn.commit().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    /// The handler's two failure channels map onto the bounded cause
    /// vocabulary: the scout-reported run error outranks a failed test found
    /// in the recorded results, and the error context keeps both texts when
    /// both are present.
    #[test]
    fn completion_event_maps_error_channels_to_outcome_and_cause() {
        struct Case {
            scenario: &'static str,
            machine_validation_error: Option<&'static str>,
            validation_result_error: Option<&'static str>,
            expect_outcome: MachineValidationOutcome,
            expect_cause: MachineValidationFailureCause,
            expect_error: &'static str,
        }

        let cases = [
            Case {
                scenario: "no errors passes",
                machine_validation_error: None,
                validation_result_error: None,
                expect_outcome: MachineValidationOutcome::Passed,
                expect_cause: MachineValidationFailureCause::None,
                expect_error: "",
            },
            Case {
                scenario: "scout-reported run error",
                machine_validation_error: Some("scout died"),
                validation_result_error: None,
                expect_outcome: MachineValidationOutcome::Failed,
                expect_cause: MachineValidationFailureCause::FailedValidationTestCompletion,
                expect_error: "scout died",
            },
            Case {
                scenario: "failed test in the recorded results",
                machine_validation_error: None,
                validation_result_error: Some("test exited 1"),
                expect_outcome: MachineValidationOutcome::Failed,
                expect_cause: MachineValidationFailureCause::FailedValidationTest,
                expect_error: "test exited 1",
            },
            Case {
                scenario: "run error outranks a failed test; both errors kept",
                machine_validation_error: Some("scout died"),
                validation_result_error: Some("test exited 1"),
                expect_outcome: MachineValidationOutcome::Failed,
                expect_cause: MachineValidationFailureCause::FailedValidationTestCompletion,
                expect_error: "scout died; test exited 1",
            },
        ];

        let machine_id = carbide_uuid::machine::MachineId::from_str(
            "fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30",
        )
        .expect("a valid machine id");
        let validation_id = carbide_uuid::machine_validation::MachineValidationId::new();

        for case in cases {
            let event = completion_event(
                machine_id,
                validation_id,
                case.machine_validation_error,
                case.validation_result_error,
            );
            assert_eq!(event.outcome, case.expect_outcome, "{}", case.scenario);
            assert_eq!(event.cause, case.expect_cause, "{}", case.scenario);
            assert_eq!(event.machine_id, machine_id, "{}", case.scenario);
            assert_eq!(event.validation_id, validation_id, "{}", case.scenario);
            assert_eq!(event.error, case.expect_error, "{}", case.scenario);
        }
    }
}
