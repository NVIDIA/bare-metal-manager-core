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
use config_version::ConfigVersion;
use db::{self, WithTransaction, machine_validation_suites};
use futures_util::FutureExt;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    FailureCause, FailureDetails, FailureSource, MachineValidationFilter, ManagedHostState,
    ValidationState,
};
use model::machine_validation::{
    MachineValidation, MachineValidationResult, MachineValidationState, MachineValidationStatus,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::cfg::file::{MachineValidationConfig, MachineValidationTestSelectionMode};
use crate::handlers::utils::convert_and_log_machine_id;

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
    let Some(rpc_id) = &req.validation_id else {
        return Err(CarbideError::MissingArgument("validation id").into());
    };
    let uuid = Uuid::try_from(rpc_id).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    let machine = match db::machine::find_by_validation_id(&mut txn, &uuid).await? {
        Some(machine) => machine,
        None => {
            tracing::error!(%uuid, "validation id not found");
            return Err(Status::invalid_argument("wrong validation ID"));
        }
    };

    if machine.id != machine_id {
        tracing::error!(validation_id = %uuid, machine_id = %machine_id, "Validation ID does not belong to provided Machine ID");
        return Err(Status::invalid_argument(
            "Validation ID does not belong to provided Machine ID",
        ));
    }

    let mut state = MachineValidationState::Success;

    let machine_validation_results = match req.machine_validation_error {
        Some(machine_validation_error) => {
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
            let mut updated_validation_health_report =
                machine.machine_validation_health_report.clone();
            updated_validation_health_report.observed_at = Some(chrono::Utc::now());
            updated_validation_health_report
                .alerts
                .push(health_report::HealthProbeAlert {
                    id: "FailedValidationTestCompletion".parse().unwrap(),
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
            state = MachineValidationState::Failed;
            machine_validation_error
        }
        None => "Success".to_owned(),
    };

    let result =
        match db::machine_validation_result::validate_current_context(&mut txn, rpc_id).await? {
            Some(error_message) => {
                db::machine::update_failure_details_by_machine_id(
                    &machine_id,
                    &mut txn,
                    FailureDetails {
                        cause: FailureCause::MachineValidation {
                            err: error_message.clone(),
                        },
                        failed_at: chrono::Utc::now(),
                        source: FailureSource::Scout,
                    },
                )
                .await?;
                state = MachineValidationState::Failed;
                error_message
            }
            None => "Success".to_owned(),
        };

    db::machine_validation::mark_machine_validation_complete(
        &mut txn,
        &machine_id,
        &uuid,
        MachineValidationStatus {
            state,
            ..MachineValidationStatus::default()
        },
    )
    .await?;
    txn.commit().await?;

    tracing::info!(
        %machine_id,
        result, "machine_validation_completed:machine_validation_results",
    );
    tracing::info!(
        %machine_id,
        machine_validation_results, "machine_validation_completed",
    );
    Ok(Response::new(rpc::MachineValidationCompletedResponse {}))
}

pub(crate) async fn persist_validation_result(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationResultPostRequest>,
) -> Result<tonic::Response<()>, Status> {
    let Some(result) = request.into_inner().result else {
        return Err(CarbideError::InvalidArgument("Validation Result".to_string()).into());
    };

    let validation_result: MachineValidationResult = result.try_into()?;

    tracing::trace!(validation_id = %validation_result.validation_id);

    let mut txn = api.txn_begin().await?;

    let machine =
        match db::machine::find_by_validation_id(&mut txn, &validation_result.validation_id).await?
        {
            Some(machine) => machine,
            None => {
                tracing::error!(%validation_result.validation_id, "validation id not found");
                return Err(Status::invalid_argument("wrong validation ID"));
            }
        };
    // Check state
    match machine.current_state() {
        ManagedHostState::Validation { validation_state } => {
            match validation_state {
                ValidationState::MachineValidation { .. } => {
                    tracing::info!("machine state is  {}", machine.current_state());
                    //Continue to persist data
                }
            }
        }
        _ => {
            tracing::error!("invalid host machine state {}", machine.current_state());
            return Err(Status::invalid_argument("wrong host machine state"));
        }
    }

    // Update the Machine validation health report based on the result
    let mut updated_validation_health_report = machine.machine_validation_health_report.clone();
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
    txn.commit().await.unwrap();
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
        Some(id) => Some(Uuid::try_from(id).map_err(CarbideError::from)?),
        None => {
            if machine_id.is_none() {
                return Err(CarbideError::MissingArgument(
                    "Validation id or Machine id is required",
                )
                .into());
            }
            None
        }
    };

    let mut txn = api.txn_begin().await?;

    let mut db_results: Vec<MachineValidationResult> = Vec::new();
    if let Some(machine_id) = machine_id.as_ref() {
        db_results = db::machine_validation_result::find_by_machine_id(
            &mut txn,
            machine_id,
            req.include_history,
        )
        .await?;

        if let Some(validation_id) = validation_id {
            db_results.retain(|x| x.validation_id == validation_id)
        }
    } else if let Some(validation_id) = validation_id {
        db_results =
            db::machine_validation_result::find_by_validation_id(&mut txn, &validation_id).await?;
    }

    let vec_rest = db_results
        .into_iter()
        .map(rpc::MachineValidationResult::from)
        .collect();

    txn.commit().await?;

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
    let ret = api
        .with_txn(|txn| db::machine_validation_config::find_config_by_name(txn, &req.name).boxed())
        .await??;

    Ok(tonic::Response::new(
        GetMachineValidationExternalConfigResponse {
            config: Some(rpc::MachineValidationExternalConfig::from(ret)),
        },
    ))
}

pub(crate) async fn add_update_machine_validation_external_config(
    api: &Api,
    request: tonic::Request<rpc::AddUpdateMachineValidationExternalConfigRequest>,
) -> Result<tonic::Response<()>, Status> {
    log_request_data(&request);

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
    let mut txn = api.txn_begin().await?;

    let db_runs = match machine_validation_run_request.machine_id {
        Some(id) => {
            let machine_id = convert_and_log_machine_id(Some(&id))?;
            db::machine_validation::find(
                &mut txn,
                &machine_id,
                machine_validation_run_request.include_history,
            )
            .await
        }
        None => {
            tracing::info!("no machine ID");
            db::machine_validation::find_all(&mut txn).await
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

    txn.commit().await?;
    Ok(ret)
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
                Status::invalid_argument(format!("Machine id {machine_id} not found."))
            })?;
            if machine
                .on_demand_machine_validation_request
                .unwrap_or_default()
            {
                let msg =
                    format!("On demand machine validation for {machine_id} is already scheduled.");
                tracing::error!(msg);
                return Err(Status::invalid_argument(msg));
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
                        tracing::error!(msg);
                        return Err(Status::invalid_argument(msg));
                    }
                    let validation_id = db::machine_validation::create_new_run(
                        &mut txn,
                        &machine_id,
                        "OnDemand".to_string(),
                        MachineValidationFilter {
                            tags: req.tags,
                            allowed_tests: req.allowed_tests,
                            run_unverfied_tests: Some(req.run_unverfied_tests),
                            contexts: Some(req.contexts),
                        },
                    )
                    .await?;
                    tracing::trace!(validation_id = %validation_id);

                    // Update machine_validation_request.
                    db::machine::set_machine_validation_request(&mut txn, &machine_id, true)
                        .await?;

                    txn.commit().await?;

                    Ok(tonic::Response::new(
                        rpc::MachineValidationOnDemandResponse {
                            validation_id: Some(validation_id.into()),
                        },
                    ))
                }
                _ => {
                    let msg = format!(
                        "On demand machine validation requires the machine to be in the {} state.  It is currently in state: {}",
                        ManagedHostState::Ready,
                        machine.current_state()
                    );
                    tracing::warn!(msg);
                    Err(Status::invalid_argument(msg))
                }
            }
        }
        rpc::machine_validation_on_demand_request::Action::Stop => Err(Status::invalid_argument(
            "Cannot stop an on-demand validation request",
        )),
    }
}

pub(crate) async fn get_machine_validation_external_configs(
    api: &Api,
    request: tonic::Request<rpc::GetMachineValidationExternalConfigsRequest>,
) -> Result<tonic::Response<rpc::GetMachineValidationExternalConfigsResponse>, Status> {
    log_request_data(&request);

    let ret = api
        .with_txn(|txn| db::machine_validation_config::find_configs(txn).boxed())
        .await??;
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
    txn.commit().await.unwrap();

    Ok(tonic::Response::new(()))
}

pub(crate) async fn update_machine_validation_test(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationTestUpdateRequest>,
) -> Result<tonic::Response<rpc::MachineValidationTestAddUpdateResponse>, Status> {
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
    let test_id = machine_validation_suites::update(&mut txn, req.clone()).await?;

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
    let req = request.into_inner();
    let mut txn = api.txn_begin().await?;

    let tests = machine_validation_suites::find(
        &mut txn,
        rpc::MachineValidationTestsGetRequest {
            test_id: Some(machine_validation_suites::generate_test_id(&req.name)),
            ..rpc::MachineValidationTestsGetRequest::default()
        },
    )
    .await?;
    if !tests.is_empty() {
        return Err(Status::invalid_argument("Name already exists"));
    }
    let version = ConfigVersion::initial();
    let test_id = machine_validation_suites::save(&mut txn, req, version).await?;

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
    let req = request.into_inner();

    let tests = api
        .with_txn(|txn| machine_validation_suites::find(txn, req).boxed())
        .await??;

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
        rpc::MachineValidationTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            version: Some(req.version.clone()),
            ..rpc::MachineValidationTestsGetRequest::default()
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
        rpc::MachineValidationTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            ..rpc::MachineValidationTestsGetRequest::default()
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
        rpc::MachineValidationTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            version: Some(req.version.clone()),
            ..rpc::MachineValidationTestsGetRequest::default()
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

    let validation_id = match req.validation_id {
        Some(id) => Uuid::try_from(id).map_err(CarbideError::from)?,
        None => {
            return Err(CarbideError::MissingArgument("Validation id").into());
        }
    };

    db::machine_validation::update_run(
        &mut txn,
        &validation_id,
        req.total
            .try_into()
            .map_err(|_e| Status::invalid_argument("total"))?,
        req.duration_to_complete.unwrap_or_default().seconds,
    )
    .await?;

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
    let tests =
        machine_validation_suites::find(&mut txn, rpc::MachineValidationTestsGetRequest::default())
            .await?;

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
                        "Updating test '{}' to state {} from config",
                        test.test_id,
                        test_config.enable
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
                    "Setting test '{}' to state {} (EnableAll mode)",
                    test.test_id,
                    enable_state
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
                    "Setting test '{}' to state {} (DisableAll mode)",
                    test.test_id,
                    enable_state
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
