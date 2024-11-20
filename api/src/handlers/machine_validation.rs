/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use crate::{
    api::{log_machine_id, log_request_data, Api},
    db::{
        machine::{Machine, MachineSearchConfig},
        machine_validation::{
            MachineValidation, MachineValidationResult, MachineValidationState,
            MachineValidationStatus,
        },
        machine_validation_config::MachineValidationExternalConfig,
        machine_validation_suites, DatabaseError,
    },
    model::machine::{
        machine_id::try_parse_machine_id, FailureCause, FailureDetails, FailureSource,
        MachineState, MachineValidationFilter, ManagedHostState,
    },
    CarbideError,
};
use ::rpc::forge::{self as rpc, GetMachineValidationExternalConfigResponse};
use config_version::ConfigVersion;
use tonic::{Request, Response, Status};
use uuid::Uuid;

// machine has completed validation
pub(crate) async fn mark_machine_validation_complete(
    api: &Api,
    request: Request<rpc::MachineValidationCompletedRequest>,
) -> Result<Response<rpc::MachineValidationCompletedResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    // Extract and check
    let machine_id = match &req.machine_id {
        Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
        None => {
            return Err(Status::invalid_argument("A machine UUID is required"));
        }
    };
    log_machine_id(&machine_id);

    // Extract and check UUID
    let Some(rpc_id) = &req.validation_id else {
        return Err(CarbideError::MissingArgument("validation id").into());
    };
    let uuid = Uuid::try_from(rpc_id).map_err(CarbideError::from)?;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin find_instance_by_machine_id",
            e,
        ))
    })?;

    let machine = match Machine::find_by_validation_id(&mut txn, &uuid)
        .await
        .map_err(CarbideError::from)?
    {
        Some(machine) => machine,
        None => {
            tracing::error!(%uuid, "validation id not found");
            return Err(Status::invalid_argument("wrong validation ID"));
        }
    };

    if *machine.id() != machine_id {
        tracing::error!(validation_id = %uuid, machine_id = %machine_id, "Validation ID does not belong to provided Machine ID");
        return Err(Status::invalid_argument(
            "Validation ID does not belong to provided Machine ID",
        ));
    }
    MachineValidation::mark_machine_validation_complete(
        &mut txn,
        &machine_id,
        &uuid,
        MachineValidationStatus {
            state: MachineValidationState::Success,
            ..MachineValidationStatus::default()
        },
    )
    .await
    .map_err(CarbideError::from)?;
    let machine_validation_results = match req.machine_validation_error {
        Some(machine_validation_error) => {
            Machine::update_failure_details_by_machine_id(
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
            .await
            .map_err(CarbideError::from)?;

            // Update the Machine validation health report to include that the
            // validation failed
            let mut updated_validation_health_report =
                machine.machine_validation_health_report().clone();
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

            Machine::update_machine_validation_health_report(
                &mut txn,
                machine.id(),
                &updated_validation_health_report,
            )
            .await
            .map_err(CarbideError::from)?;

            machine_validation_error
        }
        None => "Success".to_owned(),
    };

    let result = match MachineValidationResult::validate_current_context(&mut txn, rpc_id).await? {
        Some(error_message) => {
            Machine::update_failure_details_by_machine_id(
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
            .await
            .map_err(CarbideError::from)?;
            error_message
        }
        None => "Success".to_owned(),
    };
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit machine_validation_completed",
            e,
        ))
    })?;

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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin set_machine_validation_results ",
            e,
        ))
    })?;
    let machine = match Machine::find_by_validation_id(&mut txn, &validation_result.validation_id)
        .await
        .map_err(CarbideError::from)?
    {
        Some(machine) => machine,
        None => {
            tracing::error!(%validation_result.validation_id, "validation id not found");
            return Err(Status::invalid_argument("wrong validation ID"));
        }
    };
    // Check state
    match machine.current_state() {
        ManagedHostState::HostInit { machine_state } => {
            match machine_state {
                MachineState::MachineValidating { .. } => {
                    tracing::info!("machine state is  {}", machine.current_state());
                    //Continue to persist data
                }
                _ => {
                    tracing::error!("invalid machine state {}", machine.current_state());
                    return Err(Status::invalid_argument("wrong machine state"));
                }
            }
        }
        _ => {
            tracing::error!("invalid host machine state {}", machine.current_state());
            return Err(Status::invalid_argument("wrong host machine state"));
        }
    }

    // Update the Machine validation health report based on the result
    let mut updated_validation_health_report = machine.machine_validation_health_report().clone();
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

    Machine::update_machine_validation_health_report(
        &mut txn,
        machine.id(),
        &updated_validation_health_report,
    )
    .await
    .map_err(CarbideError::from)?;

    validation_result.create(&mut txn).await?;
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
        Some(id) => Some(try_parse_machine_id(&id).map_err(CarbideError::from)?),
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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_machine_validation_results ",
            e,
        ))
    })?;
    let mut db_results: Vec<MachineValidationResult> = Vec::new();
    if machine_id.is_some() {
        db_results = MachineValidationResult::find_by_machine_id(
            &mut txn,
            &machine_id.unwrap(),
            req.include_history,
        )
        .await?;

        if validation_id.is_some() {
            db_results.retain(|x| x.validation_id == validation_id.unwrap_or_default())
        }
    }
    if validation_id.is_some() {
        db_results =
            MachineValidationResult::find_by_validation_id(&mut txn, &validation_id.unwrap())
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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_machine_validation_external_config ",
            e,
        ))
    })?;
    let req: rpc::GetMachineValidationExternalConfigRequest = request.into_inner();
    let ret = MachineValidationExternalConfig::find_config_by_name(&mut txn, &req.name).await?;

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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin add_update_machine_validation_external_config ",
            e,
        ))
    })?;
    let req: rpc::AddUpdateMachineValidationExternalConfigRequest = request.into_inner();

    let _ = MachineValidationExternalConfig::create_or_update(
        &mut txn,
        &req.name,
        &req.description.unwrap_or_default(),
        &req.config,
    )
    .await;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit add_update_machine_validation_external_config",
            e,
        ))
    })?;
    Ok(tonic::Response::new(()))
}

pub(crate) async fn get_machine_validation_runs(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationRunListGetRequest>,
) -> Result<tonic::Response<rpc::MachineValidationRunList>, Status> {
    log_request_data(&request);
    let machine_validation_run_request: rpc::MachineValidationRunListGetRequest =
        request.into_inner();
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_machine_validation_run ",
            e,
        ))
    })?;
    let db_runs = match machine_validation_run_request.machine_id {
        Some(id) => {
            let machine_id = try_parse_machine_id(&id).map_err(CarbideError::from)?;
            log_machine_id(&machine_id);
            MachineValidation::find(
                &mut txn,
                &machine_id,
                machine_validation_run_request.include_history,
            )
            .await
        }
        None => {
            tracing::info!("no machine ID");
            MachineValidation::find_all(&mut txn).await
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
        .map(Response::new)
        .map_err(CarbideError::from)?;
    Ok(ret)
}

pub(crate) async fn on_demand_machine_validation(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationOnDemandRequest>,
) -> Result<tonic::Response<rpc::MachineValidationOnDemandResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    // Extract and check
    let machine_id = match &req.machine_id {
        Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
        None => {
            return Err(Status::invalid_argument("A machine id is required"));
        }
    };
    log_machine_id(&machine_id);

    match req.action() {
        rpc::machine_validation_on_demand_request::Action::Start => {
            let mut txn = api.database_connection.begin().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "begin  on_demand_machine_validation",
                    e,
                ))
            })?;
            let machine = Machine::find_one(
                &mut txn,
                &machine_id,
                MachineSearchConfig {
                    include_dpus: false,
                    ..MachineSearchConfig::default()
                },
            )
            .await
            .map_err(CarbideError::from)?
            .ok_or_else(|| {
                Status::invalid_argument(format!("Machine id {machine_id} not found."))
            })?;
            // Check state
            match machine.current_state() {
                ManagedHostState::Ready | ManagedHostState::Failed { .. } => {
                    let validation_id = MachineValidation::create_new_run(
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
                    .await
                    .map_err(CarbideError::from)?;
                    tracing::trace!(validation_id = %validation_id);

                    // Update machine_validation_request.
                    Machine::set_machine_validation_request(&mut txn, &machine_id, true)
                        .await
                        .map_err(CarbideError::from)?;

                    txn.commit().await.map_err(|e| {
                        CarbideError::from(DatabaseError::new(
                            file!(),
                            line!(),
                            "commit  on_demand_machine_validation",
                            e,
                        ))
                    })?;
                    Ok(tonic::Response::new(
                        rpc::MachineValidationOnDemandResponse {
                            validation_id: Some(validation_id.into()),
                        },
                    ))
                }
                _ => {
                    let msg = format!("On demand machine validation requires the machine to be in the {} state.  It is currently in state: {}", ManagedHostState::Ready, machine.current_state());
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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_machine_validation_external_configs ",
            e,
        ))
    })?;
    let ret = MachineValidationExternalConfig::find_configs(&mut txn).await?;
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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin remove_machine_validation_external_config ",
            e,
        ))
    })?;

    let _ = MachineValidationExternalConfig::remove_config(&mut txn, &req.name).await?;
    txn.commit().await.unwrap();

    Ok(tonic::Response::new(()))
}

pub(crate) async fn update_machine_validation_test(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationTestUpdateRequest>,
) -> Result<tonic::Response<rpc::MachineValidationTestAddUpdateResponse>, Status> {
    let req = request.into_inner();
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin  update_machine_validation_test",
            e,
        ))
    })?;

    let existing = machine_validation_suites::MachineValidationTest::find(
        &mut txn,
        rpc::MachineValidationTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            version: Some(req.version.clone()),
            ..rpc::MachineValidationTestsGetRequest::default()
        },
    )
    .await
    .map_err(CarbideError::from)?;
    if existing[0].read_only {
        return Err(Status::invalid_argument(
            "Cannot modify read-only test cases",
        ));
    }
    let test_id = machine_validation_suites::MachineValidationTest::update(&mut txn, req.clone())
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_machine_validation_test",
            e,
        ))
    })?;

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
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin  add_machine_validation_test",
            e,
        ))
    })?;
    let version = ConfigVersion::initial();
    let test_id = machine_validation_suites::MachineValidationTest::save(&mut txn, req, version)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit add_machine_validation_test",
            e,
        ))
    })?;

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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_machine_validation_tests ",
            e,
        ))
    })?;
    let tests = machine_validation_suites::MachineValidationTest::find(&mut txn, req)
        .await
        .map_err(CarbideError::from)?;

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
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin  update_machine_validation_test",
            e,
        ))
    })?;

    let existing = machine_validation_suites::MachineValidationTest::find(
        &mut txn,
        rpc::MachineValidationTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            version: Some(req.version.clone()),
            ..rpc::MachineValidationTestsGetRequest::default()
        },
    )
    .await
    .map_err(CarbideError::from)?;
    let _ = machine_validation_suites::MachineValidationTest::mark_verified(
        &mut txn,
        req.test_id,
        existing[0].version,
    )
    .await
    .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit machine_validation_test_verfied",
            e,
        ))
    })?;

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
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin  machine_validation_test_next_version",
            e,
        ))
    })?;

    let existing = machine_validation_suites::MachineValidationTest::find(
        &mut txn,
        rpc::MachineValidationTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            ..rpc::MachineValidationTestsGetRequest::default()
        },
    )
    .await
    .map_err(CarbideError::from)?;
    let (test_id, next_version) =
        machine_validation_suites::MachineValidationTest::clone(&mut txn, &existing[0])
            .await
            .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit machine_validation_test_next_version",
            e,
        ))
    })?;

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
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin  machine_validation_test_enable_disable_test",
            e,
        ))
    })?;

    let existing = machine_validation_suites::MachineValidationTest::find(
        &mut txn,
        rpc::MachineValidationTestsGetRequest {
            test_id: Some(req.test_id.clone()),
            version: Some(req.version.clone()),
            ..rpc::MachineValidationTestsGetRequest::default()
        },
    )
    .await
    .map_err(CarbideError::from)?;
    let _ = machine_validation_suites::MachineValidationTest::enabled_diable(
        &mut txn,
        req.test_id,
        existing[0].version,
        req.is_enabled,
    )
    .await
    .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit machine_validation_test_enable_disable_test",
            e,
        ))
    })?;

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
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin  update_machine_validation_run",
            e,
        ))
    })?;

    let validation_id = match req.validation_id {
        Some(id) => Uuid::try_from(id).map_err(CarbideError::from)?,
        None => {
            return Err(CarbideError::MissingArgument("Validation id").into());
        }
    };

    MachineValidation::update_run(
        &mut txn,
        &validation_id,
        req.total
            .try_into()
            .map_err(|_e| Status::invalid_argument("total"))?,
        req.duration_to_complete.unwrap_or_default().seconds,
    )
    .await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_machine_validation_run",
            e,
        ))
    })?;

    Ok(tonic::Response::new(rpc::MachineValidationRunResponse {
        message: "Success".to_string(),
    }))
}
