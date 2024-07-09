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
        machine::Machine,
        machine_validation::{MachineValidation, MachineValidationResult},
        DatabaseError,
    },
    model::machine::{
        machine_id::try_parse_machine_id, FailureCause, FailureDetails, FailureSource,
        MachineState, ManagedHostState,
    },
    CarbideError,
};
use ::rpc::forge::{self as rpc};
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

    Machine::update_machine_validation_time(&machine_id, &mut txn)
        .await
        .map_err(CarbideError::from)?;

    MachineValidation::update_end_time(&uuid, &mut txn)
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
            machine_validation_error
        }
        None => "Success".to_owned(),
    };

    let result = match MachineValidationResult::validate(&mut txn, &machine_id).await? {
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

    tracing::trace!(
        %machine_id,
        result, "machine_validation_completed:machine_validation_results",
    );
    tracing::trace!(
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
        ManagedHostState::HostNotReady { machine_state } => {
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

    validation_result.create(&mut txn).await?;
    txn.commit().await.unwrap();
    Ok(tonic::Response::new(()))
}

pub(crate) async fn get_machine_validation_results(
    api: &Api,
    request: tonic::Request<rpc::MachineValidationGetRequest>,
) -> Result<tonic::Response<rpc::MachineValidationResultList>, Status> {
    log_request_data(&request);
    let machine_validation_request: rpc::MachineValidationGetRequest = request.into_inner();
    let machine_id = match machine_validation_request.machine_id {
        Some(id) => try_parse_machine_id(&id).map_err(CarbideError::from)?,
        None => {
            tracing::error!("missing machine ID");
            return Err(Status::invalid_argument("Missing machine ID"));
        }
    };
    log_machine_id(&machine_id);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin get_machine_validation_results ",
            e,
        ))
    })?;

    let db_results: Result<Vec<MachineValidationResult>, CarbideError> =
        MachineValidationResult::find_by_machine_id(
            &mut txn,
            &machine_id,
            machine_validation_request.include_history,
        )
        .await;
    let ret = db_results
        .map(
            |results: Vec<MachineValidationResult>| rpc::MachineValidationResultList {
                results: results
                    .into_iter()
                    .map(rpc::MachineValidationResult::from)
                    .collect(),
            },
        )
        .map(Response::new)
        .map_err(CarbideError::from)?;
    Ok(ret)
}
