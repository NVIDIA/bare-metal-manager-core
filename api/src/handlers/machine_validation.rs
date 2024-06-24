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
    db::{machine::Machine, DatabaseError},
    model::machine::{
        machine_id::try_parse_machine_id, FailureCause, FailureDetails, FailureSource,
    },
    CarbideError,
};
use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};

// machine has completed validation
pub(crate) async fn mark_machine_validation_complete(
    api: &Api,
    request: Request<rpc::MachineValidationCompletedRequest>,
) -> Result<Response<rpc::MachineValidationCompletedResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    // Extract and check UUID
    let machine_id = match &req.machine_id {
        Some(id) => try_parse_machine_id(id).map_err(CarbideError::from)?,
        None => {
            return Err(Status::invalid_argument("A machine UUID is required"));
        }
    };
    log_machine_id(&machine_id);

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

    // TODO add code to verify the results
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
        machine_validation_results, "machine_validation_completed",
    );
    Ok(Response::new(rpc::MachineValidationCompletedResponse {}))
}
