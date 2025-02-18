/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;

use askama::Template;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc};

use crate::api::Api;

#[derive(Debug)]
struct ValidationResult {
    validation_id: String,
    name: String,
    context: String,
    status: String,
    command: String,
    args: String,
    stdout: String,
    stderr: String,
    start_time: String,
    end_time: String,
}

#[derive(Template)]
#[template(path = "validation_results_details.html")]
struct ValidationResultsDetail {
    validation_results: Vec<ValidationResult>,
}

pub async fn results_details(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(validation_id): AxumPath<String>,
) -> Response {
    let request = tonic::Request::new(forgerpc::MachineValidationGetRequest {
        validation_id: Some(rpc::common::Uuid {
            value: validation_id.clone(),
        }),
        include_history: false,
        machine_id: None,
    });
    tracing::info!(%validation_id, "results_details");

    let validation_results = match state
        .get_machine_validation_results(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(results) => results
            .results
            .into_iter()
            .map(|r: forgerpc::MachineValidationResult| ValidationResult {
                validation_id: r.validation_id.unwrap_or_default().to_string(),
                name: r.name,
                context: r.context,
                status: r.exit_code.to_string(),
                command: r.command,
                args: r.args,
                stdout: r.std_out,
                stderr: r.std_err,
                start_time: r.start_time.unwrap_or_default().to_string(),
                end_time: r.end_time.unwrap_or_default().to_string(),
            })
            .collect(),
        Err(err) => {
            tracing::error!(%err, %validation_id, "get_validation_results failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get validation results",
            )
                .into_response();
        }
    };
    // tracing::info!(%validation_results, "results_details");

    let tmpl = ValidationResultsDetail { validation_results };

    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
