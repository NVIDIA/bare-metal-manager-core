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

#[derive(Template)]
#[template(path = "validate_tests_details.html")]
struct ValidateTestsDetail {
    validate_tests: Vec<ValidateTest>,
}

struct ValidateTest {
    id: String,
    version: String,
    name: String,
    description: String,
    contexts: String,
    supported_platforms: String,
    command: String,
    args: String,
    tags: String,
    is_verified: bool,
    is_enabled: bool,
}

impl From<forgerpc::MachineValidationTest> for ValidateTest {
    fn from(test: forgerpc::MachineValidationTest) -> Self {
        ValidateTest {
            id: test.test_id,
            version: test.version,
            name: test.name,
            description: test.description.unwrap_or_default(),
            contexts: test.contexts.join(", "),
            supported_platforms: test.supported_platforms.join(", "),
            command: test.command,
            args: test.args,
            tags: test.custom_tags.join(", "),
            is_verified: test.verified,
            is_enabled: test.is_enabled,
        }
    }
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

pub async fn show_tests_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let validate_tests = match fetch_validation_tests(state).await {
        Ok(tests) => tests,
        Err(err) => {
            tracing::error!(%err, "fetch_validation_tests");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading validation tests",
            )
                .into_response();
        }
    };

    let tmpl = ValidateTestsDetail {
        validate_tests: validate_tests.into_iter().map(ValidateTest::from).collect(),
    };

    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

async fn fetch_validation_tests(
    api: Arc<Api>,
) -> Result<Vec<forgerpc::MachineValidationTest>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::MachineValidationTestsGetRequest {
        supported_platforms: Vec::new(),
        contexts: Vec::new(),
        test_id: None,
        ..forgerpc::MachineValidationTestsGetRequest::default()
    });
    api.get_machine_validation_tests(request)
        .await
        .map(|response| response.into_inner().tests)
}
