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

use std::sync::Arc;

use askama::Template;
use axum::extract::{Query as AxumQuery, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use serde::Deserialize;

use super::Base;
use crate::api::Api;

#[derive(Template)]
#[template(path = "nmxc_browser.html")]
struct NmxcBrowser {
    chassis_serial: String,
    operation: String,
    gpu_uid: String,
    response: String,
    error: String,
    status_code: u16,
    status_string: String,
    response_headers: Vec<Header>,
}

struct Header {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    chassis_serial: Option<String>,
    operation: Option<String>,
    gpu_uid: Option<String>,
}

fn browse_operation_from_query(s: &str) -> i32 {
    match s.trim() {
        "compute_node_info_list" => rpc::forge::NmxcBrowseOperation::ComputeNodeInfoList as i32,
        "gpu_info" => rpc::forge::NmxcBrowseOperation::GpuInfo as i32,
        "gpu_info_list" => rpc::forge::NmxcBrowseOperation::GpuInfoList as i32,
        _ => rpc::forge::NmxcBrowseOperation::Unspecified as i32,
    }
}

/// Runs a selected NMX-C browse operation against the endpoint mapped for `chassis_serial`.
pub async fn query(
    AxumState(state): AxumState<Arc<Api>>,
    AxumQuery(query): AxumQuery<QueryParams>,
) -> Response {
    let mut browser = NmxcBrowser {
        chassis_serial: query.chassis_serial.clone().unwrap_or_default(),
        operation: query.operation.clone().unwrap_or_default(),
        gpu_uid: query.gpu_uid.clone().unwrap_or_default(),
        response: String::new(),
        response_headers: Vec::new(),
        error: String::new(),
        status_code: 0,
        status_string: String::new(),
    };

    let op = browse_operation_from_query(&browser.operation);
    let gpu_uid = browser.gpu_uid.trim().parse::<u64>().unwrap_or(0);
    let needs_gpu_uid = op == rpc::forge::NmxcBrowseOperation::GpuInfo as i32;
    let can_query = !browser.chassis_serial.is_empty()
        && op != rpc::forge::NmxcBrowseOperation::Unspecified as i32
        && (!needs_gpu_uid || gpu_uid != 0);

    if !can_query {
        return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
    }

    let response = match state
        .nmxc_browse(tonic::Request::new(rpc::forge::NmxcBrowseRequest {
            chassis_serial: browser.chassis_serial.clone(),
            operation: op,
            gpu_uid,
        }))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(err) => {
            let message = format!(
                "Failed to execute NMX-C query: Code: {}. Message: {}",
                err.code(),
                err.message()
            );
            browser.error = message;
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    browser.response = response.body;
    browser.status_code = response.code as _;
    browser.status_string = http::StatusCode::from_u16(browser.status_code)
        .map(|code| code.canonical_reason().unwrap_or_default().to_string())
        .unwrap_or_default();

    for (name, value) in response.headers {
        browser.response_headers.push(Header { name, value })
    }

    (StatusCode::OK, Html(browser.render().unwrap())).into_response()
}

impl super::Base for NmxcBrowser {}
