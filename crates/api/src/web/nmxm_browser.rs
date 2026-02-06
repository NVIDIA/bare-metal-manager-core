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

use crate::api::Api;

#[derive(Template)]
#[template(path = "nmxm_browser.html")]
struct NmxmBrowser {
    path: String,
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
    path: Option<String>,
}

/// Queries the redfish endpoint in the query parameter
/// and displays the result
pub async fn query(
    AxumState(state): AxumState<Arc<Api>>,
    AxumQuery(query): AxumQuery<QueryParams>,
) -> Response {
    let mut browser = NmxmBrowser {
        path: query.path.clone().unwrap_or_default(),
        response: "".to_string(),
        response_headers: Vec::new(),
        error: "".to_string(),
        status_code: 0,
        status_string: "".to_string(),
    };

    if browser.path.is_empty() {
        // No query provided - Just show the form
        return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
    };

    let response = match state
        .nmxm_browse(tonic::Request::new(rpc::forge::NmxmBrowseRequest {
            path: browser.path.clone(),
        }))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(err) => {
            let message = format!(
                "Failed to execute NMX-M query: Code: {}. Message: {}",
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
