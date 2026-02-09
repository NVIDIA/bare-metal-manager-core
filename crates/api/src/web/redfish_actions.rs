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
use axum::extract::State as AxumState;
use axum::response::{Html, IntoResponse, Response};
use axum::{Extension, Json};
use axum_extra::extract::PrivateCookieJar;
use http::HeaderMap;
use hyper::http::StatusCode;
use rpc::forge::RedfishAction;
use rpc::forge::forge_server::Forge;
use serde::Deserialize;

use super::Oauth2Layer;
use crate::api::Api;
use crate::auth::AuthContext;
use crate::handlers::redfish::NUM_REQUIRED_APPROVALS;

#[derive(Template)]
#[template(path = "redfish_actions.html")]
struct RedfishBrowser {
    actions: RedfishActionsTable,
    error: Option<String>,
}

#[derive(Template)]
#[template(path = "redfish_actions_table.html")]
pub struct RedfishActionsTable {
    pub action_requests: Vec<RedfishAction>,
    pub required_approvals: usize,
    pub current_user_name: Option<String>,
}

/// Queries the redfish endpoint in the query parameter
/// and displays the result
pub async fn query(
    AxumState(state): AxumState<Arc<Api>>,
    Extension(oauth2_layer): Extension<Option<Oauth2Layer>>,
    request_headers: HeaderMap,
) -> Response {
    let cookiejar = oauth2_layer
        .map(|layer| PrivateCookieJar::from_headers(&request_headers, layer.private_cookiejar_key));

    let mut browser = RedfishBrowser {
        actions: RedfishActionsTable {
            action_requests: vec![],
            current_user_name: cookiejar.and_then(|jar| {
                jar.get("unique_name")
                    .map(|cookie| cookie.value().to_string())
            }),
            required_approvals: NUM_REQUIRED_APPROVALS,
        },
        error: None,
    };

    let requests = match state
        .redfish_list_actions(tonic::Request::new(rpc::forge::RedfishListActionsRequest {
            machine_ip: None,
        }))
        .await
    {
        Ok(results) => results.into_inner().actions,
        Err(err) => {
            tracing::error!(%err, "fetch_action_requests");
            browser.error = Some(format!("Failed to look up action requests {err}",));
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };
    browser.actions.action_requests = requests;

    (StatusCode::OK, Html(browser.render().unwrap())).into_response()
}

#[derive(Deserialize, Clone, Debug)]
pub struct ActionRequest {
    ips: Vec<String>,
    target: String,
    action: String,
    parameters: String,
}

pub async fn create(
    AxumState(state): AxumState<Arc<Api>>,
    Extension(auth_context): Extension<AuthContext>,
    Json(payload): Json<ActionRequest>,
) -> Response {
    let mut request = tonic::Request::new(rpc::forge::RedfishCreateActionRequest {
        ips: payload.ips,
        action: payload.action,
        target: payload.target,
        parameters: payload.parameters,
    });
    // Forward the middleware-added auth context.
    request.extensions_mut().insert(auth_context);
    if let Err(e) = state.redfish_create_action(request).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to create action: {e}"),
        )
            .into_response();
    }

    (StatusCode::OK, "successfully inserted request").into_response()
}

pub async fn approve(
    AxumState(state): AxumState<Arc<Api>>,
    Extension(auth_context): Extension<AuthContext>,
    request_id: String,
) -> Response {
    let mut request = tonic::Request::new(rpc::forge::RedfishActionId {
        request_id: match request_id.parse() {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("invalid request id {e}"),
                )
                    .into_response();
            }
        },
    });
    // Forward the middleware-added auth context.
    request.extensions_mut().insert(auth_context);
    if let Err(e) = state.redfish_approve_action(request).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to approve action: {e}"),
        )
            .into_response();
    }

    (StatusCode::OK, "successfully approved request").into_response()
}

pub async fn apply(
    AxumState(state): AxumState<Arc<Api>>,
    Extension(auth_context): Extension<AuthContext>,
    request_id: String,
) -> Response {
    let mut request = tonic::Request::new(rpc::forge::RedfishActionId {
        request_id: match request_id.parse() {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("invalid request id {e}"),
                )
                    .into_response();
            }
        },
    });
    // Forward the middleware-added auth context.
    request.extensions_mut().insert(auth_context);
    if let Err(e) = state.redfish_apply_action(request).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to apply action: {e}"),
        )
            .into_response();
    }

    (StatusCode::OK, "successfully applied request").into_response()
}

pub async fn cancel(AxumState(state): AxumState<Arc<Api>>, request_id: String) -> Response {
    let request = tonic::Request::new(rpc::forge::RedfishActionId {
        request_id: match request_id.parse() {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("invalid request id {e}"),
                )
                    .into_response();
            }
        },
    });
    if let Err(e) = state.redfish_cancel_action(request).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to cancel action: {e}"),
        )
            .into_response();
    }

    (StatusCode::OK, "successfully cancelled request").into_response()
}

pub mod filters {
    use std::fmt::Write;

    use askama_escape::Escaper;
    use itertools::Itertools;
    use rpc::forge::OptionalRedfishActionResult;
    use utils::managed_host_display::to_time;

    pub fn date_fmt(value: &rpc::Timestamp) -> ::askama::Result<String> {
        Ok(to_time::<String>(Some(*value), None).unwrap_or_default())
    }

    pub fn machine_ips_fmt(values: &[String]) -> ::askama::Result<String> {
        let mut result = String::new();

        for value in values {
            if !result.is_empty() {
                result += "<br>";
            }
            let mut escaped_ip = String::new();
            askama_escape::Html.write_escaped(&mut escaped_ip, value)?;
            write!(
                &mut result,
                r#"<a href="/admin/explored-endpoint/{escaped_ip}">{escaped_ip}</a>"#
            )
            .unwrap();
        }

        Ok(result)
    }

    pub fn contains_name(approvals: &[String], name: &str) -> ::askama::Result<bool> {
        Ok(approvals.iter().any(|o| o == name))
    }

    pub fn to_json(values: &[OptionalRedfishActionResult]) -> ::askama::Result<Vec<String>> {
        fn escape_quotes(s: String) -> String {
            format!("\"{}\"", s.replace('"', r#"\""#))
        }
        values
            .iter()
            .map(|v| {
                let Some(v) = &v.result else {
                    return Ok("Pending".to_string());
                };
                let mut headers: Vec<_> = v.headers.iter().collect();
                headers.sort_by_key(|(h, _)| *h);
                let headers = headers
                    .iter()
                    .map(|(h, v)| escape_quotes(format!("{h}: {v}")))
                    .join(", ");
                let out = format!(
                    "Status: {}. Body: {}. Completed at: {}. Headers: {headers}",
                    v.status,
                    escape_quotes(v.body.clone()),
                    v.completed_at
                        .as_ref()
                        .map(date_fmt)
                        .transpose()?
                        .unwrap_or("missing timestamp".to_string()),
                );
                Ok(out)
            })
            .collect::<Result<Vec<_>, _>>()
    }
}
