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
use axum::Extension;
use axum::extract::{Query as AxumQuery, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use axum_extra::extract::PrivateCookieJar;
use carbide_uuid::machine::MachineId;
use http::HeaderMap;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use serde::Deserialize;

use super::Oauth2Layer;
use crate::api::Api;
use crate::handlers::redfish::NUM_REQUIRED_APPROVALS;
use crate::web::redfish_actions::RedfishActionsTable;

#[derive(Template)]
#[template(path = "redfish_browser.html")]
struct RedfishBrowser {
    url: String,
    base_bmc_url: String,
    bmc_ip: String,
    error: String,
    machine_id: String,
    response: String,
    status_code: u16,
    status_string: String,
    response_headers: Vec<Header>,
    actions: RedfishActionsTable,
}

struct Header {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    url: Option<String>,
}

/// Queries the redfish endpoint in the query parameter
/// and displays the result
pub async fn query(
    AxumState(state): AxumState<Arc<Api>>,
    AxumQuery(query): AxumQuery<QueryParams>,
    Extension(oauth2_layer): Extension<Option<Oauth2Layer>>,
    request_headers: HeaderMap,
) -> Response {
    let cookiejar = oauth2_layer
        .map(|layer| PrivateCookieJar::from_headers(&request_headers, layer.private_cookiejar_key));

    let mut browser = RedfishBrowser {
        url: query.url.clone().unwrap_or_default(),
        base_bmc_url: "".to_string(),
        bmc_ip: "".to_string(),
        machine_id: "".to_string(),
        response: "".to_string(),
        response_headers: Vec::new(),
        error: "".to_string(),
        status_code: 0,
        status_string: "".to_string(),
        actions: RedfishActionsTable {
            action_requests: vec![],
            required_approvals: NUM_REQUIRED_APPROVALS,
            current_user_name: cookiejar.and_then(|jar| {
                jar.get("unique_name")
                    .map(|cookie| cookie.value().to_string())
            }),
        },
    };

    if browser.url.is_empty() {
        // No query provided - Just show the form
        return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
    };

    let uri: http::Uri = match browser.url.parse() {
        Ok(uri) => uri,
        Err(_) => {
            browser.error = format!("Invalid URL {}", browser.url);
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    browser.bmc_ip = match uri.host() {
        Some(host) => host.to_string(),
        None => {
            browser.error = format!("Missing host in URL {}", browser.url);
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    let bmc_ip: std::net::IpAddr = match browser.bmc_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            browser.error = format!("host in URL {} is not a valid IP", browser.url);
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    // This variable is used in order to allow building absolute path easier from
    // Javascript
    browser.base_bmc_url = {
        let scheme = match uri.scheme_str() {
            Some(scheme) => scheme.to_string(),
            None => "https".to_string(),
        };
        if let Some(port) = uri.port_u16() {
            format!("{scheme}://{bmc_ip}:{port}")
        } else {
            format!("{scheme}://{bmc_ip}")
        }
    };

    let response = match state
        .redfish_browse(tonic::Request::new(rpc::forge::RedfishBrowseRequest {
            uri: browser.url.clone(),
        }))
        .await
    {
        Ok(r) => r.into_inner(),
        Err(err) => {
            tracing::error!(%err, %bmc_ip, %browser.url, "redfish_browse");
            browser.error = format!("Failed to retrieve Redfish from API {err}");
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    browser.machine_id = match find_machine_id(state.clone(), bmc_ip).await {
        Ok(Some(machine_id)) => machine_id.to_string(),
        Ok(None) => String::new(),
        Err(err) => {
            tracing::error!(%err, url = browser.url, "find_machine_id");
            browser.error = format!("Failed to look up Machine for URL {}", browser.url);
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    let requests = match state
        .redfish_list_actions(tonic::Request::new(rpc::forge::RedfishListActionsRequest {
            machine_ip: Some(bmc_ip.to_string()),
        }))
        .await
    {
        Ok(results) => results
            .into_inner()
            .actions
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>(),
        Err(err) => {
            tracing::error!(%err, bmc_ip = browser.bmc_ip, "fetch_action_requests");
            browser.error = format!(
                "Failed to look up action requests for bmc_ip {}",
                browser.bmc_ip
            );
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };
    browser.actions.action_requests = match requests {
        Ok(ok) => ok,
        Err(err) => {
            tracing::error!(%err, bmc_ip = browser.bmc_ip, "fetch_action_requests");
            browser.error = format!(
                "Failed to deserialize action requests for bmc_ip {}",
                browser.bmc_ip
            );
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    for (name, value) in response.headers {
        browser.response_headers.push(Header { name, value })
    }

    browser.response = response.text;

    (StatusCode::OK, Html(browser.render().unwrap())).into_response()
}

async fn find_machine_id(
    api: Arc<Api>,
    bmc_ip: std::net::IpAddr,
) -> Result<Option<MachineId>, tonic::Status> {
    let machines = super::machine::fetch_machines(api, true, false).await?;

    for machine in machines.machines {
        let Some(bmc_info) = machine.bmc_info else {
            continue;
        };

        // We normalize the IPs to make string comparison more likely to succeed
        let Ok(ip) = bmc_info.ip.unwrap().parse::<std::net::IpAddr>() else {
            continue;
        };

        if ip == bmc_ip {
            return Ok(machine.id);
        }
    }

    Ok(None)
}

pub mod filters {
    pub use super::super::filters::*;
}
