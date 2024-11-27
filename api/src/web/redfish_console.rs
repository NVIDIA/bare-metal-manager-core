/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use askama::Template;
use axum::extract::{Query as AxumQuery, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use std::sync::Arc;

use super::filters;
use crate::api::Api;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "redfish_console.html")]
struct RefishConsole {
    url: String,
    bmc_ip: String,
    error: String,
    machine_id: String,
    response: String,
    status_code: u16,
    status_string: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct QueryParams {
    url: Option<String>,
}

/// Queries the redfish endpoint in the query parameter
/// and displays the result
pub async fn query(
    AxumState(state): AxumState<Arc<Api>>,
    AxumQuery(query): AxumQuery<QueryParams>,
) -> Response {
    let mut console = RefishConsole {
        url: query.url.clone().unwrap_or_default(),
        bmc_ip: "".to_string(),
        machine_id: "".to_string(),
        response: "".to_string(),
        error: "".to_string(),
        status_code: 0,
        status_string: "".to_string(),
    };

    if console.url.is_empty() {
        // No query provided - Just show the form
        return (StatusCode::OK, Html(console.render().unwrap())).into_response();
    };

    let uri: http::Uri = match console.url.parse() {
        Ok(uri) => uri,
        Err(_) => {
            console.error = format!("Invalid URL {}", console.url);
            return (StatusCode::OK, Html(console.render().unwrap())).into_response();
        }
    };

    console.bmc_ip = match uri.host() {
        Some(host) => host.to_string(),
        None => {
            console.error = format!("Missing host in URL {}", console.url);
            return (StatusCode::OK, Html(console.render().unwrap())).into_response();
        }
    };

    let bmc_ip: std::net::IpAddr = match console.bmc_ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            console.error = format!("host in URL {} is not a valid IP", console.url);
            return (StatusCode::OK, Html(console.render().unwrap())).into_response();
        }
    };

    let machine_id = match find_machine_id(state.clone(), bmc_ip).await {
        Ok(Some(machine_id)) => machine_id,
        Ok(None) => {
            console.error = format!("No Machine maps to URL {}", console.url);
            return (StatusCode::OK, Html(console.render().unwrap())).into_response();
        }
        Err(err) => {
            tracing::error!(%err, url = console.url, "find_machine_id");
            console.error = format!("Failed to look up Machine for URL {}", console.url);
            return (StatusCode::OK, Html(console.render().unwrap())).into_response();
        }
    };

    let metadata = match state
        .get_bmc_meta_data(tonic::Request::new(rpc::forge::BmcMetaDataGetRequest {
            machine_id: Some(machine_id.clone()),
            role: rpc::forge::UserRoles::Administrator.into(),
            request_type: rpc::forge::BmcRequestType::Ipmi.into(),
        }))
        .await
    {
        Ok(meta) => meta.into_inner(),
        Err(err) => {
            tracing::error!(%err, %machine_id, "get_bmc_meta_data");
            console.error = format!("Failed to retrieve BMC Metadata for URL {}", console.url);
            return (StatusCode::OK, Html(console.render().unwrap())).into_response();
        }
    };

    let http_client = {
        let builder = reqwest::Client::builder();
        let builder = builder
            .redirect(reqwest::redirect::Policy::limited(5))
            .connect_timeout(std::time::Duration::from_secs(5)) // Limit connections to 5 seconds
            .timeout(std::time::Duration::from_secs(60)); // Limit the overall request to 60 seconds

        match builder.build() {
            Ok(client) => client,
            Err(err) => {
                tracing::error!(%err, "build_http_client");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html(format!(
                        "Failed to build HTTP client for requesting {}",
                        console.url
                    )),
                )
                    .into_response();
            }
        }
    };

    let response = match http_client
        .request(http::Method::GET, console.url.clone())
        .basic_auth(metadata.user.clone(), Some(metadata.password.clone()))
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            console.error = e.to_string();
            return (StatusCode::OK, Html(console.render().unwrap())).into_response();
        }
    };
    console.status_code = response.status().as_u16();
    console.status_string = response.status().as_str().to_string();

    match response.text().await {
        Ok(response) => {
            console.response = response;
        }
        Err(e) => {
            console.error = e.to_string();
        }
    };

    (StatusCode::OK, Html(console.render().unwrap())).into_response()
}

async fn find_machine_id(
    api: Arc<Api>,
    bmc_ip: std::net::IpAddr,
) -> Result<Option<rpc::common::MachineId>, tonic::Status> {
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
