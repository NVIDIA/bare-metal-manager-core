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

use super::filters;
use crate::api::Api;
use askama::Template;
use axum::extract::{Query as AxumQuery, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use http::HeaderMap;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use serde::Deserialize;
use std::sync::Arc;
use url::Url;
use utils::HostPortPair;

#[derive(Template)]
#[template(path = "redfish_browser.html")]
struct RefishBrowser {
    url: String,
    base_bmc_url: String,
    bmc_ip: String,
    error: String,
    machine_id: String,
    response: String,
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
    url: Option<String>,
}

/// Queries the redfish endpoint in the query parameter
/// and displays the result
pub async fn query(
    AxumState(state): AxumState<Arc<Api>>,
    AxumQuery(query): AxumQuery<QueryParams>,
) -> Response {
    let mut browser = RefishBrowser {
        url: query.url.clone().unwrap_or_default(),
        base_bmc_url: "".to_string(),
        bmc_ip: "".to_string(),
        machine_id: "".to_string(),
        response: "".to_string(),
        response_headers: Vec::new(),
        error: "".to_string(),
        status_code: 0,
        status_string: "".to_string(),
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

    let metadata = match state
        .get_bmc_meta_data(tonic::Request::new(rpc::forge::BmcMetaDataGetRequest {
            machine_id: None,
            bmc_endpoint_request: Some(rpc::forge::BmcEndpointRequest {
                ip_address: bmc_ip.to_string(),
                mac_address: None,
            }),
            role: rpc::forge::UserRoles::Administrator.into(),
            request_type: rpc::forge::BmcRequestType::Ipmi.into(),
        }))
        .await
    {
        Ok(meta) => meta.into_inner(),
        Err(err) => {
            browser.error = match err.code() {
                tonic::Code::NotFound => {
                    format!("No BMC Credentials are available for URL {}", browser.url)
                }
                _ => {
                    tracing::error!(%err, %bmc_ip, "get_bmc_meta_data");
                    format!("Failed to retrieve BMC Metadata for URL {}", browser.url)
                }
            };
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    // Informational only. The data is not used for accessing the BMC
    browser.machine_id = match find_machine_id(state.clone(), bmc_ip).await {
        Ok(Some(machine_id)) => machine_id.id,
        Ok(None) => String::new(),
        Err(err) => {
            tracing::error!(%err, url = browser.url, "find_machine_id");
            browser.error = format!("Failed to look up Machine for URL {}", browser.url);
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };

    let http_client = {
        let builder = reqwest::Client::builder();
        let builder = builder
            .danger_accept_invalid_certs(true)
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
                        browser.url
                    )),
                )
                    .into_response();
            }
        }
    };

    let (url, headers) = match state.dynamic_settings.bmc_proxy.load().as_ref().clone() {
        Some(proxy) => {
            // We're configured for a proxy for talking to BMC's: Talk to the proxy URL and use a forwarded: header to specify the original host.

            // Unwrap safety: It's a valid `Uri`, so parsing/setting fields on a Url must work.
            let mut proxy_url: Url = uri.to_string().parse().unwrap();
            let orig_host = browser.bmc_ip.clone();
            match proxy {
                HostPortPair::HostOnly(h) => {
                    proxy_url.set_host(Some(&h)).unwrap();
                }
                HostPortPair::PortOnly(p) => {
                    proxy_url.set_port(Some(p)).unwrap();
                }
                HostPortPair::HostAndPort(h, p) => {
                    proxy_url.set_host(Some(&h)).unwrap();
                    proxy_url.set_port(Some(p)).unwrap();
                }
            }

            let mut headers = HeaderMap::new();
            headers.insert("forwarded", format!("host={orig_host}",).parse().unwrap());
            (proxy_url, headers)
        }
        None => (browser.url.clone().parse().unwrap(), HeaderMap::new()),
    };

    let response = match http_client
        .request(http::Method::GET, url)
        .basic_auth(metadata.user.clone(), Some(metadata.password.clone()))
        .headers(headers)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            browser.error = format!("Error sending request:\n{:?}", e);
            if let Some(status) = e.status() {
                browser.status_code = status.as_u16();
                browser.status_string = status.canonical_reason().unwrap_or_default().to_string();
            }
            return (StatusCode::OK, Html(browser.render().unwrap())).into_response();
        }
    };
    browser.status_code = response.status().as_u16();
    browser.status_string = response
        .status()
        .canonical_reason()
        .unwrap_or_default()
        .to_string();
    for (name, value) in response.headers() {
        browser.response_headers.push(Header {
            name: name.to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).to_string(),
        })
    }

    match response.text().await {
        Ok(response) => {
            browser.response = response;
        }
        Err(e) => {
            browser.error = format!("Error reading response body:\n{:?}", e);
        }
    };

    (StatusCode::OK, Html(browser.render().unwrap())).into_response()
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
