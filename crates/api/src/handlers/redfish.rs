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
use std::collections::HashMap;
use std::str::FromStr;

use arc_swap::ArcSwap;
use chrono::{DateTime, Local};
use db::redfish_actions::{
    approve_request, delete_request, fetch_request, find_serials, insert_request, list_requests,
    set_applied, update_response,
};
use db::{Transaction, WithTransaction};
use forge_secrets::credentials::CredentialProvider;
use futures_util::FutureExt;
use http::header::CONTENT_TYPE;
use http::{HeaderMap, HeaderValue, Uri};
use model::redfish::BMCResponse;
use serde::Serialize;
use sqlx::PgPool;
use utils::HostPortPair;
use uuid::Uuid;

use crate::CarbideError;
use crate::api::log_request_data;
use crate::auth::external_user_info;

// TODO: put this in carbide config?
pub const NUM_REQUIRED_APPROVALS: usize = 2;

pub async fn redfish_browse(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishBrowseRequest>,
) -> Result<tonic::Response<::rpc::forge::RedfishBrowseResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let uri: http::Uri = match request.uri.clone().parse() {
        Ok(uri) => uri,
        Err(err) => {
            return Err(CarbideError::internal(format!("Parsing uri failed: {err}")).into());
        }
    };

    let (metadata, new_uri, headers, http_client) = create_client(
        uri,
        &api.database_connection,
        api.credential_provider.as_ref(),
        &api.dynamic_settings.bmc_proxy,
    )
    .await?;

    let response = match http_client
        .request(http::Method::GET, new_uri.to_string())
        .basic_auth(metadata.user.clone(), Some(metadata.password.clone()))
        .headers(headers)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return Err(CarbideError::internal(format!("Http request failed: {e:?}")).into());
        }
    };

    let headers = response
        .headers()
        .iter()
        .map(|(x, y)| {
            (
                x.to_string(),
                String::from_utf8_lossy(y.as_bytes()).to_string(),
            )
        })
        .collect::<HashMap<String, String>>();

    let status = response.status();
    let text = response.text().await.map_err(|e| {
        CarbideError::internal(format!(
            "Error reading response body: {e}, Status: {status}"
        ))
    })?;

    Ok(tonic::Response::new(::rpc::forge::RedfishBrowseResponse {
        text,
        headers,
    }))
}
pub async fn redfish_list_actions(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishListActionsRequest>,
) -> Result<tonic::Response<::rpc::forge::RedfishListActionsResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();

    let result = api
        .with_txn(|txn| list_requests(request, txn).boxed())
        .await??;

    Ok(tonic::Response::new(
        rpc::forge::RedfishListActionsResponse {
            actions: result.into_iter().map(Into::into).collect(),
        },
    ))
}

pub async fn redfish_create_action(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishCreateActionRequest>,
) -> Result<tonic::Response<::rpc::forge::RedfishCreateActionResponse>, tonic::Status> {
    log_request_data(&request);

    let authored_by = external_user_info(&request)?.user.ok_or(
        CarbideError::ClientCertificateMissingInformation("external user name".to_string()),
    )?;

    let request = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let ip_to_serial = find_serials(&request.ips, &mut txn).await?;
    let machine_ips: Vec<_> = ip_to_serial.keys().cloned().collect();
    // this is the neatest way I could think of splitting the iterator/map into two vecs
    // explicitly in the same order. could be a for loop instead.
    let serials: Vec<_> = machine_ips
        .iter()
        .map(|ip| ip_to_serial.get(ip).unwrap())
        .collect();

    let request_id = insert_request(authored_by, request, &mut txn, machine_ips, serials).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(
        ::rpc::forge::RedfishCreateActionResponse { request_id },
    ))
}

pub async fn redfish_approve_action(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishActionId>,
) -> Result<tonic::Response<::rpc::forge::RedfishApproveActionResponse>, tonic::Status> {
    log_request_data(&request);

    let approver = external_user_info(&request)?.user.ok_or(
        CarbideError::ClientCertificateMissingInformation("external user name".to_string()),
    )?;

    let request = request.into_inner();

    let mut txn = api.txn_begin().await?;
    let action_request = fetch_request(request, &mut txn).await?;
    if action_request.approvers.contains(&approver) {
        return Err(
            CarbideError::InvalidArgument("user already approved request".to_owned()).into(),
        );
    }

    let is_approved = approve_request(approver, request, &mut txn).await?;
    if !is_approved {
        return Err(
            CarbideError::InvalidArgument("user already approved request".to_owned()).into(),
        );
    }
    txn.commit().await?;

    Ok(tonic::Response::new(
        ::rpc::forge::RedfishApproveActionResponse {},
    ))
}

pub async fn redfish_apply_action(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishActionId>,
) -> Result<tonic::Response<::rpc::forge::RedfishApplyActionResponse>, tonic::Status> {
    log_request_data(&request);

    let applier = external_user_info(&request)?.user.ok_or(
        CarbideError::ClientCertificateMissingInformation("external user name".to_string()),
    )?;

    let request = request.into_inner();

    let mut txn = api.txn_begin().await?;

    let action_request = fetch_request(request, &mut txn).await?;
    if action_request.applied_at.is_some() {
        return Err(CarbideError::InvalidArgument("action already applied".to_owned()).into());
    }

    if action_request.approvers.len() < NUM_REQUIRED_APPROVALS {
        return Err(CarbideError::InvalidArgument("insufficient approvals".to_owned()).into());
    }

    let ip_to_serial = find_serials(&action_request.machine_ips, &mut txn).await?;

    let is_applied = set_applied(applier, request, &mut txn).await?;
    if !is_applied {
        return Err(CarbideError::InvalidArgument("Request was already applied".to_owned()).into());
    }

    let mut uris: Vec<(Uri, usize)> = Vec::with_capacity(action_request.machine_ips.len());

    // Do preflight checks in the foreground while the transaction is open, so it can be rolled back
    // on any error
    for (index, (machine_ip, original_serial)) in action_request
        .machine_ips
        .into_iter()
        .zip(action_request.board_serials)
        .enumerate()
    {
        // check that serial is the same.
        if ip_to_serial.get(&machine_ip) != Some(&original_serial) {
            update_response(request, &mut txn, BMCResponse {
                headers: HashMap::new(),
                status: "not executed".to_owned(),
                body: "machine serial did not match original serial at time of request creation. IP address was reused".to_owned(),
                completed_at: DateTime::from(Local::now()),
            }, index).await?;
        } else {
            uris.push((
                Uri::builder()
                    .scheme("https")
                    .authority(machine_ip)
                    .path_and_query(&action_request.target)
                    .build()
                    .map_err(|e| {
                        CarbideError::internal(format!("invalid uri from machine_ip: {e}"))
                    })?,
                index,
            ));
        }
    }

    for (uri, index) in uris {
        // Spawn off the task to send the request, open a transaction, and store the result.
        tokio::spawn({
            let pool = api.database_connection.clone();
            let credential_provider = api.credential_provider.clone();
            let bmc_proxy = api.dynamic_settings.bmc_proxy.clone();
            let mut parameters = action_request.parameters.clone();
            async move {
                // Allow tests to trigger mock behavior by inserting a `"__TEST_BEHAVIOR__": "..."`
                // into the parameters list. Only supported in cfg(test), and not done in production.
                let test_behavior = TestBehavior::from_parameters_if_testing(&mut parameters);

                let response = handle_request(
                    parameters,
                    uri,
                    &pool,
                    credential_provider.as_ref(),
                    bmc_proxy.as_ref(),
                    test_behavior,
                )
                .await;

                // Enclosing function may have returned. Nowhere to return error to.
                update_response_in_tx(&pool, request, index, response)
                    .await
                    .inspect_err(|e| tracing::error!("Error applying redfish action: {e}"))
                    .ok();
            }
        });
    }

    txn.commit().await?;

    Ok(tonic::Response::new(
        ::rpc::forge::RedfishApplyActionResponse {},
    ))
}

async fn update_response_in_tx(
    pool: &PgPool,
    request: rpc::forge::RedfishActionId,
    index: usize,
    response: BMCResponse,
) -> Result<(), tonic::Status> {
    let mut txn = Transaction::begin(pool).await?;
    update_response(request, &mut txn, response, index).await?;
    txn.commit().await?;
    Ok(())
}

async fn handle_request(
    parameters: String,
    uri: Uri,
    pool: &PgPool,
    credential_provider: &dyn CredentialProvider,
    bmc_proxy: &ArcSwap<Option<HostPortPair>>,
    test_behavior: Option<TestBehavior>,
) -> BMCResponse {
    // Allow test mocks for returning errors at defined points
    let (metadata, new_uri, mut headers, http_client) = match (
        create_client(uri, pool, credential_provider, bmc_proxy).await,
        test_behavior.and_then(TestBehavior::into_client_creation_error),
    ) {
        (Ok(tuple), None) => tuple,
        (Err(error), _) | (_, Some(error)) => {
            // Make a UUID for easy log correlation
            let failure_uuid = Uuid::new_v4();
            tracing::error!("Redfish client creation failure {failure_uuid}: {error}");

            // Set the "response" to indicate we couldn't get a redfish client. Don't
            // leak error string in case of credentials/etc.
            return BMCResponse {
                headers: HashMap::new(),
                status: "not executed".to_string(),
                body: format!("error creating redfish client, see logs: {failure_uuid}"),
                completed_at: DateTime::from(Local::now()),
            };
        }
    };

    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    // Don't perform the request if we're mocking the response
    let result = if let Some(e) = test_behavior.and_then(TestBehavior::into_request_error) {
        Err(e)
    } else if let Some(mock_response) = test_behavior.and_then(TestBehavior::into_mock_success) {
        Ok(mock_response)
    } else {
        match http_client
            .request(http::Method::POST, new_uri.to_string())
            .basic_auth(metadata.user.clone(), Some(metadata.password.clone()))
            .body(parameters)
            .headers(headers)
            .send()
            .await
        {
            Ok(response) => {
                let headers = response
                    .headers()
                    .iter()
                    .map(|(x, y)| {
                        (
                            x.to_string(),
                            String::from_utf8_lossy(y.as_bytes()).to_string(),
                        )
                    })
                    .collect::<HashMap<String, String>>();
                let status = response.status().to_string();
                let body = response
                    .text()
                    .await
                    .unwrap_or("could not decode body as text".to_owned());
                Ok(BMCResponse {
                    status,
                    headers,
                    body,
                    completed_at: DateTime::from(Local::now()),
                })
            }
            Err(e) => Err(e.into()),
        }
    };

    match result {
        Ok(response) => response,
        Err(e) => BMCResponse {
            headers: HashMap::new(),
            status: e
                .status_code
                .map(|s| s.to_string())
                .unwrap_or("missing status".to_owned()),
            body: e.description,
            completed_at: DateTime::from(Local::now()),
        },
    }
}

async fn create_client(
    uri: http::Uri,
    pool: &PgPool,
    credential_provider: &dyn CredentialProvider,
    bmc_proxy: &ArcSwap<Option<HostPortPair>>,
) -> Result<
    (
        rpc::forge::BmcMetaDataGetResponse,
        http::Uri,
        HeaderMap,
        reqwest::Client,
    ),
    CarbideError,
> {
    let bmc_metadata_request = rpc::forge::BmcMetaDataGetRequest {
        machine_id: None,
        bmc_endpoint_request: Some(rpc::forge::BmcEndpointRequest {
            ip_address: uri.host().map(|x| x.to_string()).unwrap_or_default(),
            mac_address: None,
        }),
        role: rpc::forge::UserRoles::Administrator.into(),
        request_type: rpc::forge::BmcRequestType::Ipmi.into(),
    };

    let metadata =
        crate::handlers::bmc_metadata::get_inner(bmc_metadata_request, pool, credential_provider)
            .await?;

    let proxy_address = bmc_proxy.load();
    let (host, port, add_custom_header) = match proxy_address.as_ref() {
        // No override
        None => (metadata.ip.clone(), metadata.port, false),
        // Override the host and port
        Some(HostPortPair::HostAndPort(h, p)) => (h.to_string(), Some(*p as u32), true),
        // Only override the host
        Some(HostPortPair::HostOnly(h)) => (h.to_string(), metadata.port, true),
        // Only override the port
        Some(HostPortPair::PortOnly(p)) => (metadata.ip.clone(), Some(*p as u32), false),
    };
    let new_authority = if let Some(port) = port {
        http::uri::Authority::try_from(format!("{host}:{port}"))
            .map_err(|e| CarbideError::internal(format!("creating url {e}")))?
    } else {
        http::uri::Authority::try_from(host)
            .map_err(|e| CarbideError::internal(format!("creating url {e}")))?
    };
    let mut parts = uri.into_parts();
    parts.authority = Some(new_authority);
    let new_uri = http::Uri::from_parts(parts)
        .map_err(|e| CarbideError::internal(format!("invalid url parts {e}")))?;
    let mut headers = HeaderMap::new();
    if add_custom_header {
        headers.insert(
            "forwarded",
            format!("host={orig_host}", orig_host = metadata.ip)
                .parse()
                .unwrap(),
        );
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
                return Err(CarbideError::internal(format!(
                    "Http building failed: {err}"
                )));
            }
        }
    };
    Ok((metadata, new_uri, headers, http_client))
}

pub async fn redfish_cancel_action(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishActionId>,
) -> Result<tonic::Response<::rpc::forge::RedfishCancelActionResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();

    let mut txn = api.txn_begin().await?;

    delete_request(request, &mut txn).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(
        ::rpc::forge::RedfishCancelActionResponse {},
    ))
}

#[derive(Serialize, Copy, Clone)]
pub enum TestBehavior {
    FailureAtClientCreation,
    FailureAtRequest,
    Success,
}

impl FromStr for TestBehavior {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "FailureAtClientCreation" => Ok(TestBehavior::FailureAtClientCreation),
            "FailureAtRequest" => Ok(TestBehavior::FailureAtRequest),
            "Success" => Ok(TestBehavior::Success),
            _ => Err(()),
        }
    }
}

impl TestBehavior {
    pub fn into_client_creation_error(self) -> Option<CarbideError> {
        if let TestBehavior::FailureAtClientCreation = self {
            Some(CarbideError::internal(
                "mock failure at client creation".to_owned(),
            ))
        } else {
            None
        }
    }

    pub fn into_request_error(self) -> Option<RequestErrorInfo> {
        if let TestBehavior::FailureAtRequest = self {
            Some(RequestErrorInfo {
                status_code: Some(http::status::StatusCode::INTERNAL_SERVER_ERROR),
                description: "Mock request error".to_string(),
            })
        } else {
            None
        }
    }

    pub fn into_mock_success(self) -> Option<BMCResponse> {
        if let TestBehavior::Success = self {
            Some(BMCResponse {
                headers: Default::default(),
                status: "OK".to_string(),
                body: "Mock success".to_string(),
                completed_at: Default::default(),
            })
        } else {
            None
        }
    }

    #[cfg(test)]
    pub fn from_parameters_if_testing(parameters: &mut String) -> Option<TestBehavior> {
        let mut param_obj: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(parameters).expect("invalid parameters");
        if let Some(serde_json::Value::String(test_behavior)) =
            param_obj.remove("__TEST_BEHAVIOR__")
        {
            // Recreate the original params object without __TEST_BEHAVIOR__ (since we removed it.)
            *parameters = serde_json::to_string(&param_obj).unwrap();
            Some(test_behavior.parse().unwrap())
        } else {
            None
        }
    }

    #[cfg(not(test))]
    pub fn from_parameters_if_testing(_parameters: &mut String) -> Option<TestBehavior> {
        None
    }
}

// Subset of the data we care about from reqwest::Error, so that we can mock it (we can't build our
// own reqwest::Error as its constructors are all private.)
pub struct RequestErrorInfo {
    pub status_code: Option<http::status::StatusCode>,
    pub description: String,
}

impl From<reqwest::Error> for RequestErrorInfo {
    fn from(e: reqwest::Error) -> Self {
        Self {
            status_code: e.status(),
            description: e.to_string(),
        }
    }
}
