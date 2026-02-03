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
use std::collections::HashMap;
use std::str::FromStr;

use axum::Router;
use axum::body::Body;
use axum::extract::State as AxumState;
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures::future::join_all;
use itertools::Itertools;
use serde_json::Value;

use crate::call_router_with_new_request;

/**
This module exists to support `$expand=.($levels=N)` per the redfish spec:

https://www.dmtf.org/sites/default/files/standards/documents/DSP0268_2024.2.pdf
*/
pub fn wrap_router_with_redfish_expander(router: Router) -> Router {
    Router::new()
        .route("/{*all}", get(redfish_expand).fallback(fallback))
        .with_state(State { inner: router })
}

async fn fallback(AxumState(mut state): AxumState<State>, request: Request<Body>) -> Response {
    state.call_inner_router(request).await
}

async fn redfish_expand(
    AxumState(mut state): AxumState<State>,
    request: Request<Body>,
) -> Response {
    let expand_level = expansion_level(&request);
    let response = state.call_inner_router(request).await;

    // Parse the ?$expand=.$($levels=1) param
    let Some(expand_level) = expand_level else {
        return response;
    };

    if expand_level == 0 {
        return response;
    }

    if !response.status().is_success() {
        // Don't rewrite failed responses
        return response;
    }

    let (parts, body) = response.into_parts();
    let response_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(e) => {
            // Pretty sure this would only fail if body > usize::MAX.
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Could not read inner response body, {e}"),
            )
                .into_response();
        }
    };

    let mut json = match serde_json::from_slice::<HashMap<String, Value>>(response_bytes.as_ref()) {
        Ok(j) => j,
        Err(_) => {
            // Don't log an error if we couldn't decode the JSON, it's probably just not a redfish request.
            return (parts, response_bytes).into_response();
        }
    };
    let Some(Value::Array(members)) = json.remove("Members").or(json.remove("members")) else {
        // This error is slightly more suspicious, log it
        tracing::warn!("inner response JSON did not contain Members, returning it as-is");
        return (parts, response_bytes).into_response();
    };

    // Members look like: { "@odata.id": "/redfish/v1/Systems/1" }
    // Get the @odata.id URI strings
    let member_uris = members
        .iter()
        .filter_map(|member| match member {
            Value::Object(object) => Some(object),
            _ => {
                tracing::warn!("Invalid member JSON, expected Object: {:?}", member);
                None
            }
        })
        .filter_map(|object| match object.get("@odata.id") {
            Some(Value::String(id)) => Some(id.to_owned()),
            _ => {
                tracing::warn!(
                    "Invalid member JSON, expected @odata.id string: {:?}",
                    object
                );
                None
            }
        })
        .collect::<Vec<_>>();

    if member_uris.len() != members.len() {
        // If we had to skip any of them, don't proceed (we already logged the error above), return the original JSON unexpanded
        return (parts, response_bytes).into_response();
    }

    // Transform them to the full result of fetching each URI from the inner router
    let expanded_members: Result<Vec<Value>, MemberRequestError> =
        join_all(member_uris.into_iter().map(|uri| {
            let mut state = state.clone();
            async move {
                let response = if expand_level > 1 {
                    // Recurse into one more level
                    let req = Request::builder()
                        .method(Method::GET)
                        .uri(format!(
                            "{}?$expand=.($level={})",
                            uri.clone(),
                            expand_level - 1
                        ))
                        .body(Body::empty())
                        .unwrap();
                    redfish_expand(AxumState(state), req).await
                } else {
                    let req = Request::builder()
                        .method(Method::GET)
                        .uri(uri.clone())
                        .body(Body::empty())
                        .unwrap();
                    state.call_inner_router(req).await
                };
                let (parts, body) = response.into_parts();

                let response_bytes = match axum::body::to_bytes(body, usize::MAX).await {
                    Ok(b) => b,
                    Err(e) => return Err(MemberRequestError::Axum(uri, e)),
                };

                // Don't bother deserializing if it's unsuccessful
                if !parts.status.is_success() {
                    return Err(MemberRequestError::UnsuccessfulResponse(
                        uri,
                        parts,
                        String::from_utf8_lossy(response_bytes.to_vec().as_slice()).to_string(),
                    ));
                }

                serde_json::from_slice(response_bytes.as_ref()).map_err(|_| {
                    MemberRequestError::MalformedResponse(
                        uri,
                        String::from_utf8_lossy(response_bytes.to_vec().as_slice()).to_string(),
                    )
                })
            }
        }))
        .await
        .into_iter()
        .try_collect();

    let expanded_members = match expanded_members {
        Ok(v) => v,
        Err(error) => {
            // If any sub-request failed, return the original response
            tracing::warn!(%error, "Failed to expand Members object failed");
            return (parts, response_bytes).into_response();
        }
    };

    json.insert("Members".to_string(), Value::Array(expanded_members));

    (
        StatusCode::OK,
        serde_json::to_vec(&json).expect("serde error"),
    )
        .into_response()
}

fn expansion_level<T>(request: &Request<T>) -> Option<u8> {
    if let Some(query) = request.uri().query() {
        let params: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        params
            .get("$expand")
            .and_then(|val| {
                if val.starts_with(".($levels=") || val.starts_with("*($levels=") {
                    val.split("=").last().map(|s| s.replace(")", ""))
                } else if val == "*" || val == "." {
                    Some("1".into())
                } else {
                    None
                }
            })
            .and_then(|s| u8::from_str(&s).ok())
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct State {
    inner: Router,
}

#[derive(thiserror::Error, Debug)]
enum MemberRequestError {
    #[error("Inner request to URI {0} returned failure: {1:?}, body: {2}")]
    UnsuccessfulResponse(String, axum::http::response::Parts, String),
    #[error("Inner request to URI {0} returned a malformed response: {1}")]
    MalformedResponse(String, String),
    #[error("Error reading bytes from inner request to {0}")]
    Axum(String, axum::Error),
}

impl State {
    /// See docs in `call_router_with_new_request`
    async fn call_inner_router(&mut self, request: Request<Body>) -> axum::response::Response {
        call_router_with_new_request(&mut self.inner, request).await
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Method, Request};
    use serde_json::Value;
    use tower::Service;

    use crate::{default_host_mock, wrap_router_with_redfish_expander};

    #[tokio::test]
    async fn test_expand() {
        let tar_router = default_host_mock();
        let mut subject = wrap_router_with_redfish_expander(tar_router.clone());

        let response_body = subject
            .call(
                Request::builder()
                    .uri("/redfish/v1/Chassis/System.Embedded.1/NetworkAdapters?$expand=.($levels=1)")
                    .method(Method::GET)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body();

        let Ok(Some(Value::Object(response_object))) = serde_json::from_slice(
            axum::body::to_bytes(response_body, usize::MAX)
                .await
                .unwrap()
                .as_ref(),
        ) else {
            panic!("Could not decode NetworkAdapters")
        };

        let Some(Value::Array(network_adapters)) = response_object.get("Members") else {
            panic!("No Members array in {response_object:?}")
        };

        // Make sure each network adapter deserializes into what we expect, and that it matches what is held in the upstream router.
        for network_adapter in network_adapters {
            // Check that network_adapter is full object.
            assert!(network_adapter.get("Manufacturer").is_some());
            let Some(odata_id) = network_adapter
                .get("@odata.id")
                .and_then(serde_json::Value::as_str)
            else {
                panic!("Network adapter must contain @odata.id");
            };
            println!("{odata_id}");
            let upstream_network_adapter_body = subject
                .call(
                    Request::builder()
                        .uri(odata_id)
                        .method(Method::GET)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("Could not call tar_router")
                .into_body();

            let Ok(upstream_network_adapter) = serde_json::from_slice::<Value>(
                axum::body::to_bytes(upstream_network_adapter_body, usize::MAX)
                    .await
                    .unwrap()
                    .as_ref(),
            ) else {
                panic!("Could not deserialize tar_router response")
            };

            assert_eq!(network_adapter, &upstream_network_adapter)
        }
    }
}
