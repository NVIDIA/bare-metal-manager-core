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
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{FORWARDED, HOST};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::any;
use tokio::sync::RwLock;

use crate::http::call_router_with_new_request;

/// Multiplexed axum::Routers on a single IP/port.
///
/// HTTP header `forwarded` is used to route the request to the
/// appropriate entry.
///
/// Note: that this code is not BMC-mock specific and potentially can
/// be separate crate if needed.
pub fn combined_router(routers: Arc<RwLock<HashMap<String, Router>>>) -> Router {
    Router::new()
        .route("/{*all}", any(process))
        .with_state(CombinedRouter { routers })
}

#[derive(Clone)]
struct CombinedRouter {
    routers: Arc<RwLock<HashMap<String, Router>>>,
}

async fn process(
    State(state): State<CombinedRouter>,
    request: axum::http::Request<Body>,
) -> Response {
    let forwarded_host = forwarded_host(&request);
    let host = request
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let authority = request.uri().authority().map(|v| v.as_str().to_owned());
    let router = find_router(
        &state.routers,
        forwarded_host.as_deref(),
        host.as_deref(),
        authority.as_deref(),
    )
    .await;

    if let Some(mut router) = router {
        call_router_with_new_request(&mut router, request).await
    } else {
        no_router_response(
            forwarded_host.as_deref(),
            host.as_deref(),
            authority.as_deref(),
        )
    }
}

fn forwarded_host<B>(request: &Request<B>) -> Option<String> {
    request
        .headers()
        .get(FORWARDED)
        .and_then(|v| v.to_str().ok())
        .and_then(|fh| {
            fh.split(';')
                .find(|substr| substr.starts_with("host="))
                .map(|substr| substr.replace("host=", ""))
        })
}

async fn find_router(
    routers: &Arc<RwLock<HashMap<String, Router>>>,
    forwarded_host: Option<&str>,
    host: Option<&str>,
    authority: Option<&str>,
) -> Option<Router> {
    let routers = routers.read().await;
    forwarded_host
        .and_then(|forwarded_host| routers.get(forwarded_host).cloned())
        .or_else(|| host.and_then(|host| routers.get(host).cloned()))
        .or_else(|| authority.and_then(|authority| routers.get(authority).cloned()))
        .or_else(|| routers.get("").cloned())
}

fn no_router_response(
    forwarded_host: Option<&str>,
    host: Option<&str>,
    authority: Option<&str>,
) -> Response {
    let err = format!(
        "no router configured for forwarded_host/host/authority: {forwarded_host:?}/{host:?}/{authority:?}"
    );
    tracing::info!(
        forwarded_host = ?forwarded_host,
        host = ?host,
        authority = ?authority,
        "No BMC mock router is configured for request",
    );
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(err.into())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    use super::combined_router;

    #[tokio::test]
    async fn routes_by_forwarded_host() {
        let router = combined_router(Arc::new(RwLock::new(HashMap::from([(
            "172.20.0.20".to_string(),
            Router::new().route("/redfish/v1", get(|| async { "bmc" })),
        )]))));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/redfish/v1")
                    .header("forwarded", "host=172.20.0.20")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"bmc");
    }

    #[tokio::test]
    async fn preserves_empty_key_fallback() {
        let router = combined_router(Arc::new(RwLock::new(HashMap::from([(
            "".to_string(),
            Router::new().route("/redfish/v1", get(|| async { "default" })),
        )]))));

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/redfish/v1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"default");
    }
}
