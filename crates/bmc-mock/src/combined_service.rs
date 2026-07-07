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
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{FORWARDED, HOST};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use hyper::body::Incoming;
use tokio::sync::RwLock;
use tower::Service;

/// Tower srvice for multiplexed axum::Routers on a single IP/port.
///
/// HTTP header `forwarded` is used to route the request to the
/// appropriate entry.
///
/// Note: that this code is not BMC-mock specific and potentially can
/// be separate crate if needed.
#[derive(Clone)]
pub struct CombinedService {
    routers: Arc<RwLock<HashMap<String, Router>>>,
}

impl CombinedService {
    pub fn new(routers: Arc<RwLock<HashMap<String, Router>>>) -> Self {
        Self { routers }
    }
}

impl Service<axum::http::Request<Incoming>> for CombinedService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        let routers = self.routers.clone();
        Box::pin(async move {
            // https://datatracker.ietf.org/doc/html/rfc7239#section-5.3
            let forwarded_host = request
                .headers()
                .get(FORWARDED)
                .and_then(|v| v.to_str().ok())
                .and_then(|fh| {
                    fh.split(';')
                        .find(|substr| substr.starts_with("host="))
                        .map(|substr| substr.replace("host=", ""))
                });
            let host = request.headers().get(HOST).and_then(|v| v.to_str().ok());
            let authority = request.uri().authority().map(|v| v.as_str());
            let routers = routers.read().await;
            let router = forwarded_host
                .as_ref()
                .and_then(|forwarded_host| routers.get(forwarded_host).cloned())
                .or_else(|| host.and_then(|host| routers.get(host).cloned()))
                .or_else(|| authority.and_then(|authority| routers.get(authority).cloned()))
                .or_else(|| routers.get("").cloned());
            drop(routers);

            if let Some(mut router) = router {
                router.call(request).await
            } else {
                let err = format!(
                    "no router configured for forwarded_host/host/authority: {forwarded_host:?}/{host:?}/{authority:?}"
                );
                tracing::info!("{err}");
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(err.into())
                    .unwrap())
            }
        })
    }
}
