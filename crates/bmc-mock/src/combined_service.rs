/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
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
        let forwarded_header = request
            .headers()
            .get("forwarded")
            .map(|v| v.to_str().unwrap())
            .unwrap_or("");

        // https://datatracker.ietf.org/doc/html/rfc7239#section-5.3
        let forwarded_host = forwarded_header
            .split(';')
            .find(|substr| substr.starts_with("host="))
            .map(|substr| substr.replace("host=", ""))
            .unwrap_or_default();

        let routers = self.routers.clone();
        Box::pin(async move {
            let Some(mut router) = routers.read().await.get(&forwarded_host).cloned() else {
                let err = format!("no router configured for host: {forwarded_host}");
                tracing::info!("{err}");
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(err.into())
                    .unwrap());
            };

            router.call(request).await
        })
    }
}
