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

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::any;
use tracing::instrument;

use crate::bug::InjectedBugs;
use crate::http::call_router_with_new_request;

pub fn append(mat_host_id: String, router: Router, injected_bugs: Arc<InjectedBugs>) -> Router {
    Router::new()
        .route("/{*all}", any(process))
        .with_state(Middleware {
            mat_host_id,
            inner: router,
            injected_bugs,
        })
}

#[instrument(skip_all, fields(mat_host_id = %state.mat_host_id))]
async fn process(State(mut state): State<Middleware>, request: Request<Body>) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    if let Some(delay) = state.injected_bugs.long_response(&path) {
        tracing::warn!(
            method,
            path,
            "Error is injected waiting for {delay:?} for request",
        );
        tokio::time::sleep(delay).await;
    }
    let response = state.call_inner_router(request).await;
    if !response.status().is_success() {
        tracing::warn!(method, path, status = response.status().to_string());
    }
    response
}

#[derive(Clone)]
struct Middleware {
    mat_host_id: String,
    inner: Router,
    injected_bugs: Arc<InjectedBugs>,
}

impl Middleware {
    async fn call_inner_router(&mut self, request: Request<Body>) -> axum::response::Response {
        call_router_with_new_request(&mut self.inner, request).await
    }
}
