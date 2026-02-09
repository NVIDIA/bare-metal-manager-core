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

use axum::body::Body;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;
use tower::Service;

use crate::json::JsonExt;

pub(crate) fn not_found() -> Response {
    json!("").into_response(StatusCode::NOT_FOUND)
}

/// Wrapper arond axum::Router::call which constructs a new request object. This works
/// around an issue where if you just call inner_router.call(request) when that request's
/// Path<> is parameterized (ie. /:system_id, etc) it fails if the inner router doesn't have
/// the same number of arguments in its path as we do.
///
/// The error looks like:
///
/// Wrong number of path arguments for `Path`. Expected 1 but got 3. Note that multiple parameters must be extracted with a tuple `Path<(_, _)>` or a struct `Path<YourParams>`
pub(crate) async fn call_router_with_new_request(
    router: &mut axum::Router,
    request: axum::http::request::Request<Body>,
) -> axum::response::Response {
    let (head, body) = request.into_parts();

    // Construct a new request matching the incoming one.
    let mut rb = Request::builder().uri(&head.uri).method(&head.method);
    for (key, value) in head.headers.iter() {
        rb = rb.header(key, value);
    }
    let inner_request = rb.body(body).unwrap();

    router.call(inner_request).await.expect("Infallible error")
}
