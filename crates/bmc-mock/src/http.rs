/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use axum::body::Body;
use axum::extract::Request;
use tower::Service;

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
