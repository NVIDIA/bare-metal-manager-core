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
use axum::Router;
use common::api_fixtures::TestEnv;
use hyper::http::Request;
use hyper::http::request::Builder;

use crate::tests::common;
use crate::web::routes;
mod machine_health;
mod managed_host;

fn make_test_app(env: &TestEnv) -> Router {
    let r = routes(env.api.clone()).unwrap();
    Router::new().nest_service("/admin", r)
}

fn authenticated_request_builder() -> Builder {
    // admin:Welcome123
    Request::builder()
        .header("Host", "with.the.most")
        .header("Authorization", "Basic YWRtaW46V2VsY29tZTEyMw==")
}
