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
