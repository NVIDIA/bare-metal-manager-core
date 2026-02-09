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
use http_body_util::BodyExt;
use hyper::http::StatusCode;
use rpc::forge::AdminForceDeleteMachineRequest;
use rpc::forge::forge_server::Forge;
use tower::ServiceExt;

use crate::tests::common::api_fixtures::{create_managed_host, create_test_env};
use crate::tests::web::{authenticated_request_builder, make_test_app};

#[crate::sqlx_test]
async fn test_health_of_nonexisting_machine(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let app = make_test_app(&env);

    async fn verify_history(app: &axum::Router, machine_id: String) {
        let response = app
            .clone()
            .oneshot(
                authenticated_request_builder()
                    .uri(format!("/admin/machine/{machine_id}/health"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response
            .into_body()
            .collect()
            .await
            .expect("Empty response body?")
            .to_bytes();

        let body = String::from_utf8_lossy(&body_bytes);
        assert!(body.contains("History"));
    }

    // Health page for Machine which was never ingested
    verify_history(
        &app,
        "fm100ht09g4atrqgjb0b83b2to1qa1hfugks9mhutb0umcng1rkr54vliqg".to_string(),
    )
    .await;

    // Health page for Machine which was force deleted
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();
    env.api
        .admin_force_delete_machine(tonic::Request::new(AdminForceDeleteMachineRequest {
            host_query: host_machine_id.to_string(),
            delete_interfaces: false,
            delete_bmc_interfaces: false,
            delete_bmc_credentials: false,
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(env.find_machine(host_machine_id).await.is_empty());

    verify_history(&app, host_machine_id.to_string()).await;
}
