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

use ::rpc::forge as rpc;
use rpc::forge_server::Forge;

use super::TestEnv;

pub async fn create_tenant_keyset(
    env: &TestEnv,
    organization_id: String,
) -> (String, rpc::TenantKeyset) {
    let keyset_id = uuid::Uuid::new_v4().to_string();
    let public_keys = vec![rpc::TenantPublicKey {
        public_key: "public key".to_string(),
        comment: Some("key comment".to_string()),
    }];
    let request = rpc::CreateTenantKeysetRequest {
        keyset_identifier: Some(rpc::TenantKeysetIdentifier {
            organization_id,
            keyset_id: keyset_id.clone(),
        }),
        keyset_content: Some(rpc::TenantKeysetContent { public_keys }),
        version: uuid::Uuid::new_v4().to_string(),
    };

    let response = env
        .api
        .create_tenant_keyset(tonic::Request::new(request))
        .await;
    let keyset = response.unwrap().into_inner().keyset.unwrap();

    (keyset_id, keyset)
}
