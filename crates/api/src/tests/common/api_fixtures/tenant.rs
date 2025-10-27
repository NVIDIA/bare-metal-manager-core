/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
