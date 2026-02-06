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
use tonic::Code;

use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::tenant::create_tenant_keyset;

#[crate::sqlx_test]
async fn test_find_tenant_keyset_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    for i in 0..4 {
        let mut tenant_org_id = "tenant_org_1";
        if i % 2 != 0 {
            tenant_org_id = "tenant_org_2";
        }
        let (_id, _keyset) = create_tenant_keyset(&env, tenant_org_id.to_string()).await;
    }

    // test getting all ids
    let request_all = tonic::Request::new(rpc::TenantKeysetSearchFilter {
        tenant_org_id: None,
    });

    let ids_all = env
        .api
        .find_tenant_keyset_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.keyset_ids.len(), 4);

    // test search by tenant_org_id
    let request_tenant = tonic::Request::new(rpc::TenantKeysetSearchFilter {
        tenant_org_id: Some("tenant_org_2".to_string()),
    });

    let ids_tenant = env
        .api
        .find_tenant_keyset_ids(request_tenant)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_tenant.keyset_ids.len(), 2);
}

#[crate::sqlx_test]
async fn test_find_tenant_keysets_by_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let mut keyset1 = rpc::TenantKeyset::default();
    let mut keyset3 = rpc::TenantKeyset::default();
    for i in 0..4 {
        let mut tenant_org_id = "tenant_org_1";
        if i % 2 != 0 {
            tenant_org_id = "tenant_org_2";
        }
        let (_id, keyset) = create_tenant_keyset(&env, tenant_org_id.to_string()).await;
        if i == 1 {
            keyset1 = keyset
        } else if i == 3 {
            keyset3 = keyset;
        }
    }

    // test search by tenant_org_id
    let request_ids = tonic::Request::new(rpc::TenantKeysetSearchFilter {
        tenant_org_id: Some("tenant_org_2".to_string()),
    });

    let ids = env
        .api
        .find_tenant_keyset_ids(request_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids.keyset_ids.len(), 2);

    let request_keysets = tonic::Request::new(rpc::TenantKeysetsByIdsRequest {
        keyset_ids: ids.keyset_ids.clone(),
        include_key_data: false,
    });

    let keysets = env
        .api
        .find_tenant_keysets_by_ids(request_keysets)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(keysets.keyset.len(), 2);

    let mut keyset1_valid = false;
    let mut keyset3_valid = false;
    for keyset in keysets.keyset {
        if keyset.keyset_identifier.eq(&keyset1.keyset_identifier) {
            keyset1_valid = true;
        } else if keyset.keyset_identifier.eq(&keyset3.keyset_identifier) {
            keyset3_valid = true;
        }
    }
    assert!(keyset1_valid);
    assert!(keyset3_valid);
}

#[crate::sqlx_test()]
async fn test_find_tenant_keysets_by_ids_over_max(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // create vector of IDs with more than max allowed
    // it does not matter if these are real or not, since we are testing an error back for passing more than max
    let end_index: u32 = env.config.max_find_by_ids + 1;
    let keyset_ids: Vec<rpc::TenantKeysetIdentifier> = (1..=end_index)
        .map(|i| rpc::TenantKeysetIdentifier {
            organization_id: "tenant_org_1".to_string(),
            keyset_id: format!("keyset_id_{i}"),
        })
        .collect();
    let include_key_data = false;
    let request = tonic::Request::new(rpc::TenantKeysetsByIdsRequest {
        keyset_ids,
        include_key_data,
    });

    let response = env.api.find_tenant_keysets_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing no machine IDs"
    );
    assert_eq!(
        response.as_ref().err().unwrap().code(),
        Code::InvalidArgument
    );
    assert_eq!(
        response.err().unwrap().message(),
        format!(
            "no more than {} IDs can be accepted",
            env.config.max_find_by_ids
        )
    );
}

#[crate::sqlx_test()]
async fn test_find_tenant_keysets_by_ids_none(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let request = tonic::Request::new(rpc::TenantKeysetsByIdsRequest::default());

    let response = env.api.find_tenant_keysets_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing no machine IDs"
    );
    assert_eq!(
        response.as_ref().err().unwrap().code(),
        Code::InvalidArgument
    );
    assert_eq!(
        response.err().unwrap().message(),
        "at least one ID must be provided",
    );
}
