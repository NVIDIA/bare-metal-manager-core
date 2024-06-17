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

pub mod common;

use crate::common::api_fixtures::instance::default_tenant_config;
use crate::common::api_fixtures::{create_test_env, vpc::create_vpc};
use ::rpc::forge as rpc;
use rpc::forge_server::Forge;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain"))]
async fn test_find_vpc_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    for i in 0..4 {
        let (_vpc_id, _vpc) = create_vpc(&env, format!("vpc_{}", i)).await;
    }

    // test getting all ids
    let request_all = tonic::Request::new(rpc::VpcSearchConfig {
        name: None,
        tenant_org_id: None,
    });

    let vpc_ids_all = env
        .api
        .find_vpc_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_all.vpc_ids.len(), 4);

    // test getting ids based on name
    let request_name = tonic::Request::new(rpc::VpcSearchConfig {
        name: Some("vpc_2".to_string()),
        tenant_org_id: None,
    });

    let vpc_ids_name = env
        .api
        .find_vpc_ids(request_name)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_name.vpc_ids.len(), 1);

    // test search by tenant_org_id
    let request_tenant = tonic::Request::new(rpc::VpcSearchConfig {
        name: None,
        tenant_org_id: Some(default_tenant_config().tenant_organization_id),
    });

    let vpc_ids_tenant = env
        .api
        .find_vpc_ids(request_tenant)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_tenant.vpc_ids.len(), 4);

    // test search by tenant_org_id and name
    let request_tenant_name = tonic::Request::new(rpc::VpcSearchConfig {
        name: Some("vpc_2".to_string()),
        tenant_org_id: Some(default_tenant_config().tenant_organization_id),
    });

    let vpc_ids_tenant_name = env
        .api
        .find_vpc_ids(request_tenant_name)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_tenant_name.vpc_ids.len(), 1);
}

#[sqlx::test(fixtures("create_domain"))]
async fn test_find_vpcs_by_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let mut vpc3 = rpc::Vpc::default();
    for i in 0..4 {
        let (_vpc_id, vpc) = create_vpc(&env, format!("vpc_{}", i)).await;
        if i == 3 {
            vpc3 = vpc;
        }
    }

    let request_ids = tonic::Request::new(rpc::VpcSearchConfig {
        name: Some("vpc_3".to_string()),
        tenant_org_id: None,
    });

    let vpc_ids_list = env
        .api
        .find_vpc_ids(request_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_list.vpc_ids.len(), 1);

    let request_vpcs = tonic::Request::new(vpc_ids_list.clone());

    let vpc_list = env
        .api
        .find_vpcs_by_ids(request_vpcs)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_list.vpcs.len(), 1);

    assert_eq!(vpc3, vpc_list.vpcs[0]);
}
