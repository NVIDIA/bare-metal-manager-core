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
use std::ops::DerefMut;

use ::rpc::forge as rpc;
use carbide_uuid::vpc::VpcId;
use rpc::forge_server::Forge;

use crate::tests::common::api_fixtures::instance::default_tenant_config;
use crate::tests::common::api_fixtures::vpc::create_vpc;
use crate::tests::common::api_fixtures::{TestEnv, create_test_env};
use crate::tests::common::rpc_builder::VpcCreationRequest;

#[crate::sqlx_test]
async fn test_find_vpc_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    for i in 0..4 {
        let (_vpc_id, _vpc) = create_vpc(&env, format!("vpc_{i}"), None, None).await;
    }

    // test getting all ids
    let request_all = tonic::Request::new(rpc::VpcSearchFilter {
        name: None,
        tenant_org_id: None,
        label: None,
    });

    let vpc_ids_all = env
        .api
        .find_vpc_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_all.vpc_ids.len(), 4);

    // test getting ids based on name
    let request_name = tonic::Request::new(rpc::VpcSearchFilter {
        name: Some("vpc_2".to_string()),
        tenant_org_id: None,
        label: None,
    });

    let vpc_ids_name = env
        .api
        .find_vpc_ids(request_name)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_name.vpc_ids.len(), 1);

    // test search by tenant_org_id
    let request_tenant = tonic::Request::new(rpc::VpcSearchFilter {
        name: None,
        tenant_org_id: Some(default_tenant_config().tenant_organization_id),
        label: None,
    });

    let vpc_ids_tenant = env
        .api
        .find_vpc_ids(request_tenant)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_tenant.vpc_ids.len(), 4);

    // test search by tenant_org_id and name
    let request_tenant_name = tonic::Request::new(rpc::VpcSearchFilter {
        name: Some("vpc_2".to_string()),
        tenant_org_id: Some(default_tenant_config().tenant_organization_id),
        label: None,
    });

    let vpc_ids_tenant_name = env
        .api
        .find_vpc_ids(request_tenant_name)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_tenant_name.vpc_ids.len(), 1);
}

#[crate::sqlx_test]
async fn test_find_vpcs_by_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let mut vpc3 = rpc::Vpc::default();
    for i in 0..4 {
        let (_vpc_id, vpc) = create_vpc(&env, format!("vpc_{i}"), None, None).await;
        if i == 3 {
            vpc3 = vpc;
        }
    }

    let request_ids = tonic::Request::new(rpc::VpcSearchFilter {
        name: Some("vpc_3".to_string()),
        tenant_org_id: None,
        label: None,
    });

    let vpc_ids_list = env
        .api
        .find_vpc_ids(request_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_ids_list.vpc_ids.len(), 1);

    let request_vpcs = tonic::Request::new(rpc::VpcsByIdsRequest {
        vpc_ids: vpc_ids_list.vpc_ids.clone(),
    });

    let vpc_list = env
        .api
        .find_vpcs_by_ids(request_vpcs)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(vpc_list.vpcs.len(), 1);

    assert_eq!(vpc3, vpc_list.vpcs[0]);
}

#[crate::sqlx_test()]
async fn test_find_vpcs_by_ids_over_max(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    // create vector of IDs with more than max allowed
    // it does not matter if these are real or not, since we are testing an error back for passing more than max
    let end_index: u32 = env.config.max_find_by_ids + 1;
    let vpc_ids = (1..=end_index).map(|_| VpcId::default()).collect();

    let request = tonic::Request::new(rpc::VpcsByIdsRequest { vpc_ids });

    let response = env.api.find_vpcs_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing no machine IDs"
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
async fn test_find_vpcs_by_ids_none(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    let request = tonic::Request::new(rpc::VpcsByIdsRequest::default());

    let response = env.api.find_vpcs_by_ids(request).await;
    // validate
    assert!(
        response.is_err(),
        "expected an error when passing no machine IDs"
    );
    assert_eq!(
        response.err().unwrap().message(),
        "at least one ID must be provided",
    );
}

#[crate::sqlx_test]
async fn find_vpc_by_name(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let vpc_id = VpcId::new();

    sqlx::query(r#"
        INSERT INTO vpcs (id, name, organization_id, version) VALUES ($1, 'test vpc 1', '2829bbe3-c169-4cd9-8b2a-19a8b1618a93', 'V1-T1666644937952267');
    "#).bind(vpc_id).execute(txn.deref_mut()).await?;

    let some_vpc = db::vpc::find_by_name(&mut txn, "test vpc 1").await?;

    assert_eq!(1, some_vpc.len());

    let first = some_vpc.first();

    assert!(matches!(first, Some(x) if x.id == vpc_id));

    Ok(())
}

async fn find_vpc_by_request(
    env: &TestEnv,
    label: rpc::Label,
    name: Option<String>,
) -> rpc::VpcList {
    let request = tonic::Request::new(rpc::VpcSearchFilter {
        name,
        tenant_org_id: None,
        label: Some(label),
    });

    let mut vpc_id = env
        .api
        .find_vpc_ids(request)
        .await
        .map(|response| response.into_inner())
        .unwrap()
        .vpc_ids;

    if !vpc_id.is_empty() {
        env.api
            .find_vpcs_by_ids(tonic::Request::new(rpc::VpcsByIdsRequest {
                vpc_ids: vec![vpc_id.remove(0)],
            }))
            .await
            .map(|response| response.into_inner())
            .unwrap()
    } else {
        rpc::VpcList { vpcs: vec![] }
    }
}

#[crate::sqlx_test]
async fn test_vpc_search_based_on_labels(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    for i in 0..=3 {
        env.api
            .create_vpc(
                VpcCreationRequest::builder("", "Forge_unit_tests")
                    .metadata(rpc::Metadata {
                        name: format!("VPC_{i}{i}{i}").to_string(),
                        description: format!("VPC_{i}{i}{i} have labels").to_string(),
                        labels: vec![
                            rpc::Label {
                                key: format!("key_A_{i}{i}{i}").to_string(),
                                value: Some(format!("value_A_{i}{i}{i}").to_string()),
                            },
                            rpc::Label {
                                key: format!("key_B_{i}{i}{i}").to_string(),
                                value: None,
                            },
                        ],
                    })
                    .tonic_request(),
            )
            .await
            .unwrap()
            .into_inner();
    }

    // Test searching based on value.
    let search_label = rpc::Label {
        key: "".to_string(),
        value: Some("value_A_000".to_string()),
    };

    let vpc_matched_by_label = find_vpc_by_request(&env, search_label, None)
        .await
        .vpcs
        .remove(0);
    assert_eq!(vpc_matched_by_label.metadata.unwrap().name, "VPC_000");

    // Test searching based on key.
    let search_label = rpc::Label {
        key: "key_A_111".to_string(),
        value: None,
    };

    let vpc_matched_by_label = find_vpc_by_request(&env, search_label, None)
        .await
        .vpcs
        .remove(0);
    assert_eq!(vpc_matched_by_label.metadata.unwrap().name, "VPC_111");

    // Test searching based on key and value.
    let search_label = rpc::Label {
        key: "key_A_222".to_string(),
        value: Some("value_A_222".to_string()),
    };

    let vpc_matched_by_label = find_vpc_by_request(&env, search_label, None)
        .await
        .vpcs
        .remove(0);
    assert_eq!(vpc_matched_by_label.metadata.unwrap().name, "VPC_222");

    // Test searching based on key and name.
    let search_label = rpc::Label {
        key: "key_A_222".to_string(),
        value: None,
    };

    let vpc_matched_by_label = find_vpc_by_request(&env, search_label, Some("VPC_222".to_string()))
        .await
        .vpcs
        .remove(0);
    assert_eq!(vpc_matched_by_label.metadata.unwrap().name, "VPC_222");

    // Test searching based on key and name.
    let search_label = rpc::Label {
        key: "key_A_333".to_string(),
        value: None,
    };

    let vpc_matched_by_label =
        find_vpc_by_request(&env, search_label, Some("VPC_222".to_string())).await;
    assert_eq!(vpc_matched_by_label.vpcs.len(), 0);
}

#[crate::sqlx_test]
async fn test_vpc_find_by_segment(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let vpc_id = db::vpc::find_by_name(&mut txn, "test vpc 1")
        .await
        .unwrap()
        .first()
        .unwrap()
        .id;
    let vpc = db::vpc::find_by_segment(&mut txn, segment_id)
        .await
        .unwrap();
    assert_eq!(vpc.id.to_string(), vpc_id.to_string());
}
