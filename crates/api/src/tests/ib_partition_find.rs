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
use carbide_uuid::infiniband::IBPartitionId;
use rpc::forge_server::Forge;

use crate::cfg::file::IBFabricConfig;
use crate::tests::common;
use crate::tests::common::api_fixtures::ib_partition::create_ib_partition;
use crate::tests::common::api_fixtures::{TestEnvOverrides, create_test_env};

#[crate::sqlx_test]
async fn test_find_ib_partition_ids(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;

    for i in 0..6 {
        let mut tenant_org_id = "tenant_org_1";
        if i % 2 != 0 {
            tenant_org_id = "tenant_org_2";
        }
        let (_id, _partition) =
            create_ib_partition(&env, format!("partition_{i}"), tenant_org_id.to_string()).await;
    }

    // test getting all ids
    let request_all = tonic::Request::new(rpc::IbPartitionSearchFilter {
        name: None,
        tenant_org_id: None,
    });

    let ids_all = env
        .api
        .find_ib_partition_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.ib_partition_ids.len(), 6);

    // test getting ids based on name
    let request_name = tonic::Request::new(rpc::IbPartitionSearchFilter {
        name: Some("partition_5".to_string()),
        tenant_org_id: None,
    });

    let ids_name = env
        .api
        .find_ib_partition_ids(request_name)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_name.ib_partition_ids.len(), 1);

    // test search by tenant_org_id
    let request_tenant = tonic::Request::new(rpc::IbPartitionSearchFilter {
        name: None,
        tenant_org_id: Some("tenant_org_2".to_string()),
    });

    let ids_tenant = env
        .api
        .find_ib_partition_ids(request_tenant)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_tenant.ib_partition_ids.len(), 3);

    // test search by tenant_org_id and name
    let request_tenant_name = tonic::Request::new(rpc::IbPartitionSearchFilter {
        name: Some("partition_4".to_string()),
        tenant_org_id: Some("tenant_org_1".to_string()),
    });

    let ids_tenant_name = env
        .api
        .find_ib_partition_ids(request_tenant_name)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_tenant_name.ib_partition_ids.len(), 1);
}

#[crate::sqlx_test]
async fn test_find_ib_partitions_by_ids(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let mut partition3 = rpc::IbPartition::default();
    for i in 0..6 {
        let mut tenant_org_id = "tenant_org_1";
        if i % 2 != 0 {
            tenant_org_id = "tenant_org_2";
        }
        let (_id, partition) =
            create_ib_partition(&env, format!("partition_{i}"), tenant_org_id.to_string()).await;
        if i == 3 {
            partition3 = partition;
        }
    }

    let request_ids = tonic::Request::new(rpc::IbPartitionSearchFilter {
        name: Some("partition_3".to_string()),
        tenant_org_id: None,
    });

    let ids_list = env
        .api
        .find_ib_partition_ids(request_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_list.ib_partition_ids.len(), 1);

    let request_partitions = tonic::Request::new(rpc::IbPartitionsByIdsRequest {
        ib_partition_ids: ids_list.ib_partition_ids,
        include_history: false,
    });

    let partition_list = env
        .api
        .find_ib_partitions_by_ids(request_partitions)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(partition_list.ib_partitions.len(), 1);

    let partition3config = partition3.config.unwrap();
    let part3_list = partition_list.ib_partitions[0].clone();
    let clone3config = part3_list.config.unwrap();
    assert_eq!(
        partition3.metadata.unwrap().name,
        part3_list.metadata.unwrap().name
    );
    assert_eq!(
        partition3config.tenant_organization_id,
        clone3config.tenant_organization_id
    );
}

#[crate::sqlx_test()]
async fn test_find_ib_partitions_by_ids_over_max(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    // create vector of IDs with more than max allowed
    // it does not matter if these are real or not, since we are testing an error back for passing more than max
    let end_index: u32 = env.config.max_find_by_ids + 1;
    let ib_partition_ids: Vec<IBPartitionId> = (1..=end_index)
        .map(|_| uuid::Uuid::new_v4().into())
        .collect();

    let request = tonic::Request::new(rpc::IbPartitionsByIdsRequest {
        ib_partition_ids,
        include_history: false,
    });

    let response = env.api.find_ib_partitions_by_ids(request).await;
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
async fn test_find_ib_partitions_by_ids_none(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let request_none = tonic::Request::new(rpc::IbPartitionsByIdsRequest {
        ib_partition_ids: Vec::new(),
        include_history: false,
    });

    let response_none = env.api.find_ib_partitions_by_ids(request_none).await;
    // validate
    assert!(
        response_none.is_err(),
        "expected an error when passing no machine IDs"
    );
    assert_eq!(
        response_none.err().unwrap().message(),
        "at least one ID must be provided",
    );
}
