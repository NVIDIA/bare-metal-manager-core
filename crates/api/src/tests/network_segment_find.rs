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
use carbide_uuid::network::NetworkSegmentId;
use rpc::forge_server::Forge;

use crate::tests::common::api_fixtures::network_segment::create_network_segment;
use crate::tests::common::api_fixtures::vpc::create_vpc;
use crate::tests::common::api_fixtures::{TestEnvOverrides, create_test_env_with_overrides};

#[crate::sqlx_test]
async fn test_find_network_segment_ids(pool: sqlx::PgPool) {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    for i in 0..4 {
        let mut tenant_org_id = "tenant_org_1";
        if i % 2 != 0 {
            tenant_org_id = "tenant_org_2";
        }
        let (vpc_id, _vpc) = create_vpc(
            &env,
            format!("vpc_{i}"),
            Some(tenant_org_id.to_string()),
            None,
        )
        .await;
        create_network_segment(
            &env.api,
            format!("segment_{i}").as_str(),
            format!("192.0.{}.0/24", i + 1).as_str(),
            format!("192.0.{}.1", i + 1).as_str(),
            rpc::NetworkSegmentType::Underlay,
            Some(vpc_id),
            true,
        )
        .await;
    }

    // test getting all ids
    let request_all = tonic::Request::new(rpc::NetworkSegmentSearchFilter {
        name: None,
        tenant_org_id: None,
    });

    let ids_all = env
        .api
        .find_network_segment_ids(request_all)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_all.network_segments_ids.len(), 4);

    // test getting ids based on name
    let request_name = tonic::Request::new(rpc::NetworkSegmentSearchFilter {
        name: Some("segment_2".to_string()),
        tenant_org_id: None,
    });

    let ids_name = env
        .api
        .find_network_segment_ids(request_name)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_name.network_segments_ids.len(), 1);

    // test search by tenant_org_id
    let request_tenant = tonic::Request::new(rpc::NetworkSegmentSearchFilter {
        name: None,
        tenant_org_id: Some("tenant_org_2".to_string()),
    });

    let ids_tenant = env
        .api
        .find_network_segment_ids(request_tenant)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_tenant.network_segments_ids.len(), 2);

    // test search by tenant_org_id and name
    let request_tenant_name = tonic::Request::new(rpc::NetworkSegmentSearchFilter {
        name: Some("segment_3".to_string()),
        tenant_org_id: Some("tenant_org_2".to_string()),
    });

    let ids_tenant_name = env
        .api
        .find_network_segment_ids(request_tenant_name)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_tenant_name.network_segments_ids.len(), 1);
}

#[crate::sqlx_test]
async fn test_find_network_segment_by_ids(pool: sqlx::PgPool) {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    for i in 0..4 {
        let mut tenant_org_id = "tenant_org_1";
        if i % 2 != 0 {
            tenant_org_id = "tenant_org_2";
        }
        let (vpc_id, _vpc) = create_vpc(
            &env,
            format!("vpc_{i}"),
            Some(tenant_org_id.to_string()),
            None,
        )
        .await;
        create_network_segment(
            &env.api,
            format!("segment_{i}").as_str(),
            format!("192.0.{}.0/24", i + 1).as_str(),
            format!("192.0.{}.1", i + 1).as_str(),
            rpc::NetworkSegmentType::Underlay,
            Some(vpc_id),
            true,
        )
        .await;
    }

    let request_ids = tonic::Request::new(rpc::NetworkSegmentSearchFilter {
        name: None,
        tenant_org_id: Some("tenant_org_2".to_string()),
    });

    let ids_list = env
        .api
        .find_network_segment_ids(request_ids)
        .await
        .map(|response| response.into_inner())
        .unwrap();
    assert_eq!(ids_list.network_segments_ids.len(), 2);

    let seg_request = tonic::Request::new(rpc::NetworkSegmentsByIdsRequest {
        network_segments_ids: ids_list.network_segments_ids.clone(),
        include_history: true,
        include_num_free_ips: true,
    });

    let seg_list = env
        .api
        .find_network_segments_by_ids(seg_request)
        .await
        .map(|response| response.into_inner())
        .unwrap();

    assert_eq!(seg_list.network_segments.len(), 2);

    for segment in seg_list.network_segments {
        assert!(!segment.prefixes.is_empty());
        assert!(!segment.history.is_empty());
        assert_ne!(!segment.prefixes[0].free_ip_count, 0);
    }
}

#[crate::sqlx_test()]
async fn test_find_network_segments_by_ids_over_max(pool: sqlx::PgPool) {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    // create vector of IDs with more than max allowed
    // it does not matter if these are real or not, since we are testing an error back for passing more than max
    let end_index: u32 = env.config.max_find_by_ids + 1;
    let network_segments_ids: Vec<NetworkSegmentId> = (1..=end_index)
        .map(|_| uuid::Uuid::new_v4().into())
        .collect();

    let request = tonic::Request::new(rpc::NetworkSegmentsByIdsRequest {
        network_segments_ids,
        include_history: false,
        include_num_free_ips: false,
    });

    let response = env.api.find_network_segments_by_ids(request).await;
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
async fn test_find_network_segments_by_ids_none(pool: sqlx::PgPool) {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    let request = tonic::Request::new(rpc::NetworkSegmentsByIdsRequest::default());

    let response = env.api.find_network_segments_by_ids(request).await;
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
