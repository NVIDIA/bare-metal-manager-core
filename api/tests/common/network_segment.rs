/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide::db::network_segment_state_history::NetworkSegmentStateHistory;
use rpc::forge::forge_server::Forge;
use rpc::forge::NetworkSegmentSearchConfig;
use tonic::Request;

use super::api_fixtures::TestApi;

pub const FIXTURE_CREATED_VPC_UUID: uuid::Uuid =
    uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");
pub const FIXTURE_CREATED_DOMAIN_UUID: uuid::Uuid =
    uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

pub async fn create_network_segment_with_api(
    api: &TestApi,
    use_subdomain: bool,
    use_vpc: bool,
) -> rpc::forge::NetworkSegment {
    let mut request = rpc::forge::NetworkSegmentCreationRequest {
        mtu: Some(1500),
        name: "TEST_SEGMENT".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "192.0.2.0/24".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            reserve_first: 1,
            state: None,
            events: vec![],
            circuit_id: None,
        }],
        subdomain_id: None,
        vpc_id: None,
        segment_type: rpc::forge::NetworkSegmentType::Admin as i32,
    };
    if use_subdomain {
        request.subdomain_id = Some(FIXTURE_CREATED_DOMAIN_UUID.into());
    }

    if use_vpc {
        request.vpc_id = Some(FIXTURE_CREATED_VPC_UUID.into());
    }
    api.create_network_segment(Request::new(request))
        .await
        .expect("Unable to create network segment")
        .into_inner()
}

pub async fn get_segment_state(api: &TestApi, segment_id: uuid::Uuid) -> rpc::forge::TenantState {
    let segment = api
        .find_network_segments(Request::new(rpc::forge::NetworkSegmentQuery {
            id: Some(segment_id.into()),
            search_config: Some(NetworkSegmentSearchConfig {
                include_history: false,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .network_segments
        .remove(0);
    segment.state()
}

pub async fn get_segments(
    api: &TestApi,
    segment_id: uuid::Uuid,
    search_config: Option<NetworkSegmentSearchConfig>,
) -> rpc::forge::NetworkSegmentList {
    api.find_network_segments(Request::new(rpc::forge::NetworkSegmentQuery {
        id: Some(segment_id.into()),
        search_config,
    }))
    .await
    .unwrap()
    .into_inner()
}

pub async fn text_history(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    segment_id: uuid::Uuid,
) -> Vec<String> {
    let entries = NetworkSegmentStateHistory::for_segment(txn, &segment_id)
        .await
        .unwrap();

    // // Check that version numbers are always incrementing by 1
    if !entries.is_empty() {
        let mut version = entries[0].state_version.version_nr();
        for entry in &entries[1..] {
            assert_eq!(entry.state_version.version_nr(), version + 1);
            version += 1;
        }
    }

    let mut states = Vec::with_capacity(entries.len());
    for e in entries.into_iter() {
        states.push(e.state);
    }
    states
}
