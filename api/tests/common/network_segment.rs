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

use carbide::api::Api;
use carbide::db::network_segment_state_history::NetworkSegmentStateHistory;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    NetworkSegment, NetworkSegmentCreationRequest, NetworkSegmentSearchConfig, NetworkSegmentType,
};
use rpc::Uuid;
use tonic::Request;

pub const FIXTURE_CREATED_VPC_UUID: uuid::Uuid =
    uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");
pub const FIXTURE_CREATED_DOMAIN_UUID: uuid::Uuid =
    uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

pub struct NetworkSegmentHelper {
    inner: NetworkSegmentCreationRequest,
}

impl NetworkSegmentHelper {
    pub fn new_with_tenant_defaults() -> Self {
        Self::new_with_tenant_prefix("192.0.2.0/24", "192.0.2.1")
    }

    pub fn new_with_tenant_prefix(prefix: &str, gateway: &str) -> Self {
        let prefixes = vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: prefix.into(),
            gateway: Some(gateway.into()),
            reserve_first: 1,
            state: None,
            events: vec![],
            circuit_id: None,
            free_ip_count: 0,
        }];
        let inner = NetworkSegmentCreationRequest {
            vpc_id: Some(FIXTURE_CREATED_VPC_UUID.into()),
            name: "TEST_SEGMENT".into(),
            subdomain_id: None,
            mtu: Some(1500),
            prefixes,
            segment_type: NetworkSegmentType::Tenant as i32,
            id: None,
        };
        Self { inner }
    }

    pub fn use_default_test_domain(&mut self) {
        self.inner.subdomain_id = Some(FIXTURE_CREATED_DOMAIN_UUID.into());
    }

    pub async fn create_with_api(self, api: &Api) -> Result<NetworkSegment, tonic::Status> {
        let request = self.inner;
        api.create_network_segment(Request::new(request))
            .await
            .map(|response| response.into_inner())
    }
}

pub async fn create_network_segment_with_api(
    api: &Api,
    use_subdomain: bool,
    use_vpc: bool,
    id: Option<Uuid>,
    segment_type: i32,
    num_reserved: i32,
) -> rpc::forge::NetworkSegment {
    let request = rpc::forge::NetworkSegmentCreationRequest {
        id,
        mtu: Some(1500),
        name: "TEST_SEGMENT".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "192.0.2.0/24".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            reserve_first: num_reserved,
            state: None,
            events: vec![],
            circuit_id: None,
            free_ip_count: 0,
        }],
        subdomain_id: use_subdomain.then(|| FIXTURE_CREATED_DOMAIN_UUID.into()),
        vpc_id: use_vpc.then(|| FIXTURE_CREATED_VPC_UUID.into()),
        segment_type,
    };

    api.create_network_segment(Request::new(request))
        .await
        .expect("Unable to create network segment")
        .into_inner()
}

pub async fn get_segment_state(api: &Api, segment_id: uuid::Uuid) -> rpc::forge::TenantState {
    let segment = api
        .find_network_segments(Request::new(rpc::forge::NetworkSegmentQuery {
            id: Some(segment_id.into()),
            search_config: Some(NetworkSegmentSearchConfig {
                include_history: false,
                include_num_free_ips: false,
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
    api: &Api,
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
