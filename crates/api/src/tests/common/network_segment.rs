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
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use rpc::forge::forge_server::Forge;
use rpc::forge::{NetworkSegment, NetworkSegmentCreationRequest, NetworkSegmentType};
use sqlx::PgConnection;
use tonic::Request;

use super::api_fixtures::TestEnv;
use crate::api::Api;
use crate::tests::common::rpc_builder::VpcCreationRequest;

pub struct NetworkSegmentHelper {
    inner: NetworkSegmentCreationRequest,
}

impl NetworkSegmentHelper {
    pub fn new_with_tenant_prefix(prefix: &str, gateway: &str, vpc_id: VpcId) -> Self {
        let prefixes = vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: prefix.into(),
            gateway: Some(gateway.into()),
            reserve_first: 1,
            free_ip_count: 0,
            svi_ip: None,
        }];
        let inner = NetworkSegmentCreationRequest {
            vpc_id: Some(vpc_id),
            name: "TEST_SEGMENT".into(),
            subdomain_id: None,
            mtu: Some(1500),
            prefixes,
            segment_type: NetworkSegmentType::Tenant as i32,
            id: None,
        };
        Self { inner }
    }

    pub async fn create_with_api(self, api: &Api) -> Result<NetworkSegment, tonic::Status> {
        let request = self.inner;
        api.create_network_segment(Request::new(request))
            .await
            .map(|response| response.into_inner())
    }
}

pub async fn create_network_segment_with_api(
    env: &TestEnv,
    use_subdomain: bool,
    use_vpc: bool,
    id: Option<NetworkSegmentId>,
    segment_type: i32,
    num_reserved: i32,
) -> rpc::forge::NetworkSegment {
    let vpc_id = if use_vpc {
        env.api
            .create_vpc(
                VpcCreationRequest::builder("test vpc 1", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93")
                    .tonic_request(),
            )
            .await
            .unwrap()
            .into_inner()
            .id
    } else {
        None
    };

    let request = rpc::forge::NetworkSegmentCreationRequest {
        id,
        mtu: Some(1500),
        name: "TEST_SEGMENT".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "192.0.2.0/24".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            reserve_first: num_reserved,
            free_ip_count: 0,
            svi_ip: None,
        }],
        subdomain_id: use_subdomain.then(|| env.domain.into()),
        vpc_id,
        segment_type,
    };

    env.api
        .create_network_segment(Request::new(request))
        .await
        .expect("Unable to create network segment")
        .into_inner()
}

pub async fn get_segment_state(api: &Api, segment_id: NetworkSegmentId) -> rpc::forge::TenantState {
    let segment = api
        .find_network_segments_by_ids(Request::new(rpc::forge::NetworkSegmentsByIdsRequest {
            network_segments_ids: vec![segment_id],
            include_history: false,
            include_num_free_ips: false,
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
    request: rpc::forge::NetworkSegmentsByIdsRequest,
) -> rpc::forge::NetworkSegmentList {
    api.find_network_segments_by_ids(Request::new(request))
        .await
        .unwrap()
        .into_inner()
}

#[cfg(test)]
pub async fn text_history(txn: &mut PgConnection, segment_id: NetworkSegmentId) -> Vec<String> {
    let entries = db::network_segment_state_history::for_segment(txn, &segment_id)
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
