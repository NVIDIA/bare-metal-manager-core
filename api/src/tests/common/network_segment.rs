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

use super::api_fixtures::TestEnv;
use crate::api::Api;
use crate::db::network_segment_state_history::NetworkSegmentStateHistory;
use forge_uuid::network::NetworkSegmentId;
use forge_uuid::vpc::VpcId;
use rpc::Uuid;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    NetworkSegment, NetworkSegmentCreationRequest, NetworkSegmentSearchConfig, NetworkSegmentType,
};
use tonic::Request;

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
            state: None,
            events: vec![],
            circuit_id: None,
            free_ip_count: 0,
            svi_ip: None,
        }];
        let inner = NetworkSegmentCreationRequest {
            vpc_id: Some(vpc_id.into()),
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
    id: Option<Uuid>,
    segment_type: i32,
    num_reserved: i32,
) -> rpc::forge::NetworkSegment {
    let vpc_id = if use_vpc {
        env.api
            .create_vpc(tonic::Request::new(rpc::forge::VpcCreationRequest {
                id: None,
                name: "test vpc 1".to_string(),
                tenant_organization_id: "2829bbe3-c169-4cd9-8b2a-19a8b1618a93".to_string(),
                network_security_group_id: None,
                tenant_keyset_id: None,
                network_virtualization_type: None,
                metadata: None,
            }))
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
            state: None,
            events: vec![],
            circuit_id: None,
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
    segment_id: NetworkSegmentId,
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

#[cfg(test)]
pub async fn text_history(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    segment_id: NetworkSegmentId,
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
