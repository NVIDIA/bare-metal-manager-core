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

use std::sync::Arc;

use carbide_api_core::test_support::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY,
};
use carbide_api_core::test_support::rpc::forge::forge_server::Forge;
use carbide_network_segment_controller::context::NetworkSegmentStateHandlerServices;
use carbide_network_segment_controller::handler::NetworkSegmentStateHandler;
use carbide_network_segment_controller::io::NetworkSegmentStateControllerIO;
use carbide_utils::test_support::test_meter::TestMeter;
use ipnetwork::IpNetwork;
use state_controller::controller::StateController;
use tokio::sync::Mutex;

use crate::network::segment::TestNetworkSegment;
use crate::{ApiHandle, TestDomain, rpc};

pub struct TestNetworkController {
    api: Arc<ApiHandle>,
    controller: Arc<Mutex<StateController<NetworkSegmentStateControllerIO>>>,
}

impl TestNetworkController {
    pub(crate) fn new(api: Arc<ApiHandle>, processor_id: String, test_meter: &TestMeter) -> Self {
        let controller = StateController::builder()
            .database(
                api.database_connection.clone(),
                api.work_lock_manager_handle(),
            )
            .meter("carbide_machines", test_meter.meter())
            .processor_id(processor_id)
            .services(
                NetworkSegmentStateHandlerServices {
                    db_pool: api.database_connection.clone(),
                }
                .into(),
            )
            .state_handler(Arc::new(NetworkSegmentStateHandler::new(
                chrono::Duration::milliseconds(500),
                api.common_pools().ethernet.pool_vlan_id.clone(),
                api.common_pools().ethernet.pool_vni.clone(),
            )))
            .build_for_manual_iterations(api.cancel_token.clone())
            .expect("Unable to build state controller");
        Self {
            api,
            controller: Mutex::new(controller).into(),
        }
    }

    pub async fn create_underlay_segment(&self, domain: &TestDomain) -> TestNetworkSegment {
        let prefix = IpNetwork::new(
            FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.network(),
            FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.prefix(),
        )
        .unwrap()
        .to_string();
        let gateway = FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.ip();

        let request = rpc::forge::NetworkSegmentCreationRequest {
            id: None,
            mtu: Some(1500),
            name: "UNDERLAY".to_string(),
            prefixes: vec![rpc::forge::NetworkPrefix {
                id: None,
                prefix: prefix.to_string(),
                gateway: Some(gateway.to_string()),
                reserve_first: 3,
                free_ip_count: 0,
                svi_ip: None,
            }],
            subdomain_id: Some(domain.id),
            vpc_id: None,
            segment_type: rpc::forge::NetworkSegmentType::Underlay.into(),
        };

        let segment = self
            .api
            .create_network_segment(tonic::Request::new(request))
            .await
            .expect("Unable to create network segment")
            .into_inner();

        self.run_single_iteration().await;
        self.run_single_iteration().await;

        TestNetworkSegment {
            id: segment
                .id
                .expect("Id must be returned by create_network_segment API request"),
            relay_address: gateway,
        }
    }

    pub async fn create_admin_segment(&self, domain: &TestDomain) -> TestNetworkSegment {
        let prefix = IpNetwork::new(
            FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
            FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
        )
        .unwrap()
        .to_string();
        let gateway = FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.ip();

        let request = rpc::forge::NetworkSegmentCreationRequest {
            id: None,
            mtu: Some(1500),
            name: "ADMIN".to_string(),
            prefixes: vec![rpc::forge::NetworkPrefix {
                id: None,
                prefix: prefix.to_string(),
                gateway: Some(gateway.to_string()),
                reserve_first: 3,
                free_ip_count: 0,
                svi_ip: None,
            }],
            subdomain_id: Some(domain.id),
            vpc_id: None,
            segment_type: rpc::forge::NetworkSegmentType::Admin.into(),
        };

        let segment = self
            .api
            .create_network_segment(tonic::Request::new(request))
            .await
            .expect("Unable to create network segment")
            .into_inner();

        self.run_single_iteration().await;
        self.run_single_iteration().await;

        TestNetworkSegment {
            id: segment
                .id
                .expect("Id must be returned by create_network_segment API request"),
            relay_address: gateway,
        }
    }

    async fn run_single_iteration(&self) {
        self.controller.lock().await.run_single_iteration().await;
    }
}
