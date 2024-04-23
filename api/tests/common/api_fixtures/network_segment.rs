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

// The actual instances are at the moment created via the SQL fixtures
// in the fixtures folder. This file just contains the UUID references
// for those.

use carbide::state_controller::network_segment::handler::NetworkSegmentStateHandler;

use crate::common::network_segment::FIXTURE_CREATED_DOMAIN_UUID;

use super::TestEnv;

use rpc::forge::forge_server::Forge;

pub const FIXTURE_NETWORK_SEGMENT_ID: uuid::Uuid =
    uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");

pub const FIXTURE_NETWORK_SEGMENT_ID_1: uuid::Uuid =
    uuid::uuid!("4de5bdd6-1f28-4ed4-aba7-f52e292f0fe9");

pub async fn create_underlay_network_segment(env: &TestEnv) -> uuid::Uuid {
    create_network_segment(
        env,
        "UNDERLAY",
        "192.0.1.0/24",
        "192.0.1.1",
        rpc::forge::NetworkSegmentType::Underlay,
    )
    .await
}

pub async fn create_admin_network_segment(env: &TestEnv) -> uuid::Uuid {
    create_network_segment(
        env,
        "ADMIN",
        "192.0.2.0/24",
        "192.0.2.1",
        rpc::forge::NetworkSegmentType::Admin,
    )
    .await
}

async fn create_network_segment(
    env: &TestEnv,
    name: &str,
    prefix: &str,
    gateway: &str,
    segment_type: rpc::forge::NetworkSegmentType,
) -> uuid::Uuid {
    let request = rpc::forge::NetworkSegmentCreationRequest {
        id: None,
        mtu: Some(1500),
        name: name.to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: prefix.to_string(),
            gateway: Some(gateway.to_string()),
            reserve_first: 1,
            state: None,
            events: vec![],
            circuit_id: None,
            free_ip_count: 0,
        }],
        subdomain_id: Some(FIXTURE_CREATED_DOMAIN_UUID.into()),
        vpc_id: None,
        segment_type: segment_type as _,
    };

    let response = env
        .api
        .create_network_segment(tonic::Request::new(request))
        .await
        .expect("Unable to create network segment")
        .into_inner();
    let segment_id: uuid::Uuid = response.id.unwrap().try_into().unwrap();

    // Get the segment into ready state
    let handler = NetworkSegmentStateHandler::new(
        chrono::Duration::milliseconds(500),
        env.common_pools.ethernet.pool_vlan_id.clone(),
        env.common_pools.ethernet.pool_vni.clone(),
    );
    env.run_network_segment_controller_iteration(handler.clone())
        .await;
    env.run_network_segment_controller_iteration(handler).await;

    segment_id
}
