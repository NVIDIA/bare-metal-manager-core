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

use forge_uuid::network::NetworkSegmentId;
use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr};

use crate::common::network_segment::FIXTURE_CREATED_DOMAIN_UUID;

use super::TestEnv;

use rpc::forge::forge_server::Forge;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref FIXTURE_NETWORK_SEGMENT_ID: NetworkSegmentId =
        uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
}

lazy_static! {
    pub static ref FIXTURE_NETWORK_SEGMENT_ID_1: NetworkSegmentId =
        uuid::uuid!("4de5bdd6-1f28-4ed4-aba7-f52e292f0fe9").into();
}

lazy_static! {
    pub static ref FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY: IpNetwork =
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 1, 1)), 24).unwrap();
}

lazy_static! {
    pub static ref FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY: IpNetwork =
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24).unwrap();
}

lazy_static! {
    pub static ref FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY: IpNetwork =
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1)), 24).unwrap();
}

pub async fn create_underlay_network_segment(env: &TestEnv) -> NetworkSegmentId {
    let prefix = IpNetwork::new(
        FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.network(),
        FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.prefix(),
    )
    .unwrap()
    .to_string();
    let gateway = FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.ip().to_string();

    create_network_segment(
        env,
        "UNDERLAY",
        &prefix,  // 192.0.1.0/24
        &gateway, // 192.0.1.1
        rpc::forge::NetworkSegmentType::Underlay,
        None,
    )
    .await
}

pub async fn create_admin_network_segment(env: &TestEnv) -> NetworkSegmentId {
    let prefix = IpNetwork::new(
        FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
        FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
    )
    .unwrap()
    .to_string();
    let gateway = FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.ip().to_string();

    create_network_segment(
        env,
        "ADMIN",
        &prefix,  // 192.0.2.0/24
        &gateway, // 192.0.2.1
        rpc::forge::NetworkSegmentType::Admin,
        None,
    )
    .await
}

pub async fn create_host_inband_network_segment(env: &TestEnv) -> NetworkSegmentId {
    let prefix = IpNetwork::new(
        FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
        FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
    )
    .unwrap()
    .to_string();
    let gateway = FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.ip().to_string();

    create_network_segment(
        env,
        "HOST_INBAND",
        &prefix,  // 192.0.3.0/24
        &gateway, // 192.0.3.1
        rpc::forge::NetworkSegmentType::HostInband,
        None,
    )
    .await
}

pub async fn create_network_segment(
    env: &TestEnv,
    name: &str,
    prefix: &str,
    gateway: &str,
    segment_type: rpc::forge::NetworkSegmentType,
    vpc_id: Option<rpc::Uuid>,
) -> NetworkSegmentId {
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
        vpc_id,
        segment_type: segment_type as _,
    };

    let response = env
        .api
        .create_network_segment(tonic::Request::new(request))
        .await
        .expect("Unable to create network segment")
        .into_inner();
    let segment_id: NetworkSegmentId = response.id.unwrap().try_into().unwrap();

    // Get the segment into ready state
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    segment_id
}
