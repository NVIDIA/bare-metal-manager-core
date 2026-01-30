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

use std::net::{IpAddr, Ipv4Addr};

use ::rpc::forge::forge_server::Forge;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;

use crate::api::Api;

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

lazy_static! {
    pub static ref FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS: [IpNetwork; 11] = [
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 1, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 2, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 3, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 4, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 5, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 6, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 7, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 8, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 9, 4, 1)), 24).unwrap(),
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 5, 1)), 24).unwrap(),
    ];
}

lazy_static! {
    pub static ref FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY_2: IpNetwork =
        IpNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 6, 1)), 24).unwrap();
}

pub async fn create_underlay_network_segment(api: &Api) -> NetworkSegmentId {
    let prefix = IpNetwork::new(
        FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.network(),
        FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.prefix(),
    )
    .unwrap()
    .to_string();
    let gateway = FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.ip().to_string();

    create_network_segment(
        api,
        "UNDERLAY",
        &prefix,  // 192.0.1.0/24
        &gateway, // 192.0.1.1
        rpc::forge::NetworkSegmentType::Underlay,
        None,
        true,
    )
    .await
}

pub async fn create_admin_network_segment(api: &Api) -> NetworkSegmentId {
    let prefix = IpNetwork::new(
        FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
        FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
    )
    .unwrap()
    .to_string();
    let gateway = FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.ip().to_string();

    create_network_segment(
        api,
        "ADMIN",
        &prefix,  // 192.0.2.0/24
        &gateway, // 192.0.2.1
        rpc::forge::NetworkSegmentType::Admin,
        None,
        true,
    )
    .await
}

pub async fn create_host_inband_network_segment(
    api: &Api,
    vpc_id: Option<VpcId>,
) -> NetworkSegmentId {
    let prefix = IpNetwork::new(
        FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
        FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
    )
    .unwrap()
    .to_string();
    let gateway = FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.ip().to_string();

    create_network_segment(
        api,
        "HOST_INBAND",
        &prefix,  // 192.0.3.0/24
        &gateway, // 192.0.3.1
        rpc::forge::NetworkSegmentType::HostInband,
        vpc_id,
        true,
    )
    .await
}

pub async fn create_tenant_network_segment(
    api: &Api,
    vpc_id: Option<VpcId>,
    network: IpNetwork,
    name: &str,
    include_subdomain: bool,
) -> NetworkSegmentId {
    let prefix = IpNetwork::new(network.network(), network.prefix())
        .unwrap()
        .to_string();
    let gateway = network.ip().to_string();

    create_network_segment(
        api,
        name,
        &prefix,
        &gateway,
        rpc::forge::NetworkSegmentType::Tenant,
        vpc_id,
        include_subdomain,
    )
    .await
}

pub async fn create_network_segment(
    api: &Api,
    name: &str,
    prefix: &str,
    gateway: &str,
    segment_type: rpc::forge::NetworkSegmentType,
    vpc_id: Option<VpcId>,
    include_subdomain: bool,
) -> NetworkSegmentId {
    let subdomain_id = if include_subdomain {
        let request = ::rpc::protos::dns::DomainSearchQuery {
            id: None,
            name: Some("dwrt1.com".to_string()),
        };

        let domain = api
            .find_domain(tonic::Request::new(request))
            .await
            .expect("Unable to find a domain")
            .into_inner()
            .domains
            .first()
            .and_then(|d| d.id)
            .map(::carbide_uuid::domain::DomainId::try_from)
            .unwrap()
            .unwrap();

        Some(domain)
    } else {
        None
    };

    let request = rpc::forge::NetworkSegmentCreationRequest {
        id: None,
        mtu: Some(1500),
        name: name.to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: prefix.to_string(),
            gateway: Some(gateway.to_string()),
            reserve_first: 3,
            free_ip_count: 0,
            svi_ip: None,
        }],
        subdomain_id,
        vpc_id,
        segment_type: segment_type as _,
    };

    let segment = api
        .create_network_segment(tonic::Request::new(request))
        .await
        .expect("Unable to create network segment")
        .into_inner();
    let segment_id: NetworkSegmentId = segment.id.unwrap();

    segment_id
}
