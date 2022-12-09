/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::str::FromStr;

use carbide::db::UuidKeyedObjectFilter;
use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::Vpc;
use carbide::db::vpc_resource_state::VpcResourceState;

pub mod common;
use common::api_fixtures::{create_test_api, TestApi};
use rpc::forge::forge_server::Forge;
use tonic::Request;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

const FIXTURE_CREATED_DOMAIN_UUID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");
const FIXTURE_CREATED_VPC_UUID: uuid::Uuid = uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");

async fn create_network_segment_with_api(
    api: &TestApi,
    use_subdomain: bool,
    use_vpc: bool,
) -> rpc::forge::NetworkSegment {
    let mut request = rpc::forge::NetworkSegmentCreationRequest {
        mtu: Some(1500),
        name: "TEST_SEGMENT".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "192.0.2.1/24".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            reserve_first: 1,
            state: None,
            events: vec![],
            circuit_id: None,
        }],
        subdomain_id: None,
        vpc_id: None,
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

async fn test_network_segment_lifecycle_impl(
    pool: sqlx::PgPool,
    delete_in_ready_state: bool,
    use_subdomain: bool,
    use_vpc: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let api = create_test_api(pool.clone());
    let segment = create_network_segment_with_api(&api, use_subdomain, use_vpc).await;
    assert!(segment.created.is_some());
    assert!(segment.deleted.is_none());
    assert_eq!(segment.state(), rpc::forge::TenantState::Provisioning);

    if delete_in_ready_state {
        let mut txn = pool.begin().await.unwrap();
        let db_segment = NetworkSegment::find(
            &mut txn,
            UuidKeyedObjectFilter::One(segment.id.clone().unwrap().try_into().unwrap()),
        )
        .await
        .unwrap()
        .remove(0);

        txn.commit().await?;

        let mut txn = pool.begin().await?;
        let new_prefix = NetworkPrefix::find(&mut txn, db_segment.prefixes[0].id).await;
        NetworkPrefix::update_circuit_id(&mut txn, new_prefix.unwrap().id, "vlan_123".to_owned())
            .await
            .unwrap();
        txn.commit().await?;

        let mut txn = pool.begin().await?;
        let new_prefix = NetworkPrefix::find(&mut txn, db_segment.prefixes[0].id).await;
        assert_eq!(
            new_prefix.unwrap().circuit_id.unwrap(),
            "vlan_123".to_owned()
        );

        let segment = api
            .find_network_segments(Request::new(rpc::forge::NetworkSegmentQuery {
                id: segment.id.clone(),
            }))
            .await
            .unwrap()
            .into_inner()
            .network_segments
            .remove(0);
        assert_eq!(segment.state(), rpc::forge::TenantState::Ready);
    }

    api.delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
        id: segment.id.clone(),
    }))
    .await
    .expect("expect deletion to succeed");

    let results = api
        .find_network_segments(Request::new(rpc::forge::NetworkSegmentQuery {
            id: segment.id,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(results.network_segments.is_empty());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, true, false, false).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_with_vpc(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, true, false, true).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_with_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, true, true, false).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_with_vpc_and_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, true, true, true).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_not_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, false, false, false).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_not_ready_with_vpc(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, false, false, true).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_not_ready_with_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, false, true, false).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_not_ready_with_vpc_and_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, false, true, true).await
}

#[sqlx::test(fixtures("create_vpc"))]
async fn test_advance_network_prefix_state(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let vpc = Vpc::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_CREATED_VPC_UUID),
    )
    .await?
    .pop()
    .unwrap();

    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: None,
        mtu: 1500i32,
        vpc_id: Some(vpc.id),

        prefixes: vec![
            NewNetworkPrefix {
                prefix: "192.0.2.1/24".parse().expect("can't parse network"),
                gateway: "192.0.2.1".parse().ok(),
                num_reserved: 1,
            },
            NewNetworkPrefix {
                prefix: "2001:db8:f::/64".parse().expect("can't parse network"),
                gateway: None,
                num_reserved: 100,
            },
        ],
    }
    .persist(&mut txn)
    .await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    let new_prefix = NetworkPrefix::find(&mut txn, segment.prefixes[0].id).await?;
    assert_eq!(
        new_prefix.current_state(&mut txn).await?,
        VpcResourceState::New
    );

    new_prefix
        .advance(&mut txn, &rpc::VpcResourceStateMachineInput::Submit)
        .await?;

    new_prefix
        .advance(&mut txn, &rpc::VpcResourceStateMachineInput::Accept)
        .await?;

    new_prefix
        .advance(&mut txn, &rpc::VpcResourceStateMachineInput::Wait)
        .await?;

    new_prefix
        .advance(&mut txn, &rpc::VpcResourceStateMachineInput::VpcSuccess)
        .await?;

    let current_state = new_prefix.current_state(&mut txn).await?;

    txn.commit().await?;

    assert_eq!(current_state, VpcResourceState::Ready);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_delete_fails_with_associated_machine_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let api = create_test_api(pool.clone());
    let segment = create_network_segment_with_api(&api, false, false).await;

    let mut txn = pool.begin().await?;
    let db_segment = NetworkSegment::find(
        &mut txn,
        UuidKeyedObjectFilter::One(segment.id.clone().unwrap().try_into().unwrap()),
    )
    .await
    .unwrap()
    .remove(0);

    MachineInterface::create(
        &mut txn,
        &db_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "colklink".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;
    txn.commit().await.unwrap();

    let delete_result = api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id.clone(),
        }))
        .await;

    let err = delete_result.expect_err("Expected deletion to fail");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        err.message(),
        "Network Segment can't be deleted with associated MachineInterface"
    );

    Ok(())
}
