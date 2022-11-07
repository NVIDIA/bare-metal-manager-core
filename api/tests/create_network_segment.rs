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
use std::net::IpAddr;
use std::str::FromStr;

use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::domain::Domain;
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::vpc::Vpc;
use carbide::db::vpc_resource_state::VpcResourceState;
use carbide::CarbideError;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

const FIXTURE_CREATED_DOMAIN_UUID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");
const FIXTURE_CREATED_VPC_UUID: uuid::Uuid = uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");
const FIXTURE_CREATED_NETWORK_SEGMENT_ORPHAN_UUID: uuid::Uuid =
    uuid::uuid!("4de5bdd6-1f28-4ed4-aba7-f52e292f0fe8");

const FIXTURE_CREATED_NETWORK_SEGMENT_UUID: uuid::Uuid =
    uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_create_segment_with_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let domain = Domain::find_by_uuid(&mut txn, FIXTURE_CREATED_DOMAIN_UUID)
        .await?
        .unwrap();

    let vpc = Vpc::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_CREATED_VPC_UUID),
    )
    .await?
    .pop()
    .unwrap();

    // TODO - Find a domain based on UUID and use that on subdomain_id
    let segment: NetworkSegment = NewNetworkSegment {
        name: "integration_test".to_string(),
        subdomain_id: Some(domain.id().to_owned()),
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
    .await
    .expect("Unable to create network segment");

    let next_address = segment.next_address(&mut txn).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let new_prefix = NetworkPrefix::find(&mut txn, segment.prefixes[0].id).await;
    NetworkPrefix::update_vlan_id(&mut txn, new_prefix.unwrap().id, 123)
        .await
        .unwrap();
    txn.commit().await?;

    let mut txn = pool.begin().await?;
    let new_prefix = NetworkPrefix::find(&mut txn, segment.prefixes[0].id).await;
    assert_eq!(new_prefix.unwrap().vlan_id.unwrap(), 123);

    let _next_ipv4: IpAddr = "192.0.2.2".parse()?;
    let _next_ipv6: IpAddr = "2001:db8:f::64".parse()?;

    assert!(matches!(
        next_address.as_slice(),
        [Ok(_next_ipv4), Ok(_next_ipv6)]
    ));

    assert_eq!(next_address.len(), 2);

    Ok(())
}

#[sqlx::test(fixtures("create_vpc"))]
async fn test_create_segment_init_state(
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

    let segment = NewNetworkSegment {
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

    let new_prefix = NetworkPrefix::find(&mut txn, segment.prefixes[0].id).await;

    assert!(
        matches!(new_prefix, Ok(x) if x.current_state(&mut txn).await? == VpcResourceState::New)
    );

    Ok(())
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_network_segment_delete(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_CREATED_NETWORK_SEGMENT_ORPHAN_UUID),
    )
    .await?
    .pop()
    .unwrap();

    network_segment.delete(&mut txn).await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    let network_segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_CREATED_NETWORK_SEGMENT_ORPHAN_UUID),
    )
    .await?
    .pop();

    assert!(matches!(network_segment, None));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_network_segment_delete_fails(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_CREATED_NETWORK_SEGMENT_UUID),
    )
    .await?
    .pop()
    .unwrap();

    let delete_result = network_segment.delete(&mut txn).await;

    txn.commit().await?;

    assert!(matches!(
        delete_result,
        Err(CarbideError::NetworkSegmentDelete(_))
    ));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_network_segment_delete_fails_with_associated_machine_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_CREATED_NETWORK_SEGMENT_UUID),
    )
    .await?
    .pop()
    .unwrap();

    MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "colklink".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let delete_result = network_segment.delete(&mut txn).await;

    txn.commit().await?;

    assert!(matches!(
        delete_result,
        Err(CarbideError::NetworkSegmentDelete(_))
    ));

    Ok(())
}
