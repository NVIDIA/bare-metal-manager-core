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

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use carbide::db::network_segment::{NetworkSegment, NetworkSegmentType, NewNetworkSegment};
use carbide::db::vpc::Vpc;
use carbide::db::UuidKeyedObjectFilter;
use carbide::model::network_segment::{
    NetworkDefinition, NetworkDefinitionSegmentType, NetworkSegmentControllerState,
    NetworkSegmentDeletionState,
};
use carbide::resource_pool::common::VLANID;
use carbide::resource_pool::{DbResourcePool, ResourcePoolStats, ValueType};
use carbide::state_controller::network_segment::handler::NetworkSegmentStateHandler;
use common::api_fixtures::create_test_env;
use common::network_segment::{
    create_network_segment_with_api, get_segment_state, get_segments, text_history,
    FIXTURE_CREATED_VPC_UUID,
};
use mac_address::MacAddress;

pub mod common;
use rpc::forge::forge_server::Forge;
use rpc::forge::NetworkSegmentSearchConfig;
use tonic::Request;

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
        segment_type: NetworkSegmentType::Admin,

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

        vlan_id: None,
        vni: None,
    }
    .persist(&mut txn, NetworkSegmentControllerState::Provisioning)
    .await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;

    assert!(NetworkPrefix::find(&mut txn, segment.prefixes[0].id)
        .await
        .is_ok());
    txn.commit().await?;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_delete_fails_with_associated_machine_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let api = create_test_env(pool.clone()).await.api;
    let segment = create_network_segment_with_api(&api, false, false).await;

    let mut txn = pool.begin().await?;
    let db_segment = NetworkSegment::find(
        &mut txn,
        UuidKeyedObjectFilter::One(segment.id.clone().unwrap().try_into().unwrap()),
        carbide::db::network_segment::NetworkSegmentSearchConfig::default(),
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

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_overlapping_prefix(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(pool.clone()).await;

    // This uses prefix "192.0.2.0/24"
    let _segment = create_network_segment_with_api(&env.api, false, false).await;

    // Now try to create another one with a prefix that is contained within the exising prefix
    let request = rpc::forge::NetworkSegmentCreationRequest {
        mtu: Some(1500),
        name: "TEST_SEGMENT_2".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "192.0.2.12/31".to_string(), // is inside 192.0.2.0/24
            gateway: Some("192.0.2.13".to_string()),
            reserve_first: 1,
            state: None,
            events: vec![],
            circuit_id: None,
        }],
        subdomain_id: None,
        vpc_id: None,
        segment_type: rpc::forge::NetworkSegmentType::Tenant as i32,
    };
    match env.api.create_network_segment(Request::new(request)).await {
        Ok(_) => Err(eyre::eyre!(
            "Overlapping network prefix was allowed. DB should prevent this."
        )),
        Err(status) if status.code() == tonic::Code::Internal => Err(eyre::eyre!(
            "Overlapping network prefix was caught by DB constraint. Should be checked earlier."
        )),
        Err(status) if status.code() == tonic::Code::InvalidArgument => Ok(()),
        Err(err) => Err(err.into()), // unexpected error
    }
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_max_history_length(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let segment = create_network_segment_with_api(&env.api, true, true).await;
    let segment_id: uuid::Uuid = segment.id.clone().unwrap().try_into().unwrap();

    let state_handler = NetworkSegmentStateHandler::new(
        chrono::Duration::milliseconds(500),
        env.common_pools.ethernet.pool_vlan_id.clone(),
        env.common_pools.ethernet.pool_vni.clone(),
    );

    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;

    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        rpc::forge::TenantState::Ready
    );

    let segment = get_segments(
        &env.api,
        segment_id,
        Some(NetworkSegmentSearchConfig {
            include_history: true,
        }),
    )
    .await;
    assert!(!segment.network_segments[0].history.is_empty());

    let segment = get_segments(
        &env.api,
        segment_id,
        Some(NetworkSegmentSearchConfig {
            include_history: false,
        }),
    )
    .await;
    assert!(segment.network_segments[0].history.is_empty());

    let segment = get_segments(&env.api, segment_id, None).await;
    assert!(segment.network_segments[0].history.is_empty());

    // Now insert a lot of state changes, and see if the history limit is kept
    const HISTORY_LIMIT: usize = 250;

    let mut txn = pool.begin().await.unwrap();
    let mut version = NetworkSegment::find(
        &mut txn,
        UuidKeyedObjectFilter::One(segment_id),
        carbide::db::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()[0]
        .controller_state
        .version;
    txn.commit().await.unwrap();

    for _ in 0..HISTORY_LIMIT + 50 {
        let mut txn = pool.begin().await.unwrap();
        assert!(NetworkSegment::try_update_controller_state(
            &mut txn,
            segment_id,
            version,
            &NetworkSegmentControllerState::Deleting {
                deletion_state: NetworkSegmentDeletionState::DBDelete
            }
        )
        .await
        .unwrap());
        version = NetworkSegment::find(
            &mut txn,
            UuidKeyedObjectFilter::One(segment_id),
            carbide::db::network_segment::NetworkSegmentSearchConfig::default(),
        )
        .await
        .unwrap()[0]
            .controller_state
            .version;
        txn.commit().await.unwrap();
    }

    let mut txn = pool.begin().await.unwrap();
    let history = text_history(&mut txn, segment_id).await;
    assert_eq!(history.len(), HISTORY_LIMIT);
    for entry in &history {
        assert_eq!(
            entry,
            "{\"state\": \"deleting\", \"deletion_state\": {\"state\": \"dbdelete\"}}"
        );
    }
    txn.rollback().await.unwrap();

    Ok(())
}

/// Create a network segment, delete it - release it's vlan_id,
/// and then create an new network segment.
/// The new segment should be able to re-use the vlan_id from
/// the deleted segment.
#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_vlan_reallocate(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;

    let state_handler = NetworkSegmentStateHandler::new(
        chrono::Duration::milliseconds(500),
        env.common_pools.ethernet.pool_vlan_id.clone(),
        env.common_pools.ethernet.pool_vni.clone(),
    );

    // create_test_env makes a vlan-id pool, so clean that up first
    let mut txn = db_pool.begin().await?;
    sqlx::query("DELETE FROM resource_pool WHERE name = $1")
        .bind(VLANID)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    // Only one vlan-id available
    let mut txn = db_pool.begin().await?;
    let vlan_pool = DbResourcePool::new(VLANID.to_string(), ValueType::Integer);
    vlan_pool.populate(&mut txn, vec!["1".to_string()]).await?;
    txn.commit().await?;

    // Create a network segment rpc call
    let segment = create_network_segment_with_api(&env.api, false, true).await;
    let segment_id = segment.id.clone().unwrap().try_into()?;

    // Value is allocated
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        vlan_pool.stats(&mut *txn).await?,
        ResourcePoolStats { used: 1, free: 0 }
    );
    txn.commit().await?;

    // Delete the segment, releasing the VNI back to the pool
    env.api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id.clone(),
        }))
        .await?;
    // Ready
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    // DrainAllocatedIPs
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    // Wait for the drain period
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Deleting
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    // DBDelete
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;

    // Value is free
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        vlan_pool.stats(&mut *txn).await?,
        ResourcePoolStats { used: 0, free: 1 }
    );
    txn.commit().await?;

    // Create a new segment, re-using the VLAN
    create_network_segment_with_api(&env.api, false, true).await;

    // Value allocated again
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        vlan_pool.stats(&mut *txn).await?,
        ResourcePoolStats { used: 1, free: 0 }
    );
    txn.commit().await?;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
pub async fn test_create_initial_networks(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool.clone()).await;
    let networks = HashMap::from([
        (
            "admin".to_string(),
            NetworkDefinition {
                segment_type: NetworkDefinitionSegmentType::Admin,
                prefix: "172.20.0.0/24".to_string(),
                gateway: "172.20.0.1".to_string(),
                mtu: 9000,
                reserve_first: 5,
            },
        ),
        (
            "DEV1-C09-IPMI-01".to_string(),
            NetworkDefinition {
                segment_type: NetworkDefinitionSegmentType::Underlay,
                prefix: "172.99.0.0/26".to_string(),
                gateway: "172.99.0.1".to_string(),
                mtu: 1500,
                reserve_first: 5,
            },
        ),
    ]);

    // Create them the first time, they should exist
    env.api.create_initial_networks(&networks).await?;

    let mut txn = db_pool.begin().await?;
    let admin = NetworkSegment::find_by_name(&mut txn, "admin").await?;
    assert_eq!(admin.mtu, 9000);
    assert_eq!(admin.segment_type, NetworkSegmentType::Admin);

    let underlay = NetworkSegment::find_by_name(&mut txn, "DEV1-C09-IPMI-01").await?;
    assert_eq!(underlay.mtu, 1500);
    assert_eq!(underlay.segment_type, NetworkSegmentType::Underlay);
    txn.commit().await?;

    // Now create them again. It should succeed but not create any more
    use carbide::db::network_segment::NetworkSegmentSearchConfig; // override global rpc one
    let search_cfg = NetworkSegmentSearchConfig::default();
    let mut txn = db_pool.begin().await?;
    let num_before = NetworkSegment::find(&mut txn, UuidKeyedObjectFilter::All, search_cfg)
        .await?
        .len();
    txn.commit().await?;
    env.api.create_initial_networks(&networks).await?;
    let mut txn = db_pool.begin().await?;
    let num_after = NetworkSegment::find(&mut txn, UuidKeyedObjectFilter::All, search_cfg)
        .await?
        .len();
    txn.commit().await?;
    assert_eq!(
        num_before, num_after,
        "second create_initial_networks should not have created any segments"
    );
    Ok(())
}
