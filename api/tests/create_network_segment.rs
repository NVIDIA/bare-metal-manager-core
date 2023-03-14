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
use std::str::FromStr;

use carbide::db::UuidKeyedObjectFilter;
use carbide::kubernetes::VpcApiSimConfig;
use carbide::model::network_segment::{NetworkSegmentControllerState, NetworkSegmentDeletionState};
use carbide::state_controller::network_segment::handler::NetworkSegmentStateHandler;
use log::LevelFilter;
use mac_address::MacAddress;

use carbide::db::address_selection_strategy::AddressSelectionStrategy;
use carbide::db::machine_interface::MachineInterface;
use carbide::db::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use carbide::db::network_segment::{NetworkSegment, NewNetworkSegment};
use carbide::db::network_segment_state_history::NetworkSegmentStateHistory;
use carbide::db::vpc::Vpc;

pub mod common;
use common::api_fixtures::{create_test_env, TestApi, TestEnvConfig};
use rpc::forge::forge_server::Forge;
use rpc::forge::NetworkSegmentSearchConfig;
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

async fn get_segment_state(api: &TestApi, segment_id: uuid::Uuid) -> rpc::forge::TenantState {
    let segment = api
        .find_network_segments(Request::new(rpc::forge::NetworkSegmentQuery {
            id: Some(segment_id.into()),
            search_config: Some(NetworkSegmentSearchConfig {
                include_history: false,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .network_segments
        .remove(0);
    segment.state()
}

async fn get_segments(
    api: &TestApi,
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

async fn test_network_segment_lifecycle_impl(
    pool: sqlx::PgPool,
    delete_in_ready_state: bool,
    use_subdomain: bool,
    use_vpc: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let vpc_sim_config = VpcApiSimConfig {
        required_creation_attempts: if delete_in_ready_state { 2 } else { 1000 }, // never ready
        required_deletion_attempts: 2,
        ..Default::default()
    };
    let env = create_test_env(pool.clone(), TestEnvConfig { vpc_sim_config });

    let segment = create_network_segment_with_api(&env.api, use_subdomain, use_vpc).await;
    assert!(segment.created.is_some());
    assert!(segment.deleted.is_none());
    assert_eq!(segment.state(), rpc::forge::TenantState::Provisioning);
    let segment_id: uuid::Uuid = segment.id.clone().unwrap().try_into().unwrap();
    let prefix_id: uuid::Uuid = segment
        .prefixes
        .get(0)
        .unwrap()
        .id
        .clone()
        .unwrap()
        .try_into()
        .unwrap();

    // The TenantState only switches after the state controller recognized the update
    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        rpc::forge::TenantState::Provisioning
    );

    let state_handler = NetworkSegmentStateHandler::new(chrono::Duration::milliseconds(500));

    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;

    if delete_in_ready_state {
        // After 2 controller iterations, the segment should be ready
        assert_eq!(
            get_segment_state(&env.api, segment_id).await,
            rpc::forge::TenantState::Ready
        );

        let mut txn = pool.begin().await.unwrap();
        let prefix = NetworkPrefix::find(&mut txn, prefix_id).await;
        assert_eq!(
            prefix.as_ref().unwrap().circuit_id.clone().unwrap(),
            prefix.as_ref().unwrap().id.to_string() + "Circuit"
        );
        txn.commit().await.unwrap();
    } else {
        // The segment won't be ready, because VPC won't acknowledge creation
        assert_eq!(
            get_segment_state(&env.api, segment_id).await,
            rpc::forge::TenantState::Provisioning
        );
    }

    env.api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id.clone(),
        }))
        .await
        .expect("expect deletion to succeed");

    // After the API request, the segment should show up as deleting
    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        rpc::forge::TenantState::Terminating
    );
    // Make the controller aware about termination too
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;

    // Wait for the drain period
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // 3 controller iterations, one moves us into the Vpc deletion state, one tries
    // to delete the VPC, the third succeeds in deleting the VPC and cleans up the DB
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;

    let mut segments = env
        .api
        .find_network_segments(Request::new(rpc::forge::NetworkSegmentQuery {
            id: segment.id.clone(),
            search_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .network_segments;

    let mut txn = pool.begin().await.unwrap();
    if delete_in_ready_state {
        assert!(segments.is_empty());

        assert_eq!(
            text_history(&mut txn, segment_id).await,
            vec![
                "provisioning".to_string(),
                "ready".to_string(),
                "deleting/drain_allocated_ips".to_string(),
                "deleting/delete_vpc_resource_groups".to_string(),
            ]
        );
    } else {
        let segment = segments.remove(0);
        assert_eq!(segment.state(), rpc::forge::TenantState::Terminating);

        assert_eq!(
            text_history(&mut txn, segment_id).await,
            vec!["provisioning".to_string()]
        );
    }
    txn.commit().await.unwrap();

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
    let api = create_test_env(pool.clone(), Default::default()).api;
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
async fn test_network_segment_max_history_length(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let vpc_sim_config = VpcApiSimConfig {
        required_creation_attempts: 2,
        required_deletion_attempts: 2,
        ..Default::default()
    };
    let env = create_test_env(pool.clone(), TestEnvConfig { vpc_sim_config });

    let segment = create_network_segment_with_api(&env.api, true, true).await;
    let segment_id: uuid::Uuid = segment.id.clone().unwrap().try_into().unwrap();

    let state_handler = NetworkSegmentStateHandler::new(chrono::Duration::milliseconds(500));

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
                deletion_state: NetworkSegmentDeletionState::DeleteVPCResourceGroups
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
        assert_eq!(entry, "deleting/delete_vpc_resource_groups");
    }
    txn.rollback().await.unwrap();

    Ok(())
}

async fn text_history(
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

    entries
        .into_iter()
        .map(|entry| {
            match entry.state {
                NetworkSegmentControllerState::Provisioning => "provisioning",
                NetworkSegmentControllerState::Ready => "ready",
                NetworkSegmentControllerState::Deleting { deletion_state } => {
                    match deletion_state {
                        NetworkSegmentDeletionState::DeleteVPCResourceGroups => {
                            "deleting/delete_vpc_resource_groups"
                        }
                        NetworkSegmentDeletionState::DrainAllocatedIps { .. } => {
                            "deleting/drain_allocated_ips"
                        }
                    }
                }
            }
            .to_string()
        })
        .collect()
}
