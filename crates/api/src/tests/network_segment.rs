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

use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;

use carbide_uuid::network::NetworkSegmentId;
use common::network_segment::{
    NetworkSegmentHelper, create_network_segment_with_api, get_segment_state, get_segments,
    text_history,
};
use db::ObjectColumnFilter;
use db::network_segment::VpcColumn;
use db::vpc::IdColumn;
use forge_network::virtualization::VpcVirtualizationType;
use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::network_prefix::NewNetworkPrefix;
use model::network_segment;
use model::network_segment::{
    NetworkDefinition, NetworkDefinitionSegmentType, NetworkSegment, NetworkSegmentControllerState,
    NetworkSegmentDeletionState, NetworkSegmentType, NewNetworkSegment,
};
use model::resource_pool::common::VLANID;
use model::resource_pool::{ResourcePool, ResourcePoolStats, ValueType};
use model::vpc::UpdateVpcVirtualization;
use prometheus_text_parser::ParsedPrometheusMetrics;
use rpc::forge::forge_server::Forge;
use tonic::Request;

use crate::db_init;
use crate::tests::common;
use crate::tests::common::api_fixtures::network_segment::FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS;
use crate::tests::common::api_fixtures::{
    TEST_SITE_PREFIXES, TestEnvOverrides, create_test_env, create_test_env_with_overrides,
    get_vpc_fixture_id,
};
use crate::tests::common::rpc_builder::VpcCreationRequest;

#[crate::sqlx_test]
async fn test_advance_network_prefix_state(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::no_network_segments()).await;
    let mut txn = env.pool.begin().await?;

    let vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("test vpc 1", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    let vpc_id = vpc.id.unwrap();

    let id: NetworkSegmentId = uuid::Uuid::new_v4().into();
    let segment: NetworkSegment = db::network_segment::persist(
        NewNetworkSegment {
            id,
            name: "integration_test".to_string(),
            subdomain_id: None,
            mtu: 1500i32,
            vpc_id: Some(vpc_id),
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
            can_stretch: None,
        },
        &mut txn,
        NetworkSegmentControllerState::Provisioning,
    )
    .await?;

    txn.commit().await?;
    let mut txn = pool.begin().await?;
    let ns = db::network_segment::find_by_name(&mut txn, "integration_test")
        .await
        .unwrap();

    assert_eq!(ns.id, id);

    assert!(
        db::network_prefix::find(&mut txn, segment.prefixes[0].id)
            .await
            .is_ok()
    );
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_network_segment_delete_fails_with_associated_machine_interface(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;
    let segment = create_network_segment_with_api(
        &env,
        false,
        false,
        None,
        rpc::forge::NetworkSegmentType::Admin as i32,
        1,
    )
    .await;

    let mut txn = env.pool.begin().await?;
    let db_segment = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(db::network_segment::IdColumn, &segment.id.unwrap()),
        network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()
    .remove(0);

    db::machine_interface::create(
        &mut txn,
        &db_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        true,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;
    txn.commit().await.unwrap();

    let delete_result = env
        .api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id,
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

#[crate::sqlx_test]
async fn test_overlapping_prefix(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    // This uses prefix "192.0.2.0/24"
    let _segment = create_network_segment_with_api(
        &env,
        false,
        false,
        None,
        rpc::forge::NetworkSegmentType::Admin as i32,
        1,
    )
    .await;

    // Now try to create another one with a prefix that is contained within the exising prefix
    let request = rpc::forge::NetworkSegmentCreationRequest {
        id: None,
        mtu: Some(1500),
        name: "TEST_SEGMENT_2".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "192.0.2.12/30".to_string(), // is inside 192.0.2.0/24
            gateway: Some("192.0.2.13".to_string()),
            reserve_first: 1,
            free_ip_count: 0,
            svi_ip: None,
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

#[crate::sqlx_test]
async fn test_network_segment_max_history_length(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    let segment = create_network_segment_with_api(
        &env,
        true,
        true,
        None,
        rpc::forge::NetworkSegmentType::Admin as i32,
        1,
    )
    .await;
    let segment_id: NetworkSegmentId = segment.id.unwrap();

    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        rpc::forge::TenantState::Ready
    );

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_available_ips_count")
            .unwrap(),
        r#"{fresh="true",name="TEST_SEGMENT",prefix="192.0.2.0/24",type="admin"} 253"#
    );

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_total_ips_count")
            .unwrap(),
        r#"{fresh="true",name="TEST_SEGMENT",prefix="192.0.2.0/24",type="admin"} 256"#
    );

    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_reserved_ips_count")
            .unwrap(),
        r#"{fresh="true",name="TEST_SEGMENT",prefix="192.0.2.0/24",type="admin"} 1"#
    );

    let segment = get_segments(
        &env.api,
        rpc::forge::NetworkSegmentsByIdsRequest {
            network_segments_ids: vec![segment_id],
            include_history: true,
            include_num_free_ips: false,
        },
    )
    .await;
    assert!(!segment.network_segments[0].history.is_empty());

    let segment = get_segments(
        &env.api,
        rpc::forge::NetworkSegmentsByIdsRequest {
            network_segments_ids: vec![segment_id],
            include_history: false,
            include_num_free_ips: false,
        },
    )
    .await;
    assert!(segment.network_segments[0].history.is_empty());

    let segment = get_segments(
        &env.api,
        rpc::forge::NetworkSegmentsByIdsRequest {
            network_segments_ids: vec![segment_id],
            include_history: false,
            include_num_free_ips: false,
        },
    )
    .await;
    assert!(segment.network_segments[0].history.is_empty());

    // Now insert a lot of state changes, and see if the history limit is kept
    const HISTORY_LIMIT: usize = 250;

    let mut txn = env.pool.begin().await.unwrap();
    let mut version = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(db::network_segment::IdColumn, &segment_id),
        network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap()[0]
        .controller_state
        .version;
    txn.commit().await.unwrap();

    for _ in 0..HISTORY_LIMIT + 50 {
        let mut txn = env.pool.begin().await.unwrap();
        assert!(
            db::network_segment::try_update_controller_state(
                &mut txn,
                segment_id,
                version,
                &NetworkSegmentControllerState::Deleting {
                    deletion_state: NetworkSegmentDeletionState::DBDelete
                }
            )
            .await
            .unwrap()
        );
        version = db::network_segment::find_by(
            txn.as_mut(),
            ObjectColumnFilter::One(db::network_segment::IdColumn, &segment_id),
            network_segment::NetworkSegmentSearchConfig::default(),
        )
        .await
        .unwrap()[0]
            .controller_state
            .version;
        txn.commit().await.unwrap();
    }

    let mut txn = env.pool.begin().await.unwrap();
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

/// Create a network segment, delete it - release its vlan_id,
/// and then create an new network segment.
/// The new segment should be able to re-use the vlan_id from
/// the deleted segment.
#[crate::sqlx_test]
async fn test_vlan_reallocate(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env =
        create_test_env_with_overrides(db_pool.clone(), TestEnvOverrides::no_network_segments())
            .await;

    // create_test_env makes a vlan-id pool, so clean that up first
    let mut txn = db_pool.begin().await?;
    sqlx::query("DELETE FROM resource_pool WHERE name = $1")
        .bind(VLANID)
        .execute(&mut *txn)
        .await?;
    txn.commit().await?;

    // Only one vlan-id available
    let mut txn = db_pool.begin().await?;
    let vlan_pool = ResourcePool::new(VLANID.to_string(), ValueType::Integer);
    db::resource_pool::populate(&vlan_pool, &mut txn, vec!["1".to_string()], true).await?;
    txn.commit().await?;

    // Create a network segment rpc call
    let segment = create_network_segment_with_api(
        &env,
        false,
        true,
        None,
        rpc::forge::NetworkSegmentType::Admin as i32,
        1,
    )
    .await;

    // Value is allocated
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vlan_pool.name()).await?,
        ResourcePoolStats {
            used: 1,
            free: 0,
            auto_assign_used: 1,
            auto_assign_free: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    // Delete the segment, releasing the VNI back to the pool
    env.api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id,
        }))
        .await?;
    // Ready
    env.run_network_segment_controller_iteration().await;
    // DrainAllocatedIPs
    env.run_network_segment_controller_iteration().await;
    // Wait for the drain period
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Deleting
    env.run_network_segment_controller_iteration().await;
    // DBDelete
    env.run_network_segment_controller_iteration().await;

    // Value is free
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vlan_pool.name()).await?,
        ResourcePoolStats {
            used: 0,
            free: 1,
            auto_assign_used: 0,
            auto_assign_free: 1,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    // Create a new segment, re-using the VLAN
    create_network_segment_with_api(
        &env,
        false,
        true,
        None,
        rpc::forge::NetworkSegmentType::Admin as i32,
        1,
    )
    .await;

    // Value allocated again
    let mut txn = db_pool.begin().await?;
    assert_eq!(
        db::resource_pool::stats(&mut *txn, vlan_pool.name()).await?,
        ResourcePoolStats {
            used: 1,
            free: 0,
            auto_assign_used: 1,
            auto_assign_free: 0,
            non_auto_assign_free: 0,
            non_auto_assign_used: 0
        }
    );
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
pub async fn test_create_initial_networks(db_pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env =
        create_test_env_with_overrides(db_pool.clone(), TestEnvOverrides::no_network_segments())
            .await;
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
    crate::db_init::create_initial_networks(&env.api, &env.pool, &networks).await?;

    let mut txn = db_pool.begin().await?;
    let admin = db::network_segment::find_by_name(&mut txn, "admin").await?;
    assert_eq!(admin.mtu, 9000);
    assert_eq!(admin.segment_type, NetworkSegmentType::Admin);

    let underlay = db::network_segment::find_by_name(&mut txn, "DEV1-C09-IPMI-01").await?;
    assert_eq!(underlay.mtu, 1500);
    assert_eq!(underlay.segment_type, NetworkSegmentType::Underlay);
    txn.commit().await?;

    // Now create them again. It should succeed but not create any more
    use model::network_segment::NetworkSegmentSearchConfig; // override global rpc one
    let search_cfg = NetworkSegmentSearchConfig::default();
    let mut txn = db_pool.begin().await?;
    let num_before = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::<db::network_segment::IdColumn>::All,
        search_cfg,
    )
    .await?
    .len();
    txn.commit().await?;
    crate::db_init::create_initial_networks(&env.api, &env.pool, &networks).await?;
    let mut txn = db_pool.begin().await?;
    let num_after = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::<db::network_segment::IdColumn>::All,
        search_cfg,
    )
    .await?
    .len();
    txn.commit().await?;
    assert_eq!(
        num_before, num_after,
        "second create_initial_networks should not have created any segments"
    );
    Ok(())
}

#[crate::sqlx_test]
async fn test_find_segment_ids(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    let segment = create_network_segment_with_api(
        &env,
        false,
        false,
        None,
        rpc::forge::NetworkSegmentType::Admin as i32,
        1,
    )
    .await;
    let segment_id: NetworkSegmentId = segment.id.unwrap();

    let mut txn = env.pool.begin().await?;
    let mut segments = db::network_segment::list_segment_ids(&mut txn, None).await?;
    assert_eq!(segments.len(), 1);
    assert_eq!(segments.remove(0), segment_id);

    let mut segments =
        db::network_segment::list_segment_ids(&mut txn, Some(NetworkSegmentType::Admin)).await?;
    assert_eq!(segments.len(), 1);
    assert_eq!(segments.remove(0), segment_id);

    let segments =
        db::network_segment::list_segment_ids(&mut txn, Some(NetworkSegmentType::Underlay)).await?;
    assert_eq!(segments.len(), 0);
    let segments =
        db::network_segment::list_segment_ids(&mut txn, Some(NetworkSegmentType::Tenant)).await?;
    assert_eq!(segments.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_segment_creation_with_id(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    let id: NetworkSegmentId = uuid::Uuid::new_v4().into();
    let segment = create_network_segment_with_api(
        &env,
        false,
        false,
        Some(id),
        rpc::forge::NetworkSegmentType::Admin as i32,
        1,
    )
    .await;

    assert_eq!(segment.id, Some(id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_31_prefix_not_allowed(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    let request = rpc::forge::NetworkSegmentCreationRequest {
        id: None,
        mtu: Some(1500),
        name: "TEST_SEGMENT_1".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "192.0.2.12/31".to_string(),
            gateway: Some("192.0.2.13".to_string()),
            reserve_first: 1,
            free_ip_count: 0,
            svi_ip: None,
        }],
        subdomain_id: None,
        vpc_id: None,
        segment_type: rpc::forge::NetworkSegmentType::Tenant as i32,
    };

    for prefix in &[31, 32] {
        let mut request = request.clone();
        request.prefixes[0].prefix = format!("192.0.2.21/{prefix}");
        match env.api.create_network_segment(Request::new(request)).await {
            Ok(_) => {
                return Err(eyre::format_err!(
                    "{prefix} prefix is not allowed, but still code created segment."
                ));
            }
            Err(status) if status.code() == tonic::Code::InvalidArgument => {}
            Err(err) => {
                return Err(err.into());
            } // unexpected error
        };
    }

    Ok(())
}

// Attempt to use address space outside of what is configured in
// site_fabric_prefixes. In the test environment, this is set to 192.0.2.0/24.
#[crate::sqlx_test]
async fn test_segment_prefix_in_unconfigured_address_space(
    pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;
    let bad_prefix_segment =
        NetworkSegmentHelper::new_with_tenant_prefix("198.51.100.0/24", "198.51.100.1", vpc_id);
    let response = bad_prefix_segment.create_with_api(&env.api).await;

    // The API should have rejected our request with "invalid argument"; check
    // that it did.
    match response {
        Err(status) => {
            let status_code = status.code();
            match status_code {
                tonic::Code::InvalidArgument => Ok(()),
                _ => Err(eyre::format_err!(
                    "Unexpected gRPC error code from API: {status_code}"
                )),
            }
        }
        Ok(segment) => {
            let prefixes = segment.prefixes.iter().map(|p| p.prefix.as_str());
            let prefixes = itertools::join(prefixes, ", ");
            Err(eyre::format_err!(
                "The API did not reject our request to create a segment using \
                prefixes that fall outside of the site's address space: {prefixes}"
            ))
        }
    }
}

async fn test_network_segment_metrics(
    pool: sqlx::PgPool,
    test_type: MetricsTestType,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut overrides = TestEnvOverrides::no_network_segments();
    // This tests relies that drain period is not ended between two
    // consequential run_single_iteration
    overrides.network_segments_drain_period = Some(chrono::Duration::seconds(10));
    let env = create_test_env_with_overrides(pool.clone(), overrides).await;

    let segment =
        create_network_segment_with_api(&env, true, true, None, test_type.segment_type() as i32, 1)
            .await;
    let segment_id: NetworkSegmentId = segment.id.unwrap();

    env.run_network_segment_controller_iteration().await;

    env.run_network_segment_controller_iteration().await;

    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        rpc::forge::TenantState::Ready
    );

    let avail_str = format!(
        "{{fresh=\"true\",name=\"TEST_SEGMENT\",prefix=\"192.0.2.0/24\",type=\"{test_type}\"}} 253"
    );

    // We don't return stats for tenant network segments
    // We do return stats for underlay and tor type network segments
    if matches!(test_type, MetricsTestType::Tenant) {
        assert!(
            env.test_meter
                .formatted_metric("carbide_available_ips_count")
                .is_none()
        );
    } else {
        assert_eq!(
            env.test_meter
                .formatted_metric("carbide_available_ips_count")
                .unwrap(),
            avail_str
        );
    }

    let total_str = format!(
        "{{fresh=\"true\",name=\"TEST_SEGMENT\",prefix=\"192.0.2.0/24\",type=\"{test_type}\"}} 256"
    );

    if matches!(test_type, MetricsTestType::Tenant) {
        assert!(
            env.test_meter
                .formatted_metric("carbide_total_ips_count")
                .is_none()
        );
    } else {
        assert_eq!(
            env.test_meter
                .formatted_metric("carbide_total_ips_count")
                .unwrap(),
            total_str
        );
    }

    let reserved_str = format!(
        "{{fresh=\"true\",name=\"TEST_SEGMENT\",prefix=\"192.0.2.0/24\",type=\"{test_type}\"}} 1"
    );

    if matches!(test_type, MetricsTestType::Tenant) {
        assert!(
            env.test_meter
                .formatted_metric("carbide_reserved_ips_count")
                .is_none()
        );
    } else {
        assert_eq!(
            env.test_meter
                .formatted_metric("carbide_reserved_ips_count")
                .unwrap(),
            reserved_str
        );
    }

    drop(env);

    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::no_network_segments()).await;

    // Delete the segment, releasing the VNI back to the pool
    env.api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id,
        }))
        .await?;

    // Ready
    env.run_network_segment_controller_iteration().await;
    // DrainAllocatedIPs
    env.run_network_segment_controller_iteration().await;

    // Check to make sure we are returning stats even when the network segment
    // is not in the Ready state.
    let avail_str = format!(
        "{{fresh=\"true\",name=\"TEST_SEGMENT\",prefix=\"192.0.2.0/24\",type=\"{test_type}\"}} 253"
    );

    if matches!(test_type, MetricsTestType::Tenant) {
        assert!(
            env.test_meter
                .formatted_metric("carbide_available_ips_count")
                .is_none()
        );
    } else {
        assert_eq!(
            env.test_meter
                .formatted_metric("carbide_available_ips_count")
                .unwrap(),
            avail_str
        );
    }

    let total_str = format!(
        "{{fresh=\"true\",name=\"TEST_SEGMENT\",prefix=\"192.0.2.0/24\",type=\"{test_type}\"}} 256"
    );

    if matches!(test_type, MetricsTestType::Tenant) {
        assert!(
            env.test_meter
                .formatted_metric("carbide_total_ips_count")
                .is_none()
        );
    } else {
        assert_eq!(
            env.test_meter
                .formatted_metric("carbide_total_ips_count")
                .unwrap(),
            total_str
        );
    }

    let reserved_str = format!(
        "{{fresh=\"true\",name=\"TEST_SEGMENT\",prefix=\"192.0.2.0/24\",type=\"{test_type}\"}} 1"
    );

    if matches!(test_type, MetricsTestType::Tenant) {
        assert!(
            env.test_meter
                .formatted_metric("carbide_reserved_ips_count")
                .is_none()
        );
    } else {
        assert_eq!(
            env.test_meter
                .formatted_metric("carbide_reserved_ips_count")
                .unwrap(),
            reserved_str
        );
    }

    assert_eq!(
        env.test_meter
            .export_metrics()
            .parse::<ParsedPrometheusMetrics>()
            .unwrap(),
        test_type.fixture()
    );

    Ok(())
}

#[derive(Clone, Copy)]
enum MetricsTestType {
    Admin,
    Tenant,
    Tor,
}

impl Display for MetricsTestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricsTestType::Admin => write!(f, "admin"),
            MetricsTestType::Tenant => write!(f, "tenant"),
            MetricsTestType::Tor => write!(f, "tor"),
        }
    }
}

impl MetricsTestType {
    fn fixture(&self) -> ParsedPrometheusMetrics {
        match self {
            MetricsTestType::Admin => {
                include_str!("metrics_fixtures/test_network_segment_metrics_admin.txt")
                    .parse()
                    .unwrap()
            }
            MetricsTestType::Tenant => {
                include_str!("metrics_fixtures/test_network_segment_metrics_tenant.txt")
                    .parse()
                    .unwrap()
            }
            MetricsTestType::Tor => {
                include_str!("metrics_fixtures/test_network_segment_metrics_tor.txt")
                    .parse()
                    .unwrap()
            }
        }
    }

    fn segment_type(&self) -> NetworkSegmentType {
        match self {
            MetricsTestType::Admin => NetworkSegmentType::Admin,
            MetricsTestType::Tor => NetworkSegmentType::Underlay,
            MetricsTestType::Tenant => NetworkSegmentType::Tenant,
        }
    }
}

#[crate::sqlx_test]
async fn test_network_segment_metrics_admin(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_metrics(pool, MetricsTestType::Admin).await
}

#[crate::sqlx_test]
async fn test_network_segment_metrics_tenant(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_metrics(pool, MetricsTestType::Tenant).await
}

#[crate::sqlx_test]
async fn test_network_segment_metrics_tor(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_metrics(pool, MetricsTestType::Tor).await
}

#[crate::sqlx_test]
async fn test_update_svi_ip(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    env.create_vpc_and_tenant_segment().await;
    let vpc_id = get_vpc_fixture_id(&env).await;

    let mut txn = env.pool.begin().await?;
    let segments = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(VpcColumn, &vpc_id),
        network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;

    for segment in segments {
        for prefix in segment.prefixes {
            assert!(prefix.svi_ip.is_none());
        }
    }
    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let update_request = UpdateVpcVirtualization {
        id: vpc_id,
        if_version_match: None,
        network_virtualization_type: forge_network::virtualization::VpcVirtualizationType::Fnn,
    };
    db::vpc::update_virtualization(&update_request, &mut txn).await?;
    txn.commit().await?;

    // Already created segments must have SVI allocated.
    let mut txn = env.pool.begin().await?;
    let segments = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(VpcColumn, &vpc_id),
        network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;

    for segment in segments {
        for prefix in segment.prefixes {
            assert!(prefix.svi_ip.is_some());
        }
    }

    // Newly created segments should have SVI allocated once created.
    let _ = common::api_fixtures::network_segment::create_tenant_network_segment(
        &env.api,
        Some(vpc_id),
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1],
        "TENANT",
        true,
    )
    .await;

    // Get the tenant segment into ready state
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    let mut txn = env.pool.begin().await?;
    let segments = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(VpcColumn, &vpc_id),
        network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;

    for segment in segments {
        for prefix in segment.prefixes {
            assert!(prefix.svi_ip.is_some());
        }
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_update_svi_ip_admin_segment(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // This should create VPC for admin segment
    db_init::create_admin_vpc(&env.pool, Some(10600)).await?;

    let mut txn = env.pool.begin().await?;
    let admin_segment = db::network_segment::admin(&mut txn).await?;
    assert!(admin_segment.vpc_id.is_some());
    let admin_vpc = db::vpc::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(IdColumn, &admin_segment.vpc_id.unwrap()),
    )
    .await?;
    assert_eq!(
        admin_vpc[0].network_virtualization_type,
        VpcVirtualizationType::Fnn
    );
    db_init::update_network_segments_svi_ip(&env.pool).await?;
    let admin_segment = db::network_segment::admin(&mut txn).await?;
    for prefix in admin_segment.prefixes {
        assert!(prefix.svi_ip.is_some());
    }
    Ok(())
}

#[crate::sqlx_test]
async fn test_update_svi_ip_post_instance_allocation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let query = "UPDATE network_prefixes SET num_reserved = 2 WHERE id=$1";

    let mut txn = env.pool.begin().await?;
    let segments = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(db::network_segment::IdColumn, &segment_id),
        network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;

    // Let's make num_reserved 2 so that 3rd IP is assigned to instance.
    // This will force carbide to pick next free IP as SVI IP.
    sqlx::query(query)
        .bind(segments[0].prefixes[0].id)
        .execute(&mut *txn)
        .await
        .unwrap();

    txn.commit().await?;

    let mh = common::api_fixtures::create_managed_host(&env).await;

    let mut txn = env
        .pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert_eq!(
        db::instance_address::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();

    mh.instance_builer(&env)
        .single_interface_network_config(segment_id)
        .build()
        .await;

    // At this moment, the third IP is taken from the tenant subnet for the instance.
    let mut txn = env.pool.begin().await?;
    let mut segment = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(db::network_segment::IdColumn, &segment_id),
        network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;
    let segment = segment.remove(0);
    let update_request = UpdateVpcVirtualization {
        id: segment.vpc_id.unwrap(),
        if_version_match: None,
        network_virtualization_type: forge_network::virtualization::VpcVirtualizationType::Fnn,
    };
    db::vpc::update_virtualization(&update_request, &mut txn).await?;
    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let mut segment = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(db::network_segment::IdColumn, &segment_id),
        network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?;
    let segment = segment.remove(0);
    txn.rollback().await?;

    // Now the 4th IP is next available IP, so it should be assigned as SVI IP.
    assert_eq!(
        segment.prefixes[0].svi_ip.unwrap().to_string(),
        "192.0.4.3".to_string()
    );

    Ok(())
}

/// Verify that creating a network segment with an IPv6 prefix succeeds
/// through the full API handler chain.
#[crate::sqlx_test]
async fn test_create_network_segment_with_ipv6_prefix(
    pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let env = create_test_env_with_overrides(pool, TestEnvOverrides::no_network_segments()).await;

    let request = rpc::forge::NetworkSegmentCreationRequest {
        id: None,
        mtu: Some(1500),
        name: "IPV6_SEGMENT".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "2001:db8::/64".to_string(),
            gateway: None,
            reserve_first: 0,
            free_ip_count: 0,
            svi_ip: None,
        }],
        subdomain_id: None,
        vpc_id: None,
        segment_type: rpc::forge::NetworkSegmentType::Admin as i32,
    };

    let response = env
        .api
        .create_network_segment(Request::new(request))
        .await?
        .into_inner();

    assert_eq!(response.name, "IPV6_SEGMENT");
    assert_eq!(response.prefixes.len(), 1);
    assert_eq!(response.prefixes[0].prefix, "2001:db8::/64");
    assert!(response.prefixes[0].gateway.is_none());

    Ok(())
}

/// Verify that creating a tenant segment with both IPv4 and IPv6 prefixes
/// succeeds when the site fabric prefixes include both address families.
#[crate::sqlx_test]
async fn test_create_dual_stack_tenant_segment(pool: sqlx::PgPool) -> Result<(), eyre::Report> {
    // Include an IPv6 site fabric prefix so the containment check passes for dual-stack segments
    let mut site_prefixes = TEST_SITE_PREFIXES.to_vec();
    site_prefixes.push("2001:db8::/32".parse().unwrap());

    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            create_network_segments: Some(false),
            site_prefixes: Some(site_prefixes),
            ..Default::default()
        },
    )
    .await;

    let vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder("dual-stack vpc", "2829bbe3-c169-4cd9-8b2a-19a8b1618a93")
                .tonic_request(),
        )
        .await?
        .into_inner();

    let request = rpc::forge::NetworkSegmentCreationRequest {
        id: None,
        mtu: Some(1500),
        name: "DUAL_STACK_SEGMENT".to_string(),
        prefixes: vec![
            rpc::forge::NetworkPrefix {
                id: None,
                prefix: "192.0.2.0/24".to_string(),
                gateway: Some("192.0.2.1".to_string()),
                reserve_first: 3,
                free_ip_count: 0,
                svi_ip: None,
            },
            rpc::forge::NetworkPrefix {
                id: None,
                prefix: "2001:db8::/64".to_string(),
                gateway: None,
                reserve_first: 0,
                free_ip_count: 0,
                svi_ip: None,
            },
        ],
        subdomain_id: None,
        vpc_id: vpc.id,
        segment_type: rpc::forge::NetworkSegmentType::Tenant as i32,
    };

    let response = env
        .api
        .create_network_segment(Request::new(request))
        .await?
        .into_inner();

    assert_eq!(response.name, "DUAL_STACK_SEGMENT");
    assert_eq!(response.prefixes.len(), 2);

    // Verify both prefixes are present (order may vary)
    let prefix_strs: Vec<&str> = response
        .prefixes
        .iter()
        .map(|p| p.prefix.as_str())
        .collect();
    assert!(prefix_strs.contains(&"192.0.2.0/24"), "IPv4 prefix missing");
    assert!(
        prefix_strs.contains(&"2001:db8::/64"),
        "IPv6 prefix missing"
    );

    Ok(())
}

/// Verify that an IPv6 tenant segment prefix that is NOT contained in the site
/// fabric prefixes is correctly rejected, just like an uncontained IPv4 prefix would be.
#[crate::sqlx_test]
async fn test_ipv6_tenant_prefix_rejected_when_not_in_site_fabric(
    pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    // Site fabric prefixes include 2001:db8::/32 but NOT fd00::/8
    let mut site_prefixes = TEST_SITE_PREFIXES.to_vec();
    site_prefixes.push("2001:db8::/32".parse().unwrap());

    let env = create_test_env_with_overrides(
        pool,
        TestEnvOverrides {
            create_network_segments: Some(false),
            site_prefixes: Some(site_prefixes),
            ..Default::default()
        },
    )
    .await;

    let vpc = env
        .api
        .create_vpc(
            VpcCreationRequest::builder(
                "uncontained-ipv6-vpc",
                "2829bbe3-c169-4cd9-8b2a-19a8b1618a93",
            )
            .tonic_request(),
        )
        .await?
        .into_inner();

    // fd00:abcd::/48 is NOT contained in our site fabric prefixes
    let request = rpc::forge::NetworkSegmentCreationRequest {
        id: None,
        mtu: Some(1500),
        name: "UNCONTAINED_V6_SEGMENT".to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: "fd00:abcd::/48".to_string(),
            gateway: None,
            reserve_first: 0,
            free_ip_count: 0,
            svi_ip: None,
        }],
        subdomain_id: None,
        vpc_id: vpc.id,
        segment_type: rpc::forge::NetworkSegmentType::Tenant as i32,
    };

    let result = env.api.create_network_segment(Request::new(request)).await;

    assert!(
        result.is_err(),
        "Expected rejection of uncontained IPv6 prefix"
    );
    let status = result.unwrap_err();
    assert!(
        status
            .message()
            .contains("not contained within the configured site fabric prefixes"),
        "Error message should mention site fabric prefix containment, got: {}",
        status.message()
    );

    Ok(())
}
