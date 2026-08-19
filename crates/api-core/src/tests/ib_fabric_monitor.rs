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

use carbide_ib_fabric::IbFabricMonitor;
use carbide_ib_fabric::config::IBFabricConfig;
use carbide_ib_fabric::ib::{Filter, IBFabric, IBFabricManager};
use carbide_instrument::testing::MetricsCapture;
use carbide_uuid::instance::InstanceId;
use db::ib_membership_cleanup_intent::IbMembershipCleanupIntent;
use model::ib::{DEFAULT_IB_FABRIC_NAME, IBMtu, IBNetwork, IBQosConf, IBRateLimit, IBServiceLevel};
use model::ib_partition::PartitionKey;
use model::machine::ManagedHostState;

use crate::tests::common;
use crate::tests::common::api_fixtures::ib_partition::{DEFAULT_TENANT, create_ib_partition};
use crate::tests::common::api_fixtures::instance::create_instance_with_ib_config;
use crate::tests::common::api_fixtures::{
    TestEnv, TestEnvOverrides, TestManagedHost, create_managed_host,
};

fn cleanup_intent(fabric: &str, pkey: PartitionKey, guid: &str) -> IbMembershipCleanupIntent {
    IbMembershipCleanupIntent {
        fabric: fabric.to_string(),
        pkey,
        guid: guid.to_string(),
    }
}

async fn insert_cleanup_intent<'e>(
    db: impl sqlx::Executor<'e, Database = sqlx::Postgres>,
    intent: &IbMembershipCleanupIntent,
) {
    sqlx::query(
        "INSERT INTO ib_membership_cleanup_intents (fabric, pkey, guid) VALUES ($1, $2, $3)",
    )
    .bind(intent.fabric.clone())
    .bind(i32::from(u16::from(intent.pkey)))
    .bind(intent.guid.clone())
    .execute(db)
    .await
    .unwrap();
}

async fn insert_cleanup_intent_range(
    pool: &sqlx::PgPool,
    pkey: PartitionKey,
    range: std::ops::RangeInclusive<usize>,
) {
    let mut txn = pool.begin().await.unwrap();
    for index in range {
        insert_cleanup_intent(
            txn.as_mut(),
            &cleanup_intent(
                DEFAULT_IB_FABRIC_NAME,
                pkey,
                &format!("cleanup-page-guid-{index:03}"),
            ),
        )
        .await;
    }
    txn.commit().await.unwrap();
}

async fn cleanup_intents(pool: &sqlx::PgPool) -> Vec<IbMembershipCleanupIntent> {
    db::ib_membership_cleanup_intent::list_batch(pool, None, None)
        .await
        .unwrap()
}

async fn cleanup_intent_exists(pool: &sqlx::PgPool, intent: &IbMembershipCleanupIntent) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM ib_membership_cleanup_intents \
         WHERE fabric = $1 AND pkey = $2 AND guid = $3)",
    )
    .bind(&intent.fabric)
    .bind(i32::from(u16::from(intent.pkey)))
    .bind(&intent.guid)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn wait_until_query_is_blocked_by(
    pool: &sqlx::PgPool,
    blocker_pid: i32,
    query_fragment: &str,
) {
    for _ in 0..300 {
        let blocked: bool = sqlx::query_scalar(
            r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_stat_activity AS activity
                    WHERE activity.datname = current_database()
                      AND activity.wait_event_type = 'Lock'
                      AND $1 = ANY(pg_blocking_pids(activity.pid))
                      AND activity.query ILIKE '%' || $2 || '%'
                )
            "#,
        )
        .bind(blocker_pid)
        .bind(query_fragment)
        .fetch_one(pool)
        .await
        .unwrap();
        if blocked {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    panic!("query containing {query_fragment:?} never waited for database lock");
}

fn ib_network(pkey: PartitionKey) -> IBNetwork {
    IBNetwork {
        name: "cleanup-test".to_string(),
        pkey: pkey.into(),
        ipoib: false,
        qos_conf: Some(IBQosConf {
            mtu: IBMtu::default(),
            service_level: IBServiceLevel::default(),
            rate_limit: IBRateLimit::default(),
        }),
        associated_guids: None,
        membership: None,
    }
}

async fn membership_is_present(fabric: &Arc<dyn IBFabric>, pkey: PartitionKey, guid: &str) -> bool {
    fabric
        .find_ib_port(Some(Filter {
            guids: None,
            pkey: Some(pkey.into()),
            state: None,
        }))
        .await
        .unwrap()
        .iter()
        .any(|port| port.guid == guid)
}

fn restarted_monitor(env: &TestEnv) -> IbFabricMonitor {
    IbFabricMonitor::new(
        env.pool.clone(),
        env.config.ib_fabrics.clone(),
        env.test_meter.meter(),
        env.ib_fabric_manager.clone(),
        env.config.host_health,
        env.api.work_lock_manager_handle.clone(),
    )
}

async fn cleanup_test_env(pool: sqlx::PgPool) -> TestEnv {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });
    common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await
}

async fn live_ib_instance(
    pool: sqlx::PgPool,
) -> (TestEnv, TestManagedHost, InstanceId, PartitionKey, String) {
    let env = cleanup_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let (partition_id, partition) = create_ib_partition(
        &env,
        "cleanup-live-partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let pkey = partition.status.as_ref().unwrap().pkey().parse().unwrap();
    let managed_host = create_managed_host(&env).await;
    let ib_config = rpc::forge::InstanceInfinibandConfig {
        ib_interfaces: vec![rpc::forge::InstanceIbInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
            virtual_function_id: None,
            ib_partition_id: Some(partition_id),
            device: "MT2910 Family [ConnectX-7]".to_string(),
            vendor: None,
            device_instance: 0,
        }],
    };
    let (instance_id, guid) = {
        let (test_instance, instance) =
            create_instance_with_ib_config(&env, &managed_host, ib_config, segment_id).await;
        let guid = instance.status().infiniband().ib_interfaces[0]
            .guid()
            .to_string();
        (test_instance.id, guid)
    };

    (env, managed_host, instance_id, pkey, guid)
}

#[crate::sqlx_test]
async fn test_ib_fabric_monitor(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    let iteration_metrics = MetricsCapture::start();
    env.run_ib_fabric_monitor_iteration().await;
    let iteration_count = iteration_metrics
        .histogram_count_delta("carbide_ib_monitor_iteration_latency_milliseconds", &[]);
    // Other API tests can drive the same process-global Event concurrently.
    // The Event-level test pins exact-once behavior; this integration check
    // only proves the real monitor path reaches the Event registry.
    assert!(
        iteration_count >= 1,
        "expected the monitor pass to record latency, observed {iteration_count}"
    );
    drop(iteration_metrics);
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_fabrics_count")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machine_ib_status_updates_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_ufm_version_count")
            .unwrap(),
        r#"{fabric="default",version="mock_ufm_1.0"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_fabric_error_count"),
        None
    );
    // The default partition is found
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_ufm_partitions_count")
            .unwrap(),
        r#"{fabric="default"} 1"#
    );
    // The fabric is configured securely
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_insecure_fabric_configuration_count")
            .unwrap(),
        r#"{fabric="default"} 0"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_allow_insecure_fabric_configuration_count")
            .unwrap(),
        r#"{fabric="default"} 0"#
    );

    // Set the default partition to full membership and test again
    // We now except the fabric to be reported as insecure
    env.ib_fabric_manager
        .get_mock_manager()
        .set_default_partition_membership(model::ib::IBPortMembership::Full);
    env.run_ib_fabric_monitor_iteration().await;
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_insecure_fabric_configuration_count")
            .unwrap(),
        r#"{fabric="default"} 1"#
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_allow_insecure_fabric_configuration_count")
            .unwrap(),
        r#"{fabric="default"} 0"#
    );

    Ok(())
}

#[crate::sqlx_test]
async fn cleanup_intent_repairs_a_delayed_bind_after_monitor_restart(pool: sqlx::PgPool) {
    let env = cleanup_test_env(pool.clone()).await;
    let pkey = PartitionKey::try_from(0x101).unwrap();
    let guid = "cleanup-restart-guid";
    let intent = cleanup_intent(DEFAULT_IB_FABRIC_NAME, pkey, guid);
    let mock = env.ib_fabric_manager.get_mock_manager();
    mock.register_port(guid.to_string());
    let fabric = env
        .ib_fabric_manager
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    fabric
        .bind_ib_ports(ib_network(pkey), vec![guid.to_string()])
        .await
        .unwrap();
    insert_cleanup_intent(&pool, &intent).await;

    let first_monitor = restarted_monitor(&env);
    assert_eq!(first_monitor.run_single_iteration().await.unwrap(), 1);
    assert!(!membership_is_present(&fabric, pkey, guid).await);

    // Simulate an older bind finishing after the first monitor's unbind, then
    // replace the monitor object while retaining its database state.
    fabric
        .bind_ib_ports(ib_network(pkey), vec![guid.to_string()])
        .await
        .unwrap();
    drop(first_monitor);
    let restarted_monitor = restarted_monitor(&env);
    assert_eq!(restarted_monitor.run_single_iteration().await.unwrap(), 1);

    assert!(!membership_is_present(&fabric, pkey, guid).await);
    assert_eq!(cleanup_intents(&pool).await, vec![intent]);
}

#[crate::sqlx_test]
async fn cleanup_intent_cursor_revisits_low_keys_despite_higher_arrivals(pool: sqlx::PgPool) {
    let env = cleanup_test_env(pool.clone()).await;
    let pkey = PartitionKey::try_from(0x101).unwrap();
    let low = cleanup_intent(DEFAULT_IB_FABRIC_NAME, pkey, "cleanup-page-guid-000");
    let boundary = cleanup_intent(DEFAULT_IB_FABRIC_NAME, pkey, "cleanup-page-guid-100");
    insert_cleanup_intent_range(&pool, pkey, 0..=100).await;

    let mock = env.ib_fabric_manager.get_mock_manager();
    mock.register_port(low.guid.clone());
    mock.register_port(boundary.guid.clone());
    let fabric = env
        .ib_fabric_manager
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    fabric
        .bind_ib_ports(
            ib_network(pkey),
            vec![low.guid.clone(), boundary.guid.clone()],
        )
        .await
        .unwrap();
    let monitor = restarted_monitor(&env);

    assert_eq!(monitor.run_single_iteration().await.unwrap(), 1);
    assert!(!membership_is_present(&fabric, pkey, &low.guid).await);
    assert!(membership_is_present(&fabric, pkey, &boundary.guid).await);

    // Rebind the low tuple, then keep adding at least a full page above the
    // first cycle's fixed high-water mark. The second pass finishes that
    // finite cycle; the third must wrap and revisit the low tuple rather than
    // chase the growing tail.
    fabric
        .bind_ib_ports(ib_network(pkey), vec![low.guid.clone()])
        .await
        .unwrap();
    insert_cleanup_intent_range(&pool, pkey, 101..=200).await;
    assert_eq!(monitor.run_single_iteration().await.unwrap(), 1);
    assert!(membership_is_present(&fabric, pkey, &low.guid).await);
    assert!(!membership_is_present(&fabric, pkey, &boundary.guid).await);

    insert_cleanup_intent_range(&pool, pkey, 201..=300).await;
    assert_eq!(monitor.run_single_iteration().await.unwrap(), 1);
    assert!(!membership_is_present(&fabric, pkey, &low.guid).await);
    assert!(cleanup_intent_exists(&pool, &low).await);
    assert!(cleanup_intent_exists(&pool, &boundary).await);
}

#[crate::sqlx_test]
async fn cleanup_intent_retries_after_ufm_failure(pool: sqlx::PgPool) {
    let env = cleanup_test_env(pool.clone()).await;
    let pkey = PartitionKey::try_from(0x101).unwrap();
    let guid = "cleanup-retry-guid";
    let intent = cleanup_intent(DEFAULT_IB_FABRIC_NAME, pkey, guid);
    let mock = env.ib_fabric_manager.get_mock_manager();
    mock.register_port(guid.to_string());
    let fabric = env
        .ib_fabric_manager
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    fabric
        .bind_ib_ports(ib_network(pkey), vec![guid.to_string()])
        .await
        .unwrap();
    insert_cleanup_intent(&pool, &intent).await;
    mock.set_unbind_failure(true);

    let failure_metrics = MetricsCapture::start();
    assert_eq!(
        restarted_monitor(&env)
            .run_single_iteration()
            .await
            .unwrap(),
        0
    );
    let failed_unbinds = failure_metrics.counter_delta(
        "carbide_ib_monitor_ufm_changes_applied_total",
        &[
            ("fabric", DEFAULT_IB_FABRIC_NAME),
            ("operation", "unbind_guid_from_pkey"),
            ("status", "error"),
        ],
    );
    assert!(
        failed_unbinds >= 1.0,
        "expected the cleanup failure Event, observed {failed_unbinds}"
    );
    drop(failure_metrics);
    assert!(membership_is_present(&fabric, pkey, guid).await);
    assert_eq!(cleanup_intents(&pool).await, vec![intent.clone()]);

    mock.set_unbind_failure(false);
    assert_eq!(
        restarted_monitor(&env)
            .run_single_iteration()
            .await
            .unwrap(),
        1
    );
    assert!(!membership_is_present(&fabric, pkey, guid).await);
    assert_eq!(cleanup_intents(&pool).await, vec![intent]);
}

#[crate::sqlx_test]
async fn cleanup_intent_live_presence_supersedes_only_the_exact_tuple(pool: sqlx::PgPool) {
    let (env, _, _, pkey, guid) = live_ib_instance(pool.clone()).await;

    let exact = cleanup_intent(DEFAULT_IB_FABRIC_NAME, pkey, &guid);
    let retained = [
        cleanup_intent("other-fabric", pkey, &guid),
        cleanup_intent(
            DEFAULT_IB_FABRIC_NAME,
            PartitionKey::try_from(u16::from(pkey) + 1).unwrap(),
            &guid,
        ),
        cleanup_intent(DEFAULT_IB_FABRIC_NAME, pkey, "other-guid"),
    ];
    for intent in std::iter::once(&exact).chain(&retained) {
        insert_cleanup_intent(&pool, intent).await;
    }

    restarted_monitor(&env)
        .run_single_iteration()
        .await
        .unwrap();

    let fabric = env
        .ib_fabric_manager
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    assert!(membership_is_present(&fabric, pkey, &guid).await);
    assert_eq!(
        cleanup_intents(&pool).await,
        vec![
            retained[2].clone(),
            retained[1].clone(),
            retained[0].clone(),
        ]
    );
}

#[crate::sqlx_test]
async fn cleanup_intent_rechecks_force_deletion_after_machine_lock_wait(pool: sqlx::PgPool) {
    let (env, managed_host, _, pkey, guid) = live_ib_instance(pool.clone()).await;
    let intent = cleanup_intent(DEFAULT_IB_FABRIC_NAME, pkey, &guid);
    let fabric = env
        .ib_fabric_manager
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    fabric
        .unbind_ib_ports(pkey.into(), vec![guid.clone()])
        .await
        .unwrap();
    assert!(!membership_is_present(&fabric, pkey, &guid).await);
    insert_cleanup_intent(&pool, &intent).await;

    // Hold the intent table until the monitor has read the live Instance and
    // recorded the now-missing membership. This fixes the stale candidate and
    // its ordinary bind action before ForceDeletion begins.
    let mut scan_gate = pool.begin().await.unwrap();
    let scan_gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(scan_gate.as_mut())
        .await
        .unwrap();
    sqlx::query("LOCK TABLE ib_membership_cleanup_intents IN ACCESS EXCLUSIVE MODE")
        .execute(scan_gate.as_mut())
        .await
        .unwrap();

    let monitor = restarted_monitor(&env);
    let monitor_iteration = tokio::spawn(async move { monitor.run_single_iteration().await });
    wait_until_query_is_blocked_by(&pool, scan_gate_pid, "ib_membership_cleanup_intents").await;

    let mut force_deletion = pool.begin().await.unwrap();
    let force_deletion_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(force_deletion.as_mut())
        .await
        .unwrap();
    let machine = managed_host.host().db_machine(&mut force_deletion).await;
    db::machine::advance(
        &machine,
        force_deletion.as_mut(),
        &ManagedHostState::ForceDeletion,
        None,
    )
    .await
    .unwrap();

    scan_gate.commit().await.unwrap();
    wait_until_query_is_blocked_by(&pool, force_deletion_pid, "SELECT row_to_json").await;
    force_deletion.commit().await.unwrap();

    assert_eq!(monitor_iteration.await.unwrap().unwrap(), 0);
    assert!(!membership_is_present(&fabric, pkey, &guid).await);
    assert!(cleanup_intent_exists(&pool, &intent).await);

    assert_eq!(
        restarted_monitor(&env)
            .run_single_iteration()
            .await
            .unwrap(),
        0
    );
    assert!(!membership_is_present(&fabric, pkey, &guid).await);
    assert!(cleanup_intent_exists(&pool, &intent).await);
}

#[crate::sqlx_test]
async fn cleanup_intent_deleted_instance_cannot_supersede_desired_absence(pool: sqlx::PgPool) {
    let (env, _, instance_id, pkey, guid) = live_ib_instance(pool.clone()).await;
    let intent = cleanup_intent(DEFAULT_IB_FABRIC_NAME, pkey, &guid);
    let fabric = env
        .ib_fabric_manager
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    assert!(membership_is_present(&fabric, pkey, &guid).await);

    // Normal release first marks the Instance deleted. Its Machine can remain
    // Assigned on the tenant network with the old IB config while termination
    // proceeds, but that stale config must not supersede desired absence.
    let mut txn = pool.begin().await.unwrap();
    db::instance::mark_as_deleted(instance_id, txn.as_mut())
        .await
        .unwrap();
    insert_cleanup_intent(txn.as_mut(), &intent).await;
    txn.commit().await.unwrap();

    let monitor = restarted_monitor(&env);
    monitor.run_single_iteration().await.unwrap();

    assert!(!membership_is_present(&fabric, pkey, &guid).await);
    assert!(cleanup_intent_exists(&pool, &intent).await);

    assert_eq!(monitor.run_single_iteration().await.unwrap(), 0);
    assert!(!membership_is_present(&fabric, pkey, &guid).await);
    assert!(cleanup_intent_exists(&pool, &intent).await);
}

/// Test that IB port down detection sets PreventAllocations alert
/// and clears it when ports recover.
///
/// - Machines with down IB ports should have PreventAllocations health alert
/// - This prevents tenant allocation failures at UFM
#[crate::sqlx_test]
async fn test_ib_port_down_sets_prevent_allocations_alert(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    // Create a managed host with IB interfaces
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    // Assign a SKU to the machine (required for IB port down tracking)
    // Since BOM validation is disabled in test config, we need to manually assign a SKU
    {
        let mut txn = pool.begin().await?;
        let sku = db::sku::generate_sku_from_machine(txn.as_mut(), &host_machine_id).await?;
        db::sku::create(&mut txn, &sku).await?;
        db::machine::assign_sku(txn.as_mut(), &host_machine_id, &sku.id).await?;
        txn.commit().await?;
    }

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let discovery_info = machine
        .status
        .as_ref()
        .unwrap()
        .discovery_info
        .as_ref()
        .unwrap();
    let guid1 = discovery_info.infiniband_interfaces[0].guid.clone();

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine
        .status
        .as_ref()
        .unwrap()
        .health
        .as_ref()
        .expect("Machine should have health");
    let has_ib_port_down_alert = health.alerts.iter().any(|alert| alert.id == "IbPortDown");
    assert!(
        !has_ib_port_down_alert,
        "Machine should not have IbPortDown alert initially"
    );

    let ib_manager = env.ib_fabric_manager.get_mock_manager();
    ib_manager.set_port_state(&guid1, false);

    env.run_ib_fabric_monitor_iteration().await;

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine
        .status
        .as_ref()
        .unwrap()
        .health
        .as_ref()
        .expect("Machine should have health");
    let ib_port_down_alert = health.alerts.iter().find(|alert| alert.id == "IbPortDown");
    assert!(
        ib_port_down_alert.is_some(),
        "Machine should have IbPortDown alert after port goes down"
    );

    let alert = ib_port_down_alert.unwrap();
    assert!(
        alert
            .classifications
            .contains(&"PreventAllocations".to_string()),
        "IbPortDown alert should have PreventAllocations classification"
    );

    assert!(
        alert.message.contains(&guid1),
        "Alert message should contain the down GUID"
    );

    ib_manager.set_port_state(&guid1, true);

    env.run_ib_fabric_monitor_iteration().await;

    // Verify IbPortDown alert is cleared
    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine
        .status
        .as_ref()
        .unwrap()
        .health
        .as_ref()
        .expect("Machine should have health");
    let has_ib_port_down_alert = health.alerts.iter().any(|alert| alert.id == "IbPortDown");
    assert!(
        !has_ib_port_down_alert,
        "IbPortDown alert should be cleared after port recovers"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_ib_multiple_ports_down(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides::with_config(config),
    )
    .await;

    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

    // Assign a SKU to the machine (required for IB port down tracking)
    {
        let mut txn = pool.begin().await?;
        let sku = db::sku::generate_sku_from_machine(txn.as_mut(), &host_machine_id).await?;
        db::sku::create(&mut txn, &sku).await?;
        db::machine::assign_sku(txn.as_mut(), &host_machine_id, &sku.id).await?;
        txn.commit().await?;
    }

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let discovery_info = machine
        .status
        .as_ref()
        .unwrap()
        .discovery_info
        .as_ref()
        .unwrap();
    let guid1 = discovery_info.infiniband_interfaces[0].guid.clone();
    let guid2 = discovery_info.infiniband_interfaces[1].guid.clone();
    let total_ports = discovery_info.infiniband_interfaces.len();

    let ib_manager = env.ib_fabric_manager.get_mock_manager();
    ib_manager.set_port_state(&guid1, false);
    ib_manager.set_port_state(&guid2, false);

    env.run_ib_fabric_monitor_iteration().await;

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine
        .status
        .as_ref()
        .unwrap()
        .health
        .as_ref()
        .expect("Machine should have health");
    let ib_port_down_alert = health
        .alerts
        .iter()
        .find(|alert| alert.id == "IbPortDown")
        .expect("Machine should have IbPortDown alert");

    assert!(
        ib_port_down_alert.message.contains("2 of"),
        "Alert should indicate 2 ports are down"
    );
    assert!(
        ib_port_down_alert
            .message
            .contains(&format!("{total_ports}")),
        "Alert should indicate total port count"
    );

    assert!(
        ib_port_down_alert.message.contains(&guid1),
        "Alert message should contain first down GUID"
    );
    assert!(
        ib_port_down_alert.message.contains(&guid2),
        "Alert message should contain second down GUID"
    );

    ib_manager.set_port_state(&guid1, true);
    env.run_ib_fabric_monitor_iteration().await;

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine
        .status
        .as_ref()
        .unwrap()
        .health
        .as_ref()
        .expect("Machine should have health");
    let ib_port_down_alert = health
        .alerts
        .iter()
        .find(|alert| alert.id == "IbPortDown")
        .expect("Machine should still have IbPortDown alert with one port down");

    assert!(
        ib_port_down_alert.message.contains("1 of"),
        "Alert should now indicate 1 port is down"
    );
    assert!(
        !ib_port_down_alert.message.contains(&guid1),
        "Alert should no longer contain recovered GUID"
    );
    assert!(
        ib_port_down_alert.message.contains(&guid2),
        "Alert should still contain down GUID"
    );

    ib_manager.set_port_state(&guid2, true);
    env.run_ib_fabric_monitor_iteration().await;

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine
        .status
        .as_ref()
        .unwrap()
        .health
        .as_ref()
        .expect("Machine should have health");
    let ib_port_down_alert = health.alerts.iter().find(|alert| alert.id == "IbPortDown");

    assert!(
        ib_port_down_alert.is_none(),
        "IbPortDown alert should be cleared when all ports are up"
    );

    Ok(())
}
