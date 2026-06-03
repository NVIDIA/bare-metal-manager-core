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

use carbide_ib_fabric::config::IBFabricConfig;

use crate::tests::common;
use crate::tests::common::api_fixtures::{TestEnvOverrides, create_managed_host};

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

    env.run_ib_fabric_monitor_iteration().await;
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
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_iteration_latency_milliseconds_count")
            .unwrap(),
        r#"1"#
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
    let discovery_info = machine.discovery_info.as_ref().unwrap();
    let guid1 = discovery_info.infiniband_interfaces[0].guid.clone();

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine.health.as_ref().expect("Machine should have health");
    let has_ib_port_down_alert = health.alerts.iter().any(|alert| alert.id == "IbPortDown");
    assert!(
        !has_ib_port_down_alert,
        "Machine should not have IbPortDown alert initially"
    );

    let ib_manager = env.ib_fabric_manager.get_mock_manager();
    ib_manager.set_port_state(&guid1, false);

    env.run_ib_fabric_monitor_iteration().await;

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine.health.as_ref().expect("Machine should have health");
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
    let health = machine.health.as_ref().expect("Machine should have health");
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
    let discovery_info = machine.discovery_info.as_ref().unwrap();
    let guid1 = discovery_info.infiniband_interfaces[0].guid.clone();
    let guid2 = discovery_info.infiniband_interfaces[1].guid.clone();
    let total_ports = discovery_info.infiniband_interfaces.len();

    let ib_manager = env.ib_fabric_manager.get_mock_manager();
    ib_manager.set_port_state(&guid1, false);
    ib_manager.set_port_state(&guid2, false);

    env.run_ib_fabric_monitor_iteration().await;

    let machine = env.find_machine(host_machine_id).await.remove(0);
    let health = machine.health.as_ref().expect("Machine should have health");
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
    let health = machine.health.as_ref().expect("Machine should have health");
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
    let health = machine.health.as_ref().expect("Machine should have health");
    let ib_port_down_alert = health.alerts.iter().find(|alert| alert.id == "IbPortDown");

    assert!(
        ib_port_down_alert.is_none(),
        "IbPortDown alert should be cleared when all ports are up"
    );

    Ok(())
}
