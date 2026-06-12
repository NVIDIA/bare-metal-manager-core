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
use std::time::Duration;

use carbide_site_explorer::SiteExplorer;
use carbide_site_explorer::config::SiteExplorerConfig;
use carbide_site_explorer::test_support::{MockEndpointExplorer, TestSiteExplorer};
use carbide_test_harness::prelude::*;
use carbide_uuid::machine::MachineId;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::site_explorer::EndpointExplorationError;
use rpc::forge::forge_server::Forge;
use tonic::Request;

fn site_explorer_config() -> SiteExplorerConfig {
    SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        retained_boot_interface_window: None,
        explorations_per_run: 10,
        concurrent_explorations: 1,
        run_interval: Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allocate_secondary_vtep_ip: false,
        ..Default::default()
    }
}

fn health_site_explorer_config() -> SiteExplorerConfig {
    SiteExplorerConfig {
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..site_explorer_config()
    }
}

fn test_site_explorer(
    test_harness: &TestHarness,
    explorer_config: SiteExplorerConfig,
) -> TestSiteExplorer {
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let api = test_harness.api();
    let site_explorer = SiteExplorer::new(
        api.database_connection.clone(),
        explorer_config,
        test_harness.test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(api.runtime_config.get_firmware_config()),
        api.common_pools().clone(),
        api.work_lock_manager_handle(),
        None,
        api.credential_manager().clone(),
    );
    TestSiteExplorer::new(site_explorer, endpoint_explorer)
}

async fn find_machine(
    api: &Api,
    machine_id: MachineId,
) -> Result<rpc::forge::Machine, Box<dyn std::error::Error>> {
    let mut machines = api
        .find_machines_by_ids(Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine_id],
            include_history: true,
        }))
        .await?
        .into_inner()
        .machines;
    assert_eq!(machines.len(), 1);

    Ok(machines.remove(0))
}

#[sqlx_test]
async fn test_site_explorer_health_report(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let test_harness = TestHarness::builder(pool.clone())
        .with_resource_pools(
            ResourcePoolBuilder::default()
                .with_secondary_vtep_ip("172.30.0.0/24")
                .build(),
        )
        .build()
        .await;
    let domain = test_harness.test_domain().await;
    let network_controller = test_harness.network_controller();
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    network_controller.create_admin_segment(&domain).await;
    let explorer = test_site_explorer(&test_harness, health_site_explorer_config());

    // Start with successful site explorer iterations to update
    // ExploredEndpoints with valid info and create the managed host.
    // Site Explorer needs to run against BMC IPs on an underlay segment. The
    // old api-core fixture mutated a tenant segment into underlay for this;
    // TestHarness creates an underlay segment directly.
    let created_host = test_harness
        .managed_host_builder(&explorer, underlay_segment)
        .with_dpu_network_status_reported()
        .build()
        .await;

    let host_machine = find_machine(test_harness.api(), created_host.host_machine_id).await?;
    let alerts = &host_machine.health.as_ref().unwrap().alerts;
    assert!(
        alerts.is_empty(),
        "expected no health alerts after successful exploration, got: {alerts:#?}"
    );

    // Now mark the Machine as unreachable. A health alert should be emitted
    explorer.insert_endpoint_result(
        created_host.host_bmc_ip,
        Err(EndpointExplorationError::Unreachable { details: None }),
    );

    explorer.run_single_iteration().await?;

    let host_machine = find_machine(test_harness.api(), created_host.host_machine_id).await?;

    let mut alerts = host_machine.health.as_ref().unwrap().alerts.clone();
    assert_eq!(
        alerts.len(),
        1,
        "expected exactly one health alert after failed exploration, got: {alerts:#?}"
    );
    for alert in alerts.iter_mut() {
        assert!(alert.in_alert_since.is_some());
        alert.in_alert_since = None;
    }
    alerts
        .sort_by(|alert1, alert2| (&alert1.id, &alert1.target).cmp(&(&alert2.id, &alert2.target)));
    assert_eq!(
        alerts,
        vec![rpc::health::HealthProbeAlert {
            id: "BmcExplorationFailure".to_string(),
            target: Some(created_host.host_bmc_ip.to_string()),
            in_alert_since: None,
            message: "Endpoint exploration failed: The endpoint was not reachable due to a generic network issue: None"
                .to_string(),
            tenant_message: None,
            classifications: vec!["PreventAllocations".to_string()]
        }]
    );

    Ok(())
}

/// A Managed Host whose `expected_machines` row is later removed becomes an
/// orphan: `audit_exploration_results` emits an `OrphanManagedHost` health
/// alert on the host's Machine. Re-adding the entry clears the alert on the
/// next iteration.
#[sqlx_test]
async fn test_orphan_managed_host_alert_emitted(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let test_harness = TestHarness::builder(pool.clone()).build().await;
    let domain = test_harness.test_domain().await;
    let network_controller = test_harness.network_controller();
    let underlay_segment = network_controller.create_underlay_segment(&domain).await;
    network_controller.create_admin_segment(&domain).await;
    let explorer = test_site_explorer(&test_harness, site_explorer_config());
    let created_host = test_harness
        .managed_host_builder(&explorer, underlay_segment)
        .build()
        .await;
    let host_bmc_mac = created_host.managed_host.bmc_mac_address;
    let chassis_serial = created_host.managed_host.serial.clone();

    // Orphan the host by deleting its expected_machines entry.
    let mut txn = pool.begin().await?;
    db::expected_machine::delete_by_mac(&mut txn, host_bmc_mac).await?;
    txn.commit().await?;

    // Run an iteration: audit_exploration_results should emit the orphan alert.
    explorer.run_single_iteration().await?;
    let alerts = find_machine(test_harness.api(), created_host.host_machine_id)
        .await?
        .health
        .unwrap()
        .alerts;
    assert!(
        alerts.iter().any(|a| a.id == "OrphanManagedHost"),
        "expected OrphanManagedHost alert, got: {alerts:#?}"
    );

    // Re-add the expected_machines entry. The alert should clear next iteration.
    let mut txn = pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: host_bmc_mac,
            data: ExpectedMachineData {
                serial_number: chassis_serial,
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    explorer.run_single_iteration().await?;
    let alerts = find_machine(test_harness.api(), created_host.host_machine_id)
        .await?
        .health
        .unwrap()
        .alerts;
    assert!(
        !alerts.iter().any(|a| a.id == "OrphanManagedHost"),
        "expected no OrphanManagedHost alert after re-adding expected_machines, got: {alerts:#?}"
    );

    Ok(())
}
