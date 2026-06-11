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

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use carbide_site_explorer::config::SiteExplorerConfig;
use carbide_site_explorer::{SiteExplorer, endpoint_exploration_work_key};
use common::api_fixtures::TestEnv;
use common::api_fixtures::endpoint_explorer::MockEndpointExplorer;
use db::{self, ObjectColumnFilter};
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::hardware_info::HardwareInfo;
use model::machine::ManagedHostStateSnapshot;
use model::site_explorer::{
    Chassis, EndpointExplorationError, EndpointExplorationReport, ExploredEndpoint,
};
use model::test_support::{DpuConfig, ManagedHostConfig};
use rpc::forge::forge_server::Forge;
use rpc::{DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use sqlx::PgPool;
use tonic::Request;

use crate::sqlx_test;
use crate::test_support::fixture_config::{
    DpuConfigExt as _, FixtureDefault as _, ManagedHostConfigExt as _,
};
use crate::tests::common;
use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::TestEnvOverrides;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    create_host_inband_network_segment,
};
use crate::tests::common::api_fixtures::site_explorer::MockExploredHost;
use crate::tests::common::rpc_builder::DhcpDiscovery;

trait SiteExplorerConstructor {
    fn new_site_explorer(
        &self,
        explorer_config: SiteExplorerConfig,
        endpoint_explorer: &Arc<MockEndpointExplorer>,
    ) -> SiteExplorer;
}

impl SiteExplorerConstructor for TestEnv {
    fn new_site_explorer(
        &self,
        explorer_config: SiteExplorerConfig,
        endpoint_explorer: &Arc<MockEndpointExplorer>,
    ) -> SiteExplorer {
        SiteExplorer::new(
            self.pool.clone(),
            explorer_config,
            self.test_meter.meter(),
            endpoint_explorer.clone(),
            Arc::new(self.config.get_firmware_config()),
            self.common_pools.clone(),
            self.api.work_lock_manager_handle.clone(),
            self.rms_sim.as_rms_client(),
            self.test_credential_manager.clone(),
        )
    }
}

// Test that discover_machines will reject request of machine that was not created by site-explorer when create_machines = true
#[sqlx_test]
async fn test_disable_machine_creation_outside_site_explorer(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.site_explorer = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;
    let host_config = env.managed_host_config();

    let hardware_info = HardwareInfo::from(&host_config);
    let discovery_info = DiscoveryInfo::try_from(hardware_info.clone()).unwrap();
    let oob_mac = MacAddress::from_str("a0:88:c2:08:80:95")?;
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(oob_mac, "192.0.1.1")
                .vendor_string("NVIDIA/OOB")
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner();

    assert!(response.machine_interface_id.is_some());

    let _dm_response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: response.machine_interface_id,
            discovery_data: Some(DiscoveryData::Info(discovery_info)),
            create_machine: true,
            ..Default::default()
        }))
        .await;

    // assert!(dm_response.is_err_and(|e| e.message().contains("was not discovered by site-explore")));

    Ok(())
}

#[sqlx_test]
async fn test_site_explorer_health_report(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) =
        common::api_fixtures::create_managed_host(&env).await.into();
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let host_machine = env.find_machine(host_machine_id).await.remove(0);
    let dpu_machine = env.find_machine(dpu_machine_id).await.remove(0);
    let bmc_ip: std::net::IpAddr = host_machine
        .bmc_info
        .as_ref()
        .unwrap()
        .ip()
        .parse()
        .unwrap();
    let chassis_serial = host_machine
        .discovery_info
        .as_ref()
        .unwrap()
        .dmi_data
        .as_ref()
        .unwrap()
        .chassis_serial
        .clone();

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    // Start with one successful site explorer to update ExploredEndpoints with valid info
    endpoint_explorer.insert_endpoint_results(vec![
        (
            bmc_ip,
            Ok(ManagedHostConfig::with_serial(chassis_serial.clone()).into()),
        ),
        (
            dpu_machine.bmc_info.as_ref().unwrap().ip().parse().unwrap(),
            Ok(DpuConfig::with_serial(
                dpu_machine
                    .discovery_info
                    .as_ref()
                    .unwrap()
                    .dmi_data
                    .as_ref()
                    .unwrap()
                    .product_serial
                    .clone(),
            )
            .into()),
        ),
    ]);

    // This is a hack to Make Site Explorer work against the ingested BMC IPs
    // There is currently no separate segment for tenant, admin and underlay networks,
    // which prevents site explorer from running
    let mut txn = env.pool.begin().await?;
    let query = "UPDATE network_segments SET network_segment_type='underlay' WHERE id=$1";
    sqlx::query::<_>(query)
        .bind(segment_id)
        .execute(&mut *txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 10,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);

    // Run site explorer and check the health state of the Machine
    explorer.run_single_iteration().await.unwrap();

    let host_machine = env.find_machine(host_machine_id).await.remove(0);

    let alerts = &host_machine.health.as_ref().unwrap().alerts;
    assert!(alerts.is_empty());

    // Now mark the Machine as unreachable. A health alert should be emitted
    endpoint_explorer.insert_endpoint_result(
        host_machine
            .bmc_info
            .as_ref()
            .unwrap()
            .ip()
            .parse()
            .unwrap(),
        Err(EndpointExplorationError::Unreachable { details: None }),
    );

    explorer.run_single_iteration().await.unwrap();

    let host_machine = env.find_machine(host_machine_id).await.remove(0);

    let mut alerts = host_machine.health.as_ref().unwrap().alerts.clone();
    assert_eq!(alerts.len(), 1);
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
            target: Some(bmc_ip.to_string()),
            in_alert_since: None,
            message: "Endpoint exploration failed: The endpoint was not reachable due to a generic network issue: None"
                .to_string(),
            tenant_message: None,
            classifications: vec!["PreventAllocations".to_string()]
        }]
    );

    Ok(())
}

#[sqlx_test]
async fn test_site_explorer_new_host_fixture(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            ..Default::default()
        },
    )
    .await;

    create_host_inband_network_segment(&env.api, None).await;

    let zero_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::with_dpus(Vec::new()))
            .await?;
    assert_eq!(zero_dpu_host.dpu_snapshots.len(), 0);

    let single_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default()).await?;
    assert_eq!(single_dpu_host.dpu_snapshots.len(), 1);

    let config = ManagedHostConfig::with_dpus((0..2).map(|_| DpuConfig::default()).collect());
    let two_dpu_host = api_fixtures::site_explorer::new_host(&env, config).await?;
    assert_eq!(two_dpu_host.dpu_snapshots.len(), 2);

    Ok(())
}

#[sqlx_test]
async fn test_site_explorer_fixtures_singledpu(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;

    let mock_host = ManagedHostConfig::default();
    api_fixtures::site_explorer::register_expected_machine(&env, &mock_host, None).await;
    let mock_explored_host = MockExploredHost::new(&env, mock_host);

    let snapshot: ManagedHostStateSnapshot = mock_explored_host
        // Run host DHCP first
        .discover_dhcp_host_bmc(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_none()); // Should not have a machine-id for BMC
            Ok(())
        })
        .await?
        // Then DPU DHCP
        .discover_dhcp_dpu_bmc(0, |result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_none()); // Should not have a machine-id for BMC
            Ok(())
        })
        .await?
        // Place site explorer results into the mock site explorer
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .await
        .mark_preingestion_complete()
        .await?
        .run_site_explorer_iteration()
        .await
        // Get DHCP on the DPU interface
        .discover_dhcp_host_primary_iface(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_some());
            Ok(())
        })
        .await?
        // Run discovery
        .discover_machine(|result, _| {
            assert!(result.is_ok());
            Ok(())
        })
        .await?
        .run_site_explorer_iteration()
        .await
        .finish(|mock| async move {
            // Get the managed host snapshot from the database
            let machine_id = mock.machine_discovery_response.unwrap().machine_id.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(
                    &mut mock.test_env.db_reader(),
                    &machine_id,
                    Default::default(),
                )
                .await
                .transpose()
                .unwrap()?,
            )
        })
        .await?;

    assert_eq!(snapshot.dpu_snapshots.len(), 1);

    Ok(())
}

#[sqlx_test]
async fn test_site_explorer_fixtures_multidpu(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;

    let mock_host = ManagedHostConfig {
        dpus: vec![DpuConfig::default(), DpuConfig::default()],
        ..ManagedHostConfig::default()
    };
    api_fixtures::site_explorer::register_expected_machine(&env, &mock_host, None).await;
    let mock_explored_host = MockExploredHost::new(&env, mock_host);

    let snapshot: ManagedHostStateSnapshot = mock_explored_host
        // Run host DHCP first
        .discover_dhcp_host_bmc(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_none()); // Should not have a machine-id for BMC
            Ok(())
        })
        .await?
        .discover_dhcp_dpu_bmc(0, |result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_none()); // Should not have a machine-id for BMC
            Ok(())
        })
        .await?
        .discover_dhcp_dpu_bmc(1, |result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_none()); // Should not have a machine-id for BMC
            Ok(())
        })
        .await?
        // Place site explorer results into the mock site explorer
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .await
        .mark_preingestion_complete()
        .await?
        .run_site_explorer_iteration()
        .await
        // Get DHCP on the DPU interface
        .discover_dhcp_host_primary_iface(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_some());
            Ok(())
        })
        .await?
        // Run discovery
        .discover_machine(|result, _| {
            assert!(result.is_ok());
            Ok(())
        })
        .await?
        .run_site_explorer_iteration()
        .await
        .finish(|mock| async move {
            // Get the managed host snapshot from the database
            let machine_id = mock.machine_discovery_response.unwrap().machine_id.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(
                    &mut mock.test_env.db_reader(),
                    &machine_id,
                    Default::default(),
                )
                .await
                .transpose()
                .unwrap()?,
            )
        })
        .await?;

    assert_eq!(snapshot.dpu_snapshots.len(), 2);

    Ok(())
}

#[sqlx_test]
async fn test_site_explorer_fixtures_zerodpu_site_explorer_before_host_dhcp(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            ..Default::default()
        },
    )
    .await;

    create_host_inband_network_segment(&env.api, None).await;

    let mock_host = ManagedHostConfig {
        dpus: vec![],
        ..ManagedHostConfig::default()
    };
    api_fixtures::site_explorer::register_expected_machine(&env, &mock_host, None).await;
    let mock_explored_host = MockExploredHost::new(&env, mock_host);

    let snapshot: ManagedHostStateSnapshot = mock_explored_host
        // Run host BMC DHCP first
        .discover_dhcp_host_bmc(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_none()); // Should not have a machine-id for BMC
            Ok(())
        })
        .await?
        // Place site explorer results into the mock site explorer
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .await
        .mark_preingestion_complete()
        .await?
        .run_site_explorer_iteration()
        .await
        // Get DHCP on the host in-band NIC
        .discover_dhcp_host_primary_iface(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_some());
            Ok(())
        })
        .await?
        // Run discovery
        .discover_machine(|result, _| {
            assert!(result.is_ok());
            Ok(())
        })
        .await?
        .run_site_explorer_iteration()
        .await
        .finish(|mock| async move {
            // Get the managed host snapshot from the database
            let machine_id = mock.machine_discovery_response.unwrap().machine_id.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(
                    &mut mock.test_env.db_reader(),
                    &machine_id,
                    Default::default(),
                )
                .await
                .transpose()
                .unwrap()?,
            )
        })
        .await?;

    assert_eq!(snapshot.dpu_snapshots.len(), 0);

    Ok(())
}

/// Ensure that if a zero-dpu host DHCP's from its in-band interface before site-explorer has a
/// chance to run (and a machine_interface is created for its MAC with no machine-id), that
/// site-explorer can "repair" the situation when it discovers the machine, by migrating the machine
/// interface to the new managed host.
#[sqlx_test]
async fn test_site_explorer_fixtures_zerodpu_dhcp_before_site_explorer(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            ..Default::default()
        },
    )
    .await;

    create_host_inband_network_segment(&env.api, None).await;

    let mock_host = ManagedHostConfig {
        dpus: vec![],
        ..ManagedHostConfig::default()
    };
    api_fixtures::site_explorer::register_expected_machine(&env, &mock_host, None).await;
    let mock_explored_host = MockExploredHost::new(&env, mock_host);

    let snapshot: ManagedHostStateSnapshot = mock_explored_host
        // Run BMC DHCP first
        .discover_dhcp_host_bmc(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_none()); // Should not have a machine-id for BMC
            Ok(())
        })
        .await?
        // Get DHCP on the system in-band NIC, *before* we run site-explorer.
        .discover_dhcp_host_primary_iface(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_none());
            assert!(response.machine_interface_id.is_some());
            Ok(())
        })
        .await?
        .then(|mock| {
            let pool = mock.test_env.pool.clone();
            let mac_address = *mock.managed_host.non_dpu_macs.first().unwrap();
            async move {
                let mut txn = pool.begin().await?;
                let interfaces =
                    db::machine_interface::find_by_mac_address(txn.as_mut(), mac_address).await?;
                assert_eq!(interfaces.len(), 1);
                // There should be no machine_id yet as site-explorer has not run
                assert!(interfaces[0].machine_id.is_none());
                Ok(())
            }
        })
        .await?
        // Place mock exploration results into the mock site explorer
        .insert_site_exploration_results()?
        .run_site_explorer_iteration()
        .await
        // Mark preingestion as complete before we run site-explorer for the first time
        .mark_preingestion_complete()
        .await?
        .run_site_explorer_iteration()
        .await
        .then(|mock| {
            let pool = mock.test_env.pool.clone();
            async move {
                let mut txn = pool.begin().await?;
                let predicted_interfaces = db::predicted_machine_interface::find_by(
                    &mut txn,
                    ObjectColumnFilter::<db::predicted_machine_interface::MachineIdColumn>::All,
                )
                .await?;
                // We should not have minted a predicted_machine_interface for this, since DHCP
                // happened first, which should have created a real interface for it (which we would
                // then migrate to the new host.)
                assert_eq!(predicted_interfaces.len(), 0);
                Ok(())
            }
        })
        .await?
        // Simulate a reboot: Get DHCP on the system in-band NIC, after we run site-explorer.
        .discover_dhcp_host_primary_iface(|result, _| {
            let response = result.unwrap().into_inner();
            assert!(response.machine_id.is_some());
            Ok(())
        })
        .await?
        // Run discovery
        .discover_machine(|result, _| {
            assert!(result.is_ok());
            Ok(())
        })
        .await?
        .finish(|mock| async move {
            // Get the managed host snapshot from the database
            let machine_id = mock.machine_discovery_response.unwrap().machine_id.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(
                    &mut mock.test_env.db_reader(),
                    &machine_id,
                    Default::default(),
                )
                .await
                .transpose()
                .unwrap()?,
            )
        })
        .await?;

    assert_eq!(snapshot.dpu_snapshots.len(), 0);

    Ok(())
}

#[sqlx_test]
async fn test_delete_explored_endpoint(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Delete an endpoint that doesn't exist
    let non_existent_ip = "192.168.1.100";
    let response = env
        .api
        .delete_explored_endpoint(Request::new(rpc::forge::DeleteExploredEndpointRequest {
            ip_address: non_existent_ip.to_string(),
        }))
        .await?
        .into_inner();

    assert!(!response.deleted);
    assert_eq!(
        response.message,
        Some(format!(
            "No explored endpoint found with IP {non_existent_ip}"
        ))
    );

    // Create an explored endpoint that's not part of a managed host
    let standalone_endpoint_ip = "192.168.1.50";
    let mut txn = env.pool.begin().await?;

    db::explored_endpoints::insert(
        IpAddr::from_str(standalone_endpoint_ip)?,
        &EndpointExplorationReport::default(),
        false,
        &mut txn,
    )
    .await?;
    txn.commit().await?;

    // Verify the endpoint exists
    let mut txn = env.pool.begin().await?;
    let endpoints =
        db::explored_endpoints::find_all_by_ip(IpAddr::from_str(standalone_endpoint_ip)?, &mut txn)
            .await?;
    assert_eq!(endpoints.len(), 1);
    txn.commit().await?;

    // Delete the standalone endpoint - should succeed
    let response = env
        .api
        .delete_explored_endpoint(Request::new(rpc::forge::DeleteExploredEndpointRequest {
            ip_address: standalone_endpoint_ip.to_string(),
        }))
        .await?
        .into_inner();

    assert!(response.deleted);
    assert_eq!(
        response.message,
        Some(format!(
            "Successfully deleted explored endpoint with IP {standalone_endpoint_ip}"
        ))
    );

    // Verify the endpoint was deleted
    let mut txn = env.pool.begin().await?;
    let endpoints =
        db::explored_endpoints::find_all_by_ip(IpAddr::from_str(standalone_endpoint_ip)?, &mut txn)
            .await?;
    assert_eq!(endpoints.len(), 0);
    txn.commit().await?;

    // Create explored endpoints that are part of a managed host
    let mh = common::api_fixtures::create_managed_host(&env).await;

    // Get the machines to find their BMC IPs
    let mut txn = env.pool.begin().await?;
    let host_machine = mh.host().db_machine(&mut txn).await;
    let dpu_machine = mh.dpu().db_machine(&mut txn).await;
    txn.commit().await?;

    let host_ip = host_machine.bmc_info.ip.as_ref().unwrap();
    let dpu_ip = dpu_machine.bmc_info.ip.as_ref().unwrap();

    // Now try to delete the host endpoint - should fail because it's part of a machine
    let error = env
        .api
        .delete_explored_endpoint(Request::new(rpc::forge::DeleteExploredEndpointRequest {
            ip_address: host_ip.to_string(),
        }))
        .await
        .expect_err("Should fail with InvalidArgument error");

    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        error.message(),
        format!(
            "Cannot delete endpoint {host_ip} because a machine exists for it. Did you mean to force-delete the machine?"
        )
    );

    // Try to delete the DPU endpoint - should also fail
    let error = env
        .api
        .delete_explored_endpoint(Request::new(rpc::forge::DeleteExploredEndpointRequest {
            ip_address: dpu_ip.to_string(),
        }))
        .await
        .expect_err("Should fail with InvalidArgument error");

    assert_eq!(error.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        error.message(),
        format!(
            "Cannot delete endpoint {dpu_ip} because a machine exists for it. Did you mean to force-delete the machine?"
        )
    );

    // Verify both endpoints still exist
    let mut txn = env.pool.begin().await?;
    let host_endpoints = db::explored_endpoints::find_all_by_ip(*host_ip, &mut txn).await?;
    assert_eq!(host_endpoints.len(), 1);

    let dpu_endpoints = db::explored_endpoints::find_all_by_ip(*dpu_ip, &mut txn).await?;
    assert_eq!(dpu_endpoints.len(), 1);
    txn.commit().await?;

    Ok(())
}

#[sqlx_test]
async fn test_get_machine_position_info(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let (_host_machine_id, dpu_machine_id) =
        common::api_fixtures::create_managed_host(&env).await.into();

    let dpu_machine = env.find_machine(dpu_machine_id).await.remove(0);
    let bmc_ip: IpAddr = dpu_machine.bmc_info.as_ref().unwrap().ip().parse().unwrap();

    // Get the existing explored endpoint (created by create_managed_host) and update it with position info
    let mut txn = env.pool.begin().await?;
    let existing = db::explored_endpoints::find_by_ips(txn.as_mut(), vec![bmc_ip])
        .await?
        .pop()
        .unwrap();
    let mut report = existing.report;
    report.chassis = vec![Chassis {
        id: "Chassis_0".to_string(),
        physical_slot_number: Some(5),
        compute_tray_index: Some(2),
        topology_id: Some(10),
        revision_id: Some(3),
        ..Default::default()
    }];
    report.physical_slot_number = Some(5);
    report.compute_tray_index = Some(2);
    report.topology_id = Some(10);
    report.revision_id = Some(3);
    db::explored_endpoints::try_update(bmc_ip, existing.report_version, &report, false, &mut txn)
        .await?;
    txn.commit().await?;

    // Call the API
    let response = env
        .api
        .get_machine_position_info(tonic::Request::new(rpc::forge::MachinePositionQuery {
            machine_ids: vec![dpu_machine_id],
        }))
        .await?
        .into_inner();

    // Verify the response
    assert_eq!(response.machine_position_info.len(), 1);
    let info = &response.machine_position_info[0];
    assert_eq!(info.machine_id, Some(dpu_machine_id));
    assert_eq!(info.physical_slot_number, Some(5));
    assert_eq!(info.compute_tray_index, Some(2));
    assert_eq!(info.topology_id, Some(10));
    assert_eq!(info.revision_id, Some(3));

    Ok(())
}

/// Test get_machine_position_info with a machine that has no explored endpoint
#[sqlx_test]
async fn test_get_machine_position_info_no_endpoint(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use rpc::forge::forge_server::Forge;

    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let (_host_machine_id, dpu_machine_id) =
        common::api_fixtures::create_managed_host(&env).await.into();

    // Don't create any explored endpoint - just query

    // Call the API
    let response = env
        .api
        .get_machine_position_info(tonic::Request::new(rpc::forge::MachinePositionQuery {
            machine_ids: vec![dpu_machine_id],
        }))
        .await?
        .into_inner();

    // Machine should be in the response but with all None position info
    assert_eq!(response.machine_position_info.len(), 1);
    let info = &response.machine_position_info[0];
    assert_eq!(info.machine_id, Some(dpu_machine_id));
    assert_eq!(info.physical_slot_number, None);
    assert_eq!(info.compute_tray_index, None);
    assert_eq!(info.topology_id, None);
    assert_eq!(info.revision_id, None);

    Ok(())
}

/// A queued `set_nic_mode` only takes effect after a host power cycle, and
/// site-explorer drives that power cycle itself for every vendor -- the
/// Redfish `ComputerSystem.Reset` action is standard across BMCs. This is
/// the non-Dell guard for that behavior: a Lenovo host whose DPU needs the
/// mode correction gets an automatic `PowerCycle` on its host BMC in the
/// same pass that issued `set_nic_mode`, rather than parking on a manual
/// power cycle.
#[sqlx_test]
async fn test_site_explorer_power_cycles_non_dell_host_to_apply_nic_mode(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use model::expected_machine::{DpuMode, ExpectedMachine, ExpectedMachineData};
    use model::site_explorer::NicMode;

    let env = common::api_fixtures::create_test_env(pool).await;

    // DPU hardware reports DPU mode; the operator-declared NicMode override
    // is what forces the correction (and therefore the power cycle).
    let dpu_config = DpuConfig {
        nic_mode: Some(NicMode::Dpu),
        ..DpuConfig::default()
    };
    let mock_host = ManagedHostConfig {
        dpus: vec![dpu_config],
        vendor: Some(bmc_vendor::BMCVendor::Lenovo),
        ..ManagedHostConfig::default()
    };
    let host_bmc_mac = mock_host.bmc_mac_address;

    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: host_bmc_mac,
            data: ExpectedMachineData {
                bmc_username: "ADMIN".to_string(),
                bmc_password: "PASS".to_string(),
                serial_number: "EM-866-NIC-POWERCYCLE".to_string(),
                metadata: model::metadata::Metadata::new_with_default_name(),
                dpu_mode: DpuMode::NicMode,
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    common::api_fixtures::site_explorer::MockExploredHost::new(&env, mock_host)
        .discover_dhcp_host_bmc(|_, _| Ok(()))
        .await?
        .discover_dhcp_dpu_bmc(0, |_, _| Ok(()))
        .await?
        .insert_site_exploration_results()?
        // First iteration: initial endpoint exploration.
        .run_site_explorer_iteration()
        .await
        .mark_preingestion_complete()
        .await?
        // Second iteration: the matching loop issues `set_nic_mode` and,
        // with the DPU now needing reconfiguration, power-cycles the host
        // so the queued mode change applies.
        .run_site_explorer_iteration()
        .await;

    let nic_mode_calls = env.endpoint_explorer.set_nic_mode_calls.lock().unwrap();
    assert!(
        nic_mode_calls.iter().any(|(_, mode)| *mode == NicMode::Nic),
        "expected set_nic_mode(Nic) before the power cycle; calls so far: {nic_mode_calls:?}"
    );

    let power_calls = env
        .endpoint_explorer
        .redfish_power_control_calls
        .lock()
        .unwrap();
    assert!(
        power_calls
            .iter()
            .any(|(_, action)| matches!(action, libredfish::SystemPowerControl::PowerCycle)),
        "expected an automatic host PowerCycle on the non-Dell (Lenovo) host to apply the queued NIC mode change; power calls so far: {power_calls:?}"
    );

    Ok(())
}

/// A managed host's DPU-facing `machine_interface` is created (via DHCP) with
/// just a MAC and no `boot_interface_id`. The exploration that ingests the host
/// then backfills the vendor-specific Redfish interface id onto that row, matched
/// by MAC, at which the primary interface ends up with a full `MachineBootInterface`.
/// This is the same backfill path any DHCP-derived interface takes (the capture is
/// keyed on MAC, not on how the row was created).
#[sqlx_test]
async fn test_site_explorer_backfills_boot_interface_id_onto_machine_interface(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let dpu = DpuConfig::default();
    let host_pf_mac = dpu.host_mac_address;
    let mh = common::api_fixtures::create_managed_host_with_config(
        &env,
        ManagedHostConfig::with_dpus(vec![dpu]),
    )
    .await;

    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_machine_ids(&mut txn, &[mh.id]).await?;
    let primary = interfaces
        .get(&mh.id)
        .into_iter()
        .flatten()
        .find(|i| i.primary_interface)
        .expect("ingested host should have a primary machine_interface");

    // The primary row is the DPU host-PF interface (same factory MAC), now
    // holding both halves of the pair: its MAC plus the Redfish interface id the
    // host report named for it. The `ManagedHostConfig` fixture ids its DPU
    // interfaces "NIC.Slot.{index + 5}-1", so the first DPU is "NIC.Slot.5-1".
    assert_eq!(primary.mac_address, host_pf_mac);
    assert_eq!(
        primary.boot_interface_id.as_deref(),
        Some("NIC.Slot.5-1"),
        "exploration should backfill the Redfish interface id onto the machine_interface row",
    );

    Ok(())
}

/// A zero-DPU host whose only NIC is a plain (non-DPU) host NIC.
/// We expect to walk over the report ethernet interfaces and record
/// the NIC's Redfish-reported interface id onto its machine_interface
/// row, matched/paired with its MAC address.
#[sqlx_test]
async fn test_site_explorer_records_boot_interface_id_onto_non_dpu_nic(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            ..Default::default()
        },
    )
    .await;
    create_host_inband_network_segment(&env.api, None).await;

    let non_dpu_mac = MacAddress::from_str("d4:04:e6:84:13:98").unwrap();
    let mh = common::api_fixtures::create_managed_host_with_config(
        &env,
        ManagedHostConfig {
            dpus: vec![],
            non_dpu_macs: vec![non_dpu_mac],
            ..ManagedHostConfig::default()
        },
    )
    .await;

    let mut txn = env.pool.begin().await?;
    let interfaces = db::machine_interface::find_by_machine_ids(&mut txn, &[mh.id]).await?;
    let nic = interfaces
        .get(&mh.id)
        .into_iter()
        .flatten()
        .find(|i| i.mac_address == non_dpu_mac)
        .expect("the non-DPU host NIC should have a machine_interface row");

    assert_eq!(
        nic.boot_interface_id.as_deref(),
        Some("NIC.Embedded.1-1-1"),
        "exploration should record a non-DPU NIC's Redfish interface id on its row",
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
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let host_config = ManagedHostConfig::default();
    let host_bmc_mac = host_config.bmc_mac_address;
    let chassis_serial = host_config.serial.clone();
    let mh = common::api_fixtures::create_managed_host_with_config(&env, host_config).await;

    // Orphan the host by deleting its expected_machines entry.
    let mut txn = env.pool.begin().await?;
    db::expected_machine::delete_by_mac(&mut txn, host_bmc_mac).await?;
    txn.commit().await?;

    // Run an iteration: audit_exploration_results should emit the orphan alert.
    env.run_site_explorer_iteration().await;
    let alerts = env
        .find_machine(mh.id)
        .await
        .remove(0)
        .health
        .unwrap()
        .alerts;
    assert!(
        alerts.iter().any(|a| a.id == "OrphanManagedHost"),
        "expected OrphanManagedHost alert, got: {alerts:#?}"
    );

    // Re-add the expected_machines entry — the alert should clear next iteration.
    let mut txn = env.pool.begin().await?;
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

    env.run_site_explorer_iteration().await;
    let alerts = env
        .find_machine(mh.id)
        .await
        .remove(0)
        .health
        .unwrap()
        .alerts;
    assert!(
        !alerts.iter().any(|a| a.id == "OrphanManagedHost"),
        "expected no OrphanManagedHost alert after re-adding expected_machines, got: {alerts:#?}"
    );

    Ok(())
}

async fn host_bmc_ip(
    env: &TestEnv,
    mh: &api_fixtures::TestManagedHost,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let mut txn = env.pool.begin().await?;
    let bmc_ip = mh.host().bmc_ip(&mut txn).await.unwrap();
    txn.commit().await?;
    Ok(bmc_ip)
}

async fn explored_endpoint(
    env: &TestEnv,
    bmc_ip: IpAddr,
) -> Result<ExploredEndpoint, Box<dyn std::error::Error>> {
    let mut txn = env.pool.begin().await?;
    let endpoint = db::explored_endpoints::find_by_ips(txn.as_mut(), vec![bmc_ip])
        .await?
        .into_iter()
        .next()
        .unwrap();
    txn.commit().await?;
    Ok(endpoint)
}

fn endpoint_explore_call_count(env: &TestEnv, bmc_ip: IpAddr) -> usize {
    env.endpoint_explorer
        .explore_endpoint_calls
        .lock()
        .unwrap()
        .iter()
        .filter(|ip| **ip == bmc_ip)
        .count()
}

#[sqlx_test]
async fn test_refresh_endpoint_report_bumps_report_version(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let bmc_ip = host_bmc_ip(&env, &mh).await?;
    let initial_version = explored_endpoint(&env, bmc_ip).await?.report_version;

    env.api
        .refresh_endpoint_report(Request::new(rpc::forge::RefreshEndpointReportRequest {
            ip_address: bmc_ip.to_string(),
        }))
        .await?;

    let refreshed = explored_endpoint(&env, bmc_ip).await?;
    assert!(
        refreshed.report_version.version_nr() > initial_version.version_nr(),
        "refresh should bump report version from {} to a newer version, got {}",
        initial_version.version_nr(),
        refreshed.report_version.version_nr()
    );

    Ok(())
}

#[sqlx_test]
async fn test_refresh_endpoint_report_rejects_nonexistent_endpoint(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let err = env
        .api
        .refresh_endpoint_report(Request::new(rpc::forge::RefreshEndpointReportRequest {
            ip_address: "99.99.99.99".to_string(),
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::NotFound);

    Ok(())
}

#[sqlx_test]
async fn test_refresh_endpoint_report_rejects_duplicate_refresh(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let bmc_ip = host_bmc_ip(&env, &mh).await?;
    let _endpoint_lock = env
        .api
        .work_lock_manager_handle
        .try_acquire_lock(endpoint_exploration_work_key(bmc_ip))
        .await?;

    let err = env
        .api
        .refresh_endpoint_report(Request::new(rpc::forge::RefreshEndpointReportRequest {
            ip_address: bmc_ip.to_string(),
        }))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::AlreadyExists);

    Ok(())
}

#[sqlx_test]
async fn test_refresh_endpoint_report_lock_blocks_periodic_probe(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let bmc_ip = host_bmc_ip(&env, &mh).await?;

    env.api
        .re_explore_endpoint(Request::new(rpc::forge::ReExploreEndpointRequest {
            ip_address: bmc_ip.to_string(),
            if_version_match: None,
        }))
        .await?;

    let calls_before = endpoint_explore_call_count(&env, bmc_ip);
    let _endpoint_lock = env
        .api
        .work_lock_manager_handle
        .try_acquire_lock(endpoint_exploration_work_key(bmc_ip))
        .await?;

    env.run_site_explorer_iteration().await;

    assert_eq!(
        endpoint_explore_call_count(&env, bmc_ip),
        calls_before,
        "periodic site explorer probe should be skipped while refresh lock is held"
    );

    Ok(())
}

#[sqlx_test]
async fn test_refresh_endpoint_report_failure_persists_error_and_bumps_version(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let bmc_ip = host_bmc_ip(&env, &mh).await?;
    let initial_version = explored_endpoint(&env, bmc_ip).await?.report_version;
    env.endpoint_explorer.insert_endpoint_result(
        bmc_ip,
        Err(EndpointExplorationError::Unreachable {
            details: Some("refresh failure".to_string()),
        }),
    );
    env.api
        .refresh_endpoint_report(Request::new(rpc::forge::RefreshEndpointReportRequest {
            ip_address: bmc_ip.to_string(),
        }))
        .await?;

    let refreshed = explored_endpoint(&env, bmc_ip).await?;
    assert!(
        refreshed.report_version.version_nr() > initial_version.version_nr(),
        "failed refresh should still bump report version"
    );
    assert!(
        refreshed.report.last_exploration_error.is_some(),
        "failed refresh should persist the exploration error"
    );

    Ok(())
}

#[sqlx_test]
async fn test_refresh_endpoint_report_clears_pending_requested_exploration(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let mh = common::api_fixtures::create_managed_host(&env).await;
    let bmc_ip = host_bmc_ip(&env, &mh).await?;

    env.api
        .re_explore_endpoint(Request::new(rpc::forge::ReExploreEndpointRequest {
            ip_address: bmc_ip.to_string(),
            if_version_match: None,
        }))
        .await?;
    assert!(explored_endpoint(&env, bmc_ip).await?.exploration_requested);

    env.api
        .refresh_endpoint_report(Request::new(rpc::forge::RefreshEndpointReportRequest {
            ip_address: bmc_ip.to_string(),
        }))
        .await?;

    assert!(
        !explored_endpoint(&env, bmc_ip).await?.exploration_requested,
        "refresh should clear the pending requested exploration so the endpoint is not immediately probed again as priority work"
    );

    Ok(())
}

#[sqlx_test]
async fn test_refresh_endpoint_report_lock_is_per_endpoint(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let mh_a = common::api_fixtures::create_managed_host(&env).await;
    let mh_b = common::api_fixtures::create_managed_host(&env).await;
    let bmc_ip_a = host_bmc_ip(&env, &mh_a).await?;
    let bmc_ip_b = host_bmc_ip(&env, &mh_b).await?;
    let initial_version_b = explored_endpoint(&env, bmc_ip_b).await?.report_version;
    let _endpoint_lock = env
        .api
        .work_lock_manager_handle
        .try_acquire_lock(endpoint_exploration_work_key(bmc_ip_a))
        .await?;

    env.api
        .refresh_endpoint_report(Request::new(rpc::forge::RefreshEndpointReportRequest {
            ip_address: bmc_ip_b.to_string(),
        }))
        .await?;

    let refreshed_b = explored_endpoint(&env, bmc_ip_b).await?;
    assert!(
        refreshed_b.report_version.version_nr() > initial_version_b.version_nr(),
        "lock for endpoint {bmc_ip_a} should not block refresh for endpoint {bmc_ip_b}"
    );

    Ok(())
}
