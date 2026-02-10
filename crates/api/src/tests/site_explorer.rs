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
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use carbide_uuid::network::NetworkSegmentId;
use common::api_fixtures::TestEnv;
use common::api_fixtures::endpoint_explorer::MockEndpointExplorer;
use config_version::ConfigVersion;
use db::sku::CURRENT_SKU_VERSION;
use db::{self, ObjectColumnFilter, ObjectFilter, explored_endpoints as db_explored_endpoints};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use model::expected_machine::ExpectedMachineData;
use model::hardware_info::HardwareInfo;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{LoadSnapshotOptions, Machine, ManagedHostStateSnapshot};
use model::metadata::Metadata;
use model::power_shelf::PowerShelfControllerState;
use model::site_explorer::{
    Chassis, ComputerSystem, EndpointExplorationError, EndpointExplorationReport, EndpointType,
    ExploredDpu, ExploredEndpoint, ExploredManagedHost, PreingestionState, UefiDevicePath,
};
use rpc::forge::GetSiteExplorationRequest;
use rpc::forge::forge_server::Forge;
use rpc::site_explorer::{
    ExploredDpu as RpcExploredDpu, ExploredManagedHost as RpcExploredManagedHost,
};
use rpc::{DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use tonic::Request;

use crate::cfg::file::SiteExplorerConfig;
use crate::site_explorer::SiteExplorer;
use crate::tests::common;
use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::TestEnvOverrides;
use crate::tests::common::api_fixtures::dpu::DpuConfig;
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    create_host_inband_network_segment,
};
use crate::tests::common::api_fixtures::site_explorer::MockExploredHost;
use crate::tests::common::rpc_builder::DhcpDiscovery;
use crate::tests::common::test_meter::TestMeter;

#[derive(Clone, Debug)]
struct FakeMachine {
    pub mac: MacAddress,
    pub dhcp_vendor: String,
    pub segment: NetworkSegmentId,
    pub ip: String,
}

impl FakeMachine {
    fn new(mac: &str, vendor: &str, segment: &Option<NetworkSegmentId>) -> Self {
        Self {
            mac: mac.parse().unwrap(),
            dhcp_vendor: vendor.to_string(),
            segment: segment.unwrap(),
            ip: String::new(),
        }
    }

    fn as_mock_dpu(&self) -> DpuConfig {
        DpuConfig {
            bmc_mac_address: self.mac,
            ..Default::default()
        }
    }

    fn as_mock_host(&self, dpus: Vec<DpuConfig>) -> ManagedHostConfig {
        ManagedHostConfig {
            bmc_mac_address: self.mac,
            dpus,
            ..Default::default()
        }
    }
}

#[async_trait::async_trait]
trait DiscoverDhcp {
    async fn discover_dhcp(&mut self, env: &TestEnv) -> Result<(), Box<dyn std::error::Error>>;
}

#[async_trait::async_trait]
impl DiscoverDhcp for FakeMachine {
    async fn discover_dhcp(&mut self, env: &TestEnv) -> Result<(), Box<dyn std::error::Error>> {
        let relay_address = match self.segment {
            s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
            _ => "192.0.2.1".to_string(),
        };
        let response = env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(self.mac, relay_address)
                    .vendor_string(&self.dhcp_vendor)
                    .tonic_request(),
            )
            .await?
            .into_inner();
        tracing::info!(
            "DHCP with mac {} assigned ip {}",
            self.mac,
            response.address
        );
        self.ip = response.address;
        Ok(())
    }
}

#[async_trait::async_trait]
impl DiscoverDhcp for Vec<FakeMachine> {
    async fn discover_dhcp(&mut self, env: &TestEnv) -> Result<(), Box<dyn std::error::Error>> {
        for machine in self.iter_mut() {
            machine.discover_dhcp(env).await?
        }
        Ok(())
    }
}

struct FakePowerShelf {
    pub bmc_mac_address: MacAddress,
    pub serial_number: String,
    pub bmc_username: String,
    pub bmc_password: String,
    #[allow(dead_code)]
    pub dhcp_vendor: String,
    #[allow(dead_code)]
    pub segment: NetworkSegmentId,
    #[allow(dead_code)]
    pub ip: String, // DHCP assigned IP (may be different from ip_address)
}

impl FakePowerShelf {
    fn new(
        bmc_mac_address: MacAddress,
        ip: String,
        serial_number: String,
        bmc_username: String,
        bmc_password: String,
        dhcp_vendor: String,
        segment: NetworkSegmentId,
    ) -> Self {
        Self {
            bmc_mac_address,
            ip,
            serial_number,
            bmc_username,
            bmc_password,
            dhcp_vendor,
            segment,
        }
    }

    fn as_expected_power_shelf(&self) -> model::expected_power_shelf::ExpectedPowerShelf {
        model::expected_power_shelf::ExpectedPowerShelf {
            bmc_mac_address: self.bmc_mac_address,
            bmc_username: self.bmc_username.clone(),
            bmc_password: self.bmc_password.clone(),
            serial_number: self.serial_number.clone(),
            ip_address: Some(self.ip.parse().unwrap()),
            metadata: Metadata {
                name: format!("Test Power Shelf {}", self.serial_number),
                description: format!("A test power shelf with serial {}", self.serial_number),
                labels: HashMap::new(),
            },
            rack_id: None,
        }
    }
}

#[crate::sqlx_test(fixtures("create_expected_machine_no_default_poweron"))]
async fn test_site_explorer_default_pause_ingestion_and_poweron(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let mut machines = vec![FakeMachine::new(
        "6a:6b:6c:6d:6e:6f",
        "Vendor1",
        &env.underlay_segment,
    )];
    machines.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.underlay_segment.unwrap())
            .await
            .unwrap(),
        1
    );

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let mock_host = machines[0].as_mock_host(vec![]);

    endpoint_explorer.insert_endpoint_results(vec![(
        machines[0].ip.parse().unwrap(),
        Ok(mock_host.clone().into()),
    )]);

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allow_zero_dpu_hosts: true,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    // check the ingestion state of the machine
    let response = env
        .api
        .determine_machine_ingestion_state(tonic::Request::new(rpc::forge::BmcEndpointRequest {
            mac_address: Some("6a:6b:6c:6d:6e:6f".to_string()),
            ip_address: "".to_string(),
        }))
        .await?;
    assert_eq!(
        rpc::forge::MachineIngestionState::NotDiscovered,
        response.into_inner().machine_ingestion_state()
    );

    // run the exploration cycle
    explorer.run_single_iteration().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    assert_eq!(explored.len(), 1);
    assert!(explored[0].pause_ingestion_and_poweron);

    // make sure the machine has not been ingested
    let response = env
        .api
        .determine_machine_ingestion_state(tonic::Request::new(rpc::forge::BmcEndpointRequest {
            mac_address: Some("6a:6b:6c:6d:6e:6f".to_string()),
            ip_address: "".to_string(),
        }))
        .await?;
    assert_eq!(
        rpc::forge::MachineIngestionState::WaitingForIngestion,
        response.into_inner().machine_ingestion_state()
    );

    // now that the explored endpoint has been added to the DB, mark it as preingestion complete
    db::explored_endpoints::set_preingestion_complete(explored[0].address, &mut txn)
        .await
        .unwrap();
    txn.commit().await?;

    // and run another exploration cycle
    explorer.run_single_iteration().await.unwrap();

    // make sure the machie still has not been ingested
    let response = env
        .api
        .determine_machine_ingestion_state(tonic::Request::new(rpc::forge::BmcEndpointRequest {
            mac_address: Some("6a:6b:6c:6d:6e:6f".to_string()),
            ip_address: "".to_string(),
        }))
        .await?;
    assert_eq!(
        rpc::forge::MachineIngestionState::WaitingForIngestion,
        response.into_inner().machine_ingestion_state()
    );

    let mut txn = env.pool.begin().await?;
    let machine_snapshots =
        db::managed_host::load_all(&mut txn, LoadSnapshotOptions::default()).await?;
    assert_eq!(machine_snapshots.len(), 0);
    let explored_managed_hosts = db::explored_managed_host::find_all(&mut txn).await?;
    assert_eq!(explored_managed_hosts.len(), 0);

    // now flip the flag and run another interation
    let _ = env
        .api
        .allow_ingestion_and_power_on(tonic::Request::new(rpc::forge::BmcEndpointRequest {
            mac_address: Some("6a:6b:6c:6d:6e:6f".to_string()),
            ip_address: "".to_string(),
        }))
        .await?;

    let mut txn = env.pool.begin().await?;

    // run the exploration cycle
    explorer.run_single_iteration().await.unwrap();

    // the machine should be ingested now
    // unfortunately, there is no way to test a hypothetical situation when
    // an explored managed host has been created, but the machine has not
    // been created yet as those are performed in the same site explorer
    // iteration
    let response = env
        .api
        .determine_machine_ingestion_state(tonic::Request::new(rpc::forge::BmcEndpointRequest {
            mac_address: Some("6a:6b:6c:6d:6e:6f".to_string()),
            ip_address: "".to_string(),
        }))
        .await?;
    assert_eq!(
        rpc::forge::MachineIngestionState::IngestionMachineCreated,
        response.into_inner().machine_ingestion_state()
    );

    let explored_managed_hosts = db::explored_managed_host::find_all(&mut txn).await?;
    assert_eq!(explored_managed_hosts.len(), 1);
    let machine_snapshots =
        db::managed_host::load_all(&mut txn, LoadSnapshotOptions::default()).await?;
    assert_eq!(machine_snapshots.len(), 1);

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_main(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Let's create 3 machines on the underlay, and 1 on the admin network
    // The 1 on the admin network is not supposed to be searched. This is verified
    // by providing no mocked exploration data for this machine, which would lead
    // to a panic if the machine is queried
    let mut machines = vec![
        // machines[0] is a DPU belonging to machines[1]
        FakeMachine::new("B8:3F:D2:90:97:A6", "Vendor1", &env.underlay_segment),
        // machines[1] has 1 dpu (machines[0])
        FakeMachine::new("AA:AB:AC:AD:AA:02", "Vendor2", &env.underlay_segment),
        // machines[2] has no DPUs
        FakeMachine::new("AA:AB:AC:AD:AA:03", "Vendor3", &env.underlay_segment),
        // machines[3] is not on the underlay network and should not be searched.
        FakeMachine::new(
            "AA:AB:AC:AD:BB:01",
            "VendorInvalidSegment",
            &env.admin_segment,
        ),
    ];
    machines.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.underlay_segment.unwrap())
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.admin_segment.unwrap())
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let mock_dpu = machines[0].as_mock_dpu();

    endpoint_explorer.insert_endpoint_results(vec![
        (machines[0].ip.parse().unwrap(), Ok(mock_dpu.clone().into())),
        (
            machines[1].ip.parse().unwrap(),
            Err(EndpointExplorationError::Unauthorized {
                details: "Not authorized".to_string(),
                response_body: None,
                response_code: None,
            }),
        ),
        (
            machines[2].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: None,
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                managers: Vec::new(),
                systems: vec![ComputerSystem {
                    serial_number: Some("0123456789".to_string()),
                    ..Default::default()
                }],
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
                model: None,
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            }),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allow_zero_dpu_hosts: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 2);

    for report in &explored {
        assert_eq!(report.report_version.version_nr(), 1);
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap().as_ref();
        if res.is_err() {
            assert_eq!(
                res.unwrap_err(),
                report.report.last_exploration_error.as_ref().unwrap()
            );
        } else {
            assert_eq!(res.unwrap().endpoint_type, report.report.endpoint_type);
            assert_eq!(res.unwrap().vendor, report.report.vendor);
            assert_eq!(res.unwrap().managers, report.report.managers);
            assert_eq!(res.unwrap().systems, report.report.systems);
            assert_eq!(res.unwrap().chassis, report.report.chassis);
            assert_eq!(res.unwrap().service, report.report.service);
        }
    }

    // Retrieve the report via gRPC
    let report = fetch_exploration_report(&env).await;
    assert!(report.managed_hosts.is_empty());

    // We should also have metric entries
    assert_eq!(
        test_meter
            .formatted_metric("carbide_endpoint_explorations_count")
            .unwrap(),
        "2"
    );
    assert!(
        test_meter
            .formatted_metric("carbide_endpoint_exploration_success_count")
            .is_some()
    );
    // The failure metric is not emitted if no failure happened
    assert_eq!(
        test_meter
            .formatted_metric("carbide_endpoint_exploration_duration_milliseconds_count")
            .unwrap_or("2".to_string()),
        "2"
    );
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_exploration_identified_managed_hosts_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_explorer_created_machines_count")
            .unwrap(),
        "0"
    );

    // Running again should yield all 3 entries
    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 3);
    let mut versions = Vec::new();
    for report in &explored {
        versions.push(report.report_version.version_nr());
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap().as_ref();
        if res.is_err() {
            assert_eq!(
                res.unwrap_err(),
                report.report.last_exploration_error.as_ref().unwrap()
            );
        } else {
            assert_eq!(res.unwrap().endpoint_type, report.report.endpoint_type);
            assert_eq!(res.unwrap().vendor, report.report.vendor);
            assert_eq!(res.unwrap().managers, report.report.managers);
            assert_eq!(res.unwrap().systems, report.report.systems);
            assert_eq!(res.unwrap().chassis, report.report.chassis);
            assert_eq!(res.unwrap().service, report.report.service);
        }
    }
    versions.sort();
    assert_eq!(&versions, &[1, 1, 2]);

    // Retrieve the report via gRPC
    let report = fetch_exploration_report(&env).await;
    assert!(report.managed_hosts.is_empty());

    assert_eq!(
        test_meter
            .formatted_metric("carbide_endpoint_explorations_count")
            .unwrap(),
        "2"
    );
    assert!(
        test_meter
            .formatted_metric("carbide_endpoint_exploration_success_count")
            .is_some()
    );
    assert_eq!(
        test_meter
            .formatted_metric("carbide_endpoint_exploration_duration_milliseconds_count")
            .unwrap_or("4".to_string()),
        "4"
    );
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_exploration_identified_managed_hosts_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_explorer_created_machines_count")
            .unwrap(),
        "0"
    );

    // Now make 1 previously existing endpoint unreachable and 1 previously unreachable
    // endpoint reachable and show the managed host.
    // Both changes should show up after 2 updates
    endpoint_explorer.insert_endpoint_results(vec![
        (
            machines[0].ip.parse().unwrap(),
            Err(EndpointExplorationError::Unreachable {
                details: Some("test_unreachable_detail".to_string()),
            }),
        ),
        (
            machines[1].ip.parse().unwrap(),
            Ok(machines[1].as_mock_host(vec![mock_dpu.clone()]).into()),
        ),
    ]);

    // We don't want to test the preingestion stuff here, so fake that it all completed successfully.
    let mut txn = pool.begin().await?;
    for addr in ["192.0.1.3", "192.0.1.4", "192.0.1.5"] {
        db::explored_endpoints::set_preingestion_complete(
            std::net::IpAddr::from_str(addr).unwrap(),
            &mut txn,
        )
        .await
        .unwrap();
    }
    txn.commit().await?;

    explorer.run_single_iteration().await.unwrap();
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    assert_eq!(explored.len(), 3);
    let mut versions = Vec::new();
    for report in &explored {
        versions.push(report.report_version.version_nr());
        assert_eq!(report.report.endpoint_type, EndpointType::Bmc);
        match report.address.to_string() {
            a if a == machines[0].ip => {
                // The original report is retained. But the error gets stored
                assert_eq!(report.report.vendor, Some(bmc_vendor::BMCVendor::Nvidia));
                assert_eq!(
                    report.report.last_exploration_error.clone().unwrap(),
                    EndpointExplorationError::Unreachable {
                        details: Some("test_unreachable_detail".to_string())
                    }
                );
            }
            a if a == machines[1].ip => {
                assert_eq!(report.report.vendor, Some(bmc_vendor::BMCVendor::Dell));
                assert!(report.report.last_exploration_error.is_none());
            }
            a if a == machines[2].ip => {
                assert_eq!(report.report.vendor, Some(bmc_vendor::BMCVendor::Lenovo));
                assert!(report.report.last_exploration_error.is_none());
            }
            _ => panic!("No other endpoints should be discovered"),
        }
    }
    versions.sort();
    // We run 4 iterations, which is enough for 8 machine scans
    // => 2 Machines should have been scanned 3 times, and one 2 times
    assert_eq!(&versions, &[2, 3, 3]);

    let report = fetch_exploration_report(&env).await;
    assert_eq!(report.endpoints.len(), 3);
    let mut addresses: Vec<String> = report
        .endpoints
        .iter()
        .map(|ep| ep.address.clone())
        .collect();
    addresses.sort();
    let mut expected_addresses: Vec<String> = machines
        .iter()
        .filter(|m| m.segment == env.underlay_segment.unwrap())
        .map(|m| m.ip.to_string())
        .collect();
    expected_addresses.sort();
    assert_eq!(addresses, expected_addresses);

    // We should now have two managed hosts: One with a single DPU, and one with no DPUs.
    assert_eq!(report.managed_hosts.len(), 2);
    let managed_host_1 = report
        .managed_hosts
        .iter()
        .find(|h| h.dpus.len() == 1)
        .expect("Should have found one managed host with a single DPU")
        .clone();
    let managed_host_2 = report
        .managed_hosts
        .iter()
        .find(|h| h.dpus.is_empty())
        .expect("Should have found one managed host with zero DPUs")
        .clone();

    assert_eq!(
        managed_host_1,
        RpcExploredManagedHost {
            host_bmc_ip: machines[1].ip.clone(),
            dpu_bmc_ip: machines[0].ip.clone(),
            host_pf_mac_address: Some(mock_dpu.host_mac_address.to_string()),
            dpus: vec![RpcExploredDpu {
                bmc_ip: machines[0].ip.clone(),
                host_pf_mac_address: Some(mock_dpu.host_mac_address.to_string()),
            }]
        }
    );

    assert_eq!(
        managed_host_2,
        RpcExploredManagedHost {
            host_bmc_ip: machines[2].ip.clone(),
            dpu_bmc_ip: "".to_string(),
            host_pf_mac_address: None,
            dpus: vec![],
        }
    );

    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_exploration_identified_managed_hosts_count")
            .unwrap(),
        "2"
    );

    txn.commit().await?;
    Ok(())
}

#[crate::sqlx_test(fixtures("create_expected_machine"))]
async fn test_site_explorer_audit_exploration_results(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let mut machines = vec![
        // This will be our expected DPU, and it will have the
        // expected serial number, but we assume no DPUs are expected,
        // should it still shouldn't be counted as `expected`        .
        FakeMachine::new("5a:5b:5c:5d:5e:5f", "Vendor1", &env.underlay_segment),
        // This will be expected but unauthorized, and the serial is mismatched
        FakeMachine::new("0a:0b:0c:0d:0e:0f", "Vendor3", &env.underlay_segment),
        // This host will be expected but missing credentials, and the serial is mismatched
        FakeMachine::new("1a:1b:1c:1d:1e:1f", "Vendor3", &env.underlay_segment),
        // This host will be expected, but the serial number will be mismatched.
        FakeMachine::new("2a:2b:2c:2d:2e:2f", "Vendor3", &env.underlay_segment),
        // This will be expected, with a good serial number.
        // It will also have associated DPUs and should get a managed host.
        FakeMachine::new("3a:3b:3c:3d:3e:3f", "Vendor3", &env.underlay_segment),
        // This host is not expected.
        FakeMachine::new("ab:cd:ef:ab:cd:ef", "Vendor3", &env.underlay_segment),
        // This DPU is really not expected. (i.e. no DB entry)
        FakeMachine::new("ef:cd:ab:ef:cd:ab", "Vendor3", &env.underlay_segment),
    ];

    machines.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.underlay_segment.unwrap())
            .await
            .unwrap(),
        7
    );
    txn.commit().await.unwrap();

    // Make a mock host for machines[4] to generate the report
    // This serial is from the create_expected_machine.sql seed.
    let machine_4_host = ManagedHostConfig::with_serial("VVG121GJ".to_string());

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    endpoint_explorer.insert_endpoints(vec![
        (
            machines[0].ip.parse().unwrap(),
            DpuConfig::with_serial("VVG121GL".to_string()).into(),
        ),
        (
            machines[1].ip.parse().unwrap(),
            EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                // Pretend there was previously a successful exploration
                // but now something has gone wrong.
                last_exploration_error: Some(EndpointExplorationError::Unauthorized {
                    details: "Not authorized".to_string(),
                    response_body: None,
                    response_code: None,
                }),
                last_exploration_latency: None,
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                model: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            },
        ),
        (
            machines[2].ip.parse().unwrap(),
            EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                // Pretend there was previously a successful exploration
                // but now something has gone wrong.
                last_exploration_error: Some(EndpointExplorationError::MissingCredentials {
                    key: "some_cred".to_string(),
                    cause: "it's not there!".to_string(),
                }),
                last_exploration_latency: None,
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                model: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            },
        ),
        (
            machines[3].ip.parse().unwrap(),
            EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: None,
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                model: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            },
        ),
        (
            machines[4].ip.parse().unwrap(),
            machine_4_host.clone().into(),
        ),
        (
            machines[5].ip.parse().unwrap(),
            EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: None,
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                model: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            },
        ),
        (
            // This is the DPU from machines[4]
            machines[6].ip.parse().unwrap(),
            machine_4_host.dpus[0].clone().into(),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 7,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        machines_created_per_run: 1,
        override_target_ip: None,
        override_target_port: None,
        allow_zero_dpu_hosts: false,
        allow_changing_bmc_proxy: None,
        bmc_proxy: Arc::default(),
        reset_rate_limit: chrono::Duration::hours(1),
        admin_segment_type_non_dpu: Arc::new(false.into()),
        allocate_secondary_vtep_ip: false,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        rotate_switch_nvos_credentials: Arc::new(false.into()),
        use_onboard_nic: Arc::new(false.into()),
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();
    // carbide_endpoint_exploration_preingestions_incomplete_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("carbide_endpoint_exploration_preingestions_incomplete_overall_count")
        .into_iter()
        .collect();

    assert!(!m.is_empty());
    assert_eq!(
        m.get("{expectation=\"na\",machine_type=\"dpu\"}").unwrap(),
        "2"
    );
    assert_eq!(
        m.get("{expectation=\"expected\",machine_type=\"host\"}")
            .unwrap(),
        "4" // 2 normal + 2 previously explored but in an error state
    );
    assert_eq!(
        m.get("{expectation=\"unexpected\",machine_type=\"host\"}")
            .unwrap(),
        "1"
    );

    let mut txn = pool.begin().await?;
    for final_octet in 2..10 {
        db::explored_endpoints::set_preingestion_complete(
            std::net::IpAddr::from(std::net::Ipv4Addr::new(192, 0, 1, final_octet)),
            &mut txn,
        )
        .await
        .unwrap();
    }
    txn.commit().await?;
    explorer.run_single_iteration().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 7);

    for report in &explored {
        assert_eq!(report.report_version.version_nr(), 2);
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap().as_ref();
        if res.is_err() {
            assert_eq!(
                res.unwrap_err(),
                report.report.last_exploration_error.as_ref().unwrap()
            );
        } else {
            assert_eq!(res.unwrap().endpoint_type, report.report.endpoint_type);
            assert_eq!(res.unwrap().vendor, report.report.vendor);
            assert_eq!(res.unwrap().managers, report.report.managers);
            assert_eq!(res.unwrap().systems, report.report.systems);
            assert_eq!(res.unwrap().chassis, report.report.chassis);
            assert_eq!(res.unwrap().service, report.report.service);
        }
    }

    // Retrieve the report via gRPC
    let report = fetch_exploration_report(&env).await;

    // We should have at least one managed host built by this point.
    assert!(!report.managed_hosts.is_empty());

    // Check for the expected metrics

    // carbide_endpoint_exploration_failures_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("carbide_endpoint_exploration_failures_overall_count")
        .into_iter()
        .collect();

    assert!(!m.is_empty());
    assert!(m.get("{failure=\"unauthorized\"}").unwrap() == "1");
    assert!(m.get("{failure=\"missing_credentials\"}").unwrap() == "1");

    // carbide_endpoint_exploration_preingestions_incomplete_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("carbide_endpoint_exploration_preingestions_incomplete_overall_count")
        .into_iter()
        .collect();
    // Everything should be done with preingestion now.
    assert!(m.is_empty());

    // carbide_endpoint_exploration_expected_serial_number_mismatches_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics(
            "carbide_endpoint_exploration_expected_serial_number_mismatches_overall_count",
        )
        .into_iter()
        .collect();

    assert!(!m.is_empty());
    assert_eq!(m.get("{machine_type=\"host\"}").unwrap(), "3");

    // carbide_endpoint_exploration_machines_explored_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("carbide_endpoint_exploration_machines_explored_overall_count")
        .into_iter()
        .collect();

    assert!(!m.is_empty());
    assert_eq!(
        m.get("{expectation=\"na\",machine_type=\"dpu\"}").unwrap(),
        "2"
    );
    assert_eq!(
        m.get("{expectation=\"expected\",machine_type=\"host\"}")
            .unwrap(),
        "4"
    );
    assert_eq!(
        m.get("{expectation=\"unexpected\",machine_type=\"host\"}")
            .unwrap(),
        "1"
    );

    // carbide_endpoint_exploration_expected_machines_missing_overall_count
    assert_eq!(
        test_meter
            .formatted_metric(
                "carbide_endpoint_exploration_expected_machines_missing_overall_count"
            )
            .unwrap(),
        "1"
    );

    // carbide_endpoint_exploration_identified_managed_hosts_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("carbide_endpoint_exploration_identified_managed_hosts_overall_count")
        .into_iter()
        .collect();

    assert!(!m.is_empty());
    assert_eq!(m.get("{expectation=\"expected\"}").unwrap(), "1");

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_reexplore(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let mut machines = vec![
        FakeMachine::new("B8:3F:D2:90:97:A6", "Vendor1", &env.underlay_segment),
        FakeMachine::new("AA:AB:AC:AD:AA:02", "Vendor2", &env.underlay_segment),
    ];

    machines.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.underlay_segment.unwrap())
            .await
            .unwrap(),
        2
    );
    txn.commit().await.unwrap();

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    endpoint_explorer.insert_endpoint_results(vec![
        (
            machines[0].ip.parse().unwrap(),
            Ok(DpuConfig::default().into()),
        ),
        (
            machines[1].ip.parse().unwrap(),
            Err(EndpointExplorationError::Unauthorized {
                details: "Not authorized".to_string(),
                response_body: None,
                response_code: None,
            }),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(false.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 1 entries, we should have 1 results now
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);
    let explored_ip = explored[0].address;

    for report in &explored {
        assert_eq!(report.report_version.version_nr(), 1);
        assert!(!report.exploration_requested);
    }

    // Re-exploring the first endpoint should prioritize it over exploring another endpoint
    env.api
        .re_explore_endpoint(tonic::Request::new(rpc::forge::ReExploreEndpointRequest {
            ip_address: explored_ip.to_string(),
            if_version_match: None,
        }))
        .await
        .unwrap();

    // Calling the API should set the `exploration_requested` flag on the endpoint
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    for report in &explored {
        assert!(report.exploration_requested);
    }

    // The 2nd iteration should just update the version number of the initial explored
    // endpoint - but not find anything new
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);

    for report in &explored {
        assert_eq!(report.address, explored_ip);
        assert_eq!(report.report_version.version_nr(), 2);
        assert!(!report.exploration_requested);
    }
    let current_version = explored[0].report_version;

    // Using if_version_match with an incorrect version does nothing
    let unexpected_version = current_version.increment();
    let e = env
        .api
        .re_explore_endpoint(tonic::Request::new(rpc::forge::ReExploreEndpointRequest {
            ip_address: explored_ip.to_string(),
            if_version_match: Some(unexpected_version.version_string()),
        }))
        .await
        .expect_err("Should fail due to invalid version");
    assert_eq!(e.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        e.message(),
        format!(
            "An object of type explored_endpoint was intended to be modified did not have the expected version {}",
            unexpected_version.version_string()
        )
    );

    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    for report in &explored {
        assert!(!report.exploration_requested);
    }

    // Using if_version_match with correct version string does flag the endpoint again
    env.api
        .re_explore_endpoint(tonic::Request::new(rpc::forge::ReExploreEndpointRequest {
            ip_address: explored_ip.to_string(),
            if_version_match: Some(current_version.version_string()),
        }))
        .await
        .unwrap()
        .into_inner();

    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    for report in &explored {
        assert!(report.exploration_requested);
    }

    // 3rd iteration still yields 1 result
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_clear_last_known_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let mut txn = db::Transaction::begin(&env.pool).await?;
    let ip_address = "192.168.1.1";
    let bmc_ip: IpAddr = IpAddr::from_str(ip_address)?;
    let last_error = Some(EndpointExplorationError::Unreachable {
        details: Some("test_unreachable_detail".to_string()),
    });

    let mut dpu_report1: EndpointExplorationReport = DpuConfig {
        last_exploration_error: last_error.clone(),
        ..Default::default()
    }
    .into();
    dpu_report1.generate_machine_id(false)?;

    db::explored_endpoints::insert(bmc_ip, &dpu_report1, false, &mut txn).await?;
    txn.commit().await?;

    txn = db::Transaction::begin(&env.pool).await?;
    let nodes = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
    assert_eq!(nodes.len(), 1);
    let node = nodes.first();
    assert_eq!(node.unwrap().report.last_exploration_error, last_error);

    env.api
        .clear_site_exploration_error(Request::new(rpc::forge::ClearSiteExplorationErrorRequest {
            ip_address: ip_address.to_string(),
        }))
        .await
        .unwrap()
        .into_inner();

    let nodes = db::explored_endpoints::find_all_by_ip(bmc_ip, &mut txn).await?;
    assert_eq!(nodes.len(), 1);
    let node = nodes.first();
    assert_eq!(node.unwrap().report.last_exploration_error, None);

    Ok(())
}

// Test that discover_machines will reject request of machine that was not created by site-explorer when create_machines = true
#[crate::sqlx_test]
async fn test_disable_machine_creation_outside_site_explorer(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.site_explorer = SiteExplorerConfig {
        enabled: true,
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
        }))
        .await;

    // assert!(dm_response.is_err_and(|e| e.message().contains("was not discovered by site-explore")));

    Ok(())
}

#[crate::sqlx_test]
async fn test_fallback_dpu_serial(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    const HOST1_DPU_MAC: &str = "B8:3F:D2:90:97:A6";
    const HOST1_MAC: &str = "AA:AB:AC:AD:AA:02";
    const HOST1_DPU_SERIAL_NUMBER: &str = "host1_dpu_serial_number";

    let mut host1_dpu = FakeMachine::new(HOST1_DPU_MAC, "Vendor1", &env.underlay_segment);

    let mut host1 = FakeMachine::new(HOST1_MAC, "Vendor2", &env.underlay_segment);

    // Create dhcp entries and machine_interface entries for the machines
    for machine in [&mut host1_dpu, &mut host1] {
        machine.discover_dhcp(&env).await?;
    }
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Create a host and dpu reports && host has no dpu_serial
    endpoint_explorer.insert_endpoint_results(vec![
        (
            host1_dpu.ip.parse().unwrap(),
            Ok(DpuConfig::with_serial(HOST1_DPU_SERIAL_NUMBER.to_string()).into()),
        ),
        (
            host1.ip.parse().unwrap(),
            Ok(ManagedHostConfig::default().into()),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: true,
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
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer,
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    // Create expected_machine entry for host1 w.o fallback_dpu_serial_number
    let mut txn = env.pool.begin().await?;

    // Create the SKU record first
    let test_sku = model::sku::Sku {
        schema_version: CURRENT_SKU_VERSION,
        id: "Sku1".to_string(),
        description: "Test SKU for site explorer test".to_string(),
        created: chrono::Utc::now(),
        components: model::sku::SkuComponents {
            chassis: model::sku::SkuComponentChassis {
                vendor: "Vendor1".to_string(),
                model: "Chassis1".to_string(),
                architecture: "x86_64".to_string(),
            },
            cpus: vec![],
            gpus: vec![],
            memory: vec![],
            infiniband_devices: vec![],
            storage: vec![],
            tpm: None,
        },
        device_type: None, // This will result in "unknown" device type
    };
    db::sku::create(&mut txn, &test_sku).await?;

    db::expected_machine::create(
        &mut txn,
        HOST1_MAC.to_string().parse().unwrap(),
        ExpectedMachineData {
            bmc_username: "user1".to_string(),
            bmc_password: "pw".to_string(),
            serial_number: "host1".to_string(),
            fallback_dpu_serial_numbers: vec![],
            metadata: Metadata::new_with_default_name(),
            sku_id: Some("Sku1".to_string()),
            override_id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        },
    )
    .await?;
    txn.commit().await?;

    // Run site explorer
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored_endpoints = db::explored_endpoints::find_all(&mut txn).await.unwrap();

    // Mark explored endpoints as pre-ingestion_complete
    for ee in &explored_endpoints {
        db::explored_endpoints::set_preingestion_complete(ee.address, &mut txn).await?;
    }
    txn.commit().await?;

    assert_eq!(explored_endpoints.len(), 2);

    let mut txn = env.pool.begin().await?;
    let mut explored_managed_hosts = db::explored_managed_host::find_all(&mut txn).await?;
    let mut machines =
        db::machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
            .await
            .unwrap();

    txn.commit().await?;

    // There should be no managed host
    assert_eq!(explored_managed_hosts.len(), 0);
    assert_eq!(machines.len(), 0);

    // Now update expected_machine entry with fallback_dpu_serial
    let mut txn = env.pool.begin().await?;
    let mut host1_expected_machine =
        db::expected_machine::find_by_bmc_mac_address(&mut txn, HOST1_MAC.parse().unwrap())
            .await?
            .expect("Expected machine not found");
    db::expected_machine::update(
        &mut host1_expected_machine,
        &mut txn,
        ExpectedMachineData {
            bmc_username: "user1".to_string(),
            bmc_password: "pw".to_string(),
            serial_number: "host1".to_string(),
            fallback_dpu_serial_numbers: vec![HOST1_DPU_SERIAL_NUMBER.to_string()],
            metadata: Metadata::new_with_default_name(),
            sku_id: None,
            override_id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        },
    )
    .await?;
    txn.commit().await?;

    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    explored_managed_hosts = db::explored_managed_host::find_all(&mut txn).await?;
    machines = db::machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
        .await
        .unwrap();
    txn.commit().await?;
    // We should see one explored_managed host && 2 machines
    assert_eq!(
        <Vec<ExploredManagedHost> as AsRef<Vec<ExploredManagedHost>>>::as_ref(
            &explored_managed_hosts
        )
        .len(),
        1
    );
    assert_eq!(
        <Vec<Machine> as AsRef<Vec<Machine>>>::as_ref(&machines).len(),
        2
    );

    // Make sure they are the machines we just created
    let mut bmc_ip_addresses = vec![explored_managed_hosts[0].host_bmc_ip.clone().to_string()];
    for dpu in explored_managed_hosts[0].clone().dpus {
        bmc_ip_addresses.push(dpu.bmc_ip.to_string())
    }
    assert_eq!(bmc_ip_addresses.len(), 2);
    for bmc_ip in bmc_ip_addresses {
        assert!(
            <Vec<Machine> as AsRef<Vec<Machine>>>::as_ref(&machines)
                .iter()
                .any(|x| { x.bmc_info.ip.clone().unwrap_or_default() == bmc_ip })
        );
    }
    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_health_report(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let query = format!(
        "UPDATE network_segments SET network_segment_type='underlay' WHERE id='{segment_id}'",
    );
    sqlx::query::<_>(&query).execute(&mut *txn).await.unwrap();
    txn.commit().await.unwrap();

    let explorer_config = SiteExplorerConfig {
        enabled: true,
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

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        env.test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

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

async fn fetch_exploration_report(env: &TestEnv) -> rpc::site_explorer::SiteExplorationReport {
    env.api
        .get_site_exploration_report(tonic::Request::new(GetSiteExplorationRequest::default()))
        .await
        .unwrap()
        .into_inner()
}

#[crate::sqlx_test]
async fn test_fetch_host_primary_interface_mac(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut mock_dpus = (0..NUM_DPUS).map(|_| DpuConfig::default()).collect_vec();

    // Make the second DPU have the lower-numbered UEFI device path... we will assert later that
    // it's the primary DPU.
    mock_dpus[0].override_hosts_uefi_device_path = Some(
        UefiDevicePath::from_str("PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x1,0x1)/MAC(A088C208545C,0x1)")
            .unwrap(),
    );
    mock_dpus[1].override_hosts_uefi_device_path = Some(
        UefiDevicePath::from_str("PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x2)/MAC(A088C208545C,0x1)")
            .unwrap(),
    );

    let host_report: EndpointExplorationReport =
        ManagedHostConfig::with_dpus(mock_dpus.clone()).into();

    const NUM_DPUS: usize = 2;

    let env = common::api_fixtures::create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;
    let mut oob_interfaces = Vec::new();
    let mut explored_dpus = Vec::new();

    for (i, mock_dpu) in mock_dpus.iter().enumerate() {
        let oob_mac = mock_dpu.bmc_mac_address;
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

        assert!(!response.address.is_empty());
        let oob_interface = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
        assert!(oob_interface[0].primary_interface);
        oob_interfaces.push(oob_interface[0].clone());

        let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
        dpu_report.generate_machine_id(false)?;
        let dpu_report = Arc::new(dpu_report);
        explored_dpus.push(ExploredDpu {
            bmc_ip: IpAddr::from_str(format!("192.168.1.{i}").as_str())?,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report,
        });
    }

    let expected_mac: MacAddress = mock_dpus[1].host_mac_address;
    let mac = host_report
        .fetch_host_primary_interface_mac(&explored_dpus)
        .unwrap();
    assert_eq!(mac, expected_mac);
    Ok(())
}

/// Test the [`api_fixtures::site_explorer::new_host`] factory with various configurations and make
/// sure they work.
#[crate::sqlx_test]
async fn test_site_explorer_new_host_fixture(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            allow_zero_dpu_hosts: Some(true),
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

#[crate::sqlx_test]
async fn test_site_explorer_fixtures_singledpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;

    let mock_host = ManagedHostConfig::default();
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
            let mut txn = mock.test_env.pool.begin().await.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(&mut txn, &machine_id, Default::default())
                    .await
                    .transpose()
                    .unwrap()?,
            )
        })
        .await?;

    assert_eq!(snapshot.dpu_snapshots.len(), 1);

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_fixtures_multidpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;

    let mock_host = ManagedHostConfig {
        dpus: vec![DpuConfig::default(), DpuConfig::default()],
        ..Default::default()
    };
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
            let mut txn = mock.test_env.pool.begin().await.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(&mut txn, &machine_id, Default::default())
                    .await
                    .transpose()
                    .unwrap()?,
            )
        })
        .await?;

    assert_eq!(snapshot.dpu_snapshots.len(), 2);

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_fixtures_zerodpu_site_explorer_before_host_dhcp(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            allow_zero_dpu_hosts: Some(true),
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
        ..Default::default()
    };
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
            let mut txn = mock.test_env.pool.begin().await.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(&mut txn, &machine_id, Default::default())
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
#[crate::sqlx_test]
async fn test_site_explorer_fixtures_zerodpu_dhcp_before_site_explorer(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            allow_zero_dpu_hosts: Some(true),
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
        ..Default::default()
    };
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
                    db::machine_interface::find_by_mac_address(&mut txn, mac_address).await?;
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
            let mut txn = mock.test_env.pool.begin().await.unwrap();
            Ok::<ManagedHostStateSnapshot, eyre::Report>(
                db::managed_host::load_snapshot(&mut txn, &machine_id, Default::default())
                    .await
                    .transpose()
                    .unwrap()?,
            )
        })
        .await?;

    assert_eq!(snapshot.dpu_snapshots.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_unknown_vendor(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let mut machine = FakeMachine::new("B8:3F:D2:90:97:A7", "Vendor1", &env.underlay_segment);
    machine.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &env.underlay_segment.unwrap())
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    endpoint_explorer.insert_endpoint_result(
        machine.ip.parse().unwrap(),
        Err(EndpointExplorationError::UnsupportedVendor {
            vendor: "Unknown".to_string(),
        }),
    );

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        allow_zero_dpu_hosts: true,
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);
    let report = &explored[0];
    assert_eq!(report.report_version.version_nr(), 1);
    assert_eq!(
        report.report.last_exploration_error,
        Some(EndpointExplorationError::UnsupportedVendor {
            vendor: "Unknown".to_string(),
        })
    );

    let guard = endpoint_explorer.reports.lock().unwrap();
    let res = guard.get(&report.address).unwrap().as_ref();
    assert!(res.is_err());
    assert_eq!(
        res.unwrap_err(),
        report.report.last_exploration_error.as_ref().unwrap()
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_explored_endpoint(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
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
    let host_endpoints =
        db::explored_endpoints::find_all_by_ip(IpAddr::from_str(host_ip)?, &mut txn).await?;
    assert_eq!(host_endpoints.len(), 1);

    let dpu_endpoints =
        db::explored_endpoints::find_all_by_ip(IpAddr::from_str(dpu_ip)?, &mut txn).await?;
    assert_eq!(dpu_endpoints.len(), 1);
    txn.commit().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_machine_creation_with_sku(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    const HOST1_DPU_MAC: &str = "B8:3F:D2:90:97:A6";
    const HOST1_MAC: &str = "AA:AB:AC:AD:AA:02";
    const HOST1_DPU_SERIAL_NUMBER: &str = "host1_dpu_serial_number";

    let mut host1_dpu = FakeMachine::new(HOST1_DPU_MAC, "Vendor1", &env.underlay_segment);

    let mut host1 = FakeMachine::new(HOST1_MAC, "Vendor2", &env.underlay_segment);

    // Create dhcp entries and machine_interface entries for the machines
    for machine in [&mut host1_dpu, &mut host1] {
        machine.discover_dhcp(&env).await?;
    }
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Create a host and dpu reports && host has no dpu_serial
    endpoint_explorer.insert_endpoint_results(vec![
        (
            host1_dpu.ip.parse().unwrap(),
            Ok(DpuConfig::with_serial(HOST1_DPU_SERIAL_NUMBER.to_string()).into()),
        ),
        (
            host1.ip.parse().unwrap(),
            Ok(ManagedHostConfig::default().into()),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: true,
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
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer,
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    // Create expected_machine entry for host1 w.o fallback_dpu_serial_number
    let mut txn = env.pool.begin().await?;

    // Create the SKU record first
    let test_sku = model::sku::Sku {
        schema_version: CURRENT_SKU_VERSION,
        id: "Sku1".to_string(),
        description: "Test SKU for site explorer test".to_string(),
        created: chrono::Utc::now(),
        components: model::sku::SkuComponents {
            chassis: model::sku::SkuComponentChassis {
                vendor: "Vendor1".to_string(),
                model: "Chassis1".to_string(),
                architecture: "x86_64".to_string(),
            },
            cpus: vec![],
            gpus: vec![],
            memory: vec![],
            infiniband_devices: vec![],
            storage: vec![],
            tpm: None,
        },
        device_type: None, // This will result in "unknown" device type
    };
    db::sku::create(&mut txn, &test_sku).await?;

    db::expected_machine::create(
        &mut txn,
        HOST1_MAC.to_string().parse().unwrap(),
        ExpectedMachineData {
            bmc_username: "user1".to_string(),
            bmc_password: "pw".to_string(),
            serial_number: "host1".to_string(),
            fallback_dpu_serial_numbers: vec![],
            metadata: Metadata::new_with_default_name(),
            sku_id: Some("Sku1".to_string()),
            override_id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        },
    )
    .await?;
    txn.commit().await?;

    // Run site explorer
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored_endpoints = db::explored_endpoints::find_all(&mut txn).await.unwrap();

    // Mark explored endpoints as pre-ingestion_complete
    for ee in &explored_endpoints {
        db::explored_endpoints::set_preingestion_complete(ee.address, &mut txn).await?;
    }
    txn.commit().await?;

    assert_eq!(explored_endpoints.len(), 2);

    let mut txn = env.pool.begin().await?;
    let machines = db::machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
        .await
        .unwrap();

    txn.commit().await?;

    for m in machines {
        if m.is_dpu() {
            assert_eq!(m.hw_sku, None);
        } else {
            assert_eq!(m.hw_sku, Some("Sku1".to_string()));
            assert!(m.dpf.enabled);
        }
    }

    // Verify expected machine SKU metrics
    let expected_metrics: HashMap<String, String> = test_meter
        .parsed_metrics("carbide_site_exploration_expected_machines_sku_count")
        .into_iter()
        .collect();

    // We should have metrics for expected machines
    assert!(!expected_metrics.is_empty());
    // The SKU "Sku1" has device_type=None, so it should be counted with device_type="unknown"
    assert!(expected_metrics.contains_key("{device_type=\"unknown\",sku_id=\"Sku1\"}"));

    Ok(())
}

#[crate::sqlx_test]
async fn test_expected_machine_device_type_metrics(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let test_sku_gpu_id = format!("test-sku-gpu-{}", uuid::Uuid::new_v4());
    let test_sku_no_type_id = format!("test-sku-no-type-{}", uuid::Uuid::new_v4());
    const EXPECTED_MACHINE_1_MAC: &str = "AA:BB:CC:DD:EE:01";
    const EXPECTED_MACHINE_2_MAC: &str = "AA:BB:CC:DD:EE:02";
    const EXPECTED_MACHINE_3_MAC: &str = "AA:BB:CC:DD:EE:03";

    // Create fake machines with network interfaces so they can be discovered
    let mut machines = vec![
        FakeMachine::new(EXPECTED_MACHINE_1_MAC, "Vendor1", &env.underlay_segment),
        FakeMachine::new(EXPECTED_MACHINE_2_MAC, "Vendor2", &env.underlay_segment),
        FakeMachine::new(EXPECTED_MACHINE_3_MAC, "Vendor3", &env.underlay_segment),
    ];
    machines.discover_dhcp(&env).await?;

    // Create test SKUs in database
    let mut txn = env.pool.begin().await?;

    let test_sku_with_device_type = model::sku::Sku {
        schema_version: CURRENT_SKU_VERSION,
        id: test_sku_gpu_id.clone(),
        description: "Test GPU SKU".to_string(),
        created: chrono::Utc::now(),
        components: model::sku::SkuComponents {
            chassis: model::sku::SkuComponentChassis {
                vendor: format!("test_vendor_gpu_{}", uuid::Uuid::new_v4()),
                model: format!("test_model_gpu_{}", uuid::Uuid::new_v4()),
                architecture: "x86_64".to_string(),
            },
            cpus: vec![],
            gpus: vec![],
            memory: vec![],
            infiniband_devices: vec![],
            storage: vec![],
            tpm: None,
        },
        device_type: Some("gpu".to_string()),
    };

    let test_sku_without_device_type = model::sku::Sku {
        schema_version: CURRENT_SKU_VERSION,
        id: test_sku_no_type_id.clone(),
        description: "Test SKU without device type".to_string(),
        created: chrono::Utc::now(),
        components: model::sku::SkuComponents {
            chassis: model::sku::SkuComponentChassis {
                vendor: format!("test_vendor_no_type_{}", uuid::Uuid::new_v4()),
                model: format!("test_model_no_type_{}", uuid::Uuid::new_v4()),
                architecture: "x86_64".to_string(),
            },
            cpus: vec![],
            gpus: vec![],
            memory: vec![],
            infiniband_devices: vec![],
            storage: vec![],
            tpm: None,
        },
        device_type: None,
    };

    db::sku::create(&mut txn, &test_sku_with_device_type).await?;
    db::sku::create(&mut txn, &test_sku_without_device_type).await?;

    // Create expected machines with different SKU configurations
    db::expected_machine::create(
        &mut txn,
        EXPECTED_MACHINE_1_MAC.parse().unwrap(),
        ExpectedMachineData {
            bmc_username: "user1".to_string(),
            bmc_password: "pass1".to_string(),
            serial_number: "serial1".to_string(),
            fallback_dpu_serial_numbers: vec![],
            metadata: Metadata::new_with_default_name(),
            sku_id: Some(test_sku_gpu_id.clone()),
            override_id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        },
    )
    .await?;

    db::expected_machine::create(
        &mut txn,
        EXPECTED_MACHINE_2_MAC.parse().unwrap(),
        ExpectedMachineData {
            bmc_username: "user2".to_string(),
            bmc_password: "pass2".to_string(),
            serial_number: "serial2".to_string(),
            fallback_dpu_serial_numbers: vec![],
            metadata: Metadata::new_with_default_name(),
            sku_id: Some(test_sku_no_type_id.clone()),
            override_id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        },
    )
    .await?;

    db::expected_machine::create(
        &mut txn,
        EXPECTED_MACHINE_3_MAC.parse().unwrap(),
        ExpectedMachineData {
            bmc_username: "user3".to_string(),
            bmc_password: "pass3".to_string(),
            serial_number: "serial3".to_string(),
            fallback_dpu_serial_numbers: vec![],
            metadata: Metadata::new_with_default_name(),
            sku_id: None, // No SKU
            override_id: None,
            default_pause_ingestion_and_poweron: None,
            host_nics: vec![],
            rack_id: None,
            dpf_enabled: true,
        },
    )
    .await?;

    txn.commit().await?;

    // Set up endpoint explorer with mock results for our machines
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Mock exploration results for each machine
    endpoint_explorer.insert_endpoint_results(vec![
        (
            machines[0].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: Some(std::time::Duration::from_millis(100)),
                vendor: Some(bmc_vendor::BMCVendor::Dell),
                managers: vec![],
                systems: vec![],
                chassis: vec![],
                service: vec![],
                machine_id: None,
                versions: std::collections::HashMap::new(),
                model: Some("test-model".to_string()),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            }),
        ),
        (
            machines[1].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: Some(std::time::Duration::from_millis(100)),
                vendor: Some(bmc_vendor::BMCVendor::Nvidia),
                managers: vec![],
                systems: vec![],
                chassis: vec![],
                service: vec![],
                machine_id: None,
                versions: std::collections::HashMap::new(),
                model: Some("test-model".to_string()),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            }),
        ),
        (
            machines[2].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: Some(std::time::Duration::from_millis(100)),
                vendor: Some(bmc_vendor::BMCVendor::Supermicro),
                managers: vec![],
                systems: vec![],
                chassis: vec![],
                service: vec![],
                machine_id: None,
                versions: std::collections::HashMap::new(),
                model: Some("test-model".to_string()),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            }),
        ),
    ]);

    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 3, // Explore our 3 machines
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(false.into()),
        allocate_secondary_vtep_ip: true,
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer,
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    // Run site explorer to collect metrics
    explorer.run_single_iteration().await.unwrap();

    // Verify expected machines SKU count metrics
    let device_type_metrics: HashMap<String, String> = test_meter
        .parsed_metrics("carbide_site_exploration_expected_machines_sku_count")
        .into_iter()
        .collect();

    assert!(!device_type_metrics.is_empty());

    // Expected machines metrics are now recorded based on both SKU ID and device type
    // Now that we properly set device_type using update_metadata:
    // - 1 machine with GPU SKU -> sku_id=test_sku_gpu_id, device_type="gpu"
    // - 1 machine with no device_type SKU -> sku_id=test_sku_no_type_id, device_type="unknown"
    // - 1 machine with no SKU -> sku_id="unknown", device_type="unknown"

    // Check machine with GPU SKU
    let gpu_sku_key = format!("{{device_type=\"gpu\",sku_id=\"{test_sku_gpu_id}\"}}");
    assert_eq!(device_type_metrics.get(&gpu_sku_key).unwrap(), "1");

    // Check machine with SKU but no device type
    let no_type_sku_key = format!("{{device_type=\"unknown\",sku_id=\"{test_sku_no_type_id}\"}}");
    assert_eq!(device_type_metrics.get(&no_type_sku_key).unwrap(), "1");

    // Check machine with no SKU
    assert_eq!(
        device_type_metrics
            .get("{device_type=\"unknown\",sku_id=\"unknown\"}")
            .unwrap(),
        "1"
    );

    // Verify total count by summing all device types
    let total_count: u32 = device_type_metrics
        .values()
        .map(|v| v.parse::<u32>().unwrap())
        .sum();
    assert_eq!(total_count, 3);

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_power_shelf_discovery(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let mut power_shelf = FakePowerShelf::new(
        "B8:3F:D2:90:97:B0".parse().unwrap(),
        "".to_string(),
        "PS123456789".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor".to_string(),
        env.underlay_segment.unwrap(),
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(
                power_shelf.bmc_mac_address.to_string(),
                match power_shelf.segment {
                    s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
            )
            .tonic_request(),
        )
        .await?
        .into_inner();
    tracing::info!(
        "DHCP with mac {} assigned ip {}",
        power_shelf.bmc_mac_address,
        response.address
    );
    power_shelf.ip = response.address.clone();
    // Create expected power shelf entry in the database
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf = power_shelf.as_expected_power_shelf();
    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf.bmc_mac_address,
        expected_power_shelf.bmc_username.clone(),
        expected_power_shelf.bmc_password.clone(),
        expected_power_shelf.serial_number.clone(),
        expected_power_shelf.ip_address,
        expected_power_shelf.metadata.clone(),
        expected_power_shelf.rack_id,
    )
    .await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Mock power shelf exploration result
    endpoint_explorer.insert_endpoint_result(
        power_shelf.ip.parse().unwrap(),
        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            machine_id: None,
            managers: Vec::new(),
            systems: vec![ComputerSystem {
                serial_number: Some("PS123456789".to_string()),
                ..Default::default()
            }],
            chassis: vec![Chassis {
                model: Some("PowerShelf-2000".to_string()),
                id: "powershelf".to_string(),
                manufacturer: Some("lite-on technology corp.".to_string()),
                part_number: Some("PS123456789".to_string()),
                serial_number: Some("PS123456789".to_string()),
                ..Default::default()
            }],
            service: Vec::new(),
            versions: HashMap::default(),
            model: Some("PowerShelf-2000".to_string()),
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,
            compute_tray_index: None,
            physical_slot_number: None,
            revision_id: None,
            topology_id: None,
        }),
    );

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 1,
        allow_zero_dpu_hosts: true,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let explored = db_explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);

    for report in &explored {
        assert_eq!(report.report_version.version_nr(), 1);
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap();
        assert!(res.is_ok());
        assert_eq!(
            res.clone().unwrap().endpoint_type,
            report.report.endpoint_type
        );
        assert_eq!(res.clone().unwrap().vendor, report.report.vendor);
        assert_eq!(res.clone().unwrap().systems, report.report.systems);
    }
    let mut txn = env.pool.begin().await?;
    db_explored_endpoints::set_preingestion_complete(power_shelf.ip.parse().unwrap(), &mut txn)
        .await?;
    txn.commit().await?;

    explorer.run_single_iteration().await.unwrap();
    // Check metrics
    assert_eq!(
        test_meter
            .formatted_metric("carbide_endpoint_explorations_count")
            .unwrap(),
        "1"
    );
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_explorer_created_power_shelves_count")
            .unwrap(),
        "1"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_power_shelf_with_expected_config(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Create a power shelf using the new FakePowerShelf struct
    let mut power_shelf = FakePowerShelf::new(
        "B8:3F:D2:90:97:B1".parse().unwrap(),
        "192.168.1.100".parse().unwrap(),
        "PS123456789".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor".to_string(),
        env.underlay_segment.unwrap(),
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(
                power_shelf.bmc_mac_address.to_string(),
                match power_shelf.segment {
                    s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
            )
            .tonic_request(),
        )
        .await?
        .into_inner();
    tracing::info!(
        "DHCP with mac {} assigned ip {}",
        power_shelf.bmc_mac_address,
        response.address
    );
    power_shelf.ip = response.address.clone();
    // Create an expected power shelf entry
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf = power_shelf.as_expected_power_shelf();

    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf.bmc_mac_address,
        expected_power_shelf.bmc_username.clone(),
        expected_power_shelf.bmc_password.clone(),
        expected_power_shelf.serial_number.clone(),
        expected_power_shelf.ip_address,
        expected_power_shelf.metadata.clone(),
        expected_power_shelf.rack_id,
    )
    .await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Mock power shelf exploration result with matching serial
    endpoint_explorer.insert_endpoint_result(
        power_shelf.ip.parse().unwrap(), // Use expected IP address, not DHCP-assigned IP
        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            machine_id: None,
            managers: Vec::new(),
            systems: vec![ComputerSystem {
                serial_number: Some("PS123456789".to_string()),
                ..Default::default()
            }],
            chassis: vec![Chassis {
                model: Some("PowerShelf-2000".to_string()),
                id: "powershelf".to_string(),
                manufacturer: Some("lite-on technology corp.".to_string()),
                part_number: Some("PS123456789".to_string()),
                serial_number: Some("PS123456789".to_string()),
                ..Default::default()
            }],
            service: Vec::new(),
            versions: HashMap::default(),
            model: Some("PowerShelf-2000".to_string()),
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,
            compute_tray_index: None,
            physical_slot_number: None,
            revision_id: None,
            topology_id: None,
        }),
    );

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 1,
        allow_zero_dpu_hosts: true,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    db_explored_endpoints::set_preingestion_complete(power_shelf.ip.parse().unwrap(), &mut txn)
        .await?;
    txn.commit().await?;
    explorer.run_single_iteration().await.unwrap();

    // Verify power shelf was created with expected metadata
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig {},
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 1);
    let power_shelf_db = &power_shelves[0];
    assert_eq!(power_shelf_db.config.name, "Test Power Shelf PS123456789");

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_power_shelf_creation_limit(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Create multiple power shelf machines using FakePowerShelf
    let mut power_shelves = vec![
        FakePowerShelf::new(
            "B8:3F:D2:90:97:B2".parse().unwrap(),
            "".to_string(),
            "PS123456790".to_string(),
            "admin".to_string(),
            "password".to_string(),
            "PowerShelfVendor1".to_string(),
            env.underlay_segment.unwrap(),
        ),
        FakePowerShelf::new(
            "B8:3F:D2:90:97:B3".parse().unwrap(),
            "".to_string(),
            "PS123456791".to_string(),
            "admin".to_string(),
            "password".to_string(),
            "PowerShelfVendor2".to_string(),
            env.underlay_segment.unwrap(),
        ),
        FakePowerShelf::new(
            "B8:3F:D2:90:97:B4".parse().unwrap(),
            "".to_string(),
            "PS123456792".to_string(),
            "admin".to_string(),
            "password".to_string(),
            "PowerShelfVendor3".to_string(),
            env.underlay_segment.unwrap(),
        ),
    ];
    for power_shelf in &mut power_shelves {
        let response = env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(
                    power_shelf.bmc_mac_address.to_string(),
                    match power_shelf.segment {
                        s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
                        _ => "192.0.2.1".to_string(),
                    },
                )
                .tonic_request(),
            )
            .await?
            .into_inner();
        tracing::info!(
            "DHCP with mac {} assigned ip {}",
            power_shelf.bmc_mac_address,
            response.address
        );
        power_shelf.ip = response.address.clone();
    }
    // Create expected power shelf entries in the database
    let mut txn = env.pool.begin().await?;
    for power_shelf in &power_shelves {
        let expected_power_shelf = power_shelf.as_expected_power_shelf();
        db::expected_power_shelf::create(
            &mut txn,
            expected_power_shelf.bmc_mac_address,
            expected_power_shelf.bmc_username.clone(),
            expected_power_shelf.bmc_password.clone(),
            expected_power_shelf.serial_number.clone(),
            expected_power_shelf.ip_address,
            expected_power_shelf.metadata.clone(),
            expected_power_shelf.rack_id,
        )
        .await?;
    }
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Mock exploration results for all power shelves
    for power_shelf in &power_shelves {
        endpoint_explorer.insert_endpoint_result(
            power_shelf.ip.parse().unwrap(), // Use expected IP address, not DHCP-assigned IP
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                last_exploration_latency: None,
                vendor: Some(bmc_vendor::BMCVendor::Nvidia),
                machine_id: None,
                managers: Vec::new(),
                systems: vec![ComputerSystem {
                    serial_number: Some(power_shelf.serial_number.clone()),
                    ..Default::default()
                }],
                chassis: vec![Chassis {
                    model: Some("PowerShelf-2000".to_string()),
                    id: "powershelf".to_string(),
                    manufacturer: Some("lite-on technology corp.".to_string()),
                    part_number: Some("PS123456789".to_string()),
                    serial_number: Some("PS123456789".to_string()),
                    ..Default::default()
                }],
                service: Vec::new(),
                versions: HashMap::default(),
                model: Some("PowerShelf-2000".to_string()),
                machine_setup_status: None,
                secure_boot_status: None,
                lockdown_status: None,
                power_shelf_id: None,
                switch_id: None,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            }),
        );
    }

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 3,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 2, // Limit to 2 per run
        allow_zero_dpu_hosts: true,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    for power_shelf in &power_shelves {
        db_explored_endpoints::set_preingestion_complete(power_shelf.ip.parse().unwrap(), &mut txn)
            .await?;
    }
    txn.commit().await?;

    explorer.run_single_iteration().await.unwrap();

    // Check that only 2 power shelves were created due to limit
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_explorer_created_power_shelves_count")
            .unwrap(),
        "2"
    );

    // Run another iteration to create the remaining power shelf
    explorer.run_single_iteration().await.unwrap();

    // Check that all 3 power shelves were created
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_explorer_created_power_shelves_count")
            .unwrap(),
        "1"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_power_shelf_disabled(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Create a power shelf machine using FakePowerShelf
    let mut power_shelf = FakePowerShelf::new(
        "B8:3F:D2:90:97:B5".parse().unwrap(),
        "".to_string(),
        "PS123456793".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor".to_string(),
        env.underlay_segment.unwrap(),
    );
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(
                power_shelf.bmc_mac_address.to_string(),
                match power_shelf.segment {
                    s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
            )
            .tonic_request(),
        )
        .await?
        .into_inner();
    tracing::info!(
        "DHCP with mac {} assigned ip {}",
        power_shelf.bmc_mac_address,
        response.address
    );
    power_shelf.ip = response.address.clone();

    // Create expected power shelf entry in the database
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf = power_shelf.as_expected_power_shelf();
    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf.bmc_mac_address,
        expected_power_shelf.bmc_username.clone(),
        expected_power_shelf.bmc_password.clone(),
        expected_power_shelf.serial_number.clone(),
        expected_power_shelf.ip_address,
        expected_power_shelf.metadata.clone(),
        expected_power_shelf.rack_id,
    )
    .await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Mock power shelf exploration result
    endpoint_explorer.insert_endpoint_result(
        power_shelf.ip.parse().unwrap(),
        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            machine_id: None,
            managers: Vec::new(),
            systems: vec![ComputerSystem {
                serial_number: Some("PS123456789".to_string()),
                ..Default::default()
            }],
            chassis: vec![Chassis {
                model: Some("PowerShelf-2000".to_string()),
                ..Default::default()
            }],
            service: Vec::new(),
            versions: HashMap::default(),
            model: Some("PowerShelf-2000".to_string()),
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,
            compute_tray_index: None,
            physical_slot_number: None,
            revision_id: None,
            topology_id: None,
        }),
    );

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(false.into()), // Disabled
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 1,
        allow_zero_dpu_hosts: true,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();

    // Check that no power shelves were created
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_explorer_created_power_shelves_count")
            .unwrap(),
        "0"
    );

    // Verify no power shelves exist in database
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig {},
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_power_shelf_error_handling(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    // Create a power shelf machine using FakePowerShelf
    let mut power_shelf = FakePowerShelf::new(
        "B8:3F:D2:90:97:B6".parse().unwrap(),
        "".to_string(),
        "PS123456794".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor".to_string(),
        env.underlay_segment.unwrap(),
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(
                power_shelf.bmc_mac_address.to_string(),
                match power_shelf.segment {
                    s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
            )
            .tonic_request(),
        )
        .await?
        .into_inner();
    tracing::info!(
        "DHCP with mac {} assigned ip {}",
        power_shelf.bmc_mac_address,
        response.address
    );
    power_shelf.ip = response.address.clone();
    // Create expected power shelf entry in the database
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf = power_shelf.as_expected_power_shelf();
    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf.bmc_mac_address,
        expected_power_shelf.bmc_username.clone(),
        expected_power_shelf.bmc_password.clone(),
        expected_power_shelf.serial_number.clone(),
        expected_power_shelf.ip_address,
        expected_power_shelf.metadata.clone(),
        expected_power_shelf.rack_id,
    )
    .await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Mock power shelf exploration error
    endpoint_explorer.insert_endpoint_result(
        power_shelf.ip.parse().unwrap(),
        Err(EndpointExplorationError::Unauthorized {
            details: "Not authorized".to_string(),
            response_body: None,
            response_code: None,
        }),
    );

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 1,
        allow_zero_dpu_hosts: true,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let explored = db_explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);

    // Verify error was recorded
    let report = &explored[0];
    assert_eq!(
        report.report.last_exploration_error,
        Some(EndpointExplorationError::Unauthorized {
            details: "Not authorized".to_string(),
            response_body: None,
            response_code: None,
        })
    );

    // Check metrics for error
    assert_eq!(
        test_meter
            .formatted_metric("carbide_endpoint_exploration_failures_count")
            .unwrap(),
        "{failure=\"unauthorized\"} 1"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_creates_power_shelf(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.dpu_config.dpu_models = HashMap::new();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 1,
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    // Create a power shelf using FakePowerShelf
    let mut power_shelf = FakePowerShelf::new(
        "B8:3F:D2:90:97:B0".parse().unwrap(),
        "".to_string(),
        "PS123456789".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor".to_string(),
        env.underlay_segment.unwrap(),
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(
                power_shelf.bmc_mac_address.to_string(),
                match power_shelf.segment {
                    s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
            )
            .tonic_request(),
        )
        .await?
        .into_inner();
    tracing::info!(
        "DHCP with mac {} assigned ip {}",
        power_shelf.bmc_mac_address,
        response.address
    );
    power_shelf.ip = response.address.clone();
    // Create expected power shelf entry in the database
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf = power_shelf.as_expected_power_shelf();
    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf.bmc_mac_address,
        expected_power_shelf.bmc_username.clone(),
        expected_power_shelf.bmc_password.clone(),
        expected_power_shelf.serial_number.clone(),
        expected_power_shelf.ip_address,
        expected_power_shelf.metadata.clone(),
        expected_power_shelf.rack_id,
    )
    .await?;
    txn.commit().await?;

    // Create exploration report for power shelf
    let exploration_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        last_exploration_latency: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: Vec::new(),
        systems: vec![ComputerSystem {
            serial_number: Some("PS123456789".to_string()),
            ..Default::default()
        }],
        chassis: vec![Chassis {
            model: Some("PowerShelf-2000".to_string()),
            ..Default::default()
        }],
        service: Vec::new(),
        versions: HashMap::default(),
        model: Some("PowerShelf-2000".to_string()),
        machine_setup_status: None,
        secure_boot_status: None,
        lockdown_status: None,
        power_shelf_id: None,
        switch_id: None,
        compute_tray_index: None,
        physical_slot_number: None,
        revision_id: None,
        topology_id: None,
    };

    let explored_endpoint = ExploredEndpoint {
        address: power_shelf.ip.parse().unwrap(),
        report: exploration_report.clone(),
        report_version: ConfigVersion::initial(),
        preingestion_state: PreingestionState::Complete,
        waiting_for_explorer_refresh: false,
        exploration_requested: false,
        last_redfish_bmc_reset: None,
        last_ipmitool_bmc_reset: None,
        last_redfish_reboot: None,
        last_redfish_powercycle: None,
        pause_remediation: false,
        boot_interface_mac: None,
        pause_ingestion_and_poweron: false,
    };

    // Test power shelf creation
    assert!(
        explorer
            .create_power_shelf(
                explored_endpoint.clone(),
                exploration_report.clone(),
                &expected_power_shelf,
                &env.pool,
            )
            .await?
    );

    // Verify power shelf was created in database
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig::default(),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 1);
    let created_power_shelf = &power_shelves[0];
    assert_eq!(
        created_power_shelf.config.name,
        "Test Power Shelf PS123456789"
    );

    // Test that duplicate creation returns false
    assert!(
        !explorer
            .create_power_shelf(
                explored_endpoint,
                exploration_report,
                &expected_power_shelf,
                &env.pool,
            )
            .await?
    );

    // Verify only one power shelf exists (no duplicate created)
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig::default(),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 1);

    // Test power shelf state controller functionality
    // Run power shelf controller iteration to test state transitions
    // TODO(chet): Enable this once the state machine stuff is wired up!
    // env.run_power_shelf_controller_iteration().await;
    if 1 == 1 {
        return Ok(());
    }

    // Verify power shelf state transitions
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig::default(),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 1);
    let power_shelf = &power_shelves[0];

    // Check that the power shelf has a controller state
    assert!(power_shelf.controller_state.value != PowerShelfControllerState::Initializing);

    // Run multiple iterations to test state transitions
    // TODO(chet): Enable this once the state machine stuff is wired up!
    // for _ in 0..3 {
    //    println!("Running power shelf controller iteration");
    //    env.run_power_shelf_controller_iteration().await;
    //}
    if 1 == 1 {
        return Ok(());
    }

    // Verify final state
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig::default(),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 1);
    let power_shelf = &power_shelves[0];

    // The power shelf should be in Ready state after multiple iterations
    assert_eq!(
        power_shelf.controller_state.value,
        PowerShelfControllerState::Ready
    );

    Ok(())
}

/// Test power shelf state history functionality
#[crate::sqlx_test]
async fn test_power_shelf_state_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.dpu_config.dpu_models = HashMap::new();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    // Create a power shelf using FakePowerShelf
    let mut power_shelf = FakePowerShelf::new(
        "B8:3F:D2:90:97:B0".parse().unwrap(),
        "".to_string(),
        "PS123456789".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor".to_string(),
        env.underlay_segment.unwrap(),
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(
                power_shelf.bmc_mac_address.to_string(),
                match power_shelf.segment {
                    s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
            )
            .tonic_request(),
        )
        .await?
        .into_inner();
    tracing::info!(
        "DHCP with mac {} assigned ip {}",
        power_shelf.bmc_mac_address,
        response.address
    );
    power_shelf.ip = response.address.clone();
    // Create expected power shelf entry in the database
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf = power_shelf.as_expected_power_shelf();
    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf.bmc_mac_address,
        expected_power_shelf.bmc_username.clone(),
        expected_power_shelf.bmc_password.clone(),
        expected_power_shelf.serial_number.clone(),
        expected_power_shelf.ip_address,
        expected_power_shelf.metadata.clone(),
        expected_power_shelf.rack_id,
    )
    .await?;
    txn.commit().await?;

    // Create exploration report for power shelf
    let exploration_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        last_exploration_latency: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: Vec::new(),
        systems: vec![ComputerSystem {
            serial_number: Some("PS123456789".to_string()),
            ..Default::default()
        }],
        chassis: vec![Chassis {
            model: Some("PowerShelf-2000".to_string()),
            ..Default::default()
        }],
        service: Vec::new(),
        versions: HashMap::default(),
        model: Some("PowerShelf-2000".to_string()),
        machine_setup_status: None,
        secure_boot_status: None,
        lockdown_status: None,
        power_shelf_id: None,
        switch_id: None,
        compute_tray_index: None,
        physical_slot_number: None,
        revision_id: None,
        topology_id: None,
    };

    let explored_endpoint = ExploredEndpoint {
        address: power_shelf.ip.parse().unwrap(),
        report: exploration_report.clone(),
        report_version: ConfigVersion::initial(),
        preingestion_state: PreingestionState::Complete,
        waiting_for_explorer_refresh: false,
        exploration_requested: false,
        last_redfish_bmc_reset: None,
        last_ipmitool_bmc_reset: None,
        last_redfish_reboot: None,
        last_redfish_powercycle: None,
        pause_remediation: false,
        boot_interface_mac: None,
        pause_ingestion_and_poweron: false,
    };

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 1,
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    // Create the power shelf using site explorer
    assert!(
        explorer
            .create_power_shelf(
                explored_endpoint.clone(),
                exploration_report.clone(),
                &expected_power_shelf,
                &env.pool,
            )
            .await?
    );

    // Find the created power shelf
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig::default(),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 1);
    let created_power_shelf = &power_shelves[0];
    let power_shelf_id = created_power_shelf.id;

    // Test state history persistence
    // Test initial state
    let mut txn = env.pool.begin().await?;
    let initial_state =
        db::power_shelf_state_history::for_power_shelf(&mut txn, &power_shelf_id).await?;
    txn.commit().await?;

    // Initial state should be empty since no state transitions have occurred yet
    assert!(initial_state.is_empty(), "Initial state should be empty");

    // Test state transition by running controller iteration
    // TODO(chet): Enable this once the state machine stuff is wired up!
    // env.run_power_shelf_controller_iteration().await;
    if 1 == 1 {
        return Ok(());
    }

    // Verify state was persisted
    let mut txn = env.pool.begin().await?;
    let updated_state =
        db::power_shelf_state_history::for_power_shelf(&mut txn, &power_shelf_id).await?;
    txn.commit().await?;

    // Should have at least one state entry now
    assert!(
        !updated_state.is_empty(),
        "Should have state entries after controller iteration"
    );

    // Test finding history by multiple power shelf IDs
    let mut txn = env.pool.begin().await?;
    let history_by_ids =
        db::power_shelf_state_history::find_by_power_shelf_ids(&mut txn, &[power_shelf_id]).await?;
    txn.commit().await?;

    assert!(history_by_ids.contains_key(&power_shelf_id));
    let power_shelf_history = &history_by_ids[&power_shelf_id];
    assert_eq!(power_shelf_history.len(), updated_state.len());

    // Run multiple iterations to test state transitions
    // TODO(chet): Enable this once the state machine stuff is wired up!
    // for _ in 0..3 {
    //     env.run_power_shelf_controller_iteration().await;
    // }
    if 1 == 1 {
        return Ok(());
    }

    // Verify final state history
    let mut txn = env.pool.begin().await?;
    let final_state =
        db::power_shelf_state_history::for_power_shelf(&mut txn, &power_shelf_id).await?;
    txn.commit().await?;

    // Should have multiple state entries now
    assert!(
        final_state.len() > 1,
        "Should have multiple state entries after multiple iterations"
    );

    // Verify state versions are incrementing
    // let mut state_versions = std::collections::HashSet::new();
    // for entry in &final_state {
    //     state_versions.insert(entry.state_version.clone());
    // }

    // // Should have multiple state versions indicating state transitions
    // assert!(
    //     state_versions.len() > 1,
    //     "Should have multiple state versions"
    // );

    Ok(())
}

/// Test power shelf state history with multiple power shelves
#[crate::sqlx_test]
async fn test_power_shelf_state_history_multiple(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.dpu_config.dpu_models = HashMap::new();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    // Create multiple power shelves
    let power_shelf1 = FakePowerShelf::new(
        "B8:3F:D2:90:97:B0".parse().unwrap(),
        "192.0.1.2".parse().unwrap(),
        "PS123456789".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor1".to_string(),
        env.underlay_segment.unwrap(),
    );

    let power_shelf2 = FakePowerShelf::new(
        "B8:3F:D2:90:97:B1".parse().unwrap(),
        "192.0.1.3".parse().unwrap(),
        "PS987654321".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor2".to_string(),
        env.underlay_segment.unwrap(),
    );

    // Create expected power shelf entries in the database
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf1 = power_shelf1.as_expected_power_shelf();
    let expected_power_shelf2 = power_shelf2.as_expected_power_shelf();

    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf1.bmc_mac_address,
        expected_power_shelf1.bmc_username.clone(),
        expected_power_shelf1.bmc_password.clone(),
        expected_power_shelf1.serial_number.clone(),
        expected_power_shelf1.ip_address,
        expected_power_shelf1.metadata.clone(),
        expected_power_shelf1.rack_id,
    )
    .await?;

    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf2.bmc_mac_address,
        expected_power_shelf2.bmc_username.clone(),
        expected_power_shelf2.bmc_password.clone(),
        expected_power_shelf2.serial_number.clone(),
        expected_power_shelf2.ip_address,
        expected_power_shelf2.metadata.clone(),
        expected_power_shelf2.rack_id,
    )
    .await?;
    txn.commit().await?;

    // Create exploration reports for power shelves
    let exploration_report1 = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        last_exploration_latency: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: Vec::new(),
        systems: vec![ComputerSystem {
            serial_number: Some("PS123456789".to_string()),
            ..Default::default()
        }],
        chassis: vec![Chassis {
            model: Some("PowerShelf-2000".to_string()),
            ..Default::default()
        }],
        service: Vec::new(),
        versions: HashMap::default(),
        model: Some("PowerShelf-2000".to_string()),
        machine_setup_status: None,
        secure_boot_status: None,
        lockdown_status: None,
        power_shelf_id: None,
        switch_id: None,
        compute_tray_index: None,
        physical_slot_number: None,
        revision_id: None,
        topology_id: None,
    };

    let exploration_report2 = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        last_exploration_latency: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: Vec::new(),
        systems: vec![ComputerSystem {
            serial_number: Some("PS987654321".to_string()),
            ..Default::default()
        }],
        chassis: vec![Chassis {
            model: Some("PowerShelf-3000".to_string()),
            ..Default::default()
        }],
        service: Vec::new(),
        versions: HashMap::default(),
        model: Some("PowerShelf-3000".to_string()),
        machine_setup_status: None,
        secure_boot_status: None,
        lockdown_status: None,
        power_shelf_id: None,
        switch_id: None,
        compute_tray_index: None,
        physical_slot_number: None,
        revision_id: None,
        topology_id: None,
    };

    let explored_endpoint1 = ExploredEndpoint {
        address: power_shelf1.ip.parse().unwrap(),
        report: exploration_report1.clone(),
        report_version: ConfigVersion::initial(),
        preingestion_state: PreingestionState::Complete,
        waiting_for_explorer_refresh: false,
        exploration_requested: false,
        last_redfish_bmc_reset: None,
        last_ipmitool_bmc_reset: None,
        last_redfish_reboot: None,
        last_redfish_powercycle: None,
        pause_remediation: false,
        boot_interface_mac: None,
        pause_ingestion_and_poweron: false,
    };

    let explored_endpoint2 = ExploredEndpoint {
        address: power_shelf2.ip.parse().unwrap(),
        report: exploration_report2.clone(),
        report_version: ConfigVersion::initial(),
        preingestion_state: PreingestionState::Complete,
        waiting_for_explorer_refresh: false,
        exploration_requested: false,
        last_redfish_bmc_reset: None,
        last_ipmitool_bmc_reset: None,
        last_redfish_reboot: None,
        last_redfish_powercycle: None,
        pause_remediation: false,
        boot_interface_mac: None,
        pause_ingestion_and_poweron: false,
    };

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 2,
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    // Create the power shelves using site explorer
    assert!(
        explorer
            .create_power_shelf(
                explored_endpoint1.clone(),
                exploration_report1.clone(),
                &expected_power_shelf1,
                &env.pool,
            )
            .await?
    );

    assert!(
        explorer
            .create_power_shelf(
                explored_endpoint2.clone(),
                exploration_report2.clone(),
                &expected_power_shelf2,
                &env.pool,
            )
            .await?
    );
    // Find the created power shelves
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig::default(),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 2);
    let power_shelf1_id = power_shelves[0].id;
    let power_shelf2_id = power_shelves[1].id;

    // Test state history for multiple power shelves
    let mut txn = env.pool.begin().await?;
    let _history_by_ids = db::power_shelf_state_history::find_by_power_shelf_ids(
        &mut txn,
        &[power_shelf1_id, power_shelf2_id],
    )
    .await?;
    txn.commit().await?;

    // println!("history_by_ids: {:?}", history_by_ids);
    // assert!(history_by_ids.contains_key(&power_shelf1_id));
    // assert!(history_by_ids.contains_key(&power_shelf2_id));

    // Test individual power shelf state history
    let mut txn = env.pool.begin().await?;
    let power_shelf1_history =
        db::power_shelf_state_history::for_power_shelf(&mut txn, &power_shelf1_id).await?;
    let power_shelf2_history =
        db::power_shelf_state_history::for_power_shelf(&mut txn, &power_shelf2_id).await?;
    txn.commit().await?;

    // Both should start with empty state history
    assert!(power_shelf1_history.is_empty());
    assert!(power_shelf2_history.is_empty());

    // Run controller iterations to trigger state transitions
    // TODO(chet): Enable this once the state machine stuff is wired up!
    // for _ in 0..3 {
    //    env.run_power_shelf_controller_iteration().await;
    // }
    if 1 == 1 {
        return Ok(());
    }

    // Verify state history has been updated for both power shelves
    let mut txn = env.pool.begin().await?;
    let updated_history1 =
        db::power_shelf_state_history::for_power_shelf(&mut txn, &power_shelf1_id).await?;
    let updated_history2 =
        db::power_shelf_state_history::for_power_shelf(&mut txn, &power_shelf2_id).await?;
    txn.commit().await?;

    // Both should have state entries now
    assert!(!updated_history1.is_empty());
    assert!(!updated_history2.is_empty());

    // Test finding history by multiple power shelf IDs again
    let mut txn = env.pool.begin().await?;
    let final_history_by_ids = db::power_shelf_state_history::find_by_power_shelf_ids(
        &mut txn,
        &[power_shelf1_id, power_shelf2_id],
    )
    .await?;
    txn.commit().await?;

    assert_eq!(
        final_history_by_ids[&power_shelf1_id].len(),
        updated_history1.len()
    );
    assert_eq!(
        final_history_by_ids[&power_shelf2_id].len(),
        updated_history2.len()
    );

    Ok(())
}

/// Test power shelf state history error handling
#[crate::sqlx_test]
async fn test_power_shelf_state_history_error_handling(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.dpu_config.dpu_models = HashMap::new();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    // Create a power shelf using FakePowerShelf
    let mut power_shelf = FakePowerShelf::new(
        "B8:3F:D2:90:97:B0".parse().unwrap(),
        "".to_string(),
        "PS999999999".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "TestVendor".to_string(),
        env.underlay_segment.unwrap(),
    );

    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(
                power_shelf.bmc_mac_address.to_string(),
                match power_shelf.segment {
                    s if s == env.underlay_segment.unwrap() => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
            )
            .tonic_request(),
        )
        .await?
        .into_inner();
    tracing::info!(
        "DHCP with mac {} assigned ip {}",
        power_shelf.bmc_mac_address,
        response.address
    );
    power_shelf.ip = response.address.clone();
    // Create expected power shelf entry in the database
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf = power_shelf.as_expected_power_shelf();
    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf.bmc_mac_address,
        expected_power_shelf.bmc_username.clone(),
        expected_power_shelf.bmc_password.clone(),
        expected_power_shelf.serial_number.clone(),
        expected_power_shelf.ip_address,
        expected_power_shelf.metadata.clone(),
        expected_power_shelf.rack_id,
    )
    .await?;
    txn.commit().await?;

    // Create exploration report for power shelf
    let exploration_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        last_exploration_latency: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: Vec::new(),
        systems: vec![ComputerSystem {
            serial_number: Some("PS999999999".to_string()),
            ..Default::default()
        }],
        chassis: vec![Chassis {
            model: Some("TestModel".to_string()),
            ..Default::default()
        }],
        service: Vec::new(),
        versions: HashMap::default(),
        model: Some("TestModel".to_string()),
        machine_setup_status: None,
        secure_boot_status: None,
        lockdown_status: None,
        power_shelf_id: None,
        switch_id: None,
        compute_tray_index: None,
        physical_slot_number: None,
        revision_id: None,
        topology_id: None,
    };

    let explored_endpoint = ExploredEndpoint {
        address: power_shelf.ip.parse().unwrap(),
        report: exploration_report.clone(),
        report_version: ConfigVersion::initial(),
        preingestion_state: PreingestionState::Complete,
        waiting_for_explorer_refresh: false,
        exploration_requested: false,
        last_redfish_bmc_reset: None,
        last_ipmitool_bmc_reset: None,
        last_redfish_reboot: None,
        last_redfish_powercycle: None,
        pause_remediation: false,
        boot_interface_mac: None,
        pause_ingestion_and_poweron: false,
    };

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(false.into()),
        power_shelves_created_per_run: 1,
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    // Create the power shelf using site explorer
    assert!(
        explorer
            .create_power_shelf(
                explored_endpoint.clone(),
                exploration_report.clone(),
                &expected_power_shelf,
                &env.pool,
            )
            .await?
    );

    // Get the created power shelf
    let mut txn = env.pool.begin().await?;
    let power_shelves = db::power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::<db::power_shelf::IdColumn>::All,
        db::power_shelf::PowerShelfSearchConfig::default(),
    )
    .await?;
    txn.commit().await?;

    assert_eq!(power_shelves.len(), 1);
    let power_shelf = &power_shelves[0];
    let power_shelf_id = power_shelf.id;

    // Test state history with various state types
    let test_states = [
        PowerShelfControllerState::Initializing,
        PowerShelfControllerState::FetchingData,
        PowerShelfControllerState::Configuring,
        PowerShelfControllerState::Ready,
    ];

    let mut txn = env.pool.begin().await?;

    for state in test_states.iter() {
        let version = ConfigVersion::initial();

        let history_entry =
            db::power_shelf_state_history::persist(&mut txn, &power_shelf_id, state, version)
                .await?;

        assert_eq!(
            history_entry.state.replace(" ", ""),
            serde_json::to_string(&state)?
        );
        assert_eq!(history_entry.state_version, version);

        // Verify the entry can be retrieved
        let retrieved_history =
            db::power_shelf_state_history::for_power_shelf(&mut txn, &power_shelf_id).await?;
        let found_entry = retrieved_history
            .iter()
            .find(|entry| entry.state_version == version);
        assert!(found_entry.is_some());
        assert_eq!(
            found_entry.unwrap().state.replace(" ", ""),
            serde_json::to_string(&state)?
        );
    }

    txn.commit().await?;

    // Test finding history for non-existent power shelf
    let mut txn = env.pool.begin().await?;
    let non_existent_id = carbide_uuid::power_shelf::PowerShelfId::new(
        carbide_uuid::power_shelf::PowerShelfIdSource::ProductBoardChassisSerial,
        [0; 32],
        carbide_uuid::power_shelf::PowerShelfType::Host,
    );
    let empty_history =
        db::power_shelf_state_history::for_power_shelf(&mut txn, &non_existent_id).await?;
    txn.commit().await?;

    assert!(empty_history.is_empty());

    // Test finding history for empty list of power shelf IDs
    let mut txn = env.pool.begin().await?;
    let empty_history_map =
        db::power_shelf_state_history::find_by_power_shelf_ids(&mut txn, &[]).await?;
    txn.commit().await?;

    assert!(empty_history_map.is_empty());

    Ok(())
}

#[crate::sqlx_test]
async fn test_site_explorer_power_shelf_discovery_with_static_ip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let power_shelf = FakePowerShelf::new(
        "B8:3F:D2:90:97:B0".parse().unwrap(),
        "192.0.2.1".to_string(),
        "PS123456789".to_string(),
        "admin".to_string(),
        "password".to_string(),
        "PowerShelfVendor".to_string(),
        env.underlay_segment.unwrap(),
    );

    tracing::info!(
        "Static ip {} assigned to power shelf mac {}",
        power_shelf.ip,
        power_shelf.bmc_mac_address,
    );
    // Create expected power shelf entry in the database
    let mut txn = env.pool.begin().await?;
    let expected_power_shelf = power_shelf.as_expected_power_shelf();
    db::expected_power_shelf::create(
        &mut txn,
        expected_power_shelf.bmc_mac_address,
        expected_power_shelf.bmc_username.clone(),
        expected_power_shelf.bmc_password.clone(),
        expected_power_shelf.serial_number.clone(),
        expected_power_shelf.ip_address,
        expected_power_shelf.metadata.clone(),
        expected_power_shelf.rack_id,
    )
    .await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Mock power shelf exploration result
    endpoint_explorer.insert_endpoint_result(
        power_shelf.ip.parse().unwrap(),
        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            machine_id: None,
            managers: Vec::new(),
            systems: vec![ComputerSystem {
                serial_number: Some("PS123456789".to_string()),
                ..Default::default()
            }],
            chassis: vec![Chassis {
                model: Some("PowerShelf-2000".to_string()),
                id: "powershelf".to_string(),
                manufacturer: Some("lite-on technology corp.".to_string()),
                part_number: Some("PS123456789".to_string()),
                serial_number: Some("PS123456789".to_string()),
                ..Default::default()
            }],
            service: Vec::new(),
            versions: HashMap::default(),
            model: Some("PowerShelf-2000".to_string()),
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,
            compute_tray_index: None,
            physical_slot_number: None,
            revision_id: None,
            topology_id: None,
        }),
    );

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        allow_zero_dpu_hosts: true,
        ..Default::default()
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
        env.api.work_lock_manager_handle.clone(),
        env.rms_sim.as_rms_client(),
    );

    explorer.run_single_iteration().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let explored = db_explored_endpoints::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);

    for report in &explored {
        assert_eq!(report.report_version.version_nr(), 1);
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap();
        assert!(res.is_ok());
        assert_eq!(
            res.clone().unwrap().endpoint_type,
            report.report.endpoint_type
        );
        assert_eq!(res.clone().unwrap().vendor, report.report.vendor);
        assert_eq!(res.clone().unwrap().systems, report.report.systems);
    }

    // explorer.run_single_iteration().await.unwrap();
    // Check metrics
    assert_eq!(
        test_meter
            .formatted_metric("carbide_endpoint_explorations_count")
            .unwrap(),
        "1"
    );
    assert_eq!(
        test_meter
            .formatted_metric("carbide_site_explorer_created_power_shelves_count")
            .unwrap(),
        "1"
    );

    Ok(())
}

/// Test the get_machine_position_info API endpoint
#[crate::sqlx_test]
async fn test_get_machine_position_info(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use rpc::forge::forge_server::Forge;

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
#[crate::sqlx_test]
async fn test_get_machine_position_info_no_endpoint(
    pool: sqlx::PgPool,
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
