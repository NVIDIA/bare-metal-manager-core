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

use carbide_site_explorer::config::{SiteExplorerConfig, SiteExplorerExploreMode};
use carbide_site_explorer::{SiteExplorer, endpoint_exploration_work_key};
use common::api_fixtures::TestEnv;
use common::api_fixtures::endpoint_explorer::MockEndpointExplorer;
use db::sku::CURRENT_SKU_VERSION;
use db::{self, ObjectColumnFilter, ObjectFilter, explored_endpoints as db_explored_endpoints};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use model::expected_machine::{ExpectedMachine, ExpectedMachineData};
use model::hardware_info::HardwareInfo;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{LoadSnapshotOptions, Machine, ManagedHostStateSnapshot};
use model::metadata::Metadata;
use model::site_explorer::{
    Chassis, ComputerSystem, EndpointExplorationError, EndpointExplorationReport, EndpointType,
    ExploredDpu, ExploredEndpoint, ExploredManagedHost, UefiDevicePath,
};
use model::switch::SwitchSearchFilter;
use rpc::forge::GetSiteExplorationRequest;
use rpc::forge::forge_server::Forge;
use rpc::site_explorer::{
    ExploredDpu as RpcExploredDpu, ExploredManagedHost as RpcExploredManagedHost,
};
use rpc::{DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use sqlx::PgPool;
use tonic::Request;

use crate::sqlx_test;
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

#[derive(Clone, Debug)]
struct FakeMachine {
    pub mac: MacAddress,
    pub dhcp_vendor: String,
    pub relay_address: &'static str,
    pub ip: String,
}

const UNDERLAY_RELAY: &str = "192.0.1.1";
const ADMIN_RELAY: &str = "192.0.2.1";

impl FakeMachine {
    fn new_admin(mac: &str, vendor: &str) -> Self {
        Self {
            mac: mac.parse().unwrap(),
            dhcp_vendor: vendor.to_string(),
            relay_address: ADMIN_RELAY,
            ip: String::new(),
        }
    }

    fn new(mac: &str, vendor: &str) -> Self {
        Self {
            mac: mac.parse().unwrap(),
            dhcp_vendor: vendor.to_string(),
            relay_address: UNDERLAY_RELAY,
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

trait DiscoverDhcp {
    async fn discover_dhcp(&mut self, env: &TestEnv) -> Result<(), Box<dyn std::error::Error>>;
}

impl DiscoverDhcp for FakeMachine {
    async fn discover_dhcp(&mut self, env: &TestEnv) -> Result<(), Box<dyn std::error::Error>> {
        let response = env
            .api
            .discover_dhcp(
                DhcpDiscovery::builder(self.mac, self.relay_address)
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

impl DiscoverDhcp for Vec<FakeMachine> {
    async fn discover_dhcp(&mut self, env: &TestEnv) -> Result<(), Box<dyn std::error::Error>> {
        for machine in self.iter_mut() {
            machine.discover_dhcp(env).await?
        }
        Ok(())
    }
}

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

#[sqlx_test]
async fn test_site_explorer_default_pause_ingestion_and_poweron(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let underlay_segment = env.underlay_segment.unwrap();

    let bmc_mac_address = "6a:6b:6c:6d:6e:6f".parse().unwrap();
    let mut txn = pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address,
            data: ExpectedMachineData {
                bmc_username: "ADMIN".into(),
                bmc_password: "Pwd2023x0x0x0x0x7".into(),
                serial_number: "VVG121GL".into(),
                dpu_mode: model::expected_machine::DpuMode::NoDpu,
                default_pause_ingestion_and_poweron: Some(true),
                ..Default::default()
            },
        },
    )
    .await
    .unwrap();
    txn.commit().await?;

    let mut machines = vec![FakeMachine::new(&bmc_mac_address.to_string(), "Vendor1")];
    machines.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &underlay_segment)
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
        enabled: Arc::new(true.into()),
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        ..Default::default()
    };
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);

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
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
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

    let machine_snapshots =
        db::managed_host::load_all(&env.pool, LoadSnapshotOptions::default()).await?;
    assert_eq!(machine_snapshots.len(), 0);
    let explored_managed_hosts = db::explored_managed_host::find_all(&env.pool).await?;
    assert_eq!(explored_managed_hosts.len(), 0);

    // now flip the flag and run another interation
    let _ = env
        .api
        .allow_ingestion_and_power_on(tonic::Request::new(rpc::forge::BmcEndpointRequest {
            mac_address: Some("6a:6b:6c:6d:6e:6f".to_string()),
            ip_address: "".to_string(),
        }))
        .await?;

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

    let explored_managed_hosts = db::explored_managed_host::find_all(&env.pool).await?;
    assert_eq!(explored_managed_hosts.len(), 1);
    let machine_snapshots =
        db::managed_host::load_all(&env.pool, LoadSnapshotOptions::default()).await?;
    assert_eq!(machine_snapshots.len(), 1);

    Ok(())
}

#[sqlx_test]
async fn test_site_explorer_main(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let underlay_segment = env.underlay_segment.unwrap();

    // Let's create 3 machines on the underlay, and 1 on the admin network
    // The 1 on the admin network is not supposed to be searched. This is verified
    // by providing no mocked exploration data for this machine, which would lead
    // to a panic if the machine is queried
    let mut machines = vec![
        // machines[0] is a DPU belonging to machines[1]
        FakeMachine::new("B8:3F:D2:90:97:A6", "Vendor1"),
        // machines[1] has 1 dpu (machines[0])
        FakeMachine::new("AA:AB:AC:AD:AA:02", "Vendor2"),
        // machines[2] has no DPUs
        FakeMachine::new("AA:AB:AC:AD:AA:03", "Vendor3"),
        // machines[3] is not on the underlay network and should not be searched.
        FakeMachine::new_admin("AA:AB:AC:AD:BB:01", "VendorInvalidSegment"),
    ];
    machines.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &underlay_segment)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, env.admin_segment_ref())
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();

    // Register `expected_machines` so site-explorer accepts these hosts: the
    // host with a DPU pair takes the default `DpuMode`, and the zero-DPU host
    // declares `NoDpu` to pass the strict ingestion gate.
    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: machines[1].mac,
            data: ExpectedMachineData {
                serial_number: "host-with-dpu".to_string(),
                ..Default::default()
            },
        },
    )
    .await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: machines[2].mac,
            data: ExpectedMachineData {
                serial_number: "host-with-no-dpu".to_string(),
                dpu_mode: model::expected_machine::DpuMode::NoDpu,
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

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
                remediation_error: None,
            }),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_power_shelves: Arc::new(true.into()),
        explore_power_shelves_from_static_ip: Arc::new(true.into()),
        power_shelves_created_per_run: 1,
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);
    let test_meter = &env.test_meter;

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
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
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
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
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
    assert_eq!(explored.len(), 3);
    let mut versions = Vec::new();
    for report in &explored {
        versions.push(report.report_version.version_nr());
        assert_eq!(report.report.endpoint_type, EndpointType::Bmc);
        match report.address.to_string() {
            a if a == machines[0].ip => {
                // The original successful report is retained, while only the latest
                // exploration failure details are updated.
                assert_eq!(report.report.vendor, Some(bmc_vendor::BMCVendor::Nvidia));
                assert_eq!(
                    report.report.last_exploration_error.clone().unwrap(),
                    EndpointExplorationError::Unreachable {
                        details: Some("test_unreachable_detail".to_string())
                    }
                );
                assert!(report.report.last_exploration_latency.is_some());
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
        .filter(|m| m.relay_address == UNDERLAY_RELAY)
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

#[sqlx_test]
async fn test_site_explorer_audit_exploration_results(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let underlay_segment = env.underlay_segment.unwrap();

    let mut txn = pool.begin().await?;
    for (bmc_mac_address, serial_number, fallback_dpu_serial_numbers) in [
        ("0a:0b:0c:0d:0e:0f", "VVG121GG", vec![]),
        ("1a:1b:1c:1d:1e:1f", "VVG121GH", vec![]),
        ("2a:2b:2c:2d:2e:2f", "VVG121GI", vec![]),
        ("3a:3b:3c:3d:3e:3f", "VVG121GJ", vec!["dpu_serial1"]),
        (
            "4a:4b:4c:4d:4e:4f",
            "VVG121GK",
            vec!["dpu_serial2", "dpu_serial3"],
        ),
        ("5a:5b:5c:5d:5e:5f", "VVG121GL", vec![]),
    ] {
        db::expected_machine::create(
            &mut txn,
            ExpectedMachine {
                id: None,
                bmc_mac_address: bmc_mac_address.parse().unwrap(),
                data: ExpectedMachineData {
                    bmc_username: "ADMIN".into(),
                    bmc_password: "Pwd2023x0x0x0x0x7".into(),
                    serial_number: serial_number.into(),
                    fallback_dpu_serial_numbers: fallback_dpu_serial_numbers
                        .into_iter()
                        .map(ToString::to_string)
                        .collect(),
                    ..Default::default()
                },
            },
        )
        .await
        .unwrap();
    }
    txn.commit().await?;

    let mut machines = vec![
        // This will be our expected DPU, and it will have the
        // expected serial number, but we assume no DPUs are expected,
        // should it still shouldn't be counted as `expected`        .
        FakeMachine::new("5a:5b:5c:5d:5e:5f", "Vendor1"),
        // This will be expected but unauthorized, and the serial is mismatched
        FakeMachine::new("0a:0b:0c:0d:0e:0f", "Vendor3"),
        // This host will be expected but missing credentials, and the serial is mismatched
        FakeMachine::new("1a:1b:1c:1d:1e:1f", "Vendor3"),
        // This host will be expected, but the serial number will be mismatched.
        FakeMachine::new("2a:2b:2c:2d:2e:2f", "Vendor3"),
        // This will be expected, with a good serial number.
        // It will also have associated DPUs and should get a managed host.
        FakeMachine::new("3a:3b:3c:3d:3e:3f", "Vendor3"),
        // This host is not expected.
        FakeMachine::new("ab:cd:ef:ab:cd:ef", "Vendor3"),
        // This DPU is really not expected. (i.e. no DB entry)
        FakeMachine::new("ef:cd:ab:ef:cd:ab", "Vendor3"),
    ];

    machines.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &underlay_segment)
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
                remediation_error: None,
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
                remediation_error: None,
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
                remediation_error: None,
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
                remediation_error: None,
            },
        ),
        (
            // This is the DPU from machines[4]
            machines[6].ip.parse().unwrap(),
            machine_4_host.dpus[0].clone().into(),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 7,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        machines_created_per_run: 1,
        override_target_ip: None,
        override_target_port: None,
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
        dpu_mode: None,
        // Tests use MockEndpointExplorer. So this doesn't affect anything.
        explore_mode: SiteExplorerExploreMode::NvRedfish,
    };
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);
    let test_meter = &env.test_meter;

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
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
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

#[sqlx_test]
async fn test_site_explorer_reexplore(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let underlay_segment = env.underlay_segment.unwrap();

    let mut machines = vec![
        FakeMachine::new("B8:3F:D2:90:97:A6", "Vendor1"),
        FakeMachine::new("AA:AB:AC:AD:AA:02", "Vendor2"),
    ];

    machines.discover_dhcp(&env).await?;

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &underlay_segment)
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
        enabled: Arc::new(true.into()),
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

    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 1 entries, we should have 1 results now
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);
    let explored_ip = explored[0].address;

    for report in &explored {
        assert_eq!(report.report_version.version_nr(), 1);
        assert!(!report.exploration_requested);
    }

    // Re-exploring the first endpoint should prioritize it while preserving
    // routine capacity for another endpoint.
    env.api
        .re_explore_endpoint(tonic::Request::new(rpc::forge::ReExploreEndpointRequest {
            ip_address: explored_ip.to_string(),
            if_version_match: None,
        }))
        .await
        .unwrap();

    // Calling the API should set the `exploration_requested` flag on the endpoint
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
    txn.commit().await?;
    for report in &explored {
        assert!(report.exploration_requested);
    }

    // The 2nd iteration updates the priority endpoint and still uses the
    // routine budget to discover another endpoint.
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 2);

    let reexplored = explored
        .iter()
        .find(|report| report.address == explored_ip)
        .unwrap();
    assert_eq!(reexplored.report_version.version_nr(), 2);
    assert!(!reexplored.exploration_requested);
    let current_version = reexplored.report_version;

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
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
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
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
    txn.commit().await?;
    let reexplored = explored
        .iter()
        .find(|report| report.address == explored_ip)
        .unwrap();
    assert!(reexplored.exploration_requested);

    // 3rd iteration still yields the same two known endpoints.
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 2);

    Ok(())
}

#[sqlx_test]
async fn test_site_explorer_clear_last_known_error(
    pool: PgPool,
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
async fn test_fallback_dpu_serial(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    const HOST1_DPU_BMC_MAC: &str = "B8:3F:D2:90:97:A6";
    const HOST1_BMC_MAC: &str = "AA:AB:AC:AD:AA:02";
    const HOST1_DPU_SERIAL_NUMBER: &str = "host1_dpu_serial_number";

    let mut host1_dpu_bmc = FakeMachine::new(HOST1_DPU_BMC_MAC, "NVIDIA/BF/BMC");

    let mut host1_bmc = FakeMachine::new(HOST1_BMC_MAC, "Vendor2");

    // Create dhcp entries and machine_interface entries for the machines
    for machine in [&mut host1_dpu_bmc, &mut host1_bmc] {
        machine.discover_dhcp(&env).await?;
    }
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Create a host and dpu reports && host has no dpu_serial
    let host1_dpu_report = DpuConfig {
        serial: HOST1_DPU_SERIAL_NUMBER.to_string(),
        bmc_mac_address: HOST1_DPU_BMC_MAC.parse()?,
        ..Default::default()
    };
    let host1_report = ManagedHostConfig {
        bmc_mac_address: HOST1_BMC_MAC.parse()?,
        ..Default::default()
    };
    endpoint_explorer.insert_endpoint_results(vec![
        (
            host1_dpu_bmc.ip.parse().unwrap(),
            Ok(host1_dpu_report.into()),
        ),
        (host1_bmc.ip.parse().unwrap(), Ok(host1_report.into())),
    ]);

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
        ExpectedMachine {
            id: None,
            bmc_mac_address: HOST1_BMC_MAC.to_string().parse().unwrap(),
            data: ExpectedMachineData {
                bmc_username: "user1".to_string(),
                bmc_password: "pw".to_string(),
                serial_number: "host1".to_string(),
                fallback_dpu_serial_numbers: vec![],
                metadata: Metadata::new_with_default_name(),
                sku_id: Some("Sku1".to_string()),
                default_pause_ingestion_and_poweron: None,
                host_nics: vec![],
                rack_id: None,
                dpf_enabled: Some(true),
                bmc_ip_address: None,
                bmc_retain_credentials: None,
                dpu_mode: Default::default(),
                host_lifecycle_profile: Default::default(),
            },
        },
    )
    .await?;
    txn.commit().await?;

    // Run site explorer
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored_endpoints = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();

    // Mark explored endpoints as pre-ingestion_complete
    for ee in &explored_endpoints {
        db::explored_endpoints::set_preingestion_complete(ee.address, &mut txn).await?;
    }
    txn.commit().await?;

    assert_eq!(explored_endpoints.len(), 2);

    let mut explored_managed_hosts = db::explored_managed_host::find_all(&env.pool).await?;
    let mut machines =
        db::machine::find(&env.pool, ObjectFilter::All, MachineSearchConfig::default())
            .await
            .unwrap();

    // There should be no managed host
    assert_eq!(explored_managed_hosts.len(), 0);
    assert_eq!(machines.len(), 0);

    // Now update expected_machine entry with fallback_dpu_serial
    let mut txn = env.pool.begin().await?;
    let mut host1_expected_machine =
        db::expected_machine::find_by_bmc_mac_address(txn.as_mut(), HOST1_BMC_MAC.parse().unwrap())
            .await?
            .expect("Expected machine not found");
    host1_expected_machine.data = ExpectedMachineData {
        bmc_username: "user1".to_string(),
        bmc_password: "pw".to_string(),
        serial_number: "host1".to_string(),
        fallback_dpu_serial_numbers: vec![HOST1_DPU_SERIAL_NUMBER.to_string()],
        metadata: Metadata::new_with_default_name(),
        sku_id: None,
        default_pause_ingestion_and_poweron: None,
        host_nics: vec![],
        rack_id: None,
        dpf_enabled: Some(true),
        bmc_ip_address: None,
        bmc_retain_credentials: None,
        dpu_mode: Default::default(),
        host_lifecycle_profile: Default::default(),
    };
    db::expected_machine::update(&mut txn, &host1_expected_machine).await?;
    txn.commit().await?;

    explorer.run_single_iteration().await.unwrap();
    explored_managed_hosts = db::explored_managed_host::find_all(&env.pool).await?;
    machines = db::machine::find(&env.pool, ObjectFilter::All, MachineSearchConfig::default())
        .await
        .unwrap();

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
    let mut bmc_ip_addresses = vec![explored_managed_hosts[0].host_bmc_ip.to_string()];
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

async fn fetch_exploration_report(env: &TestEnv) -> rpc::site_explorer::SiteExplorationReport {
    env.api
        .get_site_exploration_report(tonic::Request::new(GetSiteExplorationRequest::default()))
        .await
        .unwrap()
        .into_inner()
}

#[sqlx_test]
async fn test_fetch_host_primary_interface_mac(
    pool: PgPool,
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
                    .vendor_string("NVIDIA/BF/BMC")
                    .tonic_request(),
            )
            .await
            .unwrap()
            .into_inner();

        assert!(!response.address.is_empty());
        let oob_interface =
            db::machine_interface::find_by_mac_address(txn.as_mut(), oob_mac).await?;
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
        ..Default::default()
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
        ..Default::default()
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
        ..Default::default()
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
    let host_endpoints =
        db::explored_endpoints::find_all_by_ip(IpAddr::from_str(host_ip)?, &mut txn).await?;
    assert_eq!(host_endpoints.len(), 1);

    let dpu_endpoints =
        db::explored_endpoints::find_all_by_ip(IpAddr::from_str(dpu_ip)?, &mut txn).await?;
    assert_eq!(dpu_endpoints.len(), 1);
    txn.commit().await?;

    Ok(())
}

#[sqlx_test]
async fn test_machine_creation_with_sku(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    const HOST1_DPU_BMC_MAC: &str = "B8:3F:D2:90:97:A6";
    const HOST1_BMC_MAC: &str = "AA:AB:AC:AD:AA:02";
    const HOST1_DPU_SERIAL_NUMBER: &str = "host1_dpu_serial_number";

    let mut host1_dpu_bmc = FakeMachine::new(HOST1_DPU_BMC_MAC, "NVIDIA/BF/BMC");

    let mut host1_bmc = FakeMachine::new(HOST1_BMC_MAC, "Vendor2");

    // Create dhcp entries and machine_interface entries for the machines
    for machine in [&mut host1_dpu_bmc, &mut host1_bmc] {
        machine.discover_dhcp(&env).await?;
    }
    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    // Create a host and dpu reports && host has no dpu_serial
    let host1_dpu_report = DpuConfig {
        serial: HOST1_DPU_SERIAL_NUMBER.to_string(),
        bmc_mac_address: HOST1_DPU_BMC_MAC.parse()?,
        ..Default::default()
    };
    let host1_report = ManagedHostConfig {
        bmc_mac_address: HOST1_BMC_MAC.parse()?,
        ..Default::default()
    };
    endpoint_explorer.insert_endpoint_results(vec![
        (
            host1_dpu_bmc.ip.parse().unwrap(),
            Ok(host1_dpu_report.into()),
        ),
        (host1_bmc.ip.parse().unwrap(), Ok(host1_report.into())),
    ]);

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
    let test_meter = &env.test_meter;

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
        ExpectedMachine {
            id: None,
            bmc_mac_address: HOST1_BMC_MAC.to_string().parse().unwrap(),
            data: ExpectedMachineData {
                bmc_username: "user1".to_string(),
                bmc_password: "pw".to_string(),
                serial_number: "host1".to_string(),
                fallback_dpu_serial_numbers: vec![],
                metadata: Metadata::new_with_default_name(),
                sku_id: Some("Sku1".to_string()),
                default_pause_ingestion_and_poweron: None,
                host_nics: vec![],
                rack_id: None,
                dpf_enabled: Some(true),
                bmc_ip_address: None,
                bmc_retain_credentials: None,
                dpu_mode: Default::default(),
                host_lifecycle_profile: Default::default(),
            },
        },
    )
    .await?;
    txn.commit().await?;

    // Run site explorer
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored_endpoints = db::explored_endpoints::find_all(txn.as_mut())
        .await
        .unwrap();

    // Mark explored endpoints as pre-ingestion_complete
    for ee in &explored_endpoints {
        db::explored_endpoints::set_preingestion_complete(ee.address, &mut txn).await?;
    }
    txn.commit().await?;

    assert_eq!(explored_endpoints.len(), 2);

    let machines = db::machine::find(&env.pool, ObjectFilter::All, MachineSearchConfig::default())
        .await
        .unwrap();

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

#[sqlx_test]
async fn test_site_explorer_switch_discovery(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let bmc_mac: MacAddress = "B8:3F:D2:90:97:C0".parse().unwrap();
    let serial_number = "SW-SN-001".to_string();
    let bmc_username = "ADMIN".to_string();
    let bmc_password = "Pwd2023".to_string();

    let response = env
        .api
        .discover_dhcp(DhcpDiscovery::builder(bmc_mac.to_string(), UNDERLAY_RELAY).tonic_request())
        .await?
        .into_inner();
    tracing::info!("DHCP with mac {} assigned ip {}", bmc_mac, response.address);
    let switch_ip = response.address.clone();

    let mut txn = env.pool.begin().await?;
    let expected_switch = model::expected_switch::ExpectedSwitch {
        expected_switch_id: None,
        bmc_mac_address: bmc_mac,
        nvos_mac_addresses: vec![bmc_mac],
        serial_number: serial_number.clone(),
        bmc_username: bmc_username.clone(),
        bmc_password: bmc_password.clone(),
        nvos_username: None,
        nvos_password: None,
        bmc_ip_address: None,
        nvos_ip_address: None,
        metadata: Metadata {
            name: format!("Test Switch {}", serial_number),
            description: format!("A test switch with serial {}", serial_number),
            labels: HashMap::new(),
        },
        rack_id: None,
        bmc_retain_credentials: None,
    };
    db::expected_switch::create(&mut txn, expected_switch).await?;
    txn.commit().await?;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());

    endpoint_explorer.insert_endpoint_result(
        switch_ip.parse().unwrap(),
        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            machine_id: None,
            managers: Vec::new(),
            systems: vec![ComputerSystem {
                serial_number: Some(serial_number.clone()),
                ..Default::default()
            }],
            chassis: vec![Chassis {
                id: "mgx_nvswitch_0".to_string(),
                model: Some("Switch".to_string()),
                manufacturer: Some("NVIDIA".to_string()),
                serial_number: Some(serial_number.clone()),
                part_number: Some(serial_number.clone()),
                ..Default::default()
            }],
            service: Vec::new(),
            versions: HashMap::default(),
            model: Some("Switch".to_string()),
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,
            compute_tray_index: None,
            physical_slot_number: None,
            revision_id: None,
            topology_id: None,
            remediation_error: None,
        }),
    );

    let explorer_config = SiteExplorerConfig {
        enabled: Arc::new(true.into()),
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: Arc::new(true.into()),
        create_switches: Arc::new(true.into()),
        switches_created_per_run: 1,
        ..Default::default()
    };
    let explorer = env.new_site_explorer(explorer_config, &endpoint_explorer);
    let test_meter = &env.test_meter;

    explorer.run_single_iteration().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let explored = db_explored_endpoints::find_all(txn.as_mut()).await.unwrap();
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
    db_explored_endpoints::set_preingestion_complete(switch_ip.parse().unwrap(), &mut txn).await?;
    txn.commit().await?;

    explorer.run_single_iteration().await.unwrap();

    assert_eq!(
        test_meter
            .formatted_metric("carbide_endpoint_explorations_count")
            .unwrap(),
        "1"
    );

    let mut txn = env.pool.begin().await?;
    let switches = db::switch::find_ids(txn.as_mut(), SwitchSearchFilter::default()).await?;
    println!("switches: {:?}", switches);
    txn.commit().await?;
    assert_eq!(switches.len(), 1, "Expected one switch to be created");

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

/// Integration regression guard for the auto-correct path: when an
/// `ExpectedMachine` declares `DpuMode::NicMode` but the discovered DPU
/// hardware is reporting `nic_mode: Dpu`, site-explorer should call
/// `set_nic_mode(Nic)` on the DPU during its per-host matching loop.
///
/// This exercises the full wire (site-explorer iteration → per-host mode
/// resolution → `check_and_configure_dpu_mode` → mock Redfish
/// `set_nic_mode`) that the unit tests only cover in pieces.
#[sqlx_test]
async fn test_site_explorer_auto_corrects_nic_mode_per_expected_machine(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use model::expected_machine::{DpuMode, ExpectedMachine, ExpectedMachineData};
    use model::site_explorer::NicMode;

    let env = common::api_fixtures::create_test_env(pool).await;

    // DPU hardware reports DPU mode (so it looks like a "properly
    // configured" DPU to the BF3-DPU heuristic) -- the operator-declared
    // override is what forces the correction to NIC mode.
    let dpu_config = common::api_fixtures::dpu::DpuConfig {
        nic_mode: Some(NicMode::Dpu),
        ..Default::default()
    };
    let mock_host =
        common::api_fixtures::managed_host::ManagedHostConfig::with_dpus(vec![dpu_config.clone()]);
    let host_bmc_mac = mock_host.bmc_mac_address;

    // Seed an ExpectedMachine with `dpu_mode: NicMode` that matches the
    // mock host's BMC MAC. Site-explorer's per-host resolution will look
    // this up by IP via the expected-endpoint index after DHCP assigns
    // the host its BMC IP.
    let mut txn = env.pool.begin().await?;
    db::expected_machine::create(
        &mut txn,
        ExpectedMachine {
            id: None,
            bmc_mac_address: host_bmc_mac,
            data: ExpectedMachineData {
                bmc_username: "ADMIN".to_string(),
                bmc_password: "PASS".to_string(),
                serial_number: "EM-866-NIC-OVERRIDE".to_string(),
                metadata: model::metadata::Metadata::new_with_default_name(),
                dpu_mode: DpuMode::NicMode,
                ..Default::default()
            },
        },
    )
    .await?;
    txn.commit().await?;

    // Drive the same ingestion flow as the singledpu fixture test: BMC
    // DHCP for host + DPU, seed mock exploration results, run site-
    // explorer iteration. We don't care about the final managed host
    // state here -- we only care that `set_nic_mode` was called with the
    // right target during the matching loop.
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
        // Second iteration: per-host DPU matching + check_and_configure_dpu_mode.
        .run_site_explorer_iteration()
        .await;

    let calls = env.endpoint_explorer.set_nic_mode_calls.lock().unwrap();
    assert!(
        calls.iter().any(|(_, mode)| *mode == NicMode::Nic),
        "expected at least one set_nic_mode(Nic) call triggered by the operator's NicMode declaration; calls so far: {calls:?}"
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

fn explored_managed_switch_fixture(
    bmc_ip: IpAddr,
    nvos_mac: MacAddress,
    chassis_serial: Option<&str>,
) -> model::site_explorer::ExploredManagedSwitch {
    let chassis = Chassis {
        id: "mgx_nvswitch_0".to_string(),
        manufacturer: Some("NVIDIA".to_string()),
        model: Some("Switch".to_string()),
        serial_number: chassis_serial.map(String::from),
        part_number: chassis_serial.map(String::from),
        ..Default::default()
    };
    model::site_explorer::ExploredManagedSwitch {
        bmc_ip,
        nv_os_mac_addresses: vec![nvos_mac],
        report: EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            chassis: vec![chassis],
            model: Some("Switch".to_string()),
            ..Default::default()
        },
    }
}

fn expected_switch_fixture(
    bmc_mac: MacAddress,
    nvos_mac: MacAddress,
    serial: &str,
) -> model::expected_switch::ExpectedSwitch {
    model::expected_switch::ExpectedSwitch {
        expected_switch_id: None,
        bmc_mac_address: bmc_mac,
        nvos_mac_addresses: vec![nvos_mac],
        serial_number: serial.to_string(),
        bmc_username: "ADMIN".to_string(),
        bmc_password: "Pwd2023".to_string(),
        nvos_username: None,
        nvos_password: None,
        bmc_ip_address: None,
        nvos_ip_address: None,
        metadata: Metadata {
            name: format!("Test Switch {serial}"),
            description: String::new(),
            labels: HashMap::new(),
        },
        rack_id: None,
        bmc_retain_credentials: None,
    }
}

/// When a switch is rediscovered with a chassis serial that hashes to a new
/// `SwitchId`, the BMC MAC check must keep us from inserting a second record.
#[sqlx_test]
async fn switch_skips_creation_when_bmc_mac_already_used(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let bmc_mac: MacAddress = "B8:3F:D2:90:97:D0".parse().unwrap();
    let nvos_mac: MacAddress = "B8:3F:D2:90:97:D1".parse().unwrap();

    let expected_switch = expected_switch_fixture(bmc_mac, nvos_mac, "SW-DRIFT");
    let mut txn = env.pool.begin().await?;
    db::expected_switch::create(&mut txn, expected_switch.clone()).await?;
    txn.commit().await?;

    let switch_creator =
        carbide_site_explorer::SwitchCreator::new(env.pool.clone(), SiteExplorerConfig::default());

    // First discovery, we get a real serial, which succeeds,
    // and inserts a switches row.
    assert!(
        switch_creator
            .create_managed_switch(
                &explored_managed_switch_fixture(
                    "10.0.0.1".parse().unwrap(),
                    nvos_mac,
                    Some("SW-DRIFT-v1"),
                ),
                &expected_switch,
                &env.pool,
            )
            .await?,
        "first discovery must create a switch row"
    );

    let mut txn = env.pool.begin().await?;
    let ids_after_first = db::switch::find_ids(txn.as_mut(), SwitchSearchFilter::default()).await?;
    txn.commit().await?;
    assert_eq!(ids_after_first.len(), 1);
    let original_id = ids_after_first[0];

    // Second discovery, we hit the same BMC MAC, but get a different chassis serial.
    // Without the BMC MAC check, this would give us a different SwitchId and insert
    // a second record.
    assert!(
        !switch_creator
            .create_managed_switch(
                &explored_managed_switch_fixture(
                    "10.0.0.1".parse().unwrap(),
                    nvos_mac,
                    Some("SW-DRIFT-v2"),
                ),
                &expected_switch,
                &env.pool,
            )
            .await?,
        "second discovery with drifted fingerprint must not create a duplicate row"
    );

    let mut txn = env.pool.begin().await?;
    let ids_after_second =
        db::switch::find_ids(txn.as_mut(), SwitchSearchFilter::default()).await?;
    txn.commit().await?;
    assert_eq!(
        ids_after_second,
        vec![original_id],
        "exactly one switch row, original ID preserved"
    );

    Ok(())
}

/// A switch BMC reporting `"NA"` for its chassis serial is treated as a
/// missing serial: `generate_switch_id` should error with
/// `MissingHardwareInfo::Serial` rather than give us a junk `SwitchId`, and
/// no record gets created. The next exploration cycle picks the switch up
/// once a real serial is reported.
#[sqlx_test]
async fn switch_treats_na_chassis_serial_as_missing(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let bmc_mac: MacAddress = "B8:3F:D2:90:97:D2".parse().unwrap();
    let nvos_mac: MacAddress = "B8:3F:D2:90:97:D3".parse().unwrap();

    let expected_switch = expected_switch_fixture(bmc_mac, nvos_mac, "SW-NA");
    let mut txn = env.pool.begin().await?;
    db::expected_switch::create(&mut txn, expected_switch.clone()).await?;
    txn.commit().await?;

    let switch_creator =
        carbide_site_explorer::SwitchCreator::new(env.pool.clone(), SiteExplorerConfig::default());

    let result = switch_creator
        .create_managed_switch(
            &explored_managed_switch_fixture("10.0.0.2".parse().unwrap(), nvos_mac, Some("NA")),
            &expected_switch,
            &env.pool,
        )
        .await;
    assert!(
        result.is_err(),
        "placeholder NA chassis serial must surface as an error, got: {result:?}"
    );

    let mut txn = env.pool.begin().await?;
    let ids = db::switch::find_ids(txn.as_mut(), SwitchSearchFilter::default()).await?;
    txn.commit().await?;
    assert!(
        ids.is_empty(),
        "no switch row must be inserted when chassis serial is NA"
    );

    Ok(())
}
